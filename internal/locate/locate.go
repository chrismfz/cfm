// internal/locate/locate.go
//
// Package locate answers "where is this IP (or subnet) currently
// blocked/allowed on THIS server?" across every enforcement layer cfm
// knows about:
//
//   - nft        — the cfm table (manual sets, dyn sets, per-feed sets)
//   - cfm.deny   — the static deny file in the config dir
//   - csf        — csf.deny / csf.allow / csf.tempban / csf.tempallow
//   - fail2ban   — banned entries per jail
//   - imunify360 — local ip-list (white / drop / captcha=GRAY)
//
// Strictly read-only: no state is ever modified. Sources that are not
// installed / not active are reported in Result.Skipped instead of
// failing the whole lookup, so a partial answer is always returned.
//
// Matching is containment-based in both directions: a plain-IP query
// matches subnet entries that contain it, and a CIDR query matches
// host entries inside it as well as overlapping subnet entries.
package locate

import (
	"context"
	"strings"
	"sync"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/ipquery"
)

// Location is one place the queried IP/CIDR was found.
type Location struct {
	Source string `json:"source"`           // nft | cfm.deny | csf | fail2ban | imunify360
	List   string `json:"list"`             // set name / file / jail / purpose
	Action string `json:"action"`           // ALLOW | BLOCK | CHALLENGE | MATCH
	Match  string `json:"match"`            // the stored entry that matched (ip, cidr or range)
	Reason string `json:"reason,omitempty"` // comment / ban reason when the source records one
	Feed   string `json:"feed,omitempty"`   // nft feed key when applicable
}

const (
	ActionAllow     = "ALLOW"
	ActionBlock     = "BLOCK"
	ActionChallenge = "CHALLENGE"
	ActionMatch     = "MATCH"
)

// Result is the full per-server answer for one query.
type Result struct {
	Query     string            `json:"query"`
	Locations []Location        `json:"locations"`
	Skipped   map[string]string `json:"skipped,omitempty"` // source -> why it was not probed
}

// Options configures which sources Find can reach.
type Options struct {
	BE        firewall.Backend // nft backend; nil = nft skipped
	ConfigDir string           // for cfm.deny; "" = skipped
	// CSFDir / CSFDataDir override the default csf paths (tests).
	CSFDir     string // default /etc/csf
	CSFDataDir string // default /var/lib/csf
}

// query holds the parsed search argument (plain IP or CIDR).
type query struct {
	raw string
	ipquery.Query
}

func parseQuery(arg string) (*query, error) {
	arg = strings.TrimSpace(arg)
	q, err := ipquery.ParseQuery(arg)
	if err != nil {
		return nil, err
	}
	return &query{raw: arg, Query: q}, nil
}

// matchAll matches every query against a source's entries.
func matchAll(idx *ipquery.Index[Location], qs []*query) [][]Location {
	out := make([][]Location, len(qs))
	for i, q := range qs {
		out[i] = idx.Match(q.Query)
	}
	return out
}

// Find probes every available source in parallel and aggregates hits.
// It never returns a partial-failure error: per-source problems land in
// Result.Skipped. The only error case is an unparsable query.
func Find(ctx context.Context, arg string, opts Options) (*Result, error) {
	res, err := FindMany(ctx, []string{arg}, opts)
	if err != nil {
		return nil, err
	}
	return res[arg], nil
}

// FindMany is Find for many IPs/CIDRs: each source is read once — the nft
// table and its sets, cfm.deny, the csf files, fail2ban's ban list,
// imunify360's local list — and matched against every query, where Find per
// query read them all each time. Results are keyed by the argument as given;
// an unparsable argument is an error for the whole call.
func FindMany(ctx context.Context, args []string, opts Options) (map[string]*Result, error) {
	var qs []*query
	out := make(map[string]*Result, len(args))
	byArg := map[string]int{}
	for _, a := range args {
		if _, dup := byArg[a]; dup {
			continue
		}
		q, err := parseQuery(a)
		if err != nil {
			return nil, err
		}
		byArg[a] = len(qs)
		qs = append(qs, q)
		out[a] = &Result{Query: q.raw, Skipped: map[string]string{}}
	}
	if len(qs) == 0 {
		return out, nil
	}

	// Each source answers for every query: locations parallel to qs, or why
	// it couldn't be probed.
	type answer struct {
		locs    [][]Location
		why     string   // the source couldn't be probed
		partial string   // probed, but not all of it (locs stand)
		skip    []string // per query, where only some couldn't be answered
	}
	sources := []string{"nft", "cfm.deny", "csf", "fail2ban", "imunify360"}
	answers := make([]answer, len(sources))
	var wg sync.WaitGroup
	run := func(i int, fn func() answer) {
		wg.Add(1)
		go func() { defer wg.Done(); answers[i] = fn() }()
	}

	// nft — ipquery is containment- and feed-aware.
	if opts.BE != nil {
		run(0, func() answer {
			raws := make([]string, len(qs))
			for i, q := range qs {
				raws[i] = q.raw
			}
			hits, err := ipquery.FindMany(ctx, opts.BE, raws)
			if err != nil && hits == nil {
				return answer{why: trimErr(err)}
			}
			why := ""
			if err != nil { // ran out of time part-way: what was read stands
				why = "incomplete: " + trimErr(err)
			}
			locs := make([][]Location, len(qs))
			for i, q := range qs {
				for _, h := range hits[q.raw] {
					locs[i] = append(locs[i], Location{
						Source: "nft", List: h.Set, Action: h.Action,
						Match: h.Match, Feed: h.Feed,
					})
				}
			}
			return answer{locs: locs, partial: why}
		})
	} else {
		answers[0].why = "no firewall backend"
	}

	// cfm.deny
	if opts.ConfigDir != "" {
		run(1, func() answer {
			locs, err := searchCFMDeny(opts.ConfigDir, qs)
			if err != nil {
				return answer{why: trimErr(err)}
			}
			return answer{locs: locs}
		})
	} else {
		answers[1].why = "no config dir"
	}

	// csf (file-based; works even when the csf service is stopped,
	// since csf.deny content is what csf would enforce).
	run(2, func() answer {
		locs, why := searchCSF(opts, qs)
		return answer{locs: locs, why: why}
	})

	// fail2ban
	run(3, func() answer {
		locs, why := searchFail2Ban(ctx, qs)
		return answer{locs: locs, why: why}
	})

	// imunify360
	run(4, func() answer {
		locs, skip, why := searchImunify(ctx, qs)
		return answer{locs: locs, skip: skip, why: why}
	})

	wg.Wait()
	for a, i := range byArg {
		r := out[a]
		for s, ans := range answers {
			switch {
			case ans.why != "":
				r.Skipped[sources[s]] = ans.why
			case ans.partial != "":
				r.Skipped[sources[s]] = ans.partial
			case i < len(ans.skip) && ans.skip[i] != "":
				r.Skipped[sources[s]] = ans.skip[i]
			}
			if i < len(ans.locs) {
				r.Locations = append(r.Locations, ans.locs[i]...)
			}
		}
	}
	return out, nil
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// FindWithTimeout is a convenience wrapper for callers without a ctx.
func FindWithTimeout(arg string, opts Options, timeout time.Duration) (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return Find(ctx, arg, opts)
}
