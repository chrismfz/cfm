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
	"fmt"
	"net"
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
	ip  net.IP     // set when raw is a plain IP
	net *net.IPNet // set when raw is a CIDR
}

func parseQuery(arg string) (*query, error) {
	arg = strings.TrimSpace(arg)
	if strings.Contains(arg, "/") {
		_, n, err := net.ParseCIDR(arg)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", arg)
		}
		return &query{raw: arg, net: n}, nil
	}
	ip := net.ParseIP(arg)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", arg)
	}
	return &query{raw: arg, ip: ip}, nil
}

// matchesEntry reports whether a stored entry (plain IP, CIDR, or
// "from-to" range) matches the query, containment-aware in both
// directions.
func (q *query) matchesEntry(entry string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}

	// Range "a-b" (nft interval style). Only treated as a range when both
	// halves parse as IPs, so IPv6 colons or junk never misfire.
	if i := strings.Index(entry, "-"); i > 0 {
		from := net.ParseIP(strings.TrimSpace(entry[:i]))
		to := net.ParseIP(strings.TrimSpace(entry[i+1:]))
		if from != nil && to != nil {
			if q.ip != nil {
				return ipInRange(q.ip, from, to)
			}
			// CIDR query: overlap if either range end is inside the net
			// or the net's base is inside the range.
			return q.net.Contains(from) || q.net.Contains(to) || ipInRange(q.net.IP, from, to)
		}
	}

	// CIDR entry.
	if strings.Contains(entry, "/") {
		_, en, err := net.ParseCIDR(entry)
		if err != nil {
			return false
		}
		if q.ip != nil {
			return en.Contains(q.ip)
		}
		return netsOverlap(q.net, en)
	}

	// Plain IP entry.
	eip := net.ParseIP(entry)
	if eip == nil {
		return false
	}
	if q.ip != nil {
		return q.ip.Equal(eip)
	}
	return q.net.Contains(eip)
}

func ipInRange(ip, from, to net.IP) bool {
	ip16, f16, t16 := ip.To16(), from.To16(), to.To16()
	if ip16 == nil || f16 == nil || t16 == nil {
		return false
	}
	return bytesLE(f16, ip16) && bytesLE(ip16, t16)
}

func bytesLE(a, b net.IP) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return true
}

func netsOverlap(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	if (a.IP.To4() != nil) != (b.IP.To4() != nil) {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// Find probes every available source in parallel and aggregates hits.
// It never returns a partial-failure error: per-source problems land in
// Result.Skipped. The only error case is an unparsable query.
func Find(ctx context.Context, arg string, opts Options) (*Result, error) {
	q, err := parseQuery(arg)
	if err != nil {
		return nil, err
	}

	res := &Result{Query: q.raw, Skipped: map[string]string{}}
	var mu sync.Mutex
	add := func(locs ...Location) {
		mu.Lock()
		res.Locations = append(res.Locations, locs...)
		mu.Unlock()
	}
	skip := func(source, why string) {
		mu.Lock()
		res.Skipped[source] = why
		mu.Unlock()
	}

	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() { defer wg.Done(); fn() }()
	}

	// nft — reuse ipquery (already containment- and feed-aware).
	if opts.BE != nil {
		run(func() {
			hits, err := ipquery.Find(opts.BE, q.raw)
			if err != nil {
				skip("nft", trimErr(err))
				return
			}
			for _, h := range hits {
				add(Location{
					Source: "nft", List: h.Set, Action: h.Action,
					Match: h.Match, Feed: h.Feed,
				})
			}
		})
	} else {
		res.Skipped["nft"] = "no firewall backend"
	}

	// cfm.deny
	if opts.ConfigDir != "" {
		run(func() {
			locs, err := searchCFMDeny(opts.ConfigDir, q)
			if err != nil {
				skip("cfm.deny", trimErr(err))
				return
			}
			add(locs...)
		})
	} else {
		res.Skipped["cfm.deny"] = "no config dir"
	}

	// csf (file-based; works even when the csf service is stopped,
	// since csf.deny content is what csf would enforce).
	run(func() {
		locs, why := searchCSF(opts, q)
		if why != "" {
			skip("csf", why)
			return
		}
		add(locs...)
	})

	// fail2ban
	run(func() {
		locs, why := searchFail2Ban(ctx, q)
		if why != "" {
			skip("fail2ban", why)
			return
		}
		add(locs...)
	})

	// imunify360
	run(func() {
		locs, why := searchImunify(ctx, q)
		if why != "" {
			skip("imunify360", why)
			return
		}
		add(locs...)
	})

	wg.Wait()
	return res, nil
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
