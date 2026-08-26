// Package abuseshadow reads and aggregates the LOG-ONLY abuse-shadow log
// (/var/log/cfm/cfm.abuse_shadow.log) that the web detector's entity-abuse
// signals write (Signal C rate outliers, …; see docs/webdetector-refactor.md).
// It backs the read-only `abuse_shadow` MCP tool: a bounded on-demand tail +
// pure aggregation that answers "what would the shadow signals have challenged,
// and how much of it is verified good-bot / datacenter?" during burn-in, before
// any of it is promoted to a real challenge.
//
// Same cost discipline as the other on-demand log readers (maillog/mysqllog/
// edgelog): nothing retained, a call reads only the last N lines via `tail -n N`
// under a timeout. Parsing is pure and unit-tested.
package abuseshadow

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LogPath is the fixed abuse-shadow log location (matches internal/logging).
const LogPath = "/var/log/cfm/cfm.abuse_shadow.log"

const (
	defaultLines = 5000
	maxLines     = 200000
	scanTimeout  = 20 * time.Second
	readerBuf    = 1024 * 1024
)

// Entry is one parsed shadow line.
type Entry struct {
	Signal   string  `json:"signal"`
	Host     string  `json:"host"`
	IP       string  `json:"ip"`
	RPS      float64 `json:"rps"`
	Ratio    float64 `json:"ratio"`
	Reqs     int     `json:"reqs"`
	ASN      uint    `json:"asn"`
	CC       string  `json:"cc"` // ISO-2 country of the source IP (space-free)
	Provider string  `json:"provider"`
	GoodBot  string  `json:"good_bot"`
	Verdict  string  `json:"verdict"`

	// Vhost-level signal metrics (facet/cost/dc). These lines carry
	// verdict=would_shadow and their own keys instead of the rate-outlier's
	// ip/ratio/provider; zero when the line is a different signal.
	Urls      int     `json:"urls,omitempty"`      // facet: distinct full URLs
	Paths     int     `json:"paths,omitempty"`     // facet: distinct base paths
	Expansion float64 `json:"expansion,omitempty"` // facet: urls/paths
	Frac5xx   float64 `json:"frac5xx,omitempty"`   // cost: 5xx fraction
	DCFrac    float64 `json:"dc_frac,omitempty"`   // dc: unverified-datacenter fraction
	DCReqs    int     `json:"dc_reqs,omitempty"`   // dc: datacenter requests
	DCIPs     int     `json:"dc_ips,omitempty"`    // dc: distinct datacenter IPs
}

// Parse extracts an Entry from one log line. Returns ok=false for a line that
// isn't an abuse-shadow marker. This relies on a contract the emitter upholds:
// every value is space-free (host/ip/tags/numbers only), so a plain space-split
// of the `key=value` tail is exact. The one value derived from free-form ASN org
// names — provider — is canonicalized space-free at the source (DatacenterClass
// in internal/webdetector/asnclass.go strips interior spaces, e.g. "data center"
// -> "datacenter"); a space would split the field and drop the tail here.
func Parse(line string) (Entry, bool) {
	i := strings.Index(line, "[abuse-shadow] ")
	if i < 0 {
		return Entry{}, false
	}
	fields := strings.Fields(line[i+len("[abuse-shadow] "):])
	var e Entry
	got := false
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		got = true
		switch k {
		case "signal":
			e.Signal = v
		case "host":
			e.Host = v
		case "ip":
			e.IP = v
		case "rps":
			e.RPS, _ = strconv.ParseFloat(v, 64)
		case "ratio":
			e.Ratio, _ = strconv.ParseFloat(v, 64)
		case "reqs":
			e.Reqs, _ = strconv.Atoi(v)
		case "asn":
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				e.ASN = uint(n)
			}
		case "cc":
			e.CC = dash(v)
		case "provider":
			e.Provider = dash(v)
		case "good_bot":
			e.GoodBot = dash(v)
		case "verdict":
			e.Verdict = v
		case "urls":
			e.Urls, _ = strconv.Atoi(v)
		case "paths":
			e.Paths, _ = strconv.Atoi(v)
		case "expansion":
			e.Expansion, _ = strconv.ParseFloat(v, 64)
		case "frac5xx":
			e.Frac5xx, _ = strconv.ParseFloat(v, 64)
		case "dc_frac":
			e.DCFrac, _ = strconv.ParseFloat(v, 64)
		case "dc_reqs":
			e.DCReqs, _ = strconv.Atoi(v)
		case "dc_ips":
			e.DCIPs, _ = strconv.Atoi(v)
		}
	}
	if !got || e.Signal == "" {
		return Entry{}, false
	}
	return e, true
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// kv is a {key,count} pair for the top-N breakdowns.
type kv struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// topEntity is one would-challenge target with its peak observed strength.
type topEntity struct {
	Host     string  `json:"host"`
	IP       string  `json:"ip"`
	Hits     int     `json:"hits"`      // shadow log lines for this (host,ip)
	MaxRatio float64 `json:"max_ratio"` // peak rps/median seen
	MaxReqs  int     `json:"max_reqs"`
	CC       string  `json:"cc,omitempty"`
	Provider string  `json:"provider,omitempty"`
	GoodBot  string  `json:"good_bot,omitempty"`
}

// sigHost is one vhost flagged by a per-vhost signal (facet/cost/dc): the values
// from its STRONGEST firing (facet ranked by expansion, dc by datacenter
// fraction; cost has one metric) plus how many windows fired (Hits). Reporting a
// real firing's row — not a per-field max stitched across windows — keeps the row
// truthful. Fields are per-signal (only the relevant ones are non-zero), so the
// same struct serves all three top lists.
type sigHost struct {
	Host      string  `json:"host"`
	Hits      int     `json:"hits"`
	Urls      int     `json:"urls,omitempty"`
	Paths     int     `json:"paths,omitempty"`
	Expansion float64 `json:"expansion,omitempty"`
	Frac5xx   float64 `json:"frac5xx,omitempty"`
	DCFrac    float64 `json:"dc_frac,omitempty"`
	DCReqs    int     `json:"dc_reqs,omitempty"`
	DCIPs     int     `json:"dc_ips,omitempty"`
}

// Summary is the aggregate the endpoint returns.
type Summary struct {
	Total          int         `json:"total"`
	WouldChallenge int         `json:"would_challenge"`
	ExemptGoodbot  int         `json:"exempt_goodbot"`
	UniqueHosts    int         `json:"unique_hosts"`
	UniqueIPs      int         `json:"unique_ips"`
	BySignal       []kv        `json:"by_signal"`
	ByVerdict      []kv        `json:"by_verdict"`
	ByProvider     []kv        `json:"by_provider"` // datacenter tag distribution (would_challenge only)
	ByCountry      []kv        `json:"by_country"`  // ISO-2 country distribution (would_challenge only)
	ByGoodbot      []kv        `json:"by_good_bot"` // which good bots were exempted
	TopWouldBlock  []topEntity `json:"top_would_challenge"`

	// Per-vhost signal breakdowns — which hosts each new signal flagged, ranked by
	// its own peak metric. This is what answers "is facet flagging real floods or a
	// legit ?id= site?" and "which vhosts are datacenter-heavy?". Omitted when a
	// signal never fired in the window.
	TopFacet []sigHost `json:"top_facet,omitempty"` // by expansion (urls/paths)
	TopCost  []sigHost `json:"top_cost,omitempty"`  // by 5xx fraction
	TopDC    []sigHost `json:"top_dc,omitempty"`    // by datacenter fraction
}

// Summarize aggregates parsed lines. It ranks the top would_challenge entities
// by peak ratio (the strongest outliers), and keeps the provider/good-bot splits
// so an operator can see how much of the shadow is datacenter or verified bots.
func Summarize(lines []string) Summary {
	var s Summary
	bySignal := map[string]int{}
	byVerdict := map[string]int{}
	byProvider := map[string]int{}
	byCountry := map[string]int{}
	byGoodbot := map[string]int{}
	hosts := map[string]struct{}{}
	ips := map[string]struct{}{}
	ent := map[string]*topEntity{} // key host|ip, would_challenge only
	facetHosts := map[string]*sigHost{}
	costHosts := map[string]*sigHost{}
	dcHosts := map[string]*sigHost{}

	for _, ln := range lines {
		e, ok := Parse(ln)
		if !ok {
			continue
		}
		// Only DECISION lines are aggregated. dc_fraction also emits verdict-less
		// OPERATIONAL lines to the same log — a `verified_crawler=… excluded` FCrDNS
		// note (whose `ip=%s)` even carries a trailing paren) and a `deferred_vhosts=…
		// ip_enrich_budget` line. Counting those inflated Total/unique_ips/by_signal
		// and added a junk empty-key row to by_verdict; every real decision line
		// (rate_outlier would_challenge/exempt_goodbot, facet/cost/dc would_shadow)
		// carries a verdict and these two don't, so gate on it.
		if e.Verdict == "" {
			continue
		}
		s.Total++
		bySignal[e.Signal]++
		byVerdict[e.Verdict]++
		if e.Host != "" {
			hosts[e.Host] = struct{}{}
		}
		if e.IP != "" {
			ips[e.IP] = struct{}{}
		}
		// Per-vhost signal breakdowns, keyed by host, tracking the PEAK metric seen
		// across the window's firings (each line is one throttle window).
		if e.Host != "" {
			switch e.Signal {
			case "facet_expansion":
				h := facetHosts[e.Host]
				if h == nil {
					h = &sigHost{Host: e.Host}
					facetHosts[e.Host] = h
				}
				h.Hits++
				// Keep the single STRONGEST firing's row (ranked by expansion), not a
				// per-field max that could stitch urls/paths from different windows
				// into a row that never actually happened.
				if e.Expansion > h.Expansion {
					h.Expansion = e.Expansion
					h.Urls = e.Urls
					h.Paths = e.Paths
				}
			case "cost_pressure":
				h := costHosts[e.Host]
				if h == nil {
					h = &sigHost{Host: e.Host}
					costHosts[e.Host] = h
				}
				h.Hits++
				h.Frac5xx = max(h.Frac5xx, e.Frac5xx) // single metric — no synthetic-row risk
			case "dc_fraction":
				h := dcHosts[e.Host]
				if h == nil {
					h = &sigHost{Host: e.Host}
					dcHosts[e.Host] = h
				}
				h.Hits++
				// Strongest firing's row, ranked by datacenter fraction (see facet).
				if e.DCFrac > h.DCFrac {
					h.DCFrac = e.DCFrac
					h.DCReqs = e.DCReqs
					h.DCIPs = e.DCIPs
				}
			}
		}
		switch e.Verdict {
		case "would_challenge":
			s.WouldChallenge++
			if e.Provider != "" {
				byProvider[e.Provider]++
			}
			if e.CC != "" {
				byCountry[e.CC]++
			}
			k := e.Host + "|" + e.IP
			t := ent[k]
			if t == nil {
				t = &topEntity{Host: e.Host, IP: e.IP, CC: e.CC, Provider: e.Provider}
				ent[k] = t
			}
			t.Hits++
			if e.Ratio > t.MaxRatio {
				t.MaxRatio = e.Ratio
			}
			if e.Reqs > t.MaxReqs {
				t.MaxReqs = e.Reqs
			}
		case "exempt_goodbot":
			s.ExemptGoodbot++
			if e.GoodBot != "" {
				byGoodbot[e.GoodBot]++
			}
		}
	}
	s.UniqueHosts = len(hosts)
	s.UniqueIPs = len(ips)
	s.BySignal = topKV(bySignal, 20)
	s.ByVerdict = topKV(byVerdict, 20)
	s.ByProvider = topKV(byProvider, 20)
	s.ByCountry = topKV(byCountry, 20)
	s.ByGoodbot = topKV(byGoodbot, 20)

	tops := make([]topEntity, 0, len(ent))
	for _, t := range ent {
		tops = append(tops, *t)
	}
	sort.Slice(tops, func(i, j int) bool {
		if tops[i].MaxRatio != tops[j].MaxRatio {
			return tops[i].MaxRatio > tops[j].MaxRatio
		}
		return tops[i].MaxReqs > tops[j].MaxReqs
	})
	if len(tops) > 25 {
		tops = tops[:25]
	}
	s.TopWouldBlock = tops

	// Every comparator ends on Host (unique per map key) so the order — and thus
	// which host is dropped at the 25-cap — is deterministic across calls even when
	// the ranking metrics tie (sort.Slice is not stable).
	s.TopFacet = topSigHosts(facetHosts, func(a, b *sigHost) bool {
		if a.Expansion != b.Expansion {
			return a.Expansion > b.Expansion
		}
		if a.Urls != b.Urls {
			return a.Urls > b.Urls
		}
		return a.Host < b.Host
	})
	s.TopCost = topSigHosts(costHosts, func(a, b *sigHost) bool {
		if a.Frac5xx != b.Frac5xx {
			return a.Frac5xx > b.Frac5xx
		}
		return a.Host < b.Host
	})
	s.TopDC = topSigHosts(dcHosts, func(a, b *sigHost) bool {
		if a.DCFrac != b.DCFrac {
			return a.DCFrac > b.DCFrac
		}
		if a.DCReqs != b.DCReqs {
			return a.DCReqs > b.DCReqs
		}
		return a.Host < b.Host
	})
	return s
}

// topSigHosts flattens a per-host signal map, sorts by the given less func, and
// caps at 25.
func topSigHosts(m map[string]*sigHost, less func(a, b *sigHost) bool) []sigHost {
	if len(m) == 0 {
		return nil
	}
	out := make([]sigHost, 0, len(m))
	for _, h := range m {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return less(&out[i], &out[j]) })
	if len(out) > 25 {
		out = out[:25]
	}
	return out
}

func topKV(m map[string]int, limit int) []kv {
	out := make([]kv, 0, len(m))
	for k, c := range m {
		out = append(out, kv{Key: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ScanTail streams the last `lines` lines of the abuse-shadow log to fn. Returns
// the resolved log file ("" when it doesn't exist — not an error), the number of
// lines scanned, and any error. Bounded `tail -n N` backward read + timeout.
func ScanTail(ctx context.Context, lines int, fn func(string)) (logFile string, scanned int, err error) {
	if lines <= 0 {
		lines = defaultLines
	}
	if lines > maxLines {
		lines = maxLines
	}
	if fi, e := os.Stat(LogPath); e != nil || !fi.Mode().IsRegular() {
		return "", 0, nil // no log yet (feature off / never fired) → not an error
	}
	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, tailPath(), "-n", fmt.Sprintf("%d", lines), LogPath)
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return LogPath, 0, e
	}
	if e := cmd.Start(); e != nil {
		stdout.Close()
		return LogPath, 0, e
	}
	r := bufio.NewReaderSize(stdout, readerBuf)
	for {
		chunk, rerr := r.ReadSlice('\n')
		if len(chunk) > 0 {
			scanned++
			fn(strings.TrimRight(string(chunk), "\r\n"))
		}
		if rerr != nil {
			if rerr == bufio.ErrBufferFull {
				// over-long line: drain to next newline, keep going
				for rerr == bufio.ErrBufferFull {
					_, rerr = r.ReadSlice('\n')
				}
				if rerr == nil {
					continue
				}
			}
			break
		}
	}
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if cctx.Err() != nil {
		return LogPath, scanned, fmt.Errorf("scan timed out after %s", scanTimeout)
	}
	if waitErr != nil {
		return LogPath, scanned, fmt.Errorf("tail failed: %v", waitErr)
	}
	return LogPath, scanned, nil
}

func tailPath() string {
	if p, err := exec.LookPath("tail"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/tail", "/bin/tail"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "tail"
}
