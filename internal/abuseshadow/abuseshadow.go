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

	// Per-IP challenge_score signal metrics (internal/webdetector/challenge_score.go).
	// A decision line carries fp/score/solves/tells + verdict=would_harden|would_deny;
	// a store-cap NOTE line carries note=store_cap_reached + dropped= (verdict=would_shadow).
	// Zero/empty when the line is a different signal.
	FP      string  `json:"fp,omitempty"`      // anchoring TLS fingerprint ("-" → "")
	Score   float64 `json:"score,omitempty"`   // decayed per-IP challenge score
	Solves  int     `json:"solves,omitempty"`  // lifetime tell-bearing solves
	Fast    int     `json:"fast,omitempty"`    // fast-solve tell count
	UAImp   int     `json:"uaimp,omitempty"`   // UA-lie tell count
	Farm    int     `json:"farm,omitempty"`    // solver-farm-vhost tell count
	FarmFP  int     `json:"farmfp,omitempty"`  // convicted-fingerprint tell count (>0 → convicted fp seen)
	Note    string  `json:"note,omitempty"`    // non-decision note (e.g. store_cap_reached)
	Dropped int     `json:"dropped,omitempty"` // solves dropped at the store cap (note line)

	// Humanity (ChallengeV2 Rung 1) would_v2 metrics
	// (internal/webdetector/challenge_server.go): a solve that WOULD have been
	// rejected had a challenge_v2 arm covered it. hs/tells are always present;
	// the context keys (ptr/ua_family/ua_bot/src, plus cc/asn/provider above)
	// ride only on lines from daemons that write them — an older line simply
	// lacks them. Zero/empty when the line is a different signal.
	HS       int    `json:"hs,omitempty"`        // humanity score
	Tells    string `json:"tells,omitempty"`     // comma-joined tells that fired
	PTR      string `json:"ptr,omitempty"`       // client reverse DNS ("invalid" = not a plain token)
	UAFamily string `json:"ua_family,omitempty"` // uaplausible family ("-" → "")
	UABot    bool   `json:"ua_bot,omitempty"`    // the UA SELF-DECLARES a bot (unverified)
	Src      string `json:"src,omitempty"`       // challenge provenance snapshot ("-" = none covered)
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
		case "fp":
			e.FP = dash(v) // emitter writes "-" when no X-CFM-TLS stamp
		case "score":
			e.Score, _ = strconv.ParseFloat(v, 64)
		case "solves":
			e.Solves, _ = strconv.Atoi(v)
		case "fast":
			e.Fast, _ = strconv.Atoi(v)
		case "uaimp":
			e.UAImp, _ = strconv.Atoi(v)
		case "farm":
			e.Farm, _ = strconv.Atoi(v)
		case "farmfp":
			e.FarmFP, _ = strconv.Atoi(v)
		case "note":
			e.Note = v
		case "dropped":
			e.Dropped, _ = strconv.Atoi(v)
		case "hs":
			e.HS, _ = strconv.Atoi(v)
		case "tells":
			e.Tells = v
		case "ptr":
			e.PTR = v
		case "ua_family":
			e.UAFamily = dash(v)
		case "ua_bot":
			e.UABot = v == "1"
		case "src":
			e.Src = v // "-" kept: it means "resolved, none covered", not absent
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

	// Per-IP challenge_score signal breakdown — the ONE view that surfaces the
	// would_harden soft rung, which is LOG-ONLY (only would_deny is persisted to
	// detection_history / the fleet ledger, throttled to 1/hr/IP). Omitted when no
	// challenge_score line fired in the window. See ChalScoreSummary.
	ChallengeScore *ChalScoreSummary `json:"challenge_score,omitempty"`

	// Humanity would_v2 breakdown — the solves ChallengeV2 Rung 1 WOULD have
	// rejected had an arm covered them, split by what challenged them (src) and
	// who they are. This is the sizing view for any new v2 arm: e.g. how many
	// would-rejects an auto-vhost v2 arm would add (by_src_kind "vhost") and
	// who they are (by_provider / by_ptr_domain / ua_bot). Omitted when no
	// would_v2 line fired in the window. See HumanitySummary.
	Humanity *HumanitySummary `json:"humanity,omitempty"`
}

// HumanitySummary aggregates the signal=humanity verdict=would_v2 lines.
// Everything here is shadow: an unarmed solve that would have failed was
// cleared as usual. Lines written before the context keys existed carry no
// src= and count as "(unknown)" in by_src_kind — with_context says how many
// lines could be attributed at all.
type HumanitySummary struct {
	Lines         int  `json:"lines"`
	DistinctIPs   int  `json:"distinct_ips"`
	DistinctHosts int  `json:"distinct_hosts"`
	WithContext   int  `json:"with_context"` // lines carrying src= (attributable)
	UABot         int  `json:"ua_bot"`       // lines whose UA self-declares a bot (unverified)
	BySrcKind     []kv `json:"by_src_kind"`  // per line, each distinct kind once: waf/ip/vhost/rule/fp/geo, "-" none, "(unknown)" no src=
	BySrc         []kv `json:"by_src"`       // full tokens, e.g. vhost:suspicious_vhost, waf:302
	ByFP          []kv `json:"by_fp"`
	ByTells       []kv `json:"by_tells"`
	ByProvider    []kv `json:"by_provider"`
	ByCountry     []kv `json:"by_country"`
	ByPTRDomain   []kv `json:"by_ptr_domain"` // last two PTR labels; "(none)" = context line without a PTR
}

// ChalScoreSummary is the per-IP challenge_score signal's dedicated view. The
// signal fuses a solve's tells (a convicted solver-farm FINGERPRINT — the spine,
// a UA-lie, a solver-farm vhost, a too-fast solve) into a decaying per-IP score
// and logs would_harden (soft, T1) / would_deny (hard, T2). Only would_deny is
// persisted durably (detection_history → cfm-web), and throttled to one row/hour/IP,
// so this LOG-derived view is the only place the would_harden population and the raw
// per-fingerprint / per-IP structure are visible fleet-wide. Nothing here is
// enforced. See internal/webdetector/challenge_score.go and docs/challenge-score.md.
type ChalScoreSummary struct {
	Lines       int     `json:"lines"`             // challenge_score DECISION lines in the window
	WouldHarden int     `json:"would_harden"`      // soft rung (T1) — LOG-ONLY, never persisted
	WouldDeny   int     `json:"would_deny"`        // hard rung (T2) — the ledger's 2nd source (throttled)
	Dropped     int     `json:"dropped,omitempty"` // solves dropped at the store cap (from note lines)
	DistinctIPs int     `json:"distinct_ips"`      // distinct source IPs across challenge_score lines
	DistinctFPs int     `json:"distinct_fps"`      // distinct anchoring fingerprints (excludes the empty "-")
	MaxScore    float64 `json:"max_score"`         // peak decayed score seen

	ByFP []chalFP       `json:"by_fp"` // top anchoring fingerprints by line count
	Top  []chalOffender `json:"top"`   // top offenders by peak score
}

// chalFP is one anchoring fingerprint's challenge_score footprint. `convicted` is
// true when any line for it carried farmfp>0 — i.e. the fingerprint was, at least
// once, a CONVICTED solver-farm fp while scoring (the strongest tell). fp "(none)"
// groups the lines with no X-CFM-TLS stamp: older edge, plain HTTP, or a vhost
// behind Cloudflare (the edge sends no fingerprint for a trusted-proxy relay).
type chalFP struct {
	FP          string  `json:"fp"`
	Lines       int     `json:"lines"`
	DistinctIPs int     `json:"distinct_ips"`
	WouldHarden int     `json:"would_harden"`
	WouldDeny   int     `json:"would_deny"`
	MaxScore    float64 `json:"max_score"`
	Convicted   bool    `json:"convicted"`
}

// chalOffender is one source IP's strongest (peak-score) challenge_score line, with
// the tell breakdown that opened the score.
type chalOffender struct {
	IP      string  `json:"ip"`
	FP      string  `json:"fp,omitempty"`
	Score   float64 `json:"score"`
	Verdict string  `json:"verdict"`
	Solves  int     `json:"solves"`
	Fast    int     `json:"fast"`
	UAImp   int     `json:"uaimp"`
	Farm    int     `json:"farm"`
	FarmFP  int     `json:"farmfp"`
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

	// challenge_score (per-IP signal) accumulators — its own verdict space
	// (would_harden/would_deny) and per-fingerprint structure. csFP is the running
	// per-fingerprint tally; the maps are flattened + capped after the scan.
	type csFP struct {
		lines, harden, deny int
		ips                 map[string]struct{}
		maxScore            float64
		convicted           bool
	}
	var csLines, csHarden, csDeny, csDropped int
	csMaxScore := 0.0
	csIPs := map[string]struct{}{}
	csFPs := map[string]struct{}{}
	csByFP := map[string]*csFP{}
	csTop := map[string]*chalOffender{} // key ip; keep the peak-score line per IP

	var hum HumanitySummary
	humIPs := map[string]struct{}{}
	humHosts := map[string]struct{}{}
	humSrcKind := map[string]int{}
	humSrc := map[string]int{}
	humFP := map[string]int{}
	humTells := map[string]int{}
	humProvider := map[string]int{}
	humCountry := map[string]int{}
	humPTR := map[string]int{}

	for _, ln := range lines {
		e, ok := Parse(ln)
		if !ok {
			continue
		}
		// A NOTE line is OPERATIONAL, not a decision, so it must never inflate the
		// generic Total / unique_ips / by_signal / by_verdict — not even the
		// challenge_score store-cap note, which happens to carry verdict=would_shadow
		// (so the verdict gate below would let it slip through). Account its dropped
		// count for the challenge_score section here, then skip the generic tally.
		if e.Note != "" {
			if e.Signal == "challenge_score" {
				csDropped += e.Dropped
			}
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
		// challenge_score is a per-IP (host-less) signal with its own verdict space. Its
		// store-cap NOTE line is accounted + skipped above, so a line reaching here is a
		// would_harden/would_deny decision; a stray other verdict is defensively ignored
		// (its Dropped is 0, so the add is a harmless no-op — notes never reach here).
		if e.Signal == "challenge_score" {
			if e.Verdict != "would_harden" && e.Verdict != "would_deny" {
				csDropped += e.Dropped
			} else {
				harden := e.Verdict == "would_harden"
				csLines++
				if harden {
					csHarden++
				} else {
					csDeny++
				}
				if e.IP != "" {
					csIPs[e.IP] = struct{}{}
				}
				if e.FP != "" {
					csFPs[e.FP] = struct{}{}
				}
				if e.Score > csMaxScore {
					csMaxScore = e.Score
				}
				fpKey := e.FP
				if fpKey == "" {
					fpKey = "(none)" // no X-CFM-TLS stamp (old edge / plain HTTP / behind Cloudflare)
				}
				a := csByFP[fpKey]
				if a == nil {
					a = &csFP{ips: map[string]struct{}{}}
					csByFP[fpKey] = a
				}
				a.lines++
				if harden {
					a.harden++
				} else {
					a.deny++
				}
				if e.IP != "" {
					a.ips[e.IP] = struct{}{}
				}
				if e.Score > a.maxScore {
					a.maxScore = e.Score
				}
				if e.FarmFP > 0 {
					a.convicted = true
				}
				if e.IP != "" {
					if t := csTop[e.IP]; t == nil || e.Score > t.Score {
						csTop[e.IP] = &chalOffender{
							IP: e.IP, FP: e.FP, Score: e.Score, Verdict: e.Verdict,
							Solves: e.Solves, Fast: e.Fast, UAImp: e.UAImp, Farm: e.Farm, FarmFP: e.FarmFP,
						}
					}
				}
			}
		}
		if e.Signal == "humanity" && e.Verdict == "would_v2" {
			hum.Lines++
			if e.IP != "" {
				humIPs[e.IP] = struct{}{}
			}
			if e.Host != "" {
				humHosts[e.Host] = struct{}{}
			}
			if e.UABot {
				hum.UABot++
			}
			fpKey := e.FP
			if fpKey == "" {
				fpKey = "(none)"
			}
			humFP[fpKey]++
			if e.Tells != "" {
				humTells[e.Tells]++
			}
			if e.Provider != "" {
				humProvider[e.Provider]++
			}
			if e.CC != "" {
				humCountry[e.CC]++
			}
			switch e.Src {
			case "":
				humSrcKind["(unknown)"]++
			case "-":
				hum.WithContext++
				humSrcKind["-"]++
			default:
				hum.WithContext++
				seen := map[string]bool{}
				for _, tok := range strings.Split(e.Src, ",") {
					if tok == "" {
						continue
					}
					humSrc[tok]++
					kind, _, _ := strings.Cut(tok, ":")
					if !seen[kind] {
						seen[kind] = true
						humSrcKind[kind]++
					}
				}
			}
			if e.Src != "" {
				humPTR[ptrDomain(e.PTR)]++
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
	if hum.Lines > 0 {
		hum.DistinctIPs = len(humIPs)
		hum.DistinctHosts = len(humHosts)
		hum.BySrcKind = topKV(humSrcKind, 20)
		hum.BySrc = topKV(humSrc, 25)
		hum.ByFP = topKV(humFP, 20)
		hum.ByTells = topKV(humTells, 20)
		hum.ByProvider = topKV(humProvider, 20)
		hum.ByCountry = topKV(humCountry, 20)
		hum.ByPTRDomain = topKV(humPTR, 20)
		s.Humanity = &hum
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

	// challenge_score section — omitted entirely when the signal never fired (a
	// quiet node then simply has no `challenge_score` key, distinguishing it from a
	// node that scored but stayed under the durable would_deny cut).
	if csLines > 0 || csDropped > 0 {
		cs := &ChalScoreSummary{
			Lines: csLines, WouldHarden: csHarden, WouldDeny: csDeny, Dropped: csDropped,
			DistinctIPs: len(csIPs), DistinctFPs: len(csFPs), MaxScore: csMaxScore,
		}
		// by_fp: rank by line count, then would_deny, then fp (deterministic tie-break).
		fps := make([]chalFP, 0, len(csByFP))
		for k, a := range csByFP {
			fps = append(fps, chalFP{
				FP: k, Lines: a.lines, DistinctIPs: len(a.ips),
				WouldHarden: a.harden, WouldDeny: a.deny, MaxScore: a.maxScore, Convicted: a.convicted,
			})
		}
		sort.Slice(fps, func(i, j int) bool {
			if fps[i].Lines != fps[j].Lines {
				return fps[i].Lines > fps[j].Lines
			}
			if fps[i].WouldDeny != fps[j].WouldDeny {
				return fps[i].WouldDeny > fps[j].WouldDeny
			}
			return fps[i].FP < fps[j].FP
		})
		if len(fps) > 25 {
			fps = fps[:25]
		}
		cs.ByFP = fps
		// top offenders: rank by peak score, then ip (deterministic tie-break).
		tops := make([]chalOffender, 0, len(csTop))
		for _, t := range csTop {
			tops = append(tops, *t)
		}
		sort.Slice(tops, func(i, j int) bool {
			if tops[i].Score != tops[j].Score {
				return tops[i].Score > tops[j].Score
			}
			return tops[i].IP < tops[j].IP
		})
		if len(tops) > 25 {
			tops = tops[:25]
		}
		cs.Top = tops
		s.ChallengeScore = cs
	}
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

// ptrDomain reduces a PTR to its last two labels (rate-limited-proxy-66-102-
// 6-165.google.com → google.com) so fetchers behind one operator group
// together. "(none)" when the line had no PTR. Grouping only — it is not a
// public-suffix-aware registrable domain, and it verifies nothing.
func ptrDomain(ptr string) string {
	ptr = strings.TrimSuffix(strings.ToLower(ptr), ".")
	if ptr == "" {
		return "(none)"
	}
	labels := strings.Split(ptr, ".")
	if len(labels) <= 2 {
		return ptr
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
