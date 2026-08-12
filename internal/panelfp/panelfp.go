// Package panelfp aggregates the panel burn-in signal that the edge Lua writes
// to the edge ERROR log — the `[cfm_panel_waf]` WAF actions (Phase 2e) and the
// `[cfm_panel_decision]` bridge verdicts (Phase 2d). Both markers are
// mode-dependent: a LOGONLY node records would-be actions (`logonly=would_…` /
// `logonly=would_enforce`), while an ENFORCING node (Phase 4a/4c) records the
// actual block (`[cfm_panel_waf] enforce=block`); the aggregation counts both as
// the same block-tier signal (see wafActionOf). It answers "is it safe to turn
// panel enforcement on?" — and, on an already-enforcing node, "what is it
// actually blocking?" — by separating expected internet-scanner noise from the
// residue that affects real panel users.
//
// The two numbers that gate enforcement:
//   - panel_waf.nonscanner_would_block  — non-scanner clients a panel WAF BLOCK
//     rule would have blocked (the customer-facing false-positive risk),
//   - panel_decision.ip_block_count     — requests the bridge would ip-block on
//     a panel port.
//
// Both near-zero (after excluding known scanners) ⇒ header/URI/args rules are
// safe to enforce; body-rule coverage is a separate later burn-in (2e reads no
// body). This package is pure: it parses/aggregates lines and does no I/O.
package panelfp

import (
	"sort"
	"strings"
)

const (
	markerWAF      = "[cfm_panel_waf]"
	markerDecision = "[cfm_panel_decision]"
	// nginxSuffix is where the engine appends its own request context (client:/
	// server:/request:/host:) after the cfm key=value fields — cut there first.
	nginxSuffix = ", client:"

	topN       = 20 // cap on by_rule / top_ua / by_verdict slices
	maxSamples = 3  // sample lines kept per candidate-FP rule / ip-block set
)

// knownScannerUAs are case-insensitive substrings of user-agents belonging to
// well-known internet-wide scanners / measurement services. A panel WAF hit
// from one of these is expected background noise, not a customer false positive.
// Heuristic and intentionally easy to extend.
var knownScannerUAs = []string{
	"censys", "shodan", "zgrab", "masscan", "expanse", "paloaltonetworks",
	"internet-measurement", "internetmeasurement", "netsystemsresearch",
	"leakix", "bufferover", "stretchoid", "shadowserver", "binaryedge",
	"criminalip", "gdnplus", "odin", "aresearchscan", "molfar", "censysinspect",
}

// IsScannerUA reports whether ua matches a known scanner (case-insensitive).
func IsScannerUA(ua string) bool {
	if ua == "" {
		return false
	}
	l := strings.ToLower(ua)
	for _, s := range knownScannerUAs {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// Kind is which panel-logonly marker a line carries.
type Kind int

const (
	KindNone Kind = iota
	KindWAF
	KindDecision
)

// Fields is the parsed cfm key=value portion of one panel-logonly line.
type Fields map[string]string

// Parse extracts the panel-logonly marker and its key=value fields from one edge
// error-log line. Returns KindNone if the line is not a panel WAF/decision
// logonly line. The `ua` value (WAF lines) may contain spaces, so it is captured
// as the remainder after "ua=".
func Parse(line string) (Kind, Fields) {
	var kind Kind
	var start int
	if i := strings.Index(line, markerWAF); i >= 0 {
		kind, start = KindWAF, i+len(markerWAF)
	} else if i := strings.Index(line, markerDecision); i >= 0 {
		kind, start = KindDecision, i+len(markerDecision)
	} else {
		return KindNone, nil
	}

	seg := line[start:]
	if c := strings.Index(seg, nginxSuffix); c >= 0 {
		seg = seg[:c] // drop the nginx-appended request context
	}
	seg = strings.TrimSpace(seg)

	f := Fields{}
	rest := seg
	for rest != "" {
		var tok string
		if sp := strings.IndexByte(rest, ' '); sp >= 0 {
			tok, rest = rest[:sp], rest[sp+1:]
		} else {
			tok, rest = rest, ""
		}
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		key, val := tok[:eq], tok[eq+1:]
		if key == "ua" && rest != "" {
			val += " " + rest // ua runs to end of the cfm segment
			rest = ""
		}
		f[key] = val
	}
	return kind, f
}

// wafActionOf normalises a parsed `[cfm_panel_waf]` line into (action, isBlock).
// The panel WAF marker is mode-dependent (cfm_panel.lua panel_waf_probe):
//   - LOGONLY (and any non-enforced tier, even on an enforcing node): the token
//     is `logonly=would_<action>` → field "logonly" = "would_block"/"would_challenge"/…
//   - ENFORCE, block tier: the token is `enforce=block` → field "enforce" = "block".
// Both a would-block (logonly) and an actual block (enforce) are the same
// block-tier FALSE-POSITIVE signal for burn-in, so both set isBlock — otherwise
// an already-enforcing node would silently under-count nonscanner_would_block
// (the marker changed with the Phase-4c default-enforce flip, but this parser
// still keyed only on "logonly"). The enforce hits keep a distinct ByAction
// label ("enforce_block") so the aggregate still shows which side acted.
func wafActionOf(f Fields) (action string, isBlock bool) {
	if v := f["enforce"]; v != "" {
		return "enforce_" + v, v == "block"
	}
	if v := f["logonly"]; v != "" {
		return v, v == "would_block"
	}
	return "unknown", false
}

// Summary is the aggregated panel-logonly picture.
type Summary struct {
	Window   Window     `json:"window"`
	WAF      WAFSummary `json:"panel_waf"`
	Decision DecSummary `json:"panel_decision"`
}

// Window reports how much of the tail was panel-logonly signal.
type Window struct {
	WAFLines      int `json:"waf_lines"`
	DecisionLines int `json:"decision_lines"`
}

// WAFSummary aggregates `[cfm_panel_waf]` lines.
type WAFSummary struct {
	Total              int            `json:"total"`
	ByAction           map[string]int `json:"by_action"` // would_block/would_challenge/would_logonly (logonly) + enforce_block (enforcing node)
	ScannerHits        int            `json:"scanner_hits"`
	NonScannerHits     int            `json:"nonscanner_hits"`
	NonScannerWouldBlk int            `json:"nonscanner_would_block"` // the customer-facing FP risk
	ByRule             []RuleAgg      `json:"by_rule"`
	TopUA              []UAAgg        `json:"top_ua"`
	CandidateFPs       []RuleAgg      `json:"candidate_fps"` // rules with non-scanner hits, worst first
}

// RuleAgg aggregates one WAF rule across the window, keyed by rule_id (Reason
// is the first-seen reason for that id — rule_id↔reason is 1:1 in real WAF
// output, so the key stays rule_id alone).
type RuleAgg struct {
	RuleID             string         `json:"rule_id"`
	Reason             string         `json:"reason"`
	Count              int            `json:"count"`
	ScannerHits        int            `json:"scanner_hits"`
	NonScannerHits     int            `json:"nonscanner_hits"`
	NonScannerWouldBlk int            `json:"nonscanner_would_block"`
	Actions            map[string]int `json:"actions"`
	DistinctIPs        int            `json:"distinct_ips"`
	DistinctHosts      int            `json:"distinct_hosts"`
	SampleNonScanner   []string       `json:"sample_nonscanner,omitempty"` // "ip host uri ua"
}

// UAAgg aggregates one user-agent.
type UAAgg struct {
	UA      string `json:"ua"`
	Count   int    `json:"count"`
	Scanner bool   `json:"scanner"`
}

// DecSummary aggregates `[cfm_panel_decision]` lines.
type DecSummary struct {
	Total          int          `json:"total"`
	ByVerdict      []VerdictAgg `json:"by_verdict"`
	IPBlockCount   int          `json:"ip_block_count"` // ip_action=block: the real FP risk
	IPBlockSamples []string     `json:"ip_block_samples,omitempty"`
	DistinctIPs    int          `json:"distinct_ips"`
	DistinctHosts  int          `json:"distinct_hosts"`
}

// VerdictAgg aggregates one (ip_action, vhost_action, rule_action) combination.
type VerdictAgg struct {
	IPAction    string `json:"ip_action"`
	VhostAction string `json:"vhost_action"`
	RuleAction  string `json:"rule_action"`
	Count       int    `json:"count"`
}

type ruleAcc struct {
	reason       string
	count        int
	scanner      int
	nonScanner   int
	nonScanBlock int
	actions      map[string]int
	ips          map[string]struct{}
	hosts        map[string]struct{}
	samples      []string
}

// Summarize parses and aggregates a batch of edge error-log lines (already
// filtered to panel-logonly markers is fine; non-matching lines are ignored).
func Summarize(lines []string) Summary {
	var s Summary
	s.WAF.ByAction = map[string]int{}

	rules := map[string]*ruleAcc{}       // key: rule_id
	uas := map[string]*UAAgg{}           // key: ua
	verdicts := map[string]*VerdictAgg{} // key: ip|vhost|rule
	decIPs := map[string]struct{}{}
	decHosts := map[string]struct{}{}

	for _, line := range lines {
		kind, f := Parse(line)
		switch kind {
		case KindWAF:
			s.Window.WAFLines++
			s.WAF.Total++
			action, isBlock := wafActionOf(f)
			s.WAF.ByAction[action]++
			ua := f["ua"]
			scanner := IsScannerUA(ua)
			if scanner {
				s.WAF.ScannerHits++
			} else {
				s.WAF.NonScannerHits++
				if isBlock {
					s.WAF.NonScannerWouldBlk++
				}
			}

			rid := f["rule_id"]
			if rid == "" {
				rid = "-"
			}
			ra := rules[rid]
			if ra == nil {
				ra = &ruleAcc{reason: f["reason"], actions: map[string]int{}, ips: map[string]struct{}{}, hosts: map[string]struct{}{}}
				rules[rid] = ra
			}
			if ra.reason == "" {
				ra.reason = f["reason"]
			}
			ra.count++
			ra.actions[action]++
			if ip := f["ip"]; ip != "" {
				ra.ips[ip] = struct{}{}
			}
			if h := f["host"]; h != "" {
				ra.hosts[h] = struct{}{}
			}
			if scanner {
				ra.scanner++
			} else {
				ra.nonScanner++
				if isBlock {
					ra.nonScanBlock++
				}
				if len(ra.samples) < maxSamples {
					ra.samples = append(ra.samples, sampleWAF(f))
				}
			}

			ub := uas[ua]
			if ub == nil {
				ub = &UAAgg{UA: ua, Scanner: scanner}
				uas[ua] = ub
			}
			ub.Count++

		case KindDecision:
			s.Window.DecisionLines++
			s.Decision.Total++
			ipa := orDash(f["ip_action"])
			vha := orDash(f["vhost_action"])
			rua := orDash(f["rule_action"])
			key := ipa + "|" + vha + "|" + rua
			va := verdicts[key]
			if va == nil {
				va = &VerdictAgg{IPAction: ipa, VhostAction: vha, RuleAction: rua}
				verdicts[key] = va
			}
			va.Count++
			if ipa == "block" {
				s.Decision.IPBlockCount++
				if len(s.Decision.IPBlockSamples) < maxSamples {
					s.Decision.IPBlockSamples = append(s.Decision.IPBlockSamples, sampleDecision(f))
				}
			}
			if ip := f["ip"]; ip != "" {
				decIPs[ip] = struct{}{}
			}
			if h := f["host"]; h != "" {
				decHosts[h] = struct{}{}
			}
		}
	}

	// Materialize WAF rule aggregates.
	for rid, ra := range rules {
		agg := RuleAgg{
			RuleID: rid, Reason: ra.reason, Count: ra.count,
			ScannerHits: ra.scanner, NonScannerHits: ra.nonScanner,
			NonScannerWouldBlk: ra.nonScanBlock, Actions: ra.actions,
			DistinctIPs: len(ra.ips), DistinctHosts: len(ra.hosts),
			SampleNonScanner: ra.samples,
		}
		s.WAF.ByRule = append(s.WAF.ByRule, agg)
		if ra.nonScanner > 0 {
			s.WAF.CandidateFPs = append(s.WAF.CandidateFPs, agg)
		}
	}
	sort.Slice(s.WAF.ByRule, func(i, j int) bool {
		return byRuleLess(s.WAF.ByRule[i], s.WAF.ByRule[j])
	})
	sort.Slice(s.WAF.CandidateFPs, func(i, j int) bool {
		a, b := s.WAF.CandidateFPs[i], s.WAF.CandidateFPs[j]
		if a.NonScannerWouldBlk != b.NonScannerWouldBlk {
			return a.NonScannerWouldBlk > b.NonScannerWouldBlk
		}
		if a.NonScannerHits != b.NonScannerHits {
			return a.NonScannerHits > b.NonScannerHits
		}
		return a.RuleID < b.RuleID
	})
	s.WAF.ByRule = capRules(s.WAF.ByRule)
	s.WAF.CandidateFPs = capRules(s.WAF.CandidateFPs)

	for _, ub := range uas {
		s.WAF.TopUA = append(s.WAF.TopUA, *ub)
	}
	sort.Slice(s.WAF.TopUA, func(i, j int) bool {
		if s.WAF.TopUA[i].Count != s.WAF.TopUA[j].Count {
			return s.WAF.TopUA[i].Count > s.WAF.TopUA[j].Count
		}
		return s.WAF.TopUA[i].UA < s.WAF.TopUA[j].UA
	})
	if len(s.WAF.TopUA) > topN {
		s.WAF.TopUA = s.WAF.TopUA[:topN]
	}

	for _, va := range verdicts {
		s.Decision.ByVerdict = append(s.Decision.ByVerdict, *va)
	}
	sort.Slice(s.Decision.ByVerdict, func(i, j int) bool {
		if s.Decision.ByVerdict[i].Count != s.Decision.ByVerdict[j].Count {
			return s.Decision.ByVerdict[i].Count > s.Decision.ByVerdict[j].Count
		}
		return verdictKey(s.Decision.ByVerdict[i]) < verdictKey(s.Decision.ByVerdict[j])
	})
	if len(s.Decision.ByVerdict) > topN {
		s.Decision.ByVerdict = s.Decision.ByVerdict[:topN]
	}
	s.Decision.DistinctIPs = len(decIPs)
	s.Decision.DistinctHosts = len(decHosts)

	return s
}

func byRuleLess(a, b RuleAgg) bool {
	if a.Count != b.Count {
		return a.Count > b.Count
	}
	return a.RuleID < b.RuleID
}

func capRules(r []RuleAgg) []RuleAgg {
	if len(r) > topN {
		return r[:topN]
	}
	return r
}

func verdictKey(v VerdictAgg) string { return v.IPAction + "|" + v.VhostAction + "|" + v.RuleAction }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sampleWAF(f Fields) string {
	return strings.TrimSpace(orDash(f["ip"]) + " " + orDash(f["host"]) + " " + orDash(f["uri"]) + " ua=" + orDash(f["ua"]))
}

func sampleDecision(f Fields) string {
	return strings.TrimSpace(orDash(f["ip"]) + " " + orDash(f["host"]) + " " + orDash(f["uri"]) +
		" vhost_action=" + orDash(f["vhost_action"]) + " rule_action=" + orDash(f["rule_action"]))
}
