package panelfp

import (
	"strings"
	"testing"
)

const (
	// Real-shaped lines (nginx prefix + cfm marker + cfm fields + nginx suffix).
	wafScanner1 = `2026/08/12 15:52:54 [warn] 3125281#3125281: *1072292 [lua] cfm_panel.lua:256: [cfm_panel_waf] logonly=would_challenge scope=panel:2095 ip=66.132.172.104 host=157.90.128.246 uri=/robots.txt method=GET reason=WAF_IP_HOST rule_id=602 ua=Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/), client: "66.132.172.104", server: "_", request_line: "GET /robots.txt HTTP/1.1", host: "157.90.128.246:2095"`
	wafScanner2 = `2026/08/12 15:53:34 [warn] 3125280#3125280: *1077507 [lua] cfm_panel.lua:256: [cfm_panel_waf] logonly=would_challenge scope=panel:2096 ip=66.132.224.93 host=157.90.128.201 uri=/robots.txt method=GET reason=WAF_IP_HOST rule_id=602 ua=Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/), client: "66.132.224.93"`
	// Non-scanner (ordinary browser UA) that a BLOCK rule would have blocked — the FP risk.
	wafBlockFP = `2026/08/12 16:00:00 [warn] 1#1: *1 [lua] cfm_panel.lua:256: [cfm_panel_waf] logonly=would_block scope=panel:2083 ip=203.0.113.7 host=cpanel.example.com uri=/login?x=1 method=POST reason=WAF_SQLI:BLIND rule_id=320 ua=Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/128.0, client: "203.0.113.7"`
	// Non-scanner logonly hit (not a block).
	wafLogonly = `2026/08/12 16:01:00 [warn] 1#1: *2 [lua] cfm_panel.lua:256: [cfm_panel_waf] logonly=would_logonly scope=panel:2083 ip=198.51.100.9 host=cpanel.example.com uri=/ method=GET reason=WAF_XSS rule_id=210 ua=Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0, client: "198.51.100.9"`

	decAllowChallenge = `2026/08/12 13:39:05 [warn] 1046969#1046969: *306117 [lua] cfm_panel.lua:167: panel_decision_probe(): [cfm_panel_decision] logonly=would_enforce scope=panel:2086 ip=87.236.176.108 host=webmail.mx-architecture.com uri=/ ip_action=allow vhost_action=challenge rule_action=- cached=0, client: "87.236.176.108", server: "_"`
	// The real FP risk: an ip_action=block verdict on a panel port.
	decIPBlock = `2026/08/12 16:05:00 [warn] 1#1: *9 [lua] cfm_panel.lua:170: panel_decision_probe(): [cfm_panel_decision] logonly=would_enforce scope=panel:2083 ip=203.0.113.50 host=cpanel.example.com uri=/ ip_action=block vhost_action=challenge rule_action=- cached=0, client: "203.0.113.50"`
	// Phase 4b enforce: the SAME block verdict, but the marker now reads
	// `enforce=block` (it actually denied). The aggregator keys on the
	// ip/vhost/rule_action fields, not the marker, so this must aggregate
	// identically to decIPBlock — a live enforcing node must still show up in the
	// FP-hunt ip_block_count.
	decIPBlockEnforced = `2026/08/12 16:06:00 [warn] 1#1: *9 [lua] cfm_panel.lua:170: panel_decision_probe(): [cfm_panel_decision] enforce=block scope=panel:2083 ip=203.0.113.51 host=cpanel.example.com uri=/ ip_action=block vhost_action=allow rule_action=- cached=0, client: "203.0.113.51"`
	traceLine  = `2026/08/12 15:47:44 [warn] 146679#146679: *90218079 [lua] cfm_panel.lua:934: [cfm_panel_trace] phase=validate_next corr_id=6fe host_norm=x scope=panel:2082 cookie_present=0 validator_reason=missing, client: 185.247.137.219`
)

func TestParse_WAFLine_UAWithSpaces_SuffixStripped(t *testing.T) {
	kind, f := Parse(wafScanner1)
	if kind != KindWAF {
		t.Fatalf("kind = %v, want KindWAF", kind)
	}
	checks := map[string]string{
		"logonly": "would_challenge", "scope": "panel:2095", "ip": "66.132.172.104",
		"host": "157.90.128.246", "uri": "/robots.txt", "method": "GET",
		"reason": "WAF_IP_HOST", "rule_id": "602",
	}
	for k, want := range checks {
		if f[k] != want {
			t.Errorf("field %q = %q, want %q", k, f[k], want)
		}
	}
	wantUA := "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"
	if f["ua"] != wantUA {
		t.Errorf("ua = %q, want %q", f["ua"], wantUA)
	}
	if got := f["ua"]; got == "" || strings.Contains(got, ", client:") {
		t.Errorf("ua must not include the nginx suffix, got %q", got)
	}
	if !IsScannerUA(f["ua"]) {
		t.Errorf("Censys UA should be classified as a scanner")
	}
}

func TestParse_DecisionLine(t *testing.T) {
	kind, f := Parse(decAllowChallenge)
	if kind != KindDecision {
		t.Fatalf("kind = %v, want KindDecision", kind)
	}
	if f["ip_action"] != "allow" || f["vhost_action"] != "challenge" || f["rule_action"] != "-" {
		t.Errorf("verdict fields wrong: %+v", f)
	}
	if f["host"] != "webmail.mx-architecture.com" {
		t.Errorf("host = %q", f["host"])
	}
}

func TestParse_DecisionLine_EnforceMarker(t *testing.T) {
	// Once CFM_PANEL_DECISION=enforce is live, a block verdict logs
	// `enforce=block` instead of `logonly=would_enforce`. The parser must still
	// classify it as a decision line and read the verdict fields, and Summarize
	// must still count it as an ip block (the FP-hunt tool must not go blind on
	// enforcing nodes).
	kind, f := Parse(decIPBlockEnforced)
	if kind != KindDecision {
		t.Fatalf("kind = %v, want KindDecision", kind)
	}
	if f["ip_action"] != "block" {
		t.Errorf("ip_action = %q, want block", f["ip_action"])
	}
	s := Summarize([]string{decIPBlockEnforced})
	if s.Decision.IPBlockCount != 1 {
		t.Errorf("IPBlockCount = %d, want 1 (enforce=block line must still count)", s.Decision.IPBlockCount)
	}
}

func TestParse_NonPanelLine_IsNone(t *testing.T) {
	if kind, _ := Parse(traceLine); kind != KindNone {
		t.Fatalf("panel_trace line should be KindNone, got %v", kind)
	}
	if kind, _ := Parse("2026/08/12 [error] upstream timed out"); kind != KindNone {
		t.Fatalf("ordinary error line should be KindNone, got %v", kind)
	}
}

func TestIsScannerUA(t *testing.T) {
	if !IsScannerUA("Mozilla/5.0 (compatible; CensysInspect/1.1)") {
		t.Error("censys not detected")
	}
	if IsScannerUA("Mozilla/5.0 (Windows NT 10.0) Firefox/128.0") {
		t.Error("ordinary browser wrongly flagged as scanner")
	}
	if IsScannerUA("") {
		t.Error("empty UA is not a scanner")
	}
}

func TestSummarize_SplitsScannerFromFP(t *testing.T) {
	lines := []string{
		wafScanner1, wafScanner2, // 2 scanner would_challenge, rule 602
		wafBlockFP,                                              // 1 non-scanner would_block, rule 320  <- the FP that gates enforcement
		wafLogonly,                                              // 1 non-scanner would_logonly, rule 210
		traceLine,                                               // ignored
		decAllowChallenge, decAllowChallenge, decAllowChallenge, // 3 allow/challenge/-
		decIPBlock, // 1 ip_action=block  <- the decision FP risk
	}
	s := Summarize(lines)

	if s.WAF.Total != 4 {
		t.Fatalf("WAF.Total = %d, want 4", s.WAF.Total)
	}
	if s.WAF.ScannerHits != 2 || s.WAF.NonScannerHits != 2 {
		t.Errorf("scanner/nonscanner split = %d/%d, want 2/2", s.WAF.ScannerHits, s.WAF.NonScannerHits)
	}
	if s.WAF.NonScannerWouldBlk != 1 {
		t.Errorf("NonScannerWouldBlk = %d, want 1 (rule 320)", s.WAF.NonScannerWouldBlk)
	}
	if s.WAF.ByAction["would_challenge"] != 2 || s.WAF.ByAction["would_block"] != 1 || s.WAF.ByAction["would_logonly"] != 1 {
		t.Errorf("ByAction wrong: %+v", s.WAF.ByAction)
	}
	// Candidate FPs: rules with non-scanner hits, block-first. 320 (block) must
	// rank ahead of 210 (logonly), and 602 (scanner-only) must NOT appear.
	if len(s.WAF.CandidateFPs) != 2 {
		t.Fatalf("CandidateFPs = %d rules, want 2 (320, 210); got %+v", len(s.WAF.CandidateFPs), s.WAF.CandidateFPs)
	}
	if s.WAF.CandidateFPs[0].RuleID != "320" || s.WAF.CandidateFPs[0].NonScannerWouldBlk != 1 {
		t.Errorf("top candidate FP = %+v, want rule 320 with 1 non-scanner would_block", s.WAF.CandidateFPs[0])
	}
	if len(s.WAF.CandidateFPs[0].SampleNonScanner) == 0 {
		t.Errorf("candidate FP rule 320 should carry a sample line")
	}
	for _, r := range s.WAF.CandidateFPs {
		if r.RuleID == "602" {
			t.Errorf("scanner-only rule 602 must not be a candidate FP")
		}
	}

	if s.Decision.Total != 4 {
		t.Fatalf("Decision.Total = %d, want 4", s.Decision.Total)
	}
	if s.Decision.IPBlockCount != 1 {
		t.Errorf("IPBlockCount = %d, want 1", s.Decision.IPBlockCount)
	}
	if len(s.Decision.IPBlockSamples) != 1 {
		t.Errorf("IPBlockSamples = %d, want 1", len(s.Decision.IPBlockSamples))
	}
	// The dominant verdict combo is allow/challenge/- with count 3.
	if len(s.Decision.ByVerdict) == 0 || s.Decision.ByVerdict[0].Count != 3 ||
		s.Decision.ByVerdict[0].IPAction != "allow" || s.Decision.ByVerdict[0].VhostAction != "challenge" {
		t.Errorf("top verdict = %+v, want allow/challenge/- x3", s.Decision.ByVerdict)
	}
	if s.Decision.DistinctHosts < 1 {
		t.Errorf("DistinctHosts = %d, want >=1", s.Decision.DistinctHosts)
	}
	if s.Window.WAFLines != 4 || s.Window.DecisionLines != 4 {
		t.Errorf("window = waf %d / dec %d, want 4/4", s.Window.WAFLines, s.Window.DecisionLines)
	}
}
