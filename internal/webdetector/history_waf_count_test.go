package webdetector

import (
	"path/filepath"
	"testing"
	"time"
)

// TestCountWAFEventsSince pins the count that backs cfm_metrics.waf_events_1h:
// waf_observe + waf_trigger only, node-wide, windowed by ts_unix — the same
// event set + window the /api/v1/waf/engine/summary total uses, so the health
// snapshot reconciles with security_overview's waf_last_hour.
func TestCountWAFEventsSince(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().Unix()

	// In-window WAF events (both types count).
	hs.Append(HistoryEvent{TsUnix: now - 60, Type: "waf_trigger", Host: "a.com", IP: "1.1.1.1", Mode: "block", Reason: "WAF_SQLI:42"})
	hs.Append(HistoryEvent{TsUnix: now - 120, Type: "waf_observe", Host: "b.com", IP: "2.2.2.2", Mode: "logonly", Reason: "WAF_XSS:7"})
	hs.Append(HistoryEvent{TsUnix: now - 300, Type: "waf_trigger", Host: "c.com", IP: "3.3.3.3", Mode: "logonly", Reason: "WAF_IP_HOST"})
	// Non-WAF event in window must NOT count.
	hs.Append(HistoryEvent{TsUnix: now - 30, Type: "challenge_decision", Host: "a.com", IP: "9.9.9.9", Reason: "WEB/RPS"})
	// WAF event OUTSIDE the 1h window must NOT count.
	hs.Append(HistoryEvent{TsUnix: now - 2*3600, Type: "waf_trigger", Host: "old.com", IP: "4.4.4.4", Mode: "block", Reason: "WAF_RCE:1"})

	fromUnix := time.Now().Add(-time.Hour).Unix()
	n, err := hs.CountWAFEventsSince(fromUnix)
	if err != nil {
		t.Fatalf("CountWAFEventsSince: %v", err)
	}
	if n != 3 {
		t.Fatalf("count = %d, want 3 (2 trigger + 1 observe in-window; challenge + old excluded)", n)
	}

	// A tight window (last 90s) includes only the two most recent WAF events.
	if n90, err := hs.CountWAFEventsSince(time.Now().Add(-90 * time.Second).Unix()); err != nil {
		t.Fatalf("CountWAFEventsSince(90s): %v", err)
	} else if n90 != 1 {
		t.Fatalf("count(90s) = %d, want 1 (only the now-60 trigger)", n90)
	}
}

// TestHistoryRangeQueries pin the EXPLICIT-window variants used by
// host_access_history: the detector counts must describe exactly the same
// absolute [from,to) seconds as the access-log scan, half-open on both SQL
// sides, and echo the bounds back so responses are self-describing.
func TestHistoryRangeQueries(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	base := int64(1_800_000_000) // fixed epoch: boundary math must be exact

	events := []struct {
		ts   int64
		typ  string
		rule string
	}{
		{base - 1, "waf_observed", "WAF_SQLI:1"}, // before window → excluded
		{base, "waf_observed", "WAF_SQLI:2"},     // from → included (>=)
		{base + 5, "block_trigger", ""},          // inside → included
		{base + 9, "suspicious", ""},             // inside → included
		{base + 10, "waf_observed", "WAF_RCE:3"}, // to → excluded (< to)
		{base + 11, "challenge_issued", ""},      // after window → excluded
	}
	for _, ev := range events {
		hs.Append(HistoryEvent{TsUnix: ev.ts, Type: ev.typ, Host: "ex.gr", IP: "1.2.3.4", Reason: ev.rule})
	}

	sum, err := hs.SummarizeRange("ex.gr", "", base, base+10)
	if err != nil {
		t.Fatalf("SummarizeRange: %v", err)
	}
	if sum.FromUnix != base || sum.ToUnix != base+10 {
		t.Errorf("summary bounds = [%d,%d], want [%d,%d] echoed verbatim", sum.FromUnix, sum.ToUnix, base, base+10)
	}
	if sum.TotalEvents != 3 {
		t.Errorf("total_events = %d, want 3 (from, +5, +9)", sum.TotalEvents)
	}
	if sum.WAFObserved != 1 || sum.BlockTriggers != 1 || sum.Suspicious != 1 {
		t.Errorf("waf/block/suspicious = %d/%d/%d, want 1/1/1", sum.WAFObserved, sum.BlockTriggers, sum.Suspicious)
	}

	rules, err := hs.WAFByRuleRange("ex.gr", base, base+10)
	if err != nil {
		t.Fatalf("WAFByRuleRange: %v", err)
	}
	if len(rules) != 1 || rules[0].Rule != "WAF_SQLI:2" || rules[0].Count != 1 {
		t.Errorf("rules = %+v, want exactly [WAF_SQLI:2 ×1] (boundary events excluded)", rules)
	}

	// The trailing-hours wrappers still work (now-anchored smoke check).
	if _, err := hs.Summarize("ex.gr", "", 1); err != nil {
		t.Errorf("Summarize wrapper: %v", err)
	}
	if _, err := hs.WAFByRule("ex.gr", 1); err != nil {
		t.Errorf("WAFByRule wrapper: %v", err)
	}
}
