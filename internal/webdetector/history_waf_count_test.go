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
