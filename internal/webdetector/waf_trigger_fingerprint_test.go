package webdetector

import (
	"path/filepath"
	"testing"
	"time"
)

// RecordWAFTrigger carries the client TLS fingerprint (X-CFM-TLS) into the durable
// waf_trigger event payload when the edge stamped one, and omits the key when it
// didn't — the attribution that lets the fleet reputation ledger key a WAF block on
// a fingerprint (source #3). Pure-recording: asserts only the persisted shape.
func TestRecordWAFTrigger_CarriesFingerprint(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs}

	// A block-tier trigger carrying a stamped fingerprint.
	e.RecordWAFTrigger("203.0.113.10", "shop.example", "/x?id=1' OR 1=1", "get", "block",
		"WAF_SQLI", time.Minute, 64512, "Evil Hosting", "United States", "US", 301,
		"curl/8.4.0", "", "", "c28caa00")
	// A trigger with NO fingerprint (older edge / plain-HTTP): the key must be absent.
	e.RecordWAFTrigger("203.0.113.11", "shop.example", "/y", "get", "block",
		"WAF_TRAVERSAL", time.Minute, 64512, "Evil Hosting", "United States", "US", 101,
		"curl/8.4.0", "", "", "")

	rows, err := hs.QueryEvents("", "", "waf_trigger", 10)
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 waf_trigger rows, got %d", len(rows))
	}

	var withFP, withoutFP *HistoryEvent
	for i := range rows {
		switch rows[i].IP {
		case "203.0.113.10":
			withFP = &rows[i]
		case "203.0.113.11":
			withoutFP = &rows[i]
		}
	}
	if withFP == nil || withoutFP == nil {
		t.Fatalf("missing expected rows: %+v", rows)
	}
	if withFP.Payload["fingerprint"] != "c28caa00" {
		t.Errorf("stamped trigger: fingerprint = %v, want c28caa00", withFP.Payload["fingerprint"])
	}
	if _, present := withoutFP.Payload["fingerprint"]; present {
		t.Errorf("unstamped trigger must omit the fingerprint key, got %v", withoutFP.Payload["fingerprint"])
	}
}
