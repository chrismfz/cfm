package webdetector

import (
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/tlsfp"
)

// RecordWAFTrigger attributes a WAF trigger to a client TLS fingerprint: the edge
// sends the RAW ClientHello tuple (cfm_tlsfp.value()), and RecordWAFTrigger parses
// it to the SAME canonical 8-hex id the challenge path uses (so a WAF block
// correlates with the other ledger sources on one fingerprint) — never storing the
// raw, possibly-large tuple. An absent / unparseable / client-garbage value is
// dropped, not stored. Pure-recording: asserts only the persisted shape.
func TestRecordWAFTrigger_ParsesFingerprintToCanonicalID(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.sqlite"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(hs.Close)
	e := &Engine{history: hs}

	// A realistic raw tuple as cfm_tlsfp.value() produces it.
	tuple := "1|TLSv1.3|ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384|X25519:prime256v1|h2|HTTP/2.0|"
	want, ok := tlsfp.Parse(tuple)
	if !ok || want.ID == "" {
		t.Fatalf("test tuple must parse to a valid fingerprint id; got ok=%v id=%q", ok, want.ID)
	}

	// (1) a block-tier trigger carrying the raw tuple → stored as the canonical id.
	e.RecordWAFTrigger("203.0.113.10", "shop.example", "/x?id=1", "get", "block",
		"WAF_SQLI", time.Minute, 64512, "Evil Hosting", "United States", "US", 301,
		"curl/8.4.0", "", "", tuple)
	// (2) a garbage/spoofed value that does not parse → fingerprint omitted.
	e.RecordWAFTrigger("203.0.113.11", "shop.example", "/y", "get", "block",
		"WAF_TRAVERSAL", time.Minute, 64512, "Evil Hosting", "United States", "US", 101,
		"curl/8.4.0", "", "", "garbage")
	// (3) no fingerprint at all (plain-HTTP / older edge) → omitted.
	e.RecordWAFTrigger("203.0.113.12", "shop.example", "/z", "get", "block",
		"WAF_RCE", time.Minute, 64512, "Evil Hosting", "United States", "US", 320,
		"curl/8.4.0", "", "", "")

	rows, err := hs.QueryEvents("", "", "waf_trigger", 10)
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 waf_trigger rows, got %d", len(rows))
	}

	byIP := map[string]*HistoryEvent{}
	for i := range rows {
		byIP[rows[i].IP] = &rows[i]
	}

	parsed := byIP["203.0.113.10"]
	if parsed == nil || parsed.Payload["fingerprint"] != want.ID {
		t.Fatalf("parsed trigger: fingerprint = %v, want canonical id %q", payloadFP(parsed), want.ID)
	}
	// The canonical id is NOT the raw tuple — proves the parse happened, not a raw store.
	if parsed.Payload["fingerprint"] == tuple {
		t.Error("stored the raw tuple instead of the parsed id")
	}

	for _, ip := range []string{"203.0.113.11", "203.0.113.12"} {
		ev := byIP[ip]
		if ev == nil {
			t.Fatalf("missing row for %s", ip)
		}
		if _, present := ev.Payload["fingerprint"]; present {
			t.Errorf("%s: unparseable/absent fingerprint must be omitted, got %v", ip, ev.Payload["fingerprint"])
		}
	}
}

func payloadFP(ev *HistoryEvent) interface{} {
	if ev == nil {
		return nil
	}
	return ev.Payload["fingerprint"]
}
