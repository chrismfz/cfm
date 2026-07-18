// internal/webdetector/ua_drill_test.go
//
// Tests for the UA drilldown surface: the drill request arms detailed
// per-UA tracking (unique IPs + top paths) without an emergency rule,
// and the response carries hosts/IPs/paths breakdowns with nil-safe
// enrichment.
package webdetector

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func ingestUATestTraffic(e *Engine, base float64) {
	recs := []LogRec{
		{TS: base + 0, IP: "203.0.113.10", Host: "shop.example.gr", Method: "get", URI: "/xmlrpc.php", Status: 200, UA: "Go-http-client/1.1"},
		{TS: base + 1, IP: "203.0.113.10", Host: "shop.example.gr", Method: "get", URI: "/xmlrpc.php", Status: 200, UA: "Go-http-client/1.1"},
		{TS: base + 2, IP: "203.0.113.11", Host: "blog.example.gr", Method: "get", URI: "/wp-login.php", Status: 403, UA: "Go-http-client/2.0"},
	}
	for _, r := range recs {
		e.ingest(r, "raw")
	}
}

func TestUADrill_ArmsDetailTracking(t *testing.T) {
	e, mux := newTestEngineUA(t)
	base := float64(time.Now().Unix())

	// Traffic BEFORE any drilldown: request counts aggregate, but the
	// gated IP/path maps must stay empty (no rule, no observe window).
	ingestUATestTraffic(e, base)

	rr := uaDo(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/ua-drill?ua=go-http-client", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("drill status=%d body=%s", rr.Code, rr.Body.String())
	}
	var first UADetail
	if err := json.Unmarshal(rr.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.IPTrackingActive {
		t.Fatalf("first drill should report ip_tracking_active=false (was gated), got true")
	}
	if first.Reqs != 3 {
		t.Fatalf("reqs=%d want=3 (request counts are always aggregated)", first.Reqs)
	}
	if first.UniqueIPs != 0 || len(first.TopPaths) != 0 {
		t.Fatalf("pre-arm drill must have no IP/path data, got ips=%d paths=%d", first.UniqueIPs, len(first.TopPaths))
	}
	if len(first.TopHosts) != 2 {
		t.Fatalf("top_hosts=%v want 2 hosts (always aggregated)", first.TopHosts)
	}

	// The drill call armed the observe window: traffic from now on
	// populates IPs and paths.
	if !e.uaDetailTrackingEnabled() {
		t.Fatalf("drill did not arm detail tracking")
	}
	ingestUATestTraffic(e, base+10)

	rr = uaDo(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/ua-drill?ua=Go-http-client/1.1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("drill status=%d body=%s", rr.Code, rr.Body.String())
	}
	var second UADetail
	if err := json.Unmarshal(rr.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if !second.IPTrackingActive {
		t.Fatalf("second drill should report ip_tracking_active=true")
	}
	if second.UniqueIPs != 2 {
		t.Fatalf("unique_ips=%d want=2 after arming", second.UniqueIPs)
	}
	if len(second.TopPaths) == 0 {
		t.Fatalf("expected top_paths after arming, got none")
	}
	// Enrichment rows mirror TopIPs even with no MMDB loaded (nil-safe).
	if len(second.TopIPInfo) != len(second.TopIPs) {
		t.Fatalf("top_ip_info=%d rows, want %d (mirror of top_ips)", len(second.TopIPInfo), len(second.TopIPs))
	}
	for _, info := range second.TopIPInfo {
		if info.IP == "" || info.Count <= 0 {
			t.Fatalf("bad enriched row: %+v", info)
		}
	}
}

func TestArmUAObserve_NeverShortens(t *testing.T) {
	e, _ := newTestEngineUA(t)
	e.ArmUAObserve(30 * time.Minute)
	if !e.uaDetailTrackingEnabled() {
		t.Fatalf("expected tracking enabled after arm")
	}
	before := e.uaObserveUntilUnix
	e.ArmUAObserve(1 * time.Minute)
	if e.uaObserveUntilUnix < before {
		t.Fatalf("shorter re-arm shortened the observe window: %d -> %d", before, e.uaObserveUntilUnix)
	}
}
