package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cfm/internal/dnat"
)

// TestDNATStateEndpoint_RoundTrip verifies the endpoint returns the
// in-process LogTransition / recordProbe state for both scopes. Without
// this endpoint, the CLI status command (separate process) sees nothing
// — that was the bug.
func TestDNATStateEndpoint_RoundTrip(t *testing.T) {
	// Seed the daemon-side state.
	dnat.LogTransition(dnat.ScopeWeb, "ON", "manual", "")
	dnat.LogTransition(dnat.ScopeCPanel, "OFF", "failsafe-off", "panel probe failed")

	mux := http.NewServeMux()
	// Bypass adminOnlyHandler for the unit test — we exercise the
	// handler directly without the full middleware stack.
	mux.HandleFunc("/api/v1/dnat/state", handleDNATState)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/v1/dnat/state")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out dnatStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Web.LastTransition.State != "ON" || out.Web.LastTransition.Action != "manual" {
		t.Fatalf("web transition = %+v, want state=ON action=manual", out.Web.LastTransition)
	}
	if out.CPanel.LastTransition.State != "OFF" || out.CPanel.LastTransition.Action != "failsafe-off" {
		t.Fatalf("cpanel transition = %+v, want state=OFF action=failsafe-off", out.CPanel.LastTransition)
	}
	if out.CPanel.LastTransition.Reason != "panel probe failed" {
		t.Fatalf("cpanel reason = %q, want %q", out.CPanel.LastTransition.Reason, "panel probe failed")
	}
}

func TestDNATStateEndpoint_RejectsNonGET(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/dnat/state", handleDNATState)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/api/v1/dnat/state", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}
