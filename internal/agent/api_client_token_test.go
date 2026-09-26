package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Every cfm-web call the agent makes must carry the node's Token: cfm-web is
// retiring its IP-only fallback, so a header-less call would be refused.
func TestEveryAPIClientCallSendsToken(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // path -> Token header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Token")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := &APIClient{BaseURL: srv.URL, Token: "sekrit"}
	ctx := context.Background()
	// Response parsing is not under test here; only what reached the server.
	_ = c.ReportBlock("192.0.2.1", "test", "cfm", "ttl", 60)
	_ = c.ReportLenient("192.0.2.2", "test", "cfm", "ttl", 60)
	_ = c.ReportUnblock("192.0.2.3", "cfm", "test")
	_, _ = c.FetchPendingUnblocks()
	_ = c.ConfirmUnblock(1, "192.0.2.4", true, nil)
	_, _, _ = c.SendHeartbeat(ctx, "test", "cfm", HeartbeatRequest{})
	_, _ = c.GetUpdates([]string{"cfm.conf"})
	_, _ = c.ListTrackedFiles()
	_, _ = c.FetchFingerprintPolicies(ctx)

	want := []string{
		"/api/blocklist/report",
		"/api/blocklist/report-lenient",
		"/api/blocklist/unblock",
		"/api/blocklist/pending-unblocks",
		"/api/blocklist/unblock-confirm",
		"/api/agent/heartbeat",
		"/api/agent/get-updates",
		"/api/agent/list-files",
		"/api/fingerprint-policies/fetch",
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range want {
		tok, ok := seen[p]
		switch {
		case !ok:
			t.Errorf("%s: never called", p)
		case tok != "sekrit":
			t.Errorf("%s: Token = %q, want %q", p, tok, "sekrit")
		}
	}
	if len(seen) != len(want) {
		t.Errorf("unexpected paths called: %v", seen)
	}
}

// The block/unblock reporter is built straight from cfm.conf's API_URL, which
// may be schemeless; like the heartbeat runner, that means https.
func TestAPIClientEndpointSchemeless(t *testing.T) {
	cases := map[string]string{
		"cfm.example.org":          "https://cfm.example.org/api/x",
		" cfm.example.org/ ":       "https://cfm.example.org/api/x",
		"http://cfm.example.org/":  "http://cfm.example.org/api/x",
		"https://cfm.example.org":  "https://cfm.example.org/api/x",
		"https://cfm.example.org/": "https://cfm.example.org/api/x",
		"HTTPS://cfm.example.org":  "HTTPS://cfm.example.org/api/x",
	}
	for base, want := range cases {
		if got := (&APIClient{BaseURL: base}).endpoint("/api/x"); got != want {
			t.Errorf("endpoint(%q) = %q, want %q", base, got, want)
		}
	}
}
