package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cfgpkg "cfm/internal/config"
)

const (
	gateTestAdminTok = "gate-admin-token-0123456789abcdef"
	gateTestMCPTok   = "gate-mcp-token-0123456789abcdefgh"
)

// mcpGateServer is the real /mcp mount (registerMCPServer) behind the real
// TokenMiddleware, as Start builds it, with the given admin-token binding.
func mcpGateServer(t *testing.T, mode string) (http.Handler, *TokenStore) {
	t.Helper()
	cfg := &cfgpkg.Config{}
	cfg.API.AuthToken = gateTestAdminTok
	cfg.API.MCPToken = gateTestMCPTok
	store := NewTokenStore()
	m := http.NewServeMux()
	registerMCPServer(m, cfg, store, newAdminIPPolicy(mode, t.TempDir(), ""))
	return TokenMiddleware(gateTestAdminTok, store, WithAdminTokenIPBinding(mode, t.TempDir(), ""))(m), store
}

func mcpToolsList(h http.Handler, from string, hdr map[string][]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	r.RemoteAddr = from
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	for k, vs := range hdr {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// Which bearer opens /mcp, from where: the static MCP_TOKEN and the admin
// token do, the admin token only from a source its binding allows; a scoped
// viewer token, garbage, an empty or malformed header, and a bearer hidden in
// the CFM token headers do not.
func TestMCPGateIdentities(t *testing.T) {
	const foreign = "203.0.113.9:4000"
	const loop = "127.0.0.1:4000"
	enforce, store := mcpGateServer(t, "enforce")
	scoped := store.Issue([]string{"a.example"}, nil, nil, "viewer", "t", time.Hour)
	logonly, _ := mcpGateServer(t, "logonly")
	off, _ := mcpGateServer(t, "off")
	bearer := func(v string) map[string][]string { return map[string][]string{"Authorization": {"Bearer " + v}} }
	cases := []struct {
		name string
		h    http.Handler
		from string
		hdr  map[string][]string
		want int
	}{
		{"mcp token, foreign, enforce", enforce, foreign, bearer(gateTestMCPTok), http.StatusOK},
		{"admin token, loopback, enforce", enforce, loop, bearer(gateTestAdminTok), http.StatusOK},
		{"admin token, foreign, enforce", enforce, foreign, bearer(gateTestAdminTok), http.StatusForbidden},
		{"admin token, foreign, logonly", logonly, foreign, bearer(gateTestAdminTok), http.StatusOK},
		{"admin token, foreign, off", off, foreign, bearer(gateTestAdminTok), http.StatusOK},
		{"lower-case scheme", off, foreign, map[string][]string{"Authorization": {"bearer " + gateTestMCPTok}}, http.StatusOK},
		{"scoped token", enforce, loop, bearer(scoped.Token), http.StatusUnauthorized},
		{"garbage", enforce, loop, bearer("nope"), http.StatusUnauthorized},
		{"empty bearer", enforce, loop, map[string][]string{"Authorization": {"Bearer "}}, http.StatusUnauthorized},
		{"basic scheme", enforce, loop, map[string][]string{"Authorization": {"Basic " + gateTestMCPTok}}, http.StatusUnauthorized},
		{"no header", enforce, loop, nil, http.StatusUnauthorized},
		{"X-CFM-Token header", enforce, loop, map[string][]string{"X-CFM-Token": {gateTestAdminTok}}, http.StatusUnauthorized},
		{"bad first of two Authorization", enforce, loop, map[string][]string{"Authorization": {"Bearer nope", "Bearer " + gateTestMCPTok}}, http.StatusUnauthorized},
	}
	for _, c := range cases {
		rec := mcpToolsList(c.h, c.from, c.hdr)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d (body %.120q)", c.name, rec.Code, c.want, rec.Body.String())
		}
		if c.want == http.StatusOK && !strings.Contains(rec.Body.String(), `"tools"`) {
			t.Errorf("%s: no tool list in %.120q", c.name, rec.Body.String())
		}
		if c.want == http.StatusForbidden && strings.Contains(rec.Body.String(), "admin") {
			t.Errorf("%s: refusal names the credential: %q", c.name, rec.Body.String())
		}
	}
}

// The MCP refusal is recorded as a direct auth event, like TokenMiddleware's,
// so the generic forbidden-burst signal does not count it a second time.
func TestMCPForeignAdminTokenIsADirectAuthEvent(t *testing.T) {
	h, _ := mcpGateServer(t, "enforce")
	var reason string
	var direct bool
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		reason, direct = anomalyStateFromRequest(r).snapshot()
	})
	stack := APISecurityAnomalyMiddleware(probe)
	rec := mcpToolsList(stack, "203.0.113.9:4000", map[string][]string{"Authorization": {"Bearer " + gateTestAdminTok}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if classifierReason(reason, direct) != "direct_auth_event" {
		t.Errorf("anomaly reason %q is not a direct auth event", reason)
	}
}
