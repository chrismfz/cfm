package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	webdet "cfm/internal/webdetector"
)

func newScopeTestServer(t *testing.T) (*TokenStore, http.Handler) {
	t.Helper()
	store := NewTokenStore()

	mux := http.NewServeMux()
	RegisterTokenEndpoint(mux, store)
	RegisterTokenManagementEndpoints(mux, store)

	// Every store this engine defaults (WAF/challenge excludes, manual
	// challenges, …) lives in a temp dir, never the live /var/lib/cfm: the
	// in-scope exclude test below persists an exclude for mysite.com.
	webdet.SetDefaultDirsForTest(t, t.TempDir())
	e := webdet.NewEngine(webdet.Config{
		TrafficRulesStorePath: filepath.Join(t.TempDir(), "rules.json"),
	})
	e.RegisterHTTP(mux)

	return store, TokenMiddleware("admin-secret", store)(mux)
}

func doAuthReq(h http.Handler, method, path, token string, body []byte, withCookie bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if withCookie {
		req.AddCookie(&http.Cookie{Name: "cfm-sid", Value: "pretend-admin-session"})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestScopedToken_CannotReadGlobalLists(t *testing.T) {
	store, h := newScopeTestServer(t)
	scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)

	rr := doAuthReq(h, http.MethodGet, "/api/v1/webdet/ip-short", scoped.Token, nil, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected scoped token to be blocked from global list endpoint, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestScopedToken_CannotMutateOutOfScopeVhost(t *testing.T) {
	store, h := newScopeTestServer(t)
	scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)

	body := []byte(`{"host":"other.com","ttl":"30m","reason":"manual"}`)
	rr := doAuthReq(h, http.MethodPost, "/api/v1/challenge/vhost/add", scoped.Token, body, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for out-of-scope mutation, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestScopedToken_CannotListOrRevokeOtherUsersTokens(t *testing.T) {
	store, h := newScopeTestServer(t)
	scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)
	other := store.Issue([]string{"other.com"}, nil, nil, "viewer", "other", time.Hour)

	rr := doAuthReq(h, http.MethodGet, "/api/v1/tokens/list", scoped.Token, nil, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected scoped token list to be forbidden, got %d body=%s", rr.Code, rr.Body.String())
	}

	payload, _ := json.Marshal(map[string]string{"id": other.ID})
	rr = doAuthReq(h, http.MethodPost, "/api/v1/tokens/revoke", scoped.Token, payload, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected scoped revoke to be forbidden, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestScopedToken_CanMutateInScopeVhost(t *testing.T) {
	store, h := newScopeTestServer(t)
	scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)

	// In-scope host exclude add is the per-vhost Challenge/WAF self-service the
	// embedded cPanel UI performs. It must NOT be blocked by scope enforcement
	// (regression guard for the client self-service fix — the existing tests
	// only assert that OUT-of-scope mutation is forbidden).
	rr := doAuthReq(h, http.MethodPost, "/api/v1/waf/exclude/add?type=host&value=mysite.com", scoped.Token, nil, false)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("expected scoped token to manage its own in-scope vhost, got 403 body=%s", rr.Body.String())
	}

	// The same caller must still be rejected for a host outside its scope.
	rr = doAuthReq(h, http.MethodPost, "/api/v1/waf/exclude/add?type=host&value=other.com", scoped.Token, nil, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for out-of-scope exclude, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestScopedToken_CannotBlockIPGlobally(t *testing.T) {
	store := NewTokenStore()
	scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)

	mux := http.NewServeMux()
	// nil backend: a scoped caller is rejected by the admin guard before the
	// backend is ever consulted; an admin caller passes the guard and then
	// gets 503 (no backend), which still proves the guard let it through.
	RegisterBlock(mux, nil)
	h := TokenMiddleware("admin-secret", store)(mux)

	body := []byte(`{"ip":"203.0.113.7","ttl":"30m","reason":"manual"}`)

	rr := doAuthReq(h, http.MethodPost, "/api/v1/firewall/block", scoped.Token, body, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for scoped global IP block, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = doAuthReq(h, http.MethodPost, "/api/v1/firewall/block", "admin-secret", body, false)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin token must pass the admin guard for firewall/block, got 403 body=%s", rr.Body.String())
	}

	// The bulk sibling must sit behind the same admin guard.
	batchBody := []byte(`{"ips":["203.0.113.7","203.0.113.8"],"ttl":"30m","reason":"manual"}`)
	rr = doAuthReq(h, http.MethodPost, "/api/v1/firewall/block/batch", scoped.Token, batchBody, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for scoped batch IP block, got %d body=%s", rr.Code, rr.Body.String())
	}
	rr = doAuthReq(h, http.MethodPost, "/api/v1/firewall/block/batch", "admin-secret", batchBody, false)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin token must pass the admin guard for firewall/block/batch, got 403 body=%s", rr.Body.String())
	}
}

func TestScopedToken_BeatsCookieWhenBothPresent(t *testing.T) {
	store, h := newScopeTestServer(t)
	scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)

	rr := doAuthReq(h, http.MethodGet, "/api/v1/webdet/ip-short", scoped.Token, nil, true)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected scoped token to win over cookie and remain restricted, got %d body=%s", rr.Code, rr.Body.String())
	}
}
