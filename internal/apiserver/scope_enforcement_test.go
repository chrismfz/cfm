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

func TestScopedToken_BeatsCookieWhenBothPresent(t *testing.T) {
	store, h := newScopeTestServer(t)
	scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)

	rr := doAuthReq(h, http.MethodGet, "/api/v1/webdet/ip-short", scoped.Token, nil, true)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected scoped token to win over cookie and remain restricted, got %d body=%s", rr.Code, rr.Body.String())
	}
}
