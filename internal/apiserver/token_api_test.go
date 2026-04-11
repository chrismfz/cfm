package apiserver

import (
	"net/http"
	"testing"
	"time"
)

func assertIdentityNoCacheHeaders(t *testing.T, h http.Header) {
	t.Helper()
	if got := h.Get("Cache-Control"); got != "no-store, no-cache, must-revalidate, private" {
		t.Fatalf("unexpected Cache-Control header: %q", got)
	}
	if got := h.Get("Pragma"); got != "no-cache" {
		t.Fatalf("unexpected Pragma header: %q", got)
	}
	if got := h.Get("Expires"); got != "0" {
		t.Fatalf("unexpected Expires header: %q", got)
	}
	if got := h.Get("Vary"); got != "Authorization, Cookie" {
		t.Fatalf("unexpected Vary header: %q", got)
	}
}

func TestTokensMe_AdminIdentityIsUncached(t *testing.T) {
	withSessionAllowedStub(t, true)
	_, h := newScopeTestServer(t)

	rr := doAuthReq(h, http.MethodGet, "/api/v1/tokens/me", "", nil, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	assertIdentityNoCacheHeaders(t, rr.Header())
}

func TestTokensMe_ScopedIdentityIsUncached(t *testing.T) {
	store, h := newScopeTestServer(t)
	scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)

	rr := doAuthReq(h, http.MethodGet, "/api/v1/tokens/me", scoped.Token, nil, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	assertIdentityNoCacheHeaders(t, rr.Header())
}

func TestTokensMe_MethodNotAllowedStillSendsUncachedHeaders(t *testing.T) {
	withSessionAllowedStub(t, true)
	_, h := newScopeTestServer(t)

	rr := doAuthReq(h, http.MethodPost, "/api/v1/tokens/me", "", nil, false)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d body=%s", rr.Code, rr.Body.String())
	}
	assertIdentityNoCacheHeaders(t, rr.Header())
}
