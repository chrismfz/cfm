package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestTokensMe_CookieOnlyAuthReturnsScopedIdentity(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	store := NewTokenStore()
	mux := http.NewServeMux()
	RegisterTokenManagementEndpoints(mux, store)
	// Mirror the prefix rewriter used by apiserver.go so that cookie-scoped
	// calls to /cfm-admin/api/v1/... dispatch to the underlying /api/v1/...
	// handler while preserving context.
	mux.HandleFunc("/cfm-admin/", func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = r.URL.Path[len("/cfm-admin"):]
		if r2.URL.Path == "" || r2.URL.Path[0] != '/' {
			r2.URL.Path = "/" + r2.URL.Path
		}
		mux.ServeHTTP(w, r2)
	})
	h := TokenMiddleware("admin-secret", store)(mux)

	st := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "cookie-auth", time.Hour)

	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/api/v1/tokens/me", nil)
	cookieValue, err := encodeEmbedCookie(req, st.ID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("encode cookie: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: cookieValue})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from cookie-auth tokens/me, got %d body=%s", rr.Code, rr.Body.String())
	}
	assertIdentityNoCacheHeaders(t, rr.Header())

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v body=%s", err, rr.Body.String())
	}
	if body["scoped"] != true {
		t.Fatalf("expected scoped=true, body=%s", rr.Body.String())
	}
	if body["id"] != st.ID {
		t.Fatalf("expected id=%q, got %v", st.ID, body["id"])
	}
	vhosts, _ := body["vhosts"].([]interface{})
	if len(vhosts) != 1 || vhosts[0] != "mysite.com" {
		t.Fatalf("expected vhosts=[mysite.com], got %v", body["vhosts"])
	}
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
