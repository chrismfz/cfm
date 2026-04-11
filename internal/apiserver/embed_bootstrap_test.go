package apiserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	webdet "cfm/internal/webdetector"
)

func TestEmbedBootstrapRejectsInvalidNext(t *testing.T) {
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?token="+st.Token+"&next=https://evil.example/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestEmbedBootstrapSetsCookieAndRedirects(t *testing.T) {
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?token="+st.Token+"&next=/cfm-admin/webdetector/controls/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected %d got %d", http.StatusSeeOther, rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/cfm-admin/webdetector/controls/" {
		t.Fatalf("unexpected redirect location %q", got)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected cookie to be set")
	}
	found := false
	for _, c := range cookies {
		if c.Name == embedBootstrapCookieName {
			found = true
			if c.Path != "/cfm-admin/" {
				t.Fatalf("unexpected cookie path: %q", c.Path)
			}
			if !c.HttpOnly {
				t.Fatalf("expected HttpOnly cookie")
			}
		}
	}
	if !found {
		t.Fatalf("expected %q cookie", embedBootstrapCookieName)
	}
}

func TestTokenMiddlewareAllowsScopedBootstrapCookieForCfmAdminHTML(t *testing.T) {
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	called := false
	h := TokenMiddleware("admin-secret", store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		scope, _ := r.Context().Value(webdet.CtxScopeKey{}).(map[string]struct{})
		if scope == nil {
			t.Fatalf("expected scoped context from bootstrap cookie")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/webdetector/controls/", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: encodeEmbedCookie(st.Token, time.Now().Add(time.Minute))})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected handler to be reached")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
}

func TestTokenMiddlewareAllowsEmbeddedScopedBootstrapCookieForCfmAdminPath(t *testing.T) {
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	called := false
	h := TokenMiddleware("admin-secret", store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		scope, _ := r.Context().Value(webdet.CtxScopeKey{}).(map[string]struct{})
		if scope == nil {
			t.Fatalf("expected scoped context from bootstrap cookie")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/webdetector/controls/", nil)
	req.Header.Set("X-CFM-Embedded", "cpanel")
	req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: encodeEmbedCookie(st.Token, time.Now().Add(time.Minute))})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected handler to be reached")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
}
