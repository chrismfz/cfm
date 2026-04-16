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

	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=https://evil.example/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestEmbedBootstrapValidConsumeSetsCookieAndRedirects(t *testing.T) {
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
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

func TestEmbedBootstrapRejectsReplayCode(t *testing.T) {
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	firstReq := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
	firstRR := httptest.NewRecorder()
	h.ServeHTTP(firstRR, firstReq)
	if firstRR.Code != http.StatusSeeOther {
		t.Fatalf("expected first consume %d got %d", http.StatusSeeOther, firstRR.Code)
	}

	replayReq := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
	replayRR := httptest.NewRecorder()
	h.ServeHTTP(replayRR, replayReq)
	if replayRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected replay %d got %d", http.StatusUnauthorized, replayRR.Code)
	}
}

func TestEmbedBootstrapRejectsExpiredCode(t *testing.T) {
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", -1*time.Second)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestEmbedBootstrapRejectsWrongPathForCode(t *testing.T) {
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d got %d", http.StatusUnauthorized, rr.Code)
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
		authn, _ := r.Context().Value(webdet.CtxAuthnKey{}).(bool)
		if !authn {
			t.Fatalf("expected authenticated context marker")
		}
		role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string)
		if role != webdet.CtxRoleScoped {
			t.Fatalf("expected scoped role marker, got %q", role)
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
		authn, _ := r.Context().Value(webdet.CtxAuthnKey{}).(bool)
		if !authn {
			t.Fatalf("expected authenticated context marker")
		}
		role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string)
		if role != webdet.CtxRoleScoped {
			t.Fatalf("expected scoped role marker, got %q", role)
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
