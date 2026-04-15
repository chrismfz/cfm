package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	webdet "cfm/internal/webdetector"
)

func withSessionAllowedStub(t *testing.T, allow bool) {
	t.Helper()
	orig := sessionAllowedRequest
	sessionAllowedRequest = func(_ *http.Request) bool { return allow }
	t.Cleanup(func() { sessionAllowedRequest = orig })
}

func TestTokenMiddlewareRedirectDirectTLSKeepsCfmAdminPrefix(t *testing.T) {
	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://host:6061/cfm-admin/webdetector/controls/?host=example.com", nil)
	req.RemoteAddr = "198.51.100.5:443"
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected %d got %d", http.StatusSeeOther, rr.Code)
	}
	got := rr.Header().Get("Location")
	want := "/cfm-admin/login?next=%2Fcfm-admin%2Fwebdetector%2Fcontrols%2F%3Fhost%3Dexample.com"
	if got != want {
		t.Fatalf("location mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestTokenMiddlewareRedirectProxyPrefixFromHeader(t *testing.T) {
	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://host/webdetector/controls/?host=example.com", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-Prefix", "/cfm-admin")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	got := rr.Header().Get("Location")
	want := "/cfm-admin/login?next=%2Fcfm-admin%2Fwebdetector%2Fcontrols%2F%3Fhost%3Dexample.com"
	if got != want {
		t.Fatalf("location mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestHandleLoginAndLogoutUseDetectedBasePath(t *testing.T) {
	// Login page should use base path for POST /login and /login/verify.
	req := httptest.NewRequest(http.MethodGet, "https://host/login?next=%2Fcfm-admin%2F", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Prefix", "/cfm-admin")
	rr := httptest.NewRecorder()
	handleLogin(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `const basePath="/cfm-admin";`) {
		t.Fatalf("login page missing basePath, body=%q", body)
	}
	if !strings.Contains(body, `fetch(basePath+'/login'`) {
		t.Fatalf("login page fetch should use basePath")
	}
	if !strings.Contains(body, `basePath+'/login/verify?next='`) {
		t.Fatalf("2FA redirect should use basePath")
	}

	// Logout should redirect back to prefixed login.
	logoutReq := httptest.NewRequest(http.MethodGet, "https://host/logout", nil)
	logoutReq.RemoteAddr = "127.0.0.1:12345"
	logoutReq.Header.Set("X-Forwarded-Prefix", "/cfm-admin")
	logoutRR := httptest.NewRecorder()
	handleLogout(logoutRR, logoutReq)
	if got := logoutRR.Header().Get("Location"); got != "/cfm-admin/login" {
		t.Fatalf("unexpected logout location: %s", got)
	}
}

func TestTokenMiddlewareAllowsPrefixedLoginPath(t *testing.T) {
	called := false
	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host:6061/cfm-admin/login", nil)
	req.RemoteAddr = "198.51.100.5:443"
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected prefixed login request to pass through middleware")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
}

func TestTokenMiddlewareEmbeddedRequestRejectsSessionFallback(t *testing.T) {
	withSessionAllowedStub(t, true)

	called := false
	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/dnat", nil)
	req.Header.Set("X-CFM-Embedded", "cpanel")
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if called {
		t.Fatalf("embedded request should not reach handler via session fallback")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d got %d", http.StatusUnauthorized, rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Fatalf("expected no redirect for embedded request, got Location=%q", loc)
	}
}

func TestTokenMiddlewareStandaloneRequestAllowsSessionFallback(t *testing.T) {
	withSessionAllowedStub(t, true)

	called := false
	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		authn, _ := r.Context().Value(webdet.CtxAuthnKey{}).(bool)
		if !authn {
			t.Fatalf("expected authenticated context marker")
		}
		role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string)
		if role != webdet.CtxRoleAdmin {
			t.Fatalf("expected admin role marker, got %q", role)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/dnat", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("standalone request should be allowed via session fallback")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
}

func TestTokenMiddlewareAdminTokenSetsAdminAuthMarkers(t *testing.T) {
	called := false
	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		authn, _ := r.Context().Value(webdet.CtxAuthnKey{}).(bool)
		if !authn {
			t.Fatalf("expected authenticated context marker")
		}
		role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string)
		if role != webdet.CtxRoleAdmin {
			t.Fatalf("expected admin role marker, got %q", role)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/dnat", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected handler to be reached")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
}

func TestTokenMiddlewareMissingAdminTokenRejectsPrivilegedRoutes(t *testing.T) {
	withSessionAllowedStub(t, true)

	called := false
	h := TokenMiddleware("", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/tokens/list", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if called {
		t.Fatalf("expected privileged route to be blocked when AUTH_TOKEN is missing")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d got %d", http.StatusServiceUnavailable, rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `server misconfigured: AUTH_TOKEN missing`) {
		t.Fatalf("expected clear misconfiguration error, got body=%q", rr.Body.String())
	}
}

func TestTokenMiddlewareMissingAdminTokenBlocksSystemDNAT(t *testing.T) {
	called := false
	h := TokenMiddleware("", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/dnat", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if called {
		t.Fatalf("expected system dnat route to be blocked when AUTH_TOKEN is missing")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d got %d", http.StatusServiceUnavailable, rr.Code)
	}
}
