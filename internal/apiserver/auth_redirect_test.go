package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

