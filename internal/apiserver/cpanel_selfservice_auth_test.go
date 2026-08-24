package apiserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCpanelSelfServicePathRequiresAssertionHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil)
	if isCpanelPluginSelfServicePath(req) {
		t.Fatal("no credential: path must not be self-service")
	}
	req.Header.Set("Authorization", "Bearer some-bearer-value")
	if isCpanelPluginSelfServicePath(req) {
		t.Fatal("Bearer must not mark the path self-service; it belongs to the CFM token namespace")
	}
	req.Header.Set("X-CFM-Actor-Assertion", "header.assertion.value")
	if !isCpanelPluginSelfServicePath(req) {
		t.Fatal("dedicated assertion header must mark the path self-service")
	}

	post := httptest.NewRequest(http.MethodPost, "/api/v1/cpanel/user-info", nil)
	post.Header.Set("X-CFM-Actor-Assertion", "header.assertion.value")
	if isCpanelPluginSelfServicePath(post) {
		t.Fatal("self-service bypass is GET-only")
	}
}

func TestTokenMiddlewareCpanelAuthNamespaces(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	h := TokenMiddleware("admin-secret", NewTokenStore())(next)

	assertionOnly := func() (*httptest.ResponseRecorder, bool) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil)
		req.Header.Set("X-CFM-Actor-Assertion", "header.assertion.value")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr, reached
	}

	// Assertion header alone bypasses token validation and reaches the
	// handler, which performs the strict assertion check.
	rr, ok := assertionOnly()
	if !ok || rr.Code != http.StatusOK {
		t.Fatalf("assertion header must reach handler: reached=%t status=%d", ok, rr.Code)
	}

	// A Bearer carrying an assertion-shaped credential is ordinary CFM token
	// auth: unknown value -> 401 token_invalid, never the handler.
	reached = false
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil)
	req.Header.Set("Authorization", "Bearer header.assertion.value")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if reached || rr.Code != http.StatusUnauthorized {
		t.Fatalf("bearer-only assertion must be rejected as CFM token: reached=%t status=%d", reached, rr.Code)
	}

	// Conflicting credentials fail hard: a bogus X-CFM-Token is validated as
	// such and rejects the request even with an assertion header present.
	reached = false
	req = httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil)
	req.Header.Set("X-CFM-Actor-Assertion", "header.assertion.value")
	req.Header.Set("X-CFM-Token", "bogus-token")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if reached || rr.Code != http.StatusUnauthorized {
		t.Fatalf("conflicting credentials must fail hard: reached=%t status=%d", reached, rr.Code)
	}

	// A genuine admin bearer still authenticates on this path.
	reached = false
	req = httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !reached || rr.Code != http.StatusOK {
		t.Fatalf("valid admin bearer must authenticate: reached=%t status=%d", reached, rr.Code)
	}
}
