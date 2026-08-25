package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersMiddleware_SetsBaselineHeaders(t *testing.T) {
	h := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A handler-rendered HTML response (like /login) that sets neither header.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://host/login", nil))

	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Fatalf("Referrer-Policy = %q, want strict-origin-when-cross-origin", got)
	}
}

func TestSecurityHeadersMiddleware_DoesNotOverrideExisting(t *testing.T) {
	// A handler that deliberately chooses a stricter policy keeps it.
	h := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://host/x", nil))
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want the handler's own no-referrer preserved", got)
	}
}

func TestSecurityHeadersMiddleware_PresentOnErrorResponse(t *testing.T) {
	// The baseline headers must be staged before the inner handler writes, so even
	// a short-circuited error carries them.
	h := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://host/x", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", rr.Code)
	}
	if rr.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Fatalf("Referrer-Policy missing on error response")
	}
}

// TestTokenMiddleware_AuthFailuresAreNoStore covers R10: an anonymous or invalid
// request is rejected in TokenMiddleware before any endpoint-specific header runs,
// so the 401 must carry no-store here or it could be cached as another identity.
func TestTokenMiddleware_AuthFailuresAreNoStore(t *testing.T) {
	reached := func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("auth failure must not reach the protected handler")
	}
	h := TokenMiddleware("admin-secret", NewTokenStore())(http.HandlerFunc(reached))

	cases := []struct {
		name  string
		build func() *http.Request
	}{
		{"anonymous API 401", func() *http.Request {
			// No Accept: text/html -> JSON 401, not a browser login redirect.
			return httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/status", nil)
		}},
		{"invalid token 401", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/status", nil)
			r.Header.Set("Authorization", "Bearer wrong-secret")
			return r
		}},
	}
	for _, c := range cases {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, c.build())
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s: code = %d, want 401", c.name, rr.Code)
		}
		if cc := rr.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Fatalf("%s: Cache-Control = %q, want it to contain no-store", c.name, cc)
		}
		if vary := rr.Header().Get("Vary"); !strings.Contains(vary, "Cookie") {
			t.Fatalf("%s: Vary = %q, want it to contain Cookie", c.name, vary)
		}
	}
}
