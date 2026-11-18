package apiserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFMiddlewareRejectsSessionMutatingWithoutOriginOrReferer(t *testing.T) {
	nextCalled := false
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "http://cfm.local/api/v1/firewall/block", nil)
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismSession))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if nextCalled {
		t.Fatalf("expected middleware to reject request before handler")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if body := rr.Body.String(); body != `{"error":"forbidden"}` {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestCSRFMiddlewareRejectsSessionMutatingWithInvalidOrigin(t *testing.T) {
	nextCalled := false
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPut, "http://cfm.local/api/v1/firewall/block", nil)
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismSession))
	req.Header.Set("Origin", "://not-a-valid-origin")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if nextCalled {
		t.Fatalf("expected middleware to reject invalid Origin")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareRejectsSessionMutatingWithInvalidReferer(t *testing.T) {
	nextCalled := false
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPatch, "http://cfm.local/api/v1/firewall/block", nil)
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismSession))
	req.Header.Set("Referer", "not a url")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if nextCalled {
		t.Fatalf("expected middleware to reject invalid Referer")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareAllowsSessionMutatingWithMatchingOrigin(t *testing.T) {
	nextCalled := false
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodDelete, "http://cfm.local/api/v1/firewall/block", nil)
	req.Host = "cfm.local:6060"
	req.Header.Set("Origin", "https://cfm.local")
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismSession))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected middleware to allow request")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareAllowsSessionMutatingWithMatchingReferer(t *testing.T) {
	nextCalled := false
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "http://cfm.local/api/v1/firewall/block", nil)
	req.Host = "cfm.local:6060"
	req.Header.Set("Referer", "https://cfm.local/some/path")
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismSession))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected middleware to allow matching Referer")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareSkipsTokenAuthenticatedRequests(t *testing.T) {
	nextCalled := false
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		_, _ = io.WriteString(w, "ok")
	}))

	req := httptest.NewRequest(http.MethodPost, "http://cfm.local/api/v1/firewall/block", nil)
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismTokenAdmin))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected middleware to skip non-session auth")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareAllowsTrustedForwardedHost(t *testing.T) {
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPatch, "http://127.0.0.1/api/v1/firewall/block", nil)
	req.RemoteAddr = "127.0.0.1:2345"
	req.Host = "127.0.0.1:6060"
	req.Header.Set("X-Forwarded-Host", "panel.example.com")
	req.Header.Set("Origin", "https://panel.example.com")
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismSession))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

// ── Slice-D security review I2: the scoped EMBED cookie is SameSite=None ─────
// (the cPanel iframe needs it cross-site), so it is an ambient credential a
// hostile page can ride into query-param POSTs (challenge disarm, WAF
// exclude). Embed-cookie auth must go through the same same-origin check as
// the admin session; the iframe's own XHRs are same-origin and pass.

func TestCSRFMiddlewareRejectsEmbedCookieMutatingCrossSite(t *testing.T) {
	nextCalled := false
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	// A cross-site form POST: hostile Origin, victim's embed cookie.
	req := httptest.NewRequest(http.MethodPost, "http://cfm.local/api/v1/challenge/vhost/remove?host=victim.com", nil)
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismEmbedCookie))
	req.Header.Set("Origin", "http://evil.example")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if nextCalled || rr.Code != http.StatusForbidden {
		t.Fatalf("cross-site embed-cookie POST must 403, got %d (nextCalled=%v)", rr.Code, nextCalled)
	}

	// No Origin and no Referer (a bare cross-site form) is rejected too.
	nextCalled = false
	req = httptest.NewRequest(http.MethodPost, "http://cfm.local/api/v1/challenge/vhost/add?host=victim.com&ttl=24h", nil)
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismEmbedCookie))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if nextCalled || rr.Code != http.StatusForbidden {
		t.Fatalf("origin-less embed-cookie POST must 403, got %d (nextCalled=%v)", rr.Code, nextCalled)
	}
}

func TestCSRFMiddlewareAllowsEmbedCookieSameOrigin(t *testing.T) {
	nextCalled := false
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	// The iframe's own XHR: Origin matches the request host.
	req := httptest.NewRequest(http.MethodPost, "http://cfm.local/api/v1/challenge/vhost/add?host=own.com&ttl=1h", nil)
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismEmbedCookie))
	req.Header.Set("Origin", "http://cfm.local")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !nextCalled || rr.Code != http.StatusNoContent {
		t.Fatalf("same-origin embed-cookie POST must pass, got %d (nextCalled=%v)", rr.Code, nextCalled)
	}

	// GETs stay exempt regardless of mechanism.
	nextCalled = false
	req = httptest.NewRequest(http.MethodGet, "http://cfm.local/api/v1/challenge/vhost/status?host=own.com", nil)
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismEmbedCookie))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !nextCalled {
		t.Fatalf("GET under embed-cookie auth must not be CSRF-checked")
	}
}

// The admin SSO cookie is an ambient credential: a mutating request it
// authenticates needs a same-origin Origin/Referer like a session one.
func TestCSRFMiddlewareChecksEmbedAdminCookie(t *testing.T) {
	nextCalled := false
	h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://cfm.local/cfm-admin/api/v1/waf/exclude/add", nil)
	req.Header.Set("Origin", "https://other.example")
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismEmbedAdminCookie))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if nextCalled || rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST on the admin SSO cookie: status %d, handler called=%v", rr.Code, nextCalled)
	}

	nextCalled = false
	req = httptest.NewRequest(http.MethodPost, "http://cfm.local/cfm-admin/api/v1/waf/exclude/add", nil)
	req.Header.Set("Origin", "http://cfm.local")
	req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismEmbedAdminCookie))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !nextCalled {
		t.Fatalf("same-origin POST on the admin SSO cookie was refused: status %d", rr.Code)
	}
}

// Another port on the same host is another origin: a page on a panel port
// cannot ride a cookie on the admin UI. The admin UI's own origin, with or
// without an explicit port, still passes.
func TestCSRFMiddlewareOriginPort(t *testing.T) {
	cases := []struct {
		name, host, xfh, remote, origin string
		want                             bool
	}{
		{"edge, same origin", "node.example", "node.example", "127.0.0.1:4000", "https://node.example", true},
		{"edge, panel port origin", "node.example", "node.example", "127.0.0.1:4000", "https://node.example:2083", false},
		{"edge, webmail port origin", "node.example", "node.example", "127.0.0.1:4000", "https://node.example:2096", false},
		{"edge, explicit 443", "node.example", "node.example", "127.0.0.1:4000", "https://node.example:443", true},
		{"edge on a custom port", "node.example", "node.example:9443", "127.0.0.1:4000", "https://node.example:9443", true},
		{"direct :6061", "node.example:6061", "", "198.51.100.7:4000", "https://node.example:6061", true},
		{"direct :6061, panel origin", "node.example:6061", "", "198.51.100.7:4000", "https://node.example:2087", false},
		{"proxy sends backend port in Host", "node.example:6060", "", "198.51.100.7:4000", "https://node.example", true},
		{"XFH ignored from a non-loopback peer", "node.example", "node.example:2083", "198.51.100.7:4000", "https://node.example:2083", false},
	}
	for _, c := range cases {
		called := false
		h := CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		req := httptest.NewRequest(http.MethodPost, "http://"+c.host+"/api/v1/waf/exclude/add", nil)
		req.Host = c.host
		req.RemoteAddr = c.remote
		if c.xfh != "" {
			req.Header.Set("X-Forwarded-Host", c.xfh)
		}
		req.Header.Set("Origin", c.origin)
		req = req.WithContext(withAuthnMechanism(req.Context(), authnMechanismEmbedAdminCookie))
		h.ServeHTTP(httptest.NewRecorder(), req)
		if called != c.want {
			t.Errorf("%s: allowed=%v, want %v", c.name, called, c.want)
		}
	}
}
