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
