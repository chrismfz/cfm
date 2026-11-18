package webdetector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every engine route refuses a request with no admin or scoped identity,
// except the cPanel actor-assertion lookup, whose handler authenticates it.
func TestRegisterHTTPRequiresIdentityOnEveryRoute(t *testing.T) {
	e, mux := newTestEngine(t)
	for _, rt := range e.apiRoutes() {
		if _, ok := selfAuthenticatingRoutes[rt.path]; ok {
			continue
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(method, rt.path, nil).WithContext(context.Background())
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s without identity: status %d, want 403", method, rt.path, rec.Code)
			}
		}
	}
	// The assertion lookup still reaches its handler, which refuses a
	// request without an assertion on its own terms.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("cpanel/user-info without an assertion: 200")
	}
}
