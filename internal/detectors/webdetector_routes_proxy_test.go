package detectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	webdet "cfm/internal/webdetector"
)

// The engine's routes are refused to a request that carries no authenticated
// identity, whatever path brought it to the shared mux; admin, scoped and the
// cPanel actor-assertion lookup still get through.
func TestWebdetRoutesProxyRefusesUnauthenticated(t *testing.T) {
	inner := http.NewServeMux()
	inner.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("reached")) })
	setWebdetRoutesHandler(inner)
	defer setWebdetRoutesHandler(nil)

	withRole := func(r *http.Request, role string) *http.Request {
		ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
		ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, role)
		return r.WithContext(ctx)
	}
	cases := []struct {
		name string
		req  *http.Request
		want int
	}{
		{"anonymous", httptest.NewRequest(http.MethodGet, "/api/v1/webdet/rules/export", nil), http.StatusUnauthorized},
		{"anonymous cpanel without assertion", httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil), http.StatusUnauthorized},
		{"admin", withRole(httptest.NewRequest(http.MethodGet, "/api/v1/webdet/rules/export", nil), webdet.CtxRoleAdmin), http.StatusOK},
		{"scoped", withRole(httptest.NewRequest(http.MethodGet, "/api/v1/webdet/top", nil), webdet.CtxRoleScoped), http.StatusOK},
	}
	assert := httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil)
	assert.Header.Set("X-CFM-Actor-Assertion", "x")
	cases = append(cases, struct {
		name string
		req  *http.Request
		want int
	}{"cpanel actor assertion", assert, http.StatusOK})

	for _, c := range cases {
		rec := httptest.NewRecorder()
		webdetRoutesProxy(rec, c.req)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
	}
}
