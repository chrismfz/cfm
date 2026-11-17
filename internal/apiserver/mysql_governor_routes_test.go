package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mysqlpkg "cfm/internal/detectors/mysql"
	webdet "cfm/internal/webdetector"
)

// A governor that has not connected (MySQL not up yet, or no database on the
// node) must still own its routes: before, they were not registered and fell
// through to the web UI's "/", whose HTML `cfm mysqltop` failed to parse.
func TestMySQLGovernorRoutesAnswer503JSONWhileNotRunning(t *testing.T) {
	m := http.NewServeMux()
	m.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html>"))
	}))
	registerMySQLGovernorRoutes(m, mysqlpkg.NewGovernorLifecycle()) // never started: no governor

	admin := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
		ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
		return r.WithContext(ctx)
	}

	for _, p := range append(append([]string{}, mysqlAdminRoutes...), mysqlScopedRoutes...) {
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, admin(p))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: HTTP %d, want 503 (body %q)", p, rec.Code, rec.Body)
			continue
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || !strings.HasPrefix(body["error"], "mysql governor not running") {
			t.Errorf("%s: body %q (%v), want the governor-not-running JSON", p, rec.Body, err)
		}
	}

	// The admin guard still runs first: no status leaks to a non-admin.
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/mysql/state", nil))
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "governor") {
		t.Fatalf("unauthenticated /mysql/state: HTTP %d %q, want the admin 403", rec.Code, rec.Body)
	}
}
