package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	webdet "cfm/internal/webdetector"
)

// pprofAuthzCtx builds a request context marked authenticated with the given
// role, mirroring what TokenMiddleware attaches for admin/scoped tokens.
func pprofAuthzCtx(role string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, role)
	return ctx
}

// pprofSafePaths are the registered pprof routes that respond immediately
// without running a profiler, so they are safe to exercise for the admin
// success case. /debug/pprof/profile and /debug/pprof/trace are deliberately
// excluded — they would actually sample CPU/execution for seconds.
var pprofSafePaths = []string{
	"/debug/pprof/",
	"/debug/pprof/cmdline",
	"/debug/pprof/symbol",
}

// allPprofPaths is every route registerPprofHandlers mounts. Used only for the
// deny cases, which never reach the underlying profiler.
var allPprofPaths = []string{
	"/debug/pprof/",
	"/debug/pprof/cmdline",
	"/debug/pprof/profile",
	"/debug/pprof/symbol",
	"/debug/pprof/trace",
}

// TestPprofDeniesScopedAndAnonymous is the R02 regression guard: pprof must be
// admin-only. A scoped token (issued to cPanel/DA tenants) and an
// unauthenticated request must both be refused at the handler with 403 before
// any profiler runs, so a scoped viewer can never pull host-global heap /
// goroutine / cmdline dumps.
func TestPprofDeniesScopedAndAnonymous(t *testing.T) {
	mux := http.NewServeMux()
	registerPprofHandlers(mux)

	for _, path := range allPprofPaths {
		// Scoped token — authenticated but not admin.
		reqScoped := httptest.NewRequest(http.MethodGet, path, nil).
			WithContext(pprofAuthzCtx(webdet.CtxRoleScoped))
		rrScoped := httptest.NewRecorder()
		mux.ServeHTTP(rrScoped, reqScoped)
		if rrScoped.Code != http.StatusForbidden {
			t.Errorf("scoped GET %s: expected 403, got %d", path, rrScoped.Code)
		}

		// Anonymous / no auth context — adminOnlyHandler fails closed.
		reqAnon := httptest.NewRequest(http.MethodGet, path, nil)
		rrAnon := httptest.NewRecorder()
		mux.ServeHTTP(rrAnon, reqAnon)
		if rrAnon.Code != http.StatusForbidden {
			t.Errorf("anonymous GET %s: expected 403, got %d", path, rrAnon.Code)
		}
	}
}

// TestPprofAllowsAdmin confirms the gate does not lock admins out: an
// admin-authenticated request reaches the profiler and is not refused with 403.
func TestPprofAllowsAdmin(t *testing.T) {
	mux := http.NewServeMux()
	registerPprofHandlers(mux)

	for _, path := range pprofSafePaths {
		req := httptest.NewRequest(http.MethodGet, path, nil).
			WithContext(pprofAuthzCtx(webdet.CtxRoleAdmin))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code == http.StatusForbidden {
			t.Errorf("admin GET %s: unexpectedly forbidden (403)", path)
		}
		if rr.Code != http.StatusOK {
			t.Errorf("admin GET %s: expected 200, got %d", path, rr.Code)
		}
	}
}
