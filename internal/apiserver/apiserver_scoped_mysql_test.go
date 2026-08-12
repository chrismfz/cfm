package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"cfm/internal/panelmap"
	webdet "cfm/internal/webdetector"
)

func TestScopedMySQLFilterHandler_ScopedExplicitOutOfScopeUserForbidden(t *testing.T) {
	writeScopedMySQLOwnerFixture(t)

	nextCalled := false
	h := scopedMySQLFilterHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := newScopedMySQLRequest(t, "/api/v1/mysql/user-summary?user=otheracct")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for out-of-scope user filter, got %d body=%s", rr.Code, rr.Body.String())
	}
	if nextCalled {
		t.Fatalf("expected next handler to not be called")
	}
}

func TestScopedMySQLFilterHandler_ScopedExplicitInScopeUserAllowed(t *testing.T) {
	writeScopedMySQLOwnerFixture(t)

	nextCalled := false
	h := scopedMySQLFilterHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := newScopedMySQLRequest(t, "/api/v1/mysql/user-summary?user=own")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for in-scope user filter, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !nextCalled {
		t.Fatalf("expected next handler to be called")
	}
}

func TestScopedMySQLFilterHandler_ScopedNoUserInjectsDerivedDefaults(t *testing.T) {
	writeScopedMySQLOwnerFixture(t)

	var gotUsers []string
	h := scopedMySQLFilterHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUsers = r.URL.Query()["user"]
		w.WriteHeader(http.StatusOK)
	}))

	req := newScopedMySQLRequest(t, "/api/v1/mysql/user-summary")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with auto-derived filters, got %d body=%s", rr.Code, rr.Body.String())
	}
	want := []string{"own", "own_*"}
	if !reflect.DeepEqual(gotUsers, want) {
		t.Fatalf("unexpected injected users: got=%v want=%v", gotUsers, want)
	}
}

func TestScopedMySQLFilterHandler_UsesExplicitDBUserScopeWhenPresent(t *testing.T) {
	writeScopedMySQLOwnerFixture(t)

	var gotUsers []string
	h := scopedMySQLFilterHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUsers = r.URL.Query()["user"]
		w.WriteHeader(http.StatusOK)
	}))

	req := newScopedMySQLRequestWithDBScope(t, "/api/v1/mysql/user-summary", map[string]struct{}{
		"explicit_user": {},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with explicit db user scope, got %d body=%s", rr.Code, rr.Body.String())
	}
	want := []string{"explicit_user"}
	if !reflect.DeepEqual(gotUsers, want) {
		t.Fatalf("unexpected injected users: got=%v want=%v", gotUsers, want)
	}
}

func TestScopedMySQLFilterHandler_UsesExplicitDatabaseScopeWhenPresent(t *testing.T) {
	writeScopedMySQLOwnerFixture(t)

	nextCalled := false
	h := scopedMySQLFilterHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := newScopedMySQLRequestWithDatabaseScope(t, "/api/v1/mysql/user-summary?db=explicit_db", map[string]struct{}{
		"explicit_db": {},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for in-scope explicit db filter, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !nextCalled {
		t.Fatalf("expected next handler to be called")
	}
}

func TestScopedMySQLFilterHandler_ScopedDBInjectionRejected(t *testing.T) {
	writeScopedMySQLOwnerFixture(t)

	nextCalled := false
	h := scopedMySQLFilterHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := newScopedMySQLRequest(t, "/api/v1/mysql/user-summary?db=otherdb")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for out-of-scope db filter, got %d body=%s", rr.Code, rr.Body.String())
	}
	if nextCalled {
		t.Fatalf("expected next handler to not be called")
	}
}

func TestScopedMySQLFilterHandler_EndpointFamilyInjectionRejected(t *testing.T) {
	writeScopedMySQLOwnerFixture(t)

	tests := []struct {
		name string
		path string
	}{
		{name: "summary-user", path: "/api/v1/mysql/user-summary?user=otheracct"},
		{name: "summary-db", path: "/api/v1/mysql/user-summary?db=otherdb"},
		{name: "kills-user", path: "/api/v1/mysql/user-kills?user=otheracct"},
		{name: "kills-db", path: "/api/v1/mysql/user-kills?db=otherdb"},
		{name: "history-user", path: "/api/v1/mysql/user-history?user=otheracct"},
		{name: "history-db", path: "/api/v1/mysql/user-history?db=otherdb"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := scopedMySQLFilterHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := newScopedMySQLRequest(t, tc.path)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for scoped injection, got %d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestScopedMySQLFilterHandler_AdminRolePassesThroughUnfiltered(t *testing.T) {
	nextCalled := false
	h := scopedMySQLFilterHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mysql/user-summary", nil)
	ctx := context.WithValue(req.Context(), webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req.WithContext(ctx))

	if !nextCalled {
		t.Fatalf("admin role must pass through unfiltered")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin passthrough, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestScopedMySQLFilterHandler_ScopedEmptyScopeFailsClosed(t *testing.T) {
	// A scoped (non-admin) caller whose vhost scope is somehow empty must NOT be
	// mistaken for an admin (which would let user-kill target ANY connection).
	// It must fail closed: no derivable filter -> 400, next never called.
	nextCalled := false
	h := scopedMySQLFilterHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mysql/user-kill?id=1", nil)
	ctx := context.WithValue(req.Context(), webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleScoped)
	ctx = context.WithValue(ctx, webdet.CtxScopeKey{}, map[string]struct{}{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req.WithContext(ctx))

	if nextCalled {
		t.Fatalf("scoped token with empty scope must not pass through (would act as admin)")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 fail-closed for empty scoped scope, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func writeScopedMySQLOwnerFixture(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	userDomains := filepath.Join(tmp, "userdomains")
	userDataDomains := filepath.Join(tmp, "userdatadomains")
	if err := os.WriteFile(userDomains, []byte("mysite.com: own\n"), 0644); err != nil {
		t.Fatalf("write userdomains: %v", err)
	}
	if err := os.WriteFile(userDataDomains, []byte(""), 0644); err != nil {
		t.Fatalf("write userdatadomains: %v", err)
	}

	oldUD := panelmap.UserDomainsPath
	oldUDD := panelmap.UserDataDomainsPath
	panelmap.UserDomainsPath = userDomains
	panelmap.UserDataDomainsPath = userDataDomains
	t.Cleanup(func() {
		panelmap.UserDomainsPath = oldUD
		panelmap.UserDataDomainsPath = oldUDD
	})
}

func newScopedMySQLRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, rawURL, nil)
	scope := map[string]struct{}{"mysite.com": {}}
	ctx := context.WithValue(req.Context(), webdet.CtxScopeKey{}, scope)
	return req.WithContext(ctx)
}

func newScopedMySQLRequestWithDBScope(t *testing.T, rawURL string, users map[string]struct{}) *http.Request {
	t.Helper()
	req := newScopedMySQLRequest(t, rawURL)
	ctx := context.WithValue(req.Context(), webdet.CtxDBScopeKey{}, webdet.ScopedDBScope{
		Users: users,
	})
	return req.WithContext(ctx)
}

func newScopedMySQLRequestWithDatabaseScope(t *testing.T, rawURL string, databases map[string]struct{}) *http.Request {
	t.Helper()
	req := newScopedMySQLRequest(t, rawURL)
	ctx := context.WithValue(req.Context(), webdet.CtxDBScopeKey{}, webdet.ScopedDBScope{
		Databases: databases,
	})
	return req.WithContext(ctx)
}
