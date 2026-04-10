package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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

	oldUD := cpanelUserDomainsPath
	oldUDD := cpanelUserDataDomainsPath
	cpanelUserDomainsPath = userDomains
	cpanelUserDataDomainsPath = userDataDomains
	t.Cleanup(func() {
		cpanelUserDomainsPath = oldUD
		cpanelUserDataDomainsPath = oldUDD
	})
}

func newScopedMySQLRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, rawURL, nil)
	scope := map[string]struct{}{"mysite.com": {}}
	ctx := context.WithValue(req.Context(), webdet.CtxScopeKey{}, scope)
	return req.WithContext(ctx)
}
