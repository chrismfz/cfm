package webdetector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"cfm/internal/edgelog"
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

// With a vhost filter the whole list is read and filtered before the limit.
func TestLimitUnlessFiltered(t *testing.T) {
	if got := limitUnlessFiltered(10, nil); got != 10 {
		t.Fatalf("unfiltered: %d, want 10", got)
	}
	if got := limitUnlessFiltered(10, map[string]struct{}{"a.com": {}}); got != 0 {
		t.Fatalf("filtered: %d, want 0 (no limit before the filter)", got)
	}
}

// A scoped host scan names none of the node's log files, in the main section
// or the bad-request one.
func TestStripScanFileNames(t *testing.T) {
	res := edgelog.HostScanResult{
		LogFile: "/var/log/a", FilesScanned: []string{"/var/log/a"},
		FilesFailed: []edgelog.HostFileError{{}},
		BadRequests: &edgelog.HostScanResult{
			LogFile: "/var/log/b", FilesScanned: []string{"/var/log/b"},
			FilesFailed: []edgelog.HostFileError{{}},
		},
	}
	stripScanFileNames(&res)
	for _, r := range []*edgelog.HostScanResult{&res, res.BadRequests} {
		if r.LogFile != "" || r.FilesScanned != nil || r.FilesFailed != nil {
			t.Fatalf("file names left: %+v", r)
		}
	}
}
