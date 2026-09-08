package webdetector

import (
	"net/http"
	"testing"
)

// mutatorRoutes are the state-changing challenge/waf/clam/http3 endpoints that
// must be POST-only (audit R03). Their read siblings (list/status) are
// intentionally NOT here — they stay reachable via GET.
var mutatorRoutes = []string{
	"/api/v1/challenge/vhost/add",
	"/api/v1/challenge/vhost/remove",
	"/api/v1/challenge/vhost/attack",
	"/api/v1/challenge/exclude/add",
	"/api/v1/challenge/exclude/remove",
	"/api/v1/challenge/access/add",
	"/api/v1/challenge/access/update",
	"/api/v1/challenge/access/remove",
	"/api/v1/waf/exclude/add",
	"/api/v1/waf/exclude/remove",
	"/api/v1/clam/override/add",
	"/api/v1/clam/override/remove",
	"/api/v1/clam/mode/add",
	"/api/v1/clam/mode/remove",
	"/api/v1/clam/sigignore/add",
	"/api/v1/clam/sigignore/remove",
	"/api/v1/http3/enable",
	"/api/v1/http3/disable",
}

// TestMutatorsRejectNonPOST is the audit R03 regression: every state-changing
// endpoint rejects a non-POST method with 405 BEFORE it parses params or touches
// state, so a state-changing GET can't slip past the session-CSRF boundary
// (which correctly treats GET/HEAD as safe). The refusal is method-first: it
// happens even for an admin caller, before auth.
func TestMutatorsRejectNonPOST(t *testing.T) {
	_, mux := newTestEngine(t)

	for _, path := range mutatorRoutes {
		for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			rr := doRequest(mux, adminCtx(), m, path, nil)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: expected 405, got %d", m, path, rr.Code)
			}
		}
		// GET advertises the allowed method.
		rr := doRequest(mux, adminCtx(), http.MethodGet, path, nil)
		if got := rr.Header().Get("Allow"); got != http.MethodPost {
			t.Errorf("GET %s: Allow header = %q, want POST", path, got)
		}
	}
}

// TestMutatorsAllowPOST guards against the over-correction: POST must still reach
// the handler (the method guard is not a blanket block). Anything other than 405
// proves the request passed the guard into the handler's own auth/param logic.
// The correct mutating behavior of each handler on POST is covered by the
// per-handler tests (e.g. challenge_manual_handlers_test.go, clam_sigignore_test.go,
// exclude_api_handlers_test.go); this test only pins the method gate.
func TestMutatorsAllowPOST(t *testing.T) {
	_, mux := newTestEngine(t)
	for _, path := range mutatorRoutes {
		rr := doRequest(mux, adminCtx(), http.MethodPost, path, nil)
		if rr.Code == http.StatusMethodNotAllowed {
			t.Errorf("POST %s: unexpectedly 405 — the method guard must allow POST", path)
		}
	}
}

// TestReadSiblingsStayGET makes sure the R03 fix did not turn the read siblings
// into POST-only by mistake.
func TestReadSiblingsStayGET(t *testing.T) {
	_, mux := newTestEngine(t)
	reads := []string{
		"/api/v1/challenge/vhost/status?host=x.gr",
		"/api/v1/challenge/exclude/list",
		"/api/v1/challenge/access",
		"/api/v1/challenge/access/get?id=x",
		"/api/v1/waf/exclude/list",
		"/api/v1/clam/override/list",
		"/api/v1/clam/mode/list",
		"/api/v1/clam/sigignore/list",
	}
	for _, path := range reads {
		rr := doRequest(mux, adminCtx(), http.MethodGet, path, nil)
		if rr.Code == http.StatusMethodNotAllowed {
			t.Errorf("GET %s: read endpoint wrongly rejected with 405", path)
		}
	}
}
