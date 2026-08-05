// internal/apiserver/unblock_search_authz_test.go
//
// Regression guard: /unblock and /search are admin-only.
//
// Both are root-level routes that used to be registered with a bare
// m.HandleFunc, i.e. protected only by the mux-wide TokenMiddleware. That
// authenticates but does not distinguish admin from a scoped (per-vhost
// cPanel/DA) token, so any authenticated scoped token could:
//   - /unblock: remove a global nft block AND lay down a 24h allow-whitelist
//     for an arbitrary IP across every enforcement plane (host-wide state
//     change with no per-vhost meaning);
//   - /search:  enumerate where an arbitrary IP is blocked host-wide
//     (cross-tenant reconnaissance).
//
// They are now wrapped in adminOnlyHandler like /api/v1/firewall/block. These
// tests pin that at the Register* seam so a future refactor cannot silently
// drop the gate. Mirrors TestDebugLiveRequiresAdmin (debugCtx helper).
package apiserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"cfm/internal/locate"
	"cfm/internal/unblock"
	webdet "cfm/internal/webdetector"
)

func TestSearchEndpointRequiresAdmin(t *testing.T) {
	orig := locateFind
	locateFind = func(_ context.Context, arg string, _ locate.Options) (*locate.Result, error) {
		return &locate.Result{Query: arg}, nil
	}
	t.Cleanup(func() { locateFind = orig })

	mux := http.NewServeMux()
	RegisterSearch(mux, nil, t.TempDir())

	// Anonymous (no auth context): fail closed.
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/search?ip=192.0.2.10", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("anonymous: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped token: must NOT reach the handler.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/search?ip=192.0.2.10", nil).
		WithContext(debugCtx(webdet.CtxRoleScoped))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Admin token: passes the gate and runs the lookup.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/search?ip=192.0.2.10", nil).
		WithContext(debugCtx(webdet.CtxRoleAdmin))
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUnblockEndpointRequiresAdmin(t *testing.T) {
	be := &stubFirewallBackend{}

	origUnblockDo := unblockDo
	var wg sync.WaitGroup
	unblockDo = func(_ context.Context, _ net.IP, _ unblock.Options) (*unblock.Result, error) {
		defer wg.Done()
		return &unblock.Result{WasBlocked: false}, nil
	}
	origLocate := locateFind
	locateFind = func(_ context.Context, arg string, _ locate.Options) (*locate.Result, error) {
		return &locate.Result{Query: arg}, nil
	}
	t.Cleanup(func() {
		wg.Wait()
		unblockDo = origUnblockDo
		locateFind = origLocate
	})

	mux := http.NewServeMux()
	RegisterUnblock(mux, be, t.TempDir())

	newPOST := func(ctx context.Context) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/unblock", strings.NewReader(`{"ip":"192.0.2.10"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.25:12345"
		if ctx != nil {
			req = req.WithContext(ctx)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}

	// Anonymous: fail closed, no unblock performed.
	if rr := newPOST(nil); rr.Code != http.StatusForbidden {
		t.Fatalf("anonymous: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	// Scoped token: must NOT reach the handler.
	if rr := newPOST(debugCtx(webdet.CtxRoleScoped)); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	if len(be.removed) != 0 {
		t.Fatalf("scoped/anonymous must not trigger RemoveBlock, got %v", be.removed)
	}

	// Admin token: passes the gate and performs the unblock. The handler
	// spawns one background unblockDo call; account for it before cleanup.
	wg.Add(1)
	rr := newPOST(debugCtx(webdet.CtxRoleAdmin))
	if rr.Code != http.StatusOK {
		wg.Done() // handler returned before dispatching; avoid a stuck Wait
		t.Fatalf("admin: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if len(be.removed) != 1 || be.removed[0] != "192.0.2.10" {
		t.Fatalf("admin: expected RemoveBlock for 192.0.2.10, got %v", be.removed)
	}
}
