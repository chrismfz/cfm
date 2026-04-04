// internal/apiserver/apiserver.go
//
// Package apiserver owns the single internal HTTP server that cfm exposes for:
//
//   - pprof / profiling     /debug/pprof/
//   - manual IP unblock     /unblock
//   - MySQL governor API    /api/v1/mysql/     (only when gov != nil)
//   - Web-detector API      /api/v1/webdet/    (Phase 2 — registered by webdetector)
//   - Challenge API         /api/v1/challenge/ (Phase 2 — registered by webdetector)
//
// Config keys (cfm.conf — unchanged):
//
//	LISTEN_ADDRESS = "0.0.0.0"   # bind address
//	PORT           = 6060        # single port for everything
//
// Firewall note:
//
//	The nft package resolves API_URL and populates debug_api_v4/v6 sets so
//	only the web-panel IP can reach this port. That logic is untouched —
//	it still reads cfg.Debug.Port, same as before.
//
// Usage in main.go  (the entire applyDebugServer becomes ~8 lines):
//
//	go apiserver.Start(ctx, cfg, be, cfgDir, gov)
//
// Other packages can safely attach routes before or after Start():
//
//	apiserver.Register(func(m *http.ServeMux) {
//		engine.RegisterHTTP(m)
//	})

package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	cfgpkg "cfm/internal/config"
	mysqlpkg "cfm/internal/detectors/mysql"
	"cfm/internal/firewall"
	"cfm/internal/logging"
)

// ── package-level mux (shared with Phase 2 callers via Mux()) ────────────────

var (
	mu        sync.Mutex
	sharedMux *http.ServeMux
	pending   []func(*http.ServeMux)
)

// Mux returns the shared *http.ServeMux after Start() has created it.
// Prefer Register(...) for package integration, since Register works both
// before and after Start().
func Mux() *http.ServeMux {
	mu.Lock()
	defer mu.Unlock()
	return sharedMux
}

// Register runs fn immediately if the shared mux already exists.
// Otherwise it queues fn and Start() applies it when the mux is created.
func Register(fn func(*http.ServeMux)) {
	mu.Lock()
	defer mu.Unlock()

	if sharedMux != nil {
		fn(sharedMux)
		return
	}
	pending = append(pending, fn)
}

// ── Start ─────────────────────────────────────────────────────────────────────

// Start builds the mux, registers all built-in endpoints, and begins accepting
// connections. It blocks until ctx is cancelled, then shuts down gracefully
// (up to 5 seconds).
//
// Parameters:
//
//	cfg    — active config; provides ListenAddress + Port (LISTEN_ADDRESS / PORT)
//	be     — nft firewall backend; may be nil (/unblock returns 503)
//	cfgDir — resolved config directory; used by /unblock to edit cfm.deny
//	gov    — MySQL governor; may be nil (mysql routes are simply not registered)
//
// Called from main.go applyDebugServer:
//
//	go apiserver.Start(ctx, cfg, getBackend(), cfgDir, gov)
func Start(ctx context.Context, cfg *cfgpkg.Config, be firewall.Backend, cfgDir string, gov *mysqlpkg.Governor) {
	addr := fmt.Sprintf("%s:%d", cfg.Debug.ListenAddress, cfg.Debug.Port)

	m := http.NewServeMux()

	// Publish the mux and apply any deferred registrations.
	mu.Lock()
	sharedMux = m
	for _, fn := range pending {
		fn(m)
	}
	pending = nil
	mu.Unlock()

	// ── pprof suite (/debug/pprof/) ─────────────────────────────────────────
	// CPU, heap, goroutine, trace profiling. Safe to leave permanently enabled —
	// overhead is near-zero until a client actually connects.
	//
	//   curl -o /tmp/cfm.cpu "http://127.0.0.1:6060/debug/pprof/profile?seconds=60"
	//   go tool pprof /usr/bin/cfm /tmp/cfm.cpu
	registerPprofHandlers(m)

	// ── /unblock ─────────────────────────────────────────────────────────────
	// Instant IP removal from nft, immediate JSON response, then background
	// CSF / Fail2Ban / Imunify cleanup (fire-and-forget, 20 s timeout).
	// Full handler logic lives in unblock.go.
	RegisterUnblock(m, be, cfgDir)
	// ── /api/v1/firewall/block ──────────────────────────────────────────────
	// Manual IP block endpoint used by admin UI quick actions.
	RegisterBlock(m, be)

	// ── /api/v1/system/ ────────────────────────────────────────────────────
	RegisterSystemStatus(m)

	// ── MySQL governor (/api/v1/mysql/) ─────────────────────────────────────
	// Governor already implements RegisterHTTP(mux) — just plug it in.
	// Skipped entirely when MySQL is not configured.
	if gov != nil {
		gov.RegisterHTTP(m)
		logging.Logf("[apiserver] mysql governor routes registered on %s/api/v1/mysql/", addr)
	}

	// ── HTTP server ───────────────────────────────────────────────────────────
	// ── Token store + middleware ─────────────────────────────────────────────
	store := NewTokenStore()
	store.StartPurger(ctx)

	// Register scoped token issuance endpoint (protected by middleware below).
	RegisterTokenEndpoint(m, store)

	// Wrap the mux: loopback bypass → admin token → scoped token → 401.
	authedHandler := TokenMiddleware(cfg.API.AuthToken, store)(m)

	// ── HTTP server ───────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:              addr,
		Handler:           authedHandler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}


	// Graceful shutdown when the daemon context is cancelled (reload / stop).
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			logging.Logf("[apiserver] shutdown error: %v", err)
		}
	}()

	logging.Logf("[apiserver] listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logging.Logf("[apiserver] error: %v", err)
	}
}
