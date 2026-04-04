// internal/apiserver/apiserver.go
//
// Unified internal HTTP server for cfm.
//
// Endpoints:
//   /login, /logout, /login/verify  — public auth routes
//   /debug/pprof/                   — profiling
//   /unblock                        — manual IP unblock
//   /api/v1/firewall/block          — manual IP block
//   /api/v1/system/                 — system status
//   /api/v1/auth/token              — scoped token issuance (admin token required)
//   /api/v1/webdet/                 — web detector (registered by webdetector package)
//   /api/v1/challenge/              — challenge API (registered by webdetector package)
//   /api/v1/mysql/                  — MySQL governor (registered when gov != nil)
//
// Auth stack (outermost → innermost):
//   Auth.LoadAndSave()   — loads/saves goauth session on every request
//   TokenMiddleware()    — loopback bypass | session | Bearer/Token/X-CFM-Token
//   mux                 — routes
//
// Two listeners:
//   HTTP  :6060  (PORT / LISTEN_ADDRESS)            — always started
//   HTTPS :6061  (TLS_PORT / TLS_LISTEN_ADDRESS)    — started when TLS_PORT > 0 and ssl != nil
//
// The same handler stack is shared by both listeners.

package apiserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/chrismfz/goauth"

	cfgpkg   "cfm/internal/config"
	mysqlpkg "cfm/internal/detectors/mysql"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	sslpkg   "cfm/internal/sslcollector"
)

// ── package-level mux (shared with Phase 2 callers via Register()) ────────────

var (
	mu        sync.Mutex
	sharedMux *http.ServeMux
	pending   []func(*http.ServeMux)
)

// Mux returns the shared mux after Start() has initialised it.
func Mux() *http.ServeMux {
	mu.Lock()
	defer mu.Unlock()
	return sharedMux
}

// Register queues fn to run on the shared mux.
// Safe to call before or after Start().
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

// Start builds the mux, wires auth, registers endpoints, and begins listening.
// Blocks until ctx is cancelled, then shuts down both servers gracefully.
//
// Parameters:
//   cfg    — active config (LISTEN_ADDRESS, PORT, TLS_PORT, AUTH_DB_PATH, …)
//   be     — nft backend; may be nil (/unblock returns 503)
//   cfgDir — config dir; used by /unblock to edit cfm.deny
//   gov    — MySQL governor; nil = mysql routes not registered
//   ssl    — SSLCollector; nil = TLS port not started even if TLS_PORT > 0
func Start(
	ctx context.Context,
	cfg *cfgpkg.Config,
	be firewall.Backend,
	cfgDir string,
	gov *mysqlpkg.Governor,
	ssl *sslpkg.Collector,
) {
	m := http.NewServeMux()

	// Publish mux and apply any deferred registrations.
	mu.Lock()
	sharedMux = m
	for _, fn := range pending {
		fn(m)
	}
	pending = nil
	mu.Unlock()

	// ── pprof ────────────────────────────────────────────────────────────────
	registerPprofHandlers(m)

	// ── Public auth routes (login / logout / 2FA stub) ───────────────────────
	RegisterLoginRoutes(m)

	// ── Firewall action endpoints ─────────────────────────────────────────────
	RegisterUnblock(m, be, cfgDir)
	RegisterBlock(m, be)

	// ── System status ─────────────────────────────────────────────────────────
	RegisterSystemStatus(m)

	// ── MySQL governor ────────────────────────────────────────────────────────
	if gov != nil {
		gov.RegisterHTTP(m)
		logging.Logf("[apiserver] mysql governor routes registered")
	}

	// ── Scoped token issuance ─────────────────────────────────────────────────
	store := NewTokenStore()
	store.StartPurger(ctx)
	RegisterTokenEndpoint(m, store)

	// ── goauth session store ──────────────────────────────────────────────────
	var authMgr *goauth.Manager
	if cfg.Debug.AuthDBPath != "" {
		sessionTTL := cfg.Debug.SessionTTL
		if sessionTTL <= 0 {
			sessionTTL = 8 * time.Hour
		}
		cookieName := cfg.Debug.CookieName
		if cookieName == "" {
			cookieName = "cfm-sid"
		}
		var err error
		authMgr, err = goauth.New(goauth.Config{
			DBPath:       cfg.Debug.AuthDBPath,
			SessionTTL:   sessionTTL,
			IdleTimeout:  30 * time.Minute,
			CookieName:   cookieName,
			SecureCookie: cfg.Debug.SecureCookie,
		})
		if err != nil {
			logging.Logf("[apiserver] goauth init failed: %v — browser auth disabled", err)
		} else {
			SetAuth(authMgr)
			logging.Logf("[apiserver] goauth session store: %s ttl=%s cookie=%s secure=%v",
				cfg.Debug.AuthDBPath, sessionTTL, cookieName, cfg.Debug.SecureCookie)
		}
	} else {
		logging.Logf("[apiserver] AUTH_DB_PATH not set — browser auth disabled (token-only)")
	}

	// ── Build handler stack ───────────────────────────────────────────────────
	// Innermost → outermost:
	//   mux → TokenMiddleware → LoadAndSave
	var handler http.Handler
	handler = TokenMiddleware(cfg.API.AuthToken, store)(m)
	if authMgr != nil {
		handler = authMgr.LoadAndSave(handler)
	}

	// ── HTTP server ───────────────────────────────────────────────────────────
	httpAddr := fmt.Sprintf("%s:%d", cfg.Debug.ListenAddress, cfg.Debug.Port)
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Logf("[apiserver] http error: %v", err)
		}
	}()
	logging.Logf("[apiserver] HTTP listening on %s", httpAddr)

	// ── TLS server (optional) ─────────────────────────────────────────────────
	var tlsSrv *http.Server
	if cfg.Debug.TLSPort > 0 && ssl != nil {
		tlsAddr := cfg.Debug.TLSAddress
		if tlsAddr == "" {
			tlsAddr = cfg.Debug.ListenAddress
		}
		fullTLSAddr := fmt.Sprintf("%s:%d", tlsAddr, cfg.Debug.TLSPort)

		tlsCfg := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
			GetCertificate: ssl.GetCertificate, // SNI-based, auto-rotates
		}

		ln, err := net.Listen("tcp", fullTLSAddr)
		if err != nil {
			logging.Logf("[apiserver] TLS listen failed on %s: %v", fullTLSAddr, err)
		} else {
			tlsSrv = &http.Server{
				Addr:              fullTLSAddr,
				Handler:           handler, // same stack as HTTP
				TLSConfig:         tlsCfg,
				ReadHeaderTimeout: 2 * time.Second,
				ReadTimeout:       5 * time.Second,
				WriteTimeout:      10 * time.Second,
				IdleTimeout:       60 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}
			go func() {
				if err := tlsSrv.Serve(tls.NewListener(ln, tlsCfg)); err != nil && err != http.ErrServerClosed {
					logging.Logf("[apiserver] TLS error: %v", err)
				}
			}()
			logging.Logf("[apiserver] TLS listening on %s", fullTLSAddr)
		}
	} else if cfg.Debug.TLSPort > 0 && ssl == nil {
		logging.Logf("[apiserver] TLS_PORT set but SSLCollector not available — TLS disabled")
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(shutCtx); err != nil {
		logging.Logf("[apiserver] HTTP shutdown error: %v", err)
	}
	if tlsSrv != nil {
		if err := tlsSrv.Shutdown(shutCtx); err != nil {
			logging.Logf("[apiserver] TLS shutdown error: %v", err)
		}
	}
	if authMgr != nil {
		authMgr.Close()
	}
}
