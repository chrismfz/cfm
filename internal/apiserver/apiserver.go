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
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/chrismfz/goauth"

	cfgpkg "cfm/internal/config"
	mysqlpkg "cfm/internal/detectors/mysql"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	sslpkg "cfm/internal/sslcollector"
	webui "cfm/internal/webui"
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
//
//	cfg    — active config (LISTEN_ADDRESS, PORT, TLS_PORT, AUTH_DB_PATH, …)
//	be     — nft backend; may be nil (/unblock returns 503)
//	cfgDir — config dir; used by /unblock to edit cfm.deny
//	gov    — MySQL governor; nil = mysql routes not registered
//	ssl    — SSLCollector; nil = TLS port not started even if TLS_PORT > 0
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

	// ── Embedded static UI ────────────────────────────────────────────────────
	// Serves the embedded HTML/JS/CSS at /.
	// Registered first — API routes below take priority via longest-prefix matching.
	m.Handle("/", webui.Handler())

	// /cfm-admin/ prefix rewriter — strips the prefix and re-dispatches on the
	// same mux. Enables direct port access (:6061) when HTML/JS use hardcoded
	// /cfm-admin/... paths, without any JS/HTML changes.
	//
	//   /cfm-admin/api/v1/...  → strips → /api/v1/...  → API handler
	//   /cfm-admin/assets/...  → strips → /assets/...  → webui.Handler
	//   /cfm-admin/login       → strips → /login        → login handler
	//
	m.HandleFunc("/cfm-admin/", func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/cfm-admin")
		if r2.URL.Path == "" || r2.URL.Path[0] != '/' {
			r2.URL.Path = "/" + r2.URL.Path
		}
		if r2.URL.RawPath != "" {
			r2.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, "/cfm-admin")
		}
		m.ServeHTTP(w, r2)
	})

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

	// ── goauth → autoblock bridge (FAIL/RATELIMIT tail) ──────────────────────
	startAuthAutoblock(ctx, cfg, be)

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
		authCfg := goauth.Config{
			DBPath:       cfg.Debug.AuthDBPath,
			SessionTTL:   sessionTTL,
			CookieName:   cookieName,
			SecureCookie: cfg.Debug.SecureCookie,
			SameSite:     http.SameSiteLaxMode,
		}
		if cfg.Debug.AuthSessionDBPath != "" {
			if ok := setOptionalGoauthStringField(&authCfg, "SessionDBPath", cfg.Debug.AuthSessionDBPath); ok {
				logging.Logf("[apiserver] goauth session DB path: %s", cfg.Debug.AuthSessionDBPath)
			} else {
				logging.Logf("[apiserver] AUTH_SESSION_DB_PATH is set but current goauth version does not support SessionDBPath")
			}
		}
		authMgr, err := newGoAuthWithRetry(authCfg)
		if err != nil {
			logging.Logf("[apiserver] goauth init failed: %v — browser auth disabled", err)
		} else {
			SetAuth(authMgr)
			if cfg.Debug.AuthSessionDBPath != "" {
				logging.Logf("[apiserver] goauth store: auth_db=%s session_db=%s ttl=%s cookie=%s secure=%v",
					cfg.Debug.AuthDBPath, cfg.Debug.AuthSessionDBPath, sessionTTL, cookieName, cfg.Debug.SecureCookie)
			} else {
				logging.Logf("[apiserver] goauth store: auth_db=%s session_db=%s ttl=%s cookie=%s secure=%v",
					cfg.Debug.AuthDBPath, cfg.Debug.AuthDBPath, sessionTTL, cookieName, cfg.Debug.SecureCookie)
			}
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
	handler = RequestLogMiddleware(handler)

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

func setOptionalGoauthStringField(cfg *goauth.Config, fieldName, value string) bool {
	v := reflect.ValueOf(cfg).Elem()
	f := v.FieldByName(fieldName)
	if !f.IsValid() || !f.CanSet() || f.Kind() != reflect.String {
		return false
	}
	f.SetString(value)
	return true
}

func newGoAuthWithRetry(cfg goauth.Config) (*goauth.Manager, error) {
	const attempts = 20
	const sleep = 250 * time.Millisecond

	var lastErr error
	for i := 1; i <= attempts; i++ {
		mgr, err := goauth.New(cfg)
		if err == nil {
			if i > 1 {
				logging.Logf("[apiserver] goauth init succeeded after retry %d/%d", i, attempts)
			}
			return mgr, nil
		}
		lastErr = err
		if !isGoAuthSQLiteBusy(err) {
			return nil, err
		}
		if i < attempts {
			logging.Logf("[apiserver] goauth init busy (%d/%d): %v; retrying in %s", i, attempts, err, sleep)
			time.Sleep(sleep)
		}
	}
	return nil, fmt.Errorf("goauth: retries exhausted after %d attempts: %w", attempts, lastErr)
}

func isGoAuthSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "database is locked") ||
		strings.Contains(s, "sqlite_busy") ||
		strings.Contains(s, "(261)")
}
