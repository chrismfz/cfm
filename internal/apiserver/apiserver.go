// internal/apiserver/apiserver.go
//
// Unified internal HTTP server for cfm.
//
// Endpoints:
//   /login, /logout, /login/verify  — public auth routes
//   /debug/pprof/                   — profiling
//   /unblock                        — manual IP unblock (admin token required)
//   /search                         — multi-source IP lookup (admin token required)
//   /api/v1/firewall/block          — manual IP block
//   /api/v1/firewall/block/batch    — manual bulk IP block (selfip/caller guarded)
//   /api/v1/system/                 — system status
//   /api/v1/auth/token              — scoped token issuance (admin token required)
//   /api/v1/webdet/                 — web detector (registered by webdetector package)
//   /api/v1/challenge/              — challenge API (registered by webdetector package)
//   /api/v1/mysql/                  — MySQL governor (registered when gov != nil)
//
// Handler stack (outermost → innermost — see Start()):
//   RequestLog → SecurityHeaders → AdminTransportRedirect → APISecurityAnomaly
//   → PprofWriteTimeout → Auth.LoadAndSave → TokenMiddleware → CSRF → MFARollout → mux
// SecurityHeaders (R10) sits outside AdminTransportRedirect so redirects/refusals
// carry the baseline headers too, and gives the direct :6060/:6061 listeners the
// same nosniff/Referrer-Policy the edge adds.
// AdminTransportRedirect (R01) sits outside TokenMiddleware so a direct plaintext
// :6060 admin request is upgraded to :6061 / refused before any auth runs.
//
// Two listeners:
//   HTTP  :6060  (PORT / LISTEN_ADDRESS)            — always started; LISTEN_ADDRESS
//                                                     defaults to 127.0.0.1 (loopback)
//   HTTPS :6061  (TLS_PORT / TLS_LISTEN_ADDRESS)    — started when TLS_PORT > 0 and ssl != nil
//
// The same handler stack is shared by both listeners.

package apiserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chrismfz/goauth"

	"cfm/internal/authstore"
	cfgpkg "cfm/internal/config"
	mysqlpkg "cfm/internal/detectors/mysql"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	"cfm/internal/panelmap"
	sslpkg "cfm/internal/sslcollector"
	webdet "cfm/internal/webdetector"
	webui "cfm/internal/webui"
)

// ── package-level mux (shared with Phase 2 callers via Register()) ────────────

const (
	debugAPIServerReadTimeout = 15 * time.Second
	// debugAPIServerWriteTimeout is the apiserver's hard, conn-level
	// write deadline. It MUST comfortably exceed the longest pprof
	// capture window an operator can request, otherwise the
	// /debug/pprof/profile?seconds=N stream gets killed mid-flight and
	// the client sees an EOF with no usable profile.
	//
	// Sizing: the cfm debug client caps `seconds=` at
	// pprofCPUSecondsMax = 60 (see internal/cli/debug.go). The apiserver's
	// PprofWriteTimeoutMiddleware adds pprofRequestedSafetyMargin = 15s,
	// targeting an effective 75s window for a 60s profile. 90s leaves a
	// 15s cushion above that without inviting genuinely hung handlers
	// (still bounded). Other apiserver endpoints — WAF, exclude,
	// history, hit-rates — all complete well under a second; raising
	// the ceiling for them costs nothing.
	//
	// History: was 20s. That fired during pprof CPU profile streaming
	// long before pprof finished sampling, even at the 60s cap (bundle 4
	// from 2026-05-09 returned EOF on a seconds=60 request). The
	// PprofWriteTimeoutMiddleware tries to extend the deadline via
	// http.NewResponseController(w).SetWriteDeadline, but in practice the
	// override didn't reach the underlying conn — the middleware logs an
	// error if it fails, but the conn was being killed at ~20s anyway.
	// Diagnosing the middleware is its own follow-up; bumping the base
	// is robust regardless and unblocks `cfm debug` today.
	debugAPIServerWriteTimeout = 90 * time.Second
)

var (
	mu        sync.Mutex
	sharedMux *http.ServeMux
	pending   []func(*http.ServeMux)

	mfaKeyStatePath = "/var/lib/cfm/auth-mfa.key"
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
	if err := validateStartupConfig(cfg); err != nil {
		logging.LogfAPI("[apiserver] fatal startup config error: %v", err)
		return
	}

	configureDebugCaptureFromConfig(cfg)
	setMFARolloutPolicyFromConfig(cfg)

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
	RegisterFirewallList(m, be)
	RegisterFirewallCounters(m, be) // read-only nft named-counter view (rule match volume)
	RegisterFirewallSelfTest(m, be) // read-only nftlib self-diagnostics
	RegisterNetfilterPath(m, cfg)   // read-only host-wide hook order and NAT conflicts
	RegisterSearch(m, be, cfgDir)   // read-only multi-source IP lookup

	// ── System status ─────────────────────────────────────────────────────────
	RegisterSystemStatus(m, be)

	// ── Debug API (admin-only) ───────────────────────────────────────────────
	RegisterDebugEndpoints(m)

	// ── DNAT state (admin-only; CLI status reads daemon's in-memory
	// transition/probe via this endpoint since the CLI runs in a
	// separate process) ─────────────────────────────────────────────
	RegisterDNATState(m)

	// ── Notifier admin API (admin-only) ─────────────────────────────────────
	RegisterNotifierEndpoints(m, cfgDir)
	RegisterDetectorsEndpoints(m, cfgDir)

	// ── MySQL governor ────────────────────────────────────────────────────────
	if gov != nil {
		// Global MySQL governor routes stay strictly admin-only.
		mysqlAdminMux := http.NewServeMux()
		gov.RegisterHTTPAdmin(mysqlAdminMux)
		m.Handle("/api/v1/mysql/state", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/processlist", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/top", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/locks", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/kills", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/history", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/history/events", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/history/summary", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/history/prune", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/history/truncate", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/history/timeline", adminOnlyHandler(mysqlAdminMux))
		m.Handle("/api/v1/mysql/cpu", adminOnlyHandler(mysqlAdminMux))

		// Filtered MySQL routes may be used by scoped tokens, but must always
		// carry an effective user filter (explicit or safely derived).
		mysqlScopedMux := http.NewServeMux()
		gov.RegisterHTTPScoped(mysqlScopedMux)
		m.Handle("/api/v1/mysql/user-summary", scopedMySQLFilterHandler(mysqlScopedMux))
		m.Handle("/api/v1/mysql/user-kills", scopedMySQLFilterHandler(mysqlScopedMux))
		m.Handle("/api/v1/mysql/user-history", scopedMySQLFilterHandler(mysqlScopedMux))
		m.Handle("/api/v1/mysql/user-kill", scopedMySQLFilterHandler(mysqlScopedMux))

		logging.LogfAPI("[apiserver] mysql governor routes registered (admin global + scoped filtered)")
	}

	// ── Scoped token issuance ─────────────────────────────────────────────────
	store := NewTokenStore()
	tokensPath := filepath.Join("/var/lib/cfm", "tokens.json")
	if cfg.Debug.AuthDBPath != "" {
		tokensPath = filepath.Join(filepath.Dir(cfg.Debug.AuthDBPath), "tokens.json")
	}
	if err := store.Load(tokensPath); err != nil {
		logging.LogfAPI("[apiserver] token store load: %v", err)
	}

	store.StartPurger(ctx)
	RegisterTokenEndpoint(m, store)
	RegisterTokenManagementEndpoints(m, store)
	RegisterEmbedBootstrapEndpoint(m, store)

	// ── goauth → autoblock bridge (FAIL/RATELIMIT tail) ──────────────────────
	startAuthAutoblock(ctx, cfg, be)

	// ── goauth session store ──────────────────────────────────────────────────
	// Reset package auth first so a failed reload does not leave a stale manager
	// that would panic when used without LoadAndSave middleware.
	SetAuth(nil)
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
			DBPath:           cfg.Debug.AuthDBPath,
			SessionTTL:       sessionTTL,
			CookieName:       cookieName,
			SecureCookie:     cfg.Debug.SecureCookie,
			SameSite:         http.SameSiteLaxMode,
			MFAEncryptionKey: resolveMFAEncryptionKey(cfg),
			MFAIssuer:        "cfm-admin",
		}
		if cfg.Debug.AuthSessionDBPath != "" {
			if ok := setOptionalGoauthStringField(&authCfg, "SessionDBPath", cfg.Debug.AuthSessionDBPath); ok {
				logging.LogfAPI("[apiserver] goauth session DB path: %s", cfg.Debug.AuthSessionDBPath)
			} else {
				logging.LogfAPI("[apiserver] AUTH_SESSION_DB_PATH is set but current goauth version does not support SessionDBPath")
			}
		}
		authMgr, err := initGoAuthWithRetry(ctx, authCfg)
		if err != nil {
			SetAuth(nil)
			logging.LogfAPI("[apiserver] goauth init failed: %v — browser auth disabled", err)
		} else {
			SetAuth(authMgr)
			if err := authstore.HardenSQLiteFiles(cfg.Debug.AuthDBPath, cfg.Debug.AuthSessionDBPath); err != nil {
				logging.LogfAPI("[apiserver] auth db permission hardening warning: %v", err)
			}
			if cfg.Debug.AuthSessionDBPath != "" {
				logging.LogfAPI("[apiserver] goauth store: auth_db=%s session_db=%s ttl=%s cookie=%s secure=%v",
					cfg.Debug.AuthDBPath, cfg.Debug.AuthSessionDBPath, sessionTTL, cookieName, cfg.Debug.SecureCookie)
			} else {
				logging.LogfAPI("[apiserver] goauth store: auth_db=%s session_db=%s ttl=%s cookie=%s secure=%v",
					cfg.Debug.AuthDBPath, cfg.Debug.AuthDBPath, sessionTTL, cookieName, cfg.Debug.SecureCookie)
			}
		}
	} else {
		SetAuth(nil)
		logging.LogfAPI("[apiserver] AUTH_DB_PATH not set — browser auth disabled (token-only)")
	}
	registerMeSecurityRoutes(m)

	// ── Embedded read-only MCP server (mounted at /mcp; edge: /cfm-admin/mcp) ──
	// Registered last so its in-process dispatch can reach every /api/v1 route.
	registerMCPServer(m, cfg, store)

	// Record the actual listener ports so requestPeer's Entry classification (and
	// thus AdminTransportRedirect) tracks a non-default PORT/TLS_PORT instead of
	// hardcoded 6060/6061. Set before the listeners below begin serving.
	setListenerPorts(cfg.Debug.Port, cfg.Debug.TLSPort)

	// tlsReadyFlag becomes true only once the :6061 TLS listener has actually
	// bound (below). AdminTransportRedirect reads it to decide whether a direct
	// external plaintext :6060 browser request can be upgraded to :6061 (R01).
	var tlsReadyFlag atomic.Bool

	// ── Build handler stack ───────────────────────────────────────────────────
	// Execution order (outermost → innermost):
	//   RequestLog → SecurityHeaders → AdminTransportRedirect → APISecurityAnomaly
	//   → PprofWriteTimeout → LoadAndSave → TokenMiddleware → CSRF → MFARollout → mux
	// SecurityHeaders (R10) sets baseline nosniff/Referrer-Policy on every response.
	// AdminTransportRedirect sits OUTSIDE TokenMiddleware (pre-auth) so a direct
	// plaintext admin request is upgraded/refused before any credential is
	// processed, and INSIDE RequestLog so the transport decision is logged.
	var handler http.Handler
	handler = MFARolloutMiddleware(m)
	handler = CSRFMiddleware(handler)
	handler = TokenMiddleware(cfg.API.AuthToken, store)(handler)
	if Auth != nil {
		handler = Auth.LoadAndSave(handler)
	}
	handler = PprofWriteTimeoutMiddleware(handler)
	handler = APISecurityAnomalyMiddleware(handler)
	handler = AdminTransportRedirect(handler, cfg.Debug.TLSPort, tlsReadyFlag.Load)
	handler = SecurityHeadersMiddleware(handler)
	handler = RequestLogMiddleware(handler)

	// ── HTTP server ───────────────────────────────────────────────────────────
	// Secure default: an unset LISTEN_ADDRESS binds loopback, never the wildcard,
	// so the plaintext control plane is not Internet-reachable unless the operator
	// opts in explicitly (audit R01). An explicit "0.0.0.0"/"::" is honoured as-is
	// — that is the deliberate escape hatch, upgraded per-request to :6061 by
	// AdminTransportRedirect.
	httpAddr := fmt.Sprintf("%s:%d", HTTPBindAddr(cfg.Debug.ListenAddress), cfg.Debug.Port)
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       debugAPIServerReadTimeout,
		WriteTimeout:      debugAPIServerWriteTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.LogfAPI("[apiserver] http error: %v", err)
		}
	}()
	logging.LogfAPI("[apiserver] HTTP listening on %s", httpAddr)

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
			logging.LogfAPI("[apiserver] TLS listen failed on %s: %v", fullTLSAddr, err)
		} else {
			tlsSrv = &http.Server{
				Addr:              fullTLSAddr,
				Handler:           handler, // same stack as HTTP
				TLSConfig:         tlsCfg,
				ReadHeaderTimeout: 2 * time.Second,
				ReadTimeout:       debugAPIServerReadTimeout,
				WriteTimeout:      debugAPIServerWriteTimeout,
				IdleTimeout:       60 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}
			// TLS is now bound and serving; direct :6060 browser admin traffic may
			// be upgraded to :6061 (AdminTransportRedirect / R01).
			tlsReadyFlag.Store(true)
			go func() {
				if err := tlsSrv.Serve(tls.NewListener(ln, tlsCfg)); err != nil && err != http.ErrServerClosed {
					logging.LogfAPI("[apiserver] TLS error: %v", err)
				}
			}()
			logging.LogfAPI("[apiserver] TLS listening on %s", fullTLSAddr)
		}
	} else if cfg.Debug.TLSPort > 0 && ssl == nil {
		logging.LogfAPI("[apiserver] TLS_PORT set but SSLCollector not available — TLS disabled")
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(shutCtx); err != nil {
		logging.LogfAPI("[apiserver] HTTP shutdown error: %v", err)
	}
	if tlsSrv != nil {
		if err := tlsSrv.Shutdown(shutCtx); err != nil {
			logging.LogfAPI("[apiserver] TLS shutdown error: %v", err)
		}
	}
	if authMgr != nil {
		authMgr.Close()
	}
}

func resolveMFAEncryptionKey(cfg *cfgpkg.Config) string {
	if cfg == nil {
		return ""
	}
	if key := strings.TrimSpace(cfg.Debug.AuthMFAEncryptionKey); key != "" {
		return key
	}
	token := strings.TrimSpace(cfg.API.AuthToken)
	if token == "" {
		key, err := loadOrCreateMFAEncryptionKey(mfaKeyStatePath)
		if err != nil {
			logging.LogfAPI("[apiserver] AUTH_MFA_ENCRYPTION_KEY missing and fallback key generation failed: %v", err)
			return ""
		}
		logging.LogfAPI("[apiserver] AUTH_MFA_ENCRYPTION_KEY and AUTH_TOKEN not set; using persisted MFA key at %s", mfaKeyStatePath)
		return key
	}
	sum := sha256.Sum256([]byte("cfm/goauth/mfa/v1:" + token))
	derived := base64.RawStdEncoding.EncodeToString(sum[:]) // 32-byte key when decoded
	logging.LogfAPI("[apiserver] AUTH_MFA_ENCRYPTION_KEY not set; deriving MFA key from AUTH_TOKEN")
	return derived
}

func loadOrCreateMFAEncryptionKey(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if raw, err := os.ReadFile(path); err == nil {
		key := strings.TrimSpace(string(raw))
		if key != "" {
			return key, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key := base64.RawStdEncoding.EncodeToString(buf)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(key+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return key, nil
}

func validateStartupConfig(cfg *cfgpkg.Config) error {
	if cfg == nil {
		return errors.New("nil config")
	}
	if !isAPIServerEnabled(cfg) {
		return nil
	}
	if strings.TrimSpace(cfg.API.AuthToken) == "" {
		return errors.New("AUTH_TOKEN is required when API server is enabled; set AUTH_TOKEN in cfm.conf before startup")
	}
	return nil
}

func isAPIServerEnabled(cfg *cfgpkg.Config) bool {
	if cfg == nil {
		return false
	}
	return cfg.Debug.Port > 0 || cfg.Debug.TLSPort > 0
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

func newGoAuth(cfg goauth.Config) (*goauth.Manager, error) {
	// NOTE:
	// Keep this wrapper for centralized logging around goauth initialization.
	mgr, err := goauth.New(cfg)
	if err != nil && isGoAuthSQLiteBusy(err) {
		logging.LogfAPI("[apiserver] goauth init hit SQLITE_BUSY; restart service to retry cleanly: %v", err)
	}
	return mgr, err
}

var newGoAuthForInit = newGoAuth

func initGoAuthWithRetry(ctx context.Context, cfg goauth.Config) (*goauth.Manager, error) {
	mgr, err := newGoAuthForInit(cfg)
	if err == nil || !isGoAuthSQLiteBusy(err) {
		return mgr, err
	}

	backoffs := []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 3 * time.Second}
	lastErr := err
	for i, d := range backoffs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(d):
		}
		mgr, err = newGoAuthForInit(cfg)
		if err == nil {
			logging.LogfAPI("[apiserver] goauth init recovered after SQLITE_BUSY retries (attempt=%d)", i+2)
			return mgr, nil
		}
		lastErr = err
		if !isGoAuthSQLiteBusy(err) {
			return nil, err
		}
	}
	return nil, lastErr
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

const (
	pprofMinWriteTimeout          = 60 * time.Second
	pprofRequestedSafetyMargin    = 15 * time.Second
	pprofRequestedSecondsDefault  = 30
	pprofRequestedSecondsMaxLimit = 300
)

// PprofWriteTimeoutMiddleware relaxes write deadlines for pprof handlers so
// CPU/trace captures are not cut short by the global API write timeout.
func PprofWriteTimeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeout, ok := pprofRequestTimeout(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			logging.LogfAPI("[apiserver] pprof write deadline extension failed for %s: %v", r.URL.Path, err)
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func pprofRequestTimeout(r *http.Request) (time.Duration, bool) {
	if !strings.HasPrefix(r.URL.Path, "/debug/pprof/") {
		return 0, false
	}

	if r.URL.Path == "/debug/pprof/profile" || r.URL.Path == "/debug/pprof/trace" {
		seconds := parsePprofRequestedSeconds(r.URL.Query().Get("seconds"))
		return time.Duration(seconds)*time.Second + pprofRequestedSafetyMargin, true
	}

	return pprofMinWriteTimeout, true
}

func parsePprofRequestedSeconds(raw string) int {
	seconds, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || seconds <= 0 {
		return pprofRequestedSecondsDefault
	}
	if seconds > pprofRequestedSecondsMaxLimit {
		return pprofRequestedSecondsMaxLimit
	}
	return seconds
}

// adminOnlyHandler wraps h and returns 403 unless middleware explicitly marked
// the request as admin-authenticated.
// Used to protect routes that are inherently global and meaningless to
// per-vhost cPanel/DA tokens (MySQL governor, system status, etc.).
func adminOnlyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !webdet.IsAdminRequest(r) {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"admin token required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// scopedMySQLFilterHandler ensures filtered MySQL endpoints never execute
// unbounded for scoped-token callers. If ?user= is missing, it derives safe
// defaults from scoped token vhost ownership mapping.
func scopedMySQLFilterHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only a confirmed ADMIN runs these unfiltered. Detecting "admin" by an
		// empty scope map is unsafe: a scoped token whose vhost scope is somehow
		// empty (malformed/legacy) would otherwise be treated as admin and, on
		// the WRITE endpoint /api/v1/mysql/user-kill, could kill ANY connection.
		// Key off the authenticated role and fail closed for everyone else.
		if webdet.IsAdminRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		users := deriveScopedMySQLUsers(r)
		dbs := deriveScopedMySQLDatabases(r)
		if hasExplicitUserFilter(r) {
			if !requestedMySQLUsersWithinAllowed(r, users) {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"requested user filter is outside token scope"}`, http.StatusForbidden)
				return
			}
		}

		if hasExplicitDBFilter(r) {
			if !requestedMySQLDBsWithinAllowed(r, dbs) {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"requested db filter is outside token scope"}`, http.StatusForbidden)
				return
			}
		}

		if hasExplicitUserFilter(r) {
			next.ServeHTTP(w, r)
			return
		}

		if len(users) == 0 {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"user filter required; pass ?user= or use a scoped token with mapped domains"}`, http.StatusBadRequest)
			return
		}

		r2 := r.Clone(r.Context())
		q := r.URL.Query()
		for _, u := range users {
			q.Add("user", u)
		}
		r2.URL.RawQuery = q.Encode()
		next.ServeHTTP(w, r2)
	})
}

func hasExplicitUserFilter(r *http.Request) bool {
	for _, raw := range r.URL.Query()["user"] {
		for _, part := range strings.Split(raw, ",") {
			if strings.TrimSpace(part) != "" {
				return true
			}
		}
	}
	return false
}

func deriveScopedMySQLUsers(r *http.Request) []string {
	if dbScope := scopedDBScopeFromRequest(r); dbScope != nil && len(dbScope.Users) > 0 {
		return sortedScopeKeys(dbScope.Users)
	}
	owners := deriveScopedMySQLOwners(r)
	if len(owners) == 0 {
		return nil
	}

	out := make([]string, 0, len(owners)*2)
	for _, owner := range owners {
		out = append(out, owner, owner+"_*")
	}
	return out
}

func deriveScopedMySQLDatabases(r *http.Request) []string {
	if dbScope := scopedDBScopeFromRequest(r); dbScope != nil && len(dbScope.Databases) > 0 {
		return sortedScopeKeys(dbScope.Databases)
	}
	owners := deriveScopedMySQLOwners(r)
	if len(owners) == 0 {
		return nil
	}
	out := make([]string, 0, len(owners)*2)
	for _, owner := range owners {
		out = append(out, owner, owner+"_*")
	}
	return out
}

func deriveScopedMySQLOwners(r *http.Request) []string {
	// Direct CtxScopeKey read — bypasses webdet.vhostScopeFromContext and its
	// scoped-role empty-set normalization, so the len(scope)==0 guard below is
	// load-bearing: it fails closed (nil owners) for both admin (no scope) and
	// a vhost-less scoped token. Keep it if this is ever refactored.
	scope, _ := r.Context().Value(webdet.CtxScopeKey{}).(map[string]struct{})
	if len(scope) == 0 {
		return nil
	}

	hosts := make([]string, 0, len(scope))
	for host := range scope {
		hosts = append(hosts, strings.ToLower(strings.TrimSpace(host)))
	}
	owners := cpanelOwnersForHosts(hosts)
	if len(owners) == 0 {
		return nil
	}
	return owners
}

func scopedDBScopeFromRequest(r *http.Request) *webdet.ScopedDBScope {
	if r == nil {
		return nil
	}
	scope, _ := r.Context().Value(webdet.CtxDBScopeKey{}).(webdet.ScopedDBScope)
	if len(scope.Users) == 0 && len(scope.Databases) == 0 {
		return nil
	}
	return &scope
}

func requestedMySQLUsersWithinAllowed(r *http.Request, allowed []string) bool {
	requested := requestedMySQLUsers(r)
	if len(requested) == 0 {
		return true
	}
	for _, req := range requested {
		if !mysqlPatternWithinAllowed(req, allowed) {
			return false
		}
	}
	return true
}

func hasExplicitDBFilter(r *http.Request) bool {
	for _, raw := range r.URL.Query()["db"] {
		for _, part := range strings.Split(raw, ",") {
			if strings.TrimSpace(part) != "" {
				return true
			}
		}
	}
	return false
}

func requestedMySQLDBsWithinAllowed(r *http.Request, allowed []string) bool {
	requested := requestedMySQLDBs(r)
	if len(requested) == 0 {
		return true
	}
	for _, req := range requested {
		if !mysqlPatternWithinAllowed(req, allowed) {
			return false
		}
	}
	return true
}

func requestedMySQLUsers(r *http.Request) []string {
	return requestedMySQLParamValues(r, "user")
}

func requestedMySQLDBs(r *http.Request) []string {
	return requestedMySQLParamValues(r, "db")
}

func requestedMySQLParamValues(r *http.Request, key string) []string {
	var out []string
	for _, raw := range r.URL.Query()[key] {
		for _, part := range strings.Split(raw, ",") {
			v := strings.ToLower(strings.TrimSpace(part))
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func mysqlPatternWithinAllowed(requested string, allowed []string) bool {
	reqPrefix, reqWildcard := mysqlPatternPrefix(requested)
	for _, allow := range allowed {
		allowPrefix, allowWildcard := mysqlPatternPrefix(strings.ToLower(strings.TrimSpace(allow)))
		if allowWildcard {
			if reqWildcard {
				if strings.HasPrefix(reqPrefix, allowPrefix) {
					return true
				}
				continue
			}
			if strings.HasPrefix(requested, allowPrefix) {
				return true
			}
			continue
		}
		if !reqWildcard && requested == allowPrefix {
			return true
		}
	}
	return false
}

func mysqlPatternPrefix(s string) (prefix string, wildcard bool) {
	if strings.Count(s, "*") == 1 && strings.HasSuffix(s, "*") {
		return strings.TrimSuffix(s, "*"), true
	}
	return s, false
}

// cpanelOwnersForHosts returns the distinct set of cPanel accounts owning the
// given vhosts. It delegates to the canonical reader in internal/panelmap
// (OwnerSet: the union across /etc/userdatadomains and /etc/userdomains) so
// this scope-derivation path shares one parser with the rest of CFM (§5).
func cpanelOwnersForHosts(hosts []string) []string {
	return panelmap.OwnerSet(hosts)
}
