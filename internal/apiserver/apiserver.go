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
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chrismfz/goauth"

	cfgpkg "cfm/internal/config"
	mysqlpkg "cfm/internal/detectors/mysql"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	sslpkg "cfm/internal/sslcollector"
	webdet "cfm/internal/webdetector"
	webui "cfm/internal/webui"
)

// ── package-level mux (shared with Phase 2 callers via Register()) ────────────

var (
	mu        sync.Mutex
	sharedMux *http.ServeMux
	pending   []func(*http.ServeMux)

	cpanelUserDataDomainsPath = "/etc/userdatadomains"
	cpanelUserDomainsPath     = "/etc/userdomains"
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

		logging.Logf("[apiserver] mysql governor routes registered (admin global + scoped filtered)")
	}

	// ── Scoped token issuance ─────────────────────────────────────────────────
	store := NewTokenStore()
	tokensPath := filepath.Join("/var/lib/cfm", "tokens.json")
	if cfg.Debug.AuthDBPath != "" {
		tokensPath = filepath.Join(filepath.Dir(cfg.Debug.AuthDBPath), "tokens.json")
	}
	if err := store.Load(tokensPath); err != nil {
		logging.Logf("[apiserver] token store load: %v", err)
	}

	store.StartPurger(ctx)
	RegisterTokenEndpoint(m, store)
	RegisterTokenManagementEndpoints(m, store)

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
		authMgr, err := newGoAuth(authCfg)
		if err != nil {
			SetAuth(nil)
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
		SetAuth(nil)
		logging.Logf("[apiserver] AUTH_DB_PATH not set — browser auth disabled (token-only)")
	}

	// ── Build handler stack ───────────────────────────────────────────────────
	// Innermost → outermost:
	//   mux → TokenMiddleware → LoadAndSave
	var handler http.Handler
	handler = TokenMiddleware(cfg.API.AuthToken, store)(m)
	if Auth != nil {
		handler = Auth.LoadAndSave(handler)
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

func newGoAuth(cfg goauth.Config) (*goauth.Manager, error) {
	// NOTE:
	// Current pinned goauth version (v0.0.0-20260404230222-598d5f52a7aa)
	// can return init errors after opening the DB without closing it.
	//
	// Retrying goauth.New() in-process would accumulate leaked handles and
	// worsen SQLITE_BUSY lock contention. Keep initialization single-attempt
	// until goauth guarantees cleanup on failed New().
	mgr, err := goauth.New(cfg)
	if err != nil && isGoAuthSQLiteBusy(err) {
		logging.Logf("[apiserver] goauth init hit SQLITE_BUSY; restart service to retry cleanly: %v", err)
	}
	return mgr, err
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

// adminOnlyHandler wraps h and returns 403 for any scoped token.
// Admin tokens and the loopback bypass both produce a nil scope and pass through.
// Used to protect routes that are inherently global and meaningless to
// per-vhost cPanel/DA tokens (MySQL governor, system status, etc.).
func adminOnlyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, _ := r.Context().Value(webdet.CtxScopeKey{}).(map[string]struct{}); v != nil {
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
		scope, _ := r.Context().Value(webdet.CtxScopeKey{}).(map[string]struct{})
		if len(scope) == 0 {
			// Admin token / authenticated UI session: keep existing handler
			// semantics (user= or db= validation remains in governor handlers).
			next.ServeHTTP(w, r)
			return
		}

		users := deriveScopedMySQLUsers(r)
		if hasExplicitUserFilter(r) {
			if !requestedMySQLUsersWithinAllowed(r, users) {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"requested user filter is outside token scope"}`, http.StatusForbidden)
				return
			}
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

	out := make([]string, 0, len(owners)*2)
	for _, owner := range owners {
		out = append(out, owner, owner+"_*")
	}
	return out
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

func requestedMySQLUsers(r *http.Request) []string {
	var out []string
	for _, raw := range r.URL.Query()["user"] {
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

func cpanelOwnersForHosts(hosts []string) []string {
	if len(hosts) == 0 {
		return nil
	}
	hostSet := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		if h != "" {
			hostSet[h] = struct{}{}
		}
	}
	owners := map[string]struct{}{}
	collectCpanelOwnersFromUserDataDomains(hostSet, owners)
	collectCpanelOwnersFromUserDomains(hostSet, owners)
	if len(owners) == 0 {
		return nil
	}
	out := make([]string, 0, len(owners))
	for owner := range owners {
		out = append(out, owner)
	}
	sort.Strings(out)
	return out
}

func collectCpanelOwnersFromUserDataDomains(hostSet, owners map[string]struct{}) {
	f, err := os.Open(cpanelUserDataDomainsPath)
	if err != nil {
		return
	}
	defer f.Close()
	collectCpanelOwners(f, hostSet, owners, true)
}

func collectCpanelOwnersFromUserDomains(hostSet, owners map[string]struct{}) {
	f, err := os.Open(cpanelUserDomainsPath)
	if err != nil {
		return
	}
	defer f.Close()
	collectCpanelOwners(f, hostSet, owners, false)
}

func collectCpanelOwners(f *os.File, hostSet, owners map[string]struct{}, userDataDomains bool) {
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 || colon+1 >= len(line) {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(line[:colon]))
		if _, ok := hostSet[host]; !ok {
			continue
		}
		rest := strings.TrimSpace(line[colon+1:])
		var owner string
		if userDataDomains {
			parts := strings.SplitN(rest, "==", 2)
			if len(parts) == 0 {
				continue
			}
			owner = strings.ToLower(strings.TrimSpace(parts[0]))
		} else {
			owner = strings.ToLower(strings.TrimSpace(rest))
		}
		if owner == "" {
			continue
		}
		owners[owner] = struct{}{}
	}
}
