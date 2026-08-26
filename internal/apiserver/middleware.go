// internal/apiserver/middleware.go
//
// Bearer token middleware for the cfm apiserver.
//
// Auth order per request:
//  1. Public path (/login, /logout, /api/v1/embed/{,admin-}bootstrap) → pass through
//  2. Authorization: Bearer / X-CFM-Token / Token            → validate admin or scoped token
//  3. Admin SSO bootstrap cookie (cfm-embed-admin; /cfm-admin) → allow full-admin UI request
//  4. Scoped bootstrap cookie (cfm-embed-scope; /cfm-admin)  → allow scoped embedded/admin UI request
//  5. Embedded request without valid token/cookie             → 401 (no session fallback)
//  6. Valid goauth session cookie                             → allow (only if no token header, non-embedded)
//  7. Browser request (Accept: text/html)                     → redirect to /login
//  8. Everything else                                         → 401 / 403
//

package apiserver

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

type apiAnomalyReasonSetter interface {
	SetAPIAnomalyReason(reason string)
}

func setAPIAnomalyReason(w http.ResponseWriter, r *http.Request, reason string) {
	if state := anomalyStateFromRequest(r); state != nil {
		state.setReason(reason)
	}
	if s, ok := w.(apiAnomalyReasonSetter); ok {
		s.SetAPIAnomalyReason(reason)
	}
}

var sessionAllowedRequest = sessionAllowed

type authnMechanism string

const (
	authnMechanismUnknown          authnMechanism = ""
	authnMechanismSession          authnMechanism = "session_cookie"
	authnMechanismTokenAdmin       authnMechanism = "token_admin"
	authnMechanismTokenScoped      authnMechanism = "token_scoped"
	authnMechanismEmbedCookie      authnMechanism = "embed_bootstrap_cookie"
	authnMechanismEmbedAdminCookie authnMechanism = "embed_admin_cookie"
)

type authnMechanismCtxKey struct{}

func withAuthnMechanism(ctx context.Context, mech authnMechanism) context.Context {
	if mech == authnMechanismUnknown {
		return ctx
	}
	return context.WithValue(ctx, authnMechanismCtxKey{}, mech)
}

func authnMechanismFromContext(ctx context.Context) authnMechanism {
	if ctx == nil {
		return authnMechanismUnknown
	}
	v, _ := ctx.Value(authnMechanismCtxKey{}).(authnMechanism)
	return v
}

// authnSubjectCtxKey carries a stable NON-SECRET per-identity subject (admin
// constant, scoped/embed token ID, or a session-cookie hash) used only to key
// rate-limit buckets so one caller cannot drain another's (audit Step 8). It must
// never hold raw credential material.
type authnSubjectCtxKey struct{}

func withAuthnSubject(ctx context.Context, subject string) context.Context {
	if subject == "" {
		return ctx
	}
	return context.WithValue(ctx, authnSubjectCtxKey{}, subject)
}

func authnSubjectFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(authnSubjectCtxKey{}).(string)
	return v
}

var (
	embedBootstrapAuthLogMu   sync.Mutex
	embedBootstrapAuthLastLog time.Time
	embedAdminAuthLogMu       sync.Mutex
	embedAdminAuthLastLog     time.Time
	sessionCookieAuthLogMu    sync.Mutex
	sessionCookieAuthLastLog  time.Time
)

func shouldLogEmbedBootstrapAuth(now time.Time) bool {
	embedBootstrapAuthLogMu.Lock()
	defer embedBootstrapAuthLogMu.Unlock()
	if !embedBootstrapAuthLastLog.IsZero() && now.Sub(embedBootstrapAuthLastLog) < 15*time.Second {
		return false
	}
	embedBootstrapAuthLastLog = now
	return true
}

// shouldLogEmbedAdminAuth throttles the admin-SSO auth-source line on its OWN
// timestamp, so busy scoped-embed traffic can't starve the (higher-privilege,
// far rarer) admin audit line by sharing one window.
func shouldLogEmbedAdminAuth(now time.Time) bool {
	embedAdminAuthLogMu.Lock()
	defer embedAdminAuthLogMu.Unlock()
	if !embedAdminAuthLastLog.IsZero() && now.Sub(embedAdminAuthLastLog) < 15*time.Second {
		return false
	}
	embedAdminAuthLastLog = now
	return true
}

func shouldLogSessionCookieAuth(now time.Time) bool {
	sessionCookieAuthLogMu.Lock()
	defer sessionCookieAuthLogMu.Unlock()
	if !sessionCookieAuthLastLog.IsZero() && now.Sub(sessionCookieAuthLastLog) < 60*time.Second {
		return false
	}
	sessionCookieAuthLastLog = now
	return true
}

// isPublicPath returns true if the request path requires no auth.
// cfmBase returns the path prefix used by the UI when generating redirects.
//
// Priority:
//  1. X-Forwarded-Prefix (trusted only from loopback peer)
//  2. X-CFM-Base (trusted only from loopback peer)
//  3. request path prefix (/cfm-admin) for direct :6061 access
func cfmBase(r *http.Request) string {
	if b := trustedProxyBase(r); b != "" {
		return b
	}
	if strings.HasPrefix(r.URL.Path, "/cfm-admin/") || r.URL.Path == "/cfm-admin" {
		return "/cfm-admin"
	}
	return ""
}

func trustedProxyBase(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ""
	}
	for _, raw := range []string{
		r.Header.Get("X-Forwarded-Prefix"),
		r.Header.Get("X-CFM-Base"),
	} {
		if b := normalizePathPrefix(raw); b != "" {
			return b
		}
	}
	return ""
}

func normalizePathPrefix(raw string) string {
	if raw == "" {
		return ""
	}
	// Some proxies send a comma-separated list; first hop is what we need.
	p := strings.TrimSpace(strings.Split(raw, ",")[0])
	if p == "" || !strings.HasPrefix(p, "/") {
		return ""
	}
	p = "/" + strings.Trim(strings.TrimSpace(p), "/")
	if p == "/" {
		return ""
	}
	return p
}

func isPublicPath(r *http.Request) bool {
	path := authMiddlewarePath(r)
	if isPublicAssetPath(r, path) {
		return true
	}
	for _, p := range []string{"/login", "/logout", "/api/v1/embed/bootstrap", "/api/v1/embed/admin-bootstrap"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	// MCP surface: the /mcp endpoint, its OAuth endpoints (/mcp/oauth/*) and the
	// OAuth discovery documents are self-authenticating (mcpserver's own bearer /
	// OAuth gate), so they bypass session/token auth here. See internal/mcpserver.
	if isMCPPublicPath(r) {
		return true
	}
	return false
}

func isMCPPublicPath(r *http.Request) bool {
	path := authMiddlewarePath(r)
	return path == "/mcp" || strings.HasPrefix(path, "/mcp/") ||
		path == "/.well-known/oauth-protected-resource" ||
		path == "/.well-known/oauth-authorization-server" ||
		path == "/.well-known/openid-configuration"
}

func authMiddlewarePath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	path := r.URL.Path
	if strings.HasPrefix(path, "/cfm-admin/") {
		path = strings.TrimPrefix(path, "/cfm-admin")
		if path == "" || path[0] != '/' {
			path = "/" + path
		}
	}
	return path
}

func isPublicAssetPath(r *http.Request, normalizedPath string) bool {
	if r == nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	path := strings.TrimSpace(normalizedPath)
	if !strings.HasPrefix(path, "/assets/") {
		return false
	}
	if strings.Contains(path, "..") {
		return false
	}
	switch {
	case strings.HasSuffix(path, ".js"),
		strings.HasSuffix(path, ".css"),
		strings.HasSuffix(path, ".map"),
		strings.HasSuffix(path, ".png"),
		strings.HasSuffix(path, ".jpg"),
		strings.HasSuffix(path, ".jpeg"),
		strings.HasSuffix(path, ".svg"),
		strings.HasSuffix(path, ".ico"),
		strings.HasSuffix(path, ".woff"),
		strings.HasSuffix(path, ".woff2"),
		strings.HasSuffix(path, ".ttf"):
		return true
	default:
		return false
	}
}

func isRequiredHealthPath(_ *http.Request) bool {
	return false
}

func isCpanelEmbeddedRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	for _, h := range []string{"X-CFM-Embedded", "X-CPanel-Embedded"} {
		v := strings.ToLower(strings.TrimSpace(r.Header.Get(h)))
		switch v {
		case "1", "true", "cpanel", "embedded":
			return true
		}
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/cpanel/") {
		return true
	}
	return false
}

// isEmbedShellBootstrapRequest identifies unauthenticated iframe bootstrap page
// loads where we can safely serve the static HTML shell and let postMessage
// bearer token auth handle subsequent API calls.
func isEmbedShellBootstrapRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	if r.Method != http.MethodGet {
		return false
	}
	path := r.URL.Path
	if strings.HasPrefix(path, "/cfm-admin/") {
		path = strings.TrimPrefix(path, "/cfm-admin")
		if path == "" || path[0] != '/' {
			path = "/" + path
		}
	}
	if strings.HasPrefix(path, "/api/") || path == "/login" || strings.HasPrefix(path, "/login/") || path == "/logout" {
		return false
	}
	// Primary signal on first load (from embed bootstrap redirect).
	if strings.TrimSpace(r.URL.Query().Get("cfmExpectedOrigin")) != "" {
		return strings.Contains(r.Header.Get("Accept"), "text/html")
	}
	// Subsequent in-iframe navigations often drop query params; keep allowing
	// HTML shell routes when browser explicitly marks iframe destination.
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")), "iframe") {
		return strings.Contains(r.Header.Get("Accept"), "text/html")
	}
	return false
}

// cPanel plugin actor-assertion route: allow request through auth middleware
// and let the endpoint perform strict assertion validation. One credential
// namespace per header: only X-CFM-Actor-Assertion carries plugin assertions;
// Authorization: Bearer is exclusively the CFM admin/scoped token namespace,
// so a Bearer-only request falls through to normal token validation instead
// of being mistaken for an assertion bearer.
func isCpanelPluginSelfServicePath(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	if r.Method != http.MethodGet || r.URL.Path != "/api/v1/cpanel/user-info" {
		return false
	}
	return strings.TrimSpace(r.Header.Get("X-CFM-Actor-Assertion")) != ""
}

// TokenMiddleware enforces auth on all non-public routes. Optional
// TokenMiddlewareOption knobs (e.g. WithAdminTokenIPBinding) default to off, so
// existing two-arg callers are unaffected.
func TokenMiddleware(adminToken string, store *TokenStore, opts ...TokenMiddlewareOption) func(http.Handler) http.Handler {
	var mwCfg tokenMiddlewareConfig
	for _, o := range opts {
		if o != nil {
			o(&mwCfg)
		}
	}
	if adminToken == "" {
		logging.LogfAPI("[apiserver] auth_reject=server_misconfigured_missing_auth_token")
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if isRequiredHealthPath(r) {
					next.ServeHTTP(w, r)
					return
				}
				if _, supplied := extractToken(r); supplied {
					auditAuthAttempt(r, authAttemptAudit{Kind: "token", Result: "unavailable", AuthMech: "unknown", Status: http.StatusServiceUnavailable})
				}
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"server misconfigured: AUTH_TOKEN missing"}`, http.StatusServiceUnavailable)
			})
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			embedded := isCpanelEmbeddedRequest(r)

			// MCP owns its bearer/OAuth namespace. Its gate performs the canonical
			// audit and must see MCP_TOKEN values that are intentionally invalid here.
			if isMCPPublicPath(r) {
				next.ServeHTTP(w, r)
				return
			}
			publicPath := isPublicPath(r) || isCpanelPluginSelfServicePath(r)

			// ── 1. Bearer / X-CFM-Token / Token header ────────────────────
			tok, tokenHeaderSupplied := extractToken(r)
			if suspicious, detail := suspiciousAuthHeader(r); suspicious {
				logging.LogfAPI("[apiserver] event=api_anomaly src_ip=%s reason=suspicious_auth_header count=1 method=%s path=%q status=0 detail=%q ua=%q",
					realIPFromRequest(r), r.Method, r.URL.Path, detail, strings.TrimSpace(r.UserAgent()))
				auditAuthAttempt(r, authAttemptAudit{Kind: "token", Result: "malformed", AuthMech: "unknown", Status: http.StatusUnauthorized})
				publishRequestAnomaly(r, "AUTH_TOKEN_MALFORMED", http.StatusUnauthorized)
				setAPIAnomalyReason(w, r, "token_malformed")
				rejectTokenAuth(w)
				return
			}
			if tokenHeaderSupplied && tok == "" {
				auditAuthAttempt(r, authAttemptAudit{Kind: "token", Result: "malformed", AuthMech: "unknown", Status: http.StatusUnauthorized})
				publishRequestAnomaly(r, "AUTH_TOKEN_MALFORMED", http.StatusUnauthorized)
				setAPIAnomalyReason(w, r, "token_malformed")
				rejectTokenAuth(w)
				return
			}
			if tok != "" {
				if tokenMatch(tok, adminToken) {
					// Optional source-IP binding: the admin token is only ever
					// presented server-to-server (cfm-web at the API_URL host) or
					// over loopback (WHM plugin). A match from any other IP is a
					// leaked-token signal.
					if mwCfg.adminIP.active() && !adminTokenSourceAllowed(r, mwCfg.adminIP) {
						if mwCfg.adminIP.mode == adminIPModeEnforce {
							auditAuthAttempt(r, authAttemptAudit{Kind: "token", Result: "blocked_source_ip", AuthMech: string(authnMechanismTokenAdmin), Status: http.StatusForbidden})
							// Publish a structured anomaly (enforce ONLY — logonly must
							// stay observe-only so burn-in never blocks/challenges the
							// source) so a leaked admin token used even ONCE from a foreign
							// IP alerts, instead of needing a 5-in-30s forbidden burst.
							// classifierReason() lists "admin_token_source_ip" as a direct
							// event so the generic burst signal does not double-count this.
							publishRequestAnomaly(r, "ADMIN_TOKEN_FOREIGN_IP", http.StatusForbidden)
							logging.LogfAPI("[apiserver] event=api_audit reason=admin_token_source_ip src_ip=%s method=%s path=%q status=%d",
								realIPFromRequest(r), r.Method, r.URL.Path, http.StatusForbidden)
							setAPIAnomalyReason(w, r, "admin_token_source_ip")
							setAuthIdentityNoCacheHeaders(w) // identity-sensitive rejection
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(http.StatusForbidden)
							// Opaque body (matches rejectIP) — do not confirm to the caller
							// that the token they presented is the valid admin token.
							_, _ = w.Write(mustJSON(map[string]string{"error": "forbidden: source IP not allowed"}))
							return
						}
						// logonly (burn-in): record what enforce WOULD block, then allow.
						// Unsampled by design — expected volume is ~zero (only cfm-web and
						// the WHM plugin present the admin token, both allowlisted) and each
						// line is security evidence; a leaked-token spray in logonly is the
						// one case that could make this chatty.
						logging.LogfAPI("[apiserver] admin_token_source_ip logonly=would_block src_ip=%s method=%s path=%q",
							realIPFromRequest(r), r.Method, r.URL.Path)
					}
					auditAuthAttempt(r, authAttemptAudit{Kind: "token", Result: "success", AuthMech: string(authnMechanismTokenAdmin), Status: http.StatusOK})
					ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
					ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
					ctx = withAuthnMechanism(ctx, authnMechanismTokenAdmin)
					ctx = withAuthnSubject(ctx, "admin") // single admin bucket (rate limit, Step 8)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				if st, ok := store.Lookup(tok); ok {
					auditAuthAttempt(r, authAttemptAudit{Kind: "token", Result: "success", AuthMech: string(authnMechanismTokenScoped), TokenID: st.ID, Status: http.StatusOK})
					ctx := context.WithValue(r.Context(), webdet.CtxScopeKey{}, st.Vhosts)
					ctx = context.WithValue(ctx, webdet.CtxDBScopeKey{}, webdet.ScopedDBScope{
						Users:     st.DBUsers,
						Databases: st.Databases,
					})
					ctx = context.WithValue(ctx, webdet.CtxAuthnKey{}, true)
					ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleScoped)
					ctx = withAuthnMechanism(ctx, authnMechanismTokenScoped)
					ctx = withAuthnSubject(ctx, st.ID) // per-token bucket: one scoped token can't drain another (Step 8)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				auditAuthAttempt(r, authAttemptAudit{Kind: "token", Result: "invalid", AuthMech: "unknown", Status: http.StatusUnauthorized})
				publishRequestAnomaly(r, "AUTH_TOKEN_INVALID", http.StatusUnauthorized)
				setAPIAnomalyReason(w, r, "token_invalid")
				rejectTokenAuth(w)
				return
			}
			if publicPath {
				next.ServeHTTP(w, r)
				return
			}

			// ── 2a. Admin SSO bootstrap cookie (HTML under /cfm-admin only) ─
			// Checked before the scoped cookie: it grants the full-admin role,
			// and an SSO'd admin browser only ever carries this cookie.
			if !tokenHeaderSupplied {
				if ctx, ok := embedAdminContextFromCookie(w, r); ok {
					ctx = withAuthnMechanism(ctx, authnMechanismEmbedAdminCookie)
					if shouldLogEmbedAdminAuth(time.Now()) {
						logging.LogfAPI("[apiserver] auth_source=embed_admin_cookie src_ip=%s method=%s path=%q ua=%q (sampled_every=15s)",
							realIPFromRequest(r), r.Method, r.URL.Path, strings.TrimSpace(r.UserAgent()))
					}
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// ── 2b. Scoped bootstrap cookie (HTML under /cfm-admin only) ────
			if !tokenHeaderSupplied {
				if ctx, ok := embedScopedContextFromCookie(w, r, store); ok {
					ctx = withAuthnMechanism(ctx, authnMechanismEmbedCookie)
					if shouldLogEmbedBootstrapAuth(time.Now()) {
						logging.LogfAPI("[apiserver] auth_source=embed_bootstrap_cookie src_ip=%s method=%s path=%q ua=%q (sampled_every=15s)",
							realIPFromRequest(r), r.Method, r.URL.Path, strings.TrimSpace(r.UserAgent()))
					}
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// ── 3. Embedded requests require token or embed bootstrap cookie ─
			if embedded {
				logging.LogfAPI("[apiserver] auth_reject=missing_scoped_embedded")
				setAuthIdentityNoCacheHeaders(w) // identity-sensitive 401 (audit R10)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", `Bearer realm="cfm"`)
				setAPIAnomalyReason(w, r, "auth_missing")
				http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
				return
			}

			// ── 4. Valid goauth session (fallback when no token header) ───
			if !tokenHeaderSupplied && sessionAllowedRequest(r) {
				if shouldLogSessionCookieAuth(time.Now()) {
					logging.LogfAPI("[apiserver] auth_source=session_cookie src_ip=%s method=%s path=%q ua=%q (sampled_every=60s)",
						realIPFromRequest(r), r.Method, r.URL.Path, strings.TrimSpace(r.UserAgent()))
				}
				ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
				ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
				ctx = withAuthnMechanism(ctx, authnMechanismSession)
				if u, ok := authUserFromContext(r.Context()); ok && u != nil && u.Username != "" {
					ctx = withAuthnSubject(ctx, "user:"+u.Username) // per-user session bucket (Step 8)
				}
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// ── 5. No token — redirect browsers, 401 API clients ──────────
			if strings.Contains(r.Header.Get("Accept"), "text/html") {
				if isEmbedShellBootstrapRequest(r) {
					logging.LogfAPI("[apiserver] auth_source=embed_shell_bootstrap")
					next.ServeHTTP(w, r)
					return
				}
				setAPIAnomalyReason(w, r, "auth_missing")
				base := cfmBase(r)
				next := r.URL.RequestURI()
				if base != "" && !strings.HasPrefix(next, base+"/") && next != base {
					next = base + next
				}
				http.Redirect(w, r,
					base+"/login?next="+url.QueryEscape(next),
					http.StatusSeeOther)
				return
			}

			setAuthIdentityNoCacheHeaders(w) // identity-sensitive 401 (audit R10)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="cfm"`)
			setAPIAnomalyReason(w, r, "auth_missing")
			http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
		})
	}
}

func tokenMatch(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func extractToken(r *http.Request) (string, bool) {
	if len(r.Header.Values("Authorization")) > 0 {
		parts := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1]), true
		}
		return "", true
	}
	// Values()/Get() match case-insensitively; the header map itself stores
	// MIME-canonicalized keys ("X-Cfm-Token"), which a literal index misses.
	if vals := r.Header.Values("X-CFM-Token"); len(vals) > 0 {
		return strings.TrimSpace(vals[0]), true
	}
	if vals := r.Header.Values("Token"); len(vals) > 0 {
		return strings.TrimSpace(vals[0]), true
	}
	return "", false
}

func suspiciousAuthHeader(r *http.Request) (bool, string) {
	hasAuthorization := len(r.Header.Values("Authorization")) > 0
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	// Case-insensitive lookups: the header map stores MIME-canonicalized keys,
	// which a literal "X-CFM-Token" index never matches.
	hasXCFM := len(r.Header.Values("X-CFM-Token")) > 0
	hasToken := len(r.Header.Values("Token")) > 0
	if auth != "" && (hasXCFM || hasToken) {
		return true, "multiple_auth_schemes"
	}
	if auth == "" {
		if hasAuthorization {
			return true, "authorization_header_empty"
		}
		if hasXCFM && hasToken {
			return true, "multiple_token_headers"
		}
		return false, ""
	}
	parts := strings.Fields(auth)
	if len(parts) == 0 {
		return true, "authorization_header_empty"
	}
	scheme := strings.ToLower(parts[0])
	if scheme == "bearer" {
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			return true, "malformed_bearer"
		}
		return false, ""
	}
	if strings.Contains(strings.ToLower(auth), "bearer ") {
		return true, "multiple_auth_schemes"
	}
	return false, ""
}

func rejectTokenAuth(w http.ResponseWriter) {
	// An auth failure is identity-sensitive and must never be cached as another
	// identity — set no-store here at the outer auth layer, not only in the
	// success handlers, because anonymous/invalid requests are rejected before any
	// endpoint-specific headers run (audit R10).
	setAuthIdentityNoCacheHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="cfm"`)
	http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
}
