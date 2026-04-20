// internal/apiserver/middleware.go
//
// Bearer token middleware for the cfm apiserver.
//
// Auth order per request:
//  1. Public path (/login, /logout, /api/v1/embed/bootstrap) → pass through
//  2. Authorization: Bearer / X-CFM-Token / Token            → validate admin or scoped token
//  3. Scoped bootstrap cookie (cfm-embed-scope; /cfm-admin)  → allow scoped embedded/admin UI request
//  4. Embedded request without valid token/cookie             → 401 (no session fallback)
//  5. Valid goauth session cookie                             → allow (only if no token header, non-embedded)
//  6. Browser request (Accept: text/html)                     → redirect to /login
//  7. Everything else                                         → 401 / 403
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

func setAPIAnomalyReason(w http.ResponseWriter, reason string) {
	if s, ok := w.(apiAnomalyReasonSetter); ok {
		s.SetAPIAnomalyReason(reason)
	}
}

var sessionAllowedRequest = sessionAllowed

var (
	embedBootstrapAuthLogMu   sync.Mutex
	embedBootstrapAuthLastLog time.Time
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
	path := r.URL.Path
	if strings.HasPrefix(path, "/cfm-admin/") {
		path = strings.TrimPrefix(path, "/cfm-admin")
		if path == "" || path[0] != '/' {
			path = "/" + path
		}
	}
	if isPublicAssetPath(r, path) {
		return true
	}
	for _, p := range []string{"/login", "/logout", "/api/v1/embed/bootstrap"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
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
// and let the endpoint perform strict assertion validation.
func isCpanelPluginSelfServicePath(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	if r.Method != http.MethodGet || r.URL.Path != "/api/v1/cpanel/user-info" {
		return false
	}
	// Require actor assertion so this bypass is narrow.
	hasActorAssertion := strings.TrimSpace(r.Header.Get("X-CFM-Actor-Assertion")) != ""
	hasBearer := false
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(auth, "Bearer ") && strings.TrimSpace(auth[7:]) != "" {
		hasBearer = true
	}
	if !hasActorAssertion && !hasBearer {
		return false
	}
	return true
}

// TokenMiddleware enforces auth on all non-public routes.
func TokenMiddleware(adminToken string, store *TokenStore) func(http.Handler) http.Handler {
	if adminToken == "" {
		logging.LogfAPI("[apiserver] auth_reject=server_misconfigured_missing_auth_token")
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if isRequiredHealthPath(r) {
					next.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"server misconfigured: AUTH_TOKEN missing"}`, http.StatusServiceUnavailable)
			})
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			embedded := isCpanelEmbeddedRequest(r)

			if maybeHandlePreAuthLoginChallenge(w, r) {
				return
			}

			// ── 1. Public paths ────────────────────────────────────────────
			if isPublicPath(r) || isCpanelPluginSelfServicePath(r) {
				next.ServeHTTP(w, r)
				return
			}

			// ── 2. Bearer / X-CFM-Token / Token header ────────────────────
			tok, tokenHeaderSupplied := extractToken(r)
			if suspicious, detail := suspiciousAuthHeader(r); suspicious {
				logging.LogfAPI("[apiserver] event=api_anomaly src_ip=%s reason=suspicious_auth_header count=1 method=%s path=%q status=0 detail=%q ua=%q",
					realIPFromRequest(r), r.Method, r.URL.Path, detail, strings.TrimSpace(r.UserAgent()))
			}
			if tok != "" {
				if tokenMatch(tok, adminToken) {
					logging.LogfAPI("[apiserver] auth_source=token_admin src_ip=%s method=%s path=%q ua=%q",
						realIPFromRequest(r), r.Method, r.URL.Path, strings.TrimSpace(r.UserAgent()))
					ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
					ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				if st, ok := store.Lookup(tok); ok {
					if embedded {
						logging.LogfAPI("[apiserver] auth_source=token_scoped_embedded src_ip=%s method=%s path=%q ua=%q",
							realIPFromRequest(r), r.Method, r.URL.Path, strings.TrimSpace(r.UserAgent()))
					} else {
						logging.LogfAPI("[apiserver] auth_source=token_scoped src_ip=%s method=%s path=%q ua=%q",
							realIPFromRequest(r), r.Method, r.URL.Path, strings.TrimSpace(r.UserAgent()))
					}
					ctx := context.WithValue(r.Context(), webdet.CtxScopeKey{}, st.Vhosts)
					ctx = context.WithValue(ctx, webdet.CtxDBScopeKey{}, webdet.ScopedDBScope{
						Users:     st.DBUsers,
						Databases: st.Databases,
					})
					ctx = context.WithValue(ctx, webdet.CtxAuthnKey{}, true)
					ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleScoped)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				if embedded {
					logging.LogfAPI("[apiserver] auth_reject=invalid_scoped_embedded")
				}
				w.Header().Set("Content-Type", "application/json")
				setAPIAnomalyReason(w, "token_invalid")
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// ── 3. Scoped bootstrap cookie (HTML under /cfm-admin only) ─────
			if !tokenHeaderSupplied {
				if ctx, ok := embedScopedContextFromCookie(w, r, store); ok {
					if shouldLogEmbedBootstrapAuth(time.Now()) {
						logging.LogfAPI("[apiserver] auth_source=embed_bootstrap_cookie src_ip=%s method=%s path=%q ua=%q (sampled_every=15s)",
							realIPFromRequest(r), r.Method, r.URL.Path, strings.TrimSpace(r.UserAgent()))
					}
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// ── 4. Embedded requests require token or embed bootstrap cookie ─
			if embedded {
				logging.LogfAPI("[apiserver] auth_reject=missing_scoped_embedded")
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", `Bearer realm="cfm"`)
				setAPIAnomalyReason(w, "auth_missing")
				http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
				return
			}

			// ── 5. Valid goauth session (fallback when no token header) ───
			if !tokenHeaderSupplied && sessionAllowedRequest(r) {
				if shouldLogSessionCookieAuth(time.Now()) {
					logging.LogfAPI("[apiserver] auth_source=session_cookie src_ip=%s method=%s path=%q ua=%q (sampled_every=60s)",
						realIPFromRequest(r), r.Method, r.URL.Path, strings.TrimSpace(r.UserAgent()))
				}
				ctx := context.WithValue(r.Context(), webdet.CtxAuthnKey{}, true)
				ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// ── 6. No token — redirect browsers, 401 API clients ──────────
			if strings.Contains(r.Header.Get("Accept"), "text/html") {
				if isEmbedShellBootstrapRequest(r) {
					logging.LogfAPI("[apiserver] auth_source=embed_shell_bootstrap")
					next.ServeHTTP(w, r)
					return
				}
				setAPIAnomalyReason(w, "auth_missing")
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

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="cfm"`)
			setAPIAnomalyReason(w, "auth_missing")
			http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
		})
	}
}

func tokenMatch(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func extractToken(r *http.Request) (string, bool) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[7:]), true
	}
	if _, ok := r.Header["X-CFM-Token"]; ok {
		return strings.TrimSpace(r.Header.Get("X-CFM-Token")), true
	}
	if _, ok := r.Header["Token"]; ok {
		return strings.TrimSpace(r.Header.Get("Token")), true
	}
	return "", false
}

func suspiciousAuthHeader(r *http.Request) (bool, string) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	hasXCFM := len(r.Header["X-CFM-Token"]) > 0
	hasToken := len(r.Header["Token"]) > 0
	if auth != "" && (hasXCFM || hasToken) {
		return true, "multiple_auth_schemes"
	}
	if auth == "" {
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
