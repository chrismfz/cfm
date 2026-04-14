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
	"sync"
	"strings"
	"time"

	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

var sessionAllowedRequest = sessionAllowed

var (
	embedBootstrapAuthLogMu   sync.Mutex
	embedBootstrapAuthLastLog time.Time
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
	for _, p := range []string{"/login", "/logout", "/api/v1/embed/bootstrap"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func isRequiredHealthPath(r *http.Request) bool {
	path := r.URL.Path
	if strings.HasPrefix(path, "/cfm-admin/") {
		path = strings.TrimPrefix(path, "/cfm-admin")
		if path == "" || path[0] != '/' {
			path = "/" + path
		}
	}
	return path == "/api/v1/system/status"
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
		logging.Logf("[apiserver] auth_reject=server_misconfigured_missing_auth_token")
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

			// ── 1. Public paths ────────────────────────────────────────────
			if isPublicPath(r) || isCpanelPluginSelfServicePath(r) {
				next.ServeHTTP(w, r)
				return
			}

			// ── 2. Bearer / X-CFM-Token / Token header ────────────────────
			tok, tokenHeaderSupplied := extractToken(r)
			if tok != "" {
				if tokenMatch(tok, adminToken) {
					logging.Logf("[apiserver] auth_source=token_admin")
					next.ServeHTTP(w, r)
					return
				}
				if st, ok := store.Lookup(tok); ok {
					if embedded {
						logging.Logf("[apiserver] auth_source=token_scoped_embedded")
					} else {
						logging.Logf("[apiserver] auth_source=token_scoped")
					}
					ctx := context.WithValue(r.Context(), webdet.CtxScopeKey{}, st.Vhosts)
					ctx = context.WithValue(ctx, webdet.CtxDBScopeKey{}, webdet.ScopedDBScope{
						Users:     st.DBUsers,
						Databases: st.Databases,
					})
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				if embedded {
					logging.Logf("[apiserver] auth_reject=invalid_scoped_embedded")
				}
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

				// ── 3. Scoped bootstrap cookie (HTML under /cfm-admin only) ─────
				if !tokenHeaderSupplied {
					if ctx, ok := embedScopedContextFromCookie(r, store); ok {
						if shouldLogEmbedBootstrapAuth(time.Now()) {
							logging.Logf("[apiserver] auth_source=embed_bootstrap_cookie (sampled_every=15s)")
						}
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}

			// ── 4. Embedded requests require token or embed bootstrap cookie ─
			if embedded {
				logging.Logf("[apiserver] auth_reject=missing_scoped_embedded")
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", `Bearer realm="cfm"`)
				http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
				return
			}

			// ── 5. Valid goauth session (fallback when no token header) ───
			if !tokenHeaderSupplied && sessionAllowedRequest(r) {
				logging.Logf("[apiserver] auth_source=session_cookie")
				next.ServeHTTP(w, r)
				return
			}

			// ── 6. No token — redirect browsers, 401 API clients ──────────
			if strings.Contains(r.Header.Get("Accept"), "text/html") {
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
