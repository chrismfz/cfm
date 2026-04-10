// internal/apiserver/middleware.go
//
// Bearer token middleware for the cfm apiserver.
//
// Auth order per request:
//  1. Public path (/login, /logout, /login/verify) → pass through
//  2. Authorization: Bearer / X-CFM-Token / Token  → validate admin or scoped token
//  3. Valid goauth session cookie                  → allow (only if no token header)
//  4. Browser request (Accept: text/html)          → redirect to /login
//  5. Everything else                              → 401 / 403
//

package apiserver

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"

	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
)

// isPublicPath returns true if the request path requires no auth.
// cfmBase returns the path prefix used by the UI when generating redirects.
//
// Priority:
//   1) X-Forwarded-Prefix (trusted only from loopback peer)
//   2) X-CFM-Base (trusted only from loopback peer)
//   3) request path prefix (/cfm-admin) for direct :6061 access
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
	for _, p := range []string{"/login", "/logout"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
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
// If adminToken is empty the middleware is disabled (backwards compat).
func TokenMiddleware(adminToken string, store *TokenStore) func(http.Handler) http.Handler {
	if adminToken == "" {
		logging.Logf("[apiserver] AUTH_TOKEN not set — token middleware disabled")
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// ── 1. Public paths ────────────────────────────────────────────
			if isPublicPath(r) || isCpanelPluginSelfServicePath(r) {
				next.ServeHTTP(w, r)
				return
			}

			// ── 2. Bearer / X-CFM-Token / Token header ────────────────────
			tok := extractToken(r)
			if tok != "" {
				if tokenMatch(tok, adminToken) {
					logging.Logf("[apiserver] auth_source=admin_token")
					next.ServeHTTP(w, r)
					return
				}
				if st, ok := store.Lookup(tok); ok {
					logging.Logf("[apiserver] auth_source=scoped_token")
					ctx := context.WithValue(r.Context(), webdet.CtxScopeKey{}, st.Vhosts)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// ── 3. Valid goauth session (fallback when no token header) ───
			if sessionAllowed(r) {
				logging.Logf("[apiserver] auth_source=session_cookie")
				next.ServeHTTP(w, r)
				return
			}

			// ── 4. No token — redirect browsers, 401 API clients ──────────
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

func extractToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if t := strings.TrimSpace(r.Header.Get("X-CFM-Token")); t != "" {
		return t
	}
	if t := strings.TrimSpace(r.Header.Get("Token")); t != "" {
		return t
	}
	return ""
}
