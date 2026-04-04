// internal/apiserver/middleware.go
//
// Bearer token middleware for the cfm apiserver.
//
// Auth order per request:
//  1. Public path (/login, /logout, /login/verify) → pass through
//  2. Direct loopback with no real XFF             → bypass (CLI on server)
//  3. Valid goauth session cookie                  → allow
//  4. Authorization: Bearer / X-CFM-Token / Token  → validate admin or scoped token
//  5. Browser request (Accept: text/html)          → redirect to /login
//  6. Everything else                              → 401
//
// When AUTH_TOKEN is empty the middleware is a no-op (backwards compat).

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
func isPublicPath(r *http.Request) bool {
	for _, p := range []string{"/login", "/logout"} {
		if r.URL.Path == p || strings.HasPrefix(r.URL.Path, p+"/") {
			return true
		}
	}
	return false
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
			if isPublicPath(r) {
				next.ServeHTTP(w, r)
				return
			}

			// ── 2. Loopback bypass (CLI, local curl, Laravel same-server) ─
			if isLoopbackDirect(r) {
				next.ServeHTTP(w, r)
				return
			}

			// ── 3. Valid goauth session ────────────────────────────────────
			if sessionAllowed(r) {
				next.ServeHTTP(w, r)
				return
			}

			// ── 4. Bearer / X-CFM-Token / Token header ────────────────────
			tok := extractToken(r)
			if tok != "" {
				if tokenMatch(tok, adminToken) {
					next.ServeHTTP(w, r)
					return
				}
				if st, ok := store.Lookup(tok); ok {
					ctx := context.WithValue(r.Context(), webdet.CtxScopeKey{}, st.Vhosts)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// ── 5. No token — redirect browsers, 401 API clients ──────────
			if strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r,
					"/login?next="+url.QueryEscape(r.URL.RequestURI()),
					http.StatusSeeOther)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="cfm"`)
			http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
		})
	}
}

// isLoopbackDirect returns true when the TCP connection is directly from loopback
// and not proxied (no real X-Forwarded-For set by nginx).
func isLoopbackDirect(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return true
	}
	first := strings.TrimSpace(strings.Split(xff, ",")[0])
	fwdIP := net.ParseIP(first)
	return fwdIP != nil && fwdIP.IsLoopback()
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
