// internal/apiserver/middleware.go
//
// Bearer token middleware for the cfm apiserver.
//
// Auth rules (in order):
//  1. Direct loopback connection with no X-Forwarded-For → bypass (CLI on server)
//  2. Authorization: Bearer <adminToken>               → allow, no scope restriction
//  3. Authorization: Bearer <scopedToken>              → allow, inject vhost scope into ctx
//  4. Anything else                                    → 401
//
// When AUTH_TOKEN is empty in cfm.conf the middleware is a no-op so existing
// installs keep working before they set the token.
//
// realIP logic (mirrors goauth pattern):
//   Trust X-Forwarded-For ONLY when the direct TCP connection is from loopback.
//   External clients connecting directly cannot inject XFF.
//   nginx/OpenResty proxy → loopback RemoteAddr + real client in XFF → must auth.

package apiserver

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	webdet "cfm/internal/webdetector"
	"cfm/internal/logging"
)

// TokenMiddleware returns an http.Handler middleware that enforces bearer token auth.
// If adminToken is empty the middleware is disabled (all requests pass) — backwards compat.
func TokenMiddleware(adminToken string, store *TokenStore) func(http.Handler) http.Handler {
	if adminToken == "" {
		logging.Logf("[apiserver] AUTH_TOKEN not set — token middleware disabled (set AUTH_TOKEN to enable)")
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// ── 1. Loopback bypass (CLI, local curl, etc.) ────────────────
			if isLoopbackDirect(r) {
				next.ServeHTTP(w, r)
				return
			}

			// ── 2. Extract token from any accepted header ─────────────────
			// Accepted (in priority order):
			//   Authorization: Bearer <token>   — standard, used by Vue / goauth
			//   X-CFM-Token: <token>            — explicit cfm header
			//   Token: <token>                  — used by api_client.go / Laravel
			tok := extractToken(r)
			if tok == "" {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", `Bearer realm="cfm"`)
				http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
				return
			}

			// ── 3. Admin token (constant-time compare) ────────────────────
			if tokenMatch(tok, adminToken) {
				next.ServeHTTP(w, r)
				return
			}

			// ── 4. Scoped token ───────────────────────────────────────────
			if st, ok := store.Lookup(tok); ok {
				// Inject vhost scope into context so parseVhostFilter picks it up.
				// nil vhosts on a scoped token means viewer with no domain restriction
				// (shouldn't happen via issuance, but handle gracefully).
				ctx := context.WithValue(r.Context(), webdet.CtxScopeKey{}, st.Vhosts)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// ── 5. Unknown / expired token ────────────────────────────────
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
		})
	}
}

// isLoopbackDirect returns true when the TCP connection comes directly from
// loopback AND is not being proxied (no X-Forwarded-For header, or XFF itself
// is loopback). This is the safe bypass for CLI tools running on the server.
//
// nginx proxy case: RemoteAddr=127.0.0.1 but XFF=<real-client-IP> → returns false → must auth.
func isLoopbackDirect(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false // not from loopback at all
	}
	// From loopback — check if proxied
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return true // direct loopback, no proxy → CLI bypass
	}
	// Has XFF — check if XFF itself is also loopback (curl through a local proxy)
	first := strings.TrimSpace(strings.Split(xff, ",")[0])
	fwdIP := net.ParseIP(first)
	return fwdIP != nil && fwdIP.IsLoopback()
}

// tokenMatch performs a constant-time string comparison to prevent timing attacks.
func tokenMatch(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// extractToken pulls the bearer token from any of the three accepted headers.
// Priority: Authorization: Bearer > X-CFM-Token > Token
// Returns empty string if none found.
func extractToken(r *http.Request) string {
	// Authorization: Bearer <token>
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	// X-CFM-Token: <token>
	if t := strings.TrimSpace(r.Header.Get("X-CFM-Token")); t != "" {
		return t
	}
	// Token: <token>  (used by api_client.go and Laravel)
	if t := strings.TrimSpace(r.Header.Get("Token")); t != "" {
		return t
	}
	return ""
}
