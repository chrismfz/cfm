package apiserver

import "net/http"

// SecurityHeadersMiddleware sets the control-plane's baseline browser-safety
// response headers on every response, so the direct listeners (:6060 HTTP and
// :6061 TLS) enforce the same policy as the OpenResty/Angie edge instead of
// depending on edge-only headers (audit R10). The direct control plane must carry
// its own security model — a request that reaches :6061 straight from the Internet
// never passes through the edge, so headers that only the edge added were absent
// (R10 saw login responses with no X-Content-Type-Options / Referrer-Policy).
//
// It sets ONLY headers that are safe on every response — static assets, API JSON,
// redirects, and auth failures alike:
//
//   - X-Content-Type-Options: nosniff — http.Error already emits this on the API
//     JSON errors, but handler-rendered HTML (e.g. /login) did not; setting it here
//     covers every path uniformly.
//   - Referrer-Policy: strict-origin-when-cross-origin — the modern browser default
//     (so it changes no behaviour) made explicit. Deliberately NOT no-referrer:
//     CSRFMiddleware falls back to the Referer header when Origin is absent
//     (csrf_middleware.go), and no-referrer would strip the same-origin Referer.
//
// It deliberately sets NO frame or CSP directive and NO HSTS:
//
//   - Frame policy (X-Frame-Options / CSP frame-ancestors) must allow CFM's admin
//     UI to be embedded in the cPanel iframe (CLAUDE.md §6), whose origin is
//     per-install and derived from panel-auth config — a blanket DENY/SAMEORIGIN
//     would break that integration, so it is left to a separate, config-aware change.
//   - HSTS is host-wide (it ignores the port), so an HSTS emitted on :6061 would
//     force the browser to HTTPS for the whole host — including the plaintext :6060
//     that remains a supported/degraded admin surface (audit R01 / Step 5). Adding
//     it is a deliberate decision for once :6060's transport end-state is settled.
//
// See docs/security/control-plane-headers.md.
//
// Values are set only when absent, so a specific handler may still choose a
// stricter policy for its own response.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if h.Get("X-Content-Type-Options") == "" {
			h.Set("X-Content-Type-Options", "nosniff")
		}
		if h.Get("Referrer-Policy") == "" {
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		}
		next.ServeHTTP(w, r)
	})
}
