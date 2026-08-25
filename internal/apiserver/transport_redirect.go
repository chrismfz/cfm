package apiserver

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"cfm/internal/logging"
)

// AdminTransportRedirect upgrades direct external plaintext :6060 browser admin
// traffic to the HTTPS :6061 listener (audit R01 / Step 5). See
// docs/security/direct-6060-transport-policy.md.
//
// It runs PRE-AUTH (outside TokenMiddleware) so a doomed request is redirected or
// rejected before any credential is processed. It acts ONLY on a request that
// arrived on the :6060 HTTP listener from a non-loopback peer
// (requestPeer.Entry == "6060") targeting a browser admin route. Everything else
// passes through untouched:
//
//   - the edge backend hop (Entry == "edge", already effective-https);
//   - the :6061 TLS listener (Entry == "6061");
//   - the loopback CLI / local curl (loopback peer — plaintext never hits the wire);
//   - machine /api/v1 traffic (no Accept: text/html — design §6a leaves it as-is).
//
// With the default loopback-bound :6060 (LISTEN_ADDRESS=127.0.0.1) there is no
// external plaintext at all, so this middleware is a safety net that only fires
// if an operator re-exposes :6060 on a public address.
//
// tlsReady must report true only once the :6061 listener has actually bound
// (config alone is not enough — audit Step 5).
func AdminTransportRedirect(next http.Handler, tlsPort int, tlsReady func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := requestPeer(r)

		// Candidates are only direct requests on the :6060 HTTP listener.
		if peer.Entry != "6060" {
			next.ServeHTTP(w, r)
			return
		}
		// Loopback plaintext never touches the wire (local CLI/curl). Exempt.
		if peer.ImmediateIP != nil && peer.ImmediateIP.IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}
		// Scope to browser admin traffic; machine/API/CLI passes through.
		if !isBrowserAdminRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		host := hostOnly(r.Host)

		// TLS not (yet) usable, port invalid, or no usable Host to build a target →
		// explicit degraded HTTP fallback, logged. (Challenge-gating of this state
		// is deferred to Step 4 — see the design doc.)
		if !tlsReady() || !validTLSPort(tlsPort) || host == "" {
			logging.LogfAPI("[apiserver] event=admin_http_fallback src_ip=%s method=%s path=%q reason=%s",
				realIPFromRequest(r), r.Method, r.URL.Path, tlsFallbackReason(tlsReady(), tlsPort, host))
			next.ServeHTTP(w, r)
			return
		}

		// TLS ready: upgrade safe browser navigation; refuse unsafe methods.
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			target := "https://" + net.JoinHostPort(host, strconv.Itoa(tlsPort)) + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusFound)
		default:
			// A state-changing request arrived over plaintext. Do NOT process it
			// (no HTTP session/credential handling) and do NOT auto-redirect it (a
			// method-preserving redirect would re-send the already-leaked body).
			// Refuse so the operator re-submits from an HTTPS page.
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"HTTPS required for admin writes — use the TLS port :`+strconv.Itoa(tlsPort)+`"}`, http.StatusForbidden)
		}
	})
}

// isBrowserAdminRequest reports whether r looks like browser admin navigation:
// a /cfm-admin/* path, or any request whose Accept advertises text/html. The
// CLI and machine API clients hit /api/v1 or /debug and send no text/html, so
// they are excluded.
func isBrowserAdminRequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/cfm-admin") {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func validTLSPort(p int) bool { return p > 0 && p <= 65535 }

func tlsFallbackReason(ready bool, port int, host string) string {
	switch {
	case !validTLSPort(port):
		return "tls_port_invalid"
	case host == "":
		return "no_host"
	case !ready:
		return "tls_not_ready"
	default:
		return "unknown"
	}
}
