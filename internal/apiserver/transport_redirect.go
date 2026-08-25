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

		// A state-changing request arrived over direct plaintext. Never process it
		// (no session/credential handling over cleartext) and never auto-redirect it
		// (a method-preserving redirect would re-send the already-leaked body). Refuse
		// UNCONDITIONALLY — independent of TLS state and of Host — so the invariant
		// "plaintext admin writes are never processed" holds even in the degraded
		// window and for a crafted empty-Host request. Only GET/HEAD can be safely
		// upgraded (TLS ready) or degraded-served (TLS down).
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeHTTPSRequired(w, tlsPort)
			return
		}

		host := hostOnly(r.Host)

		// TLS not (yet) usable, port invalid, or no usable Host to build a target →
		// explicit degraded HTTP fallback for safe GET/HEAD navigation, logged. Writes
		// were already refused above, so this window is read-only. (Challenge-gating of
		// this read-only window is deferred to Step 4 — see the design doc.)
		if !tlsReady() || !validTLSPort(tlsPort) || host == "" {
			logging.LogfAPI("[apiserver] event=admin_http_fallback src_ip=%s method=%s path=%q reason=%s",
				realIPFromRequest(r), r.Method, r.URL.Path, tlsFallbackReason(tlsReady(), tlsPort, host))
			next.ServeHTTP(w, r)
			return
		}

		// TLS ready: upgrade safe browser navigation to the TLS port.
		target := "https://" + net.JoinHostPort(host, strconv.Itoa(tlsPort)) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusFound)
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

// writeHTTPSRequired refuses a state-changing plaintext admin request with 403 and
// a JSON body (kept application/json — http.Error would rewrite it to text/plain).
// It points at the TLS port when that port is valid; otherwise it stays generic
// (the operator has exposed :6060 with no usable TLS port — a misconfiguration, so
// naming ":0" would be worse than useless).
func writeHTTPSRequired(w http.ResponseWriter, tlsPort int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	body := `{"error":"HTTPS required for admin writes"}`
	if validTLSPort(tlsPort) {
		body = `{"error":"HTTPS required for admin writes — use the TLS port :` + strconv.Itoa(tlsPort) + `"}`
	}
	_, _ = w.Write([]byte(body))
}

// HTTPBindAddr resolves the plaintext :6060 bind address, applying R01's secure
// default: an unset LISTEN_ADDRESS binds loopback (127.0.0.1), never the wildcard
// — the plaintext control plane must not reach the Internet unless the operator
// opts in explicitly. An explicit "0.0.0.0"/"::" is returned unchanged: that is
// the deliberate opt-in escape hatch (then upgraded per-request by
// AdminTransportRedirect), so we must NOT silently fold it to loopback here.
// Exported so the daemon's startup log reports the real bind, not the raw config.
func HTTPBindAddr(listenAddr string) string {
	if strings.TrimSpace(listenAddr) == "" {
		return "127.0.0.1"
	}
	return listenAddr
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
