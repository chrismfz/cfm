package apiserver

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"cfm/internal/logging"
)

var (
	errInvalidCSRFSource = errors.New("invalid csrf source")
	csrfUnsafeMethods    = map[string]struct{}{
		http.MethodPost:   {},
		http.MethodPut:    {},
		http.MethodPatch:  {},
		http.MethodDelete: {},
	}
)

// CSRFMiddleware enforces Origin/Referer checks for unsafe methods when
// authentication happened through a browser cookie — the admin session
// cookie AND the scoped embed-bootstrap cookie.
//
// Notes:
//   - Bearer token auth (admin/scoped) is exempt: an Authorization header
//     cannot be attached by a cross-site form, so it is not an ambient
//     credential.
//   - The scoped EMBED cookie is deliberately SameSite=None (the cPanel
//     iframe needs it cross-site), which makes it an ambient credential a
//     hostile page can ride: the arm/exclude endpoints accept query-param
//     POSTs, so without this check a cross-site form could disarm a
//     customer's challenge with the customer's own browser (slice-D
//     security review I2). The iframe's own XHRs are same-origin to the
//     daemon and pass the Origin/Referer validation unchanged.
//   - The admin SSO cookie (cfm-embed-admin) is an ambient browser
//     credential like the session cookie, so it is checked the same way.
//   - Public auth routes (for example POST /login) are naturally exempt because
//     TokenMiddleware treats them as public and does not mark session authn.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !csrfRequiresCheck(r) {
			next.ServeHTTP(w, r)
			return
		}
		if ok, reason := validateCSRFSameOrigin(r); !ok {
			logging.LogfAPI("[apiserver] event=csrf_reject path=%q method=%s src_ip=%s reason=%s",
				r.URL.Path, r.Method, realIPFromRequest(r), reason)
			setAPIAnomalyReason(w, r, "csrf_reject")
			publishRequestAnomaly(r, "CSRF_REJECT", http.StatusForbidden)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func csrfRequiresCheck(r *http.Request) bool {
	if r == nil {
		return false
	}
	if _, ok := csrfUnsafeMethods[r.Method]; !ok {
		return false
	}
	mech := authnMechanismFromContext(r.Context())
	return mech == authnMechanismSession || mech == authnMechanismEmbedCookie ||
		mech == authnMechanismEmbedAdminCookie
}

func validateCSRFSameOrigin(r *http.Request) (bool, string) {
	allowed := csrfAllowedHosts(r)
	if len(allowed) == 0 {
		return false, "host_unavailable"
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		host, port, err := hostPortFromURL(origin)
		if err != nil {
			return false, "origin_invalid"
		}
		if allowed.match(host, port) {
			return true, ""
		}
		return false, "origin_mismatch"
	}
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" {
		return false, "origin_missing"
	}
	host, port, err := hostPortFromURL(ref)
	if err != nil {
		return false, "referer_invalid"
	}
	if allowed.match(host, port) {
		return true, ""
	}
	return false, "referer_mismatch"
}

// csrfHosts maps each host a same-origin request may name to the explicit,
// non-default ports it arrived on.
type csrfHosts map[string]map[string]struct{}

// match reports whether a source origin (host, port; "" = default port) is
// this request's own. A source with a default port matches on the host alone,
// as it always has (a proxy in front may send Host with the daemon's port).
// A source with an explicit other port must have arrived on that port: the
// other services on the same host (the panel ports, webmail) are other
// origins.
func (c csrfHosts) match(host, port string) bool {
	ports, ok := c[host]
	if !ok {
		return false
	}
	if port == "" {
		return true
	}
	_, ok = ports[port]
	return ok
}

func (c csrfHosts) add(hostport string) {
	host, port := splitCanonicalHostPort(hostport)
	if host == "" {
		return
	}
	if c[host] == nil {
		c[host] = map[string]struct{}{}
	}
	if port != "" {
		c[host][port] = struct{}{}
	}
}

// csrfAllowedHosts collects the request's own host[:port] values: Host, and
// the browser's own Host (port included) the edge passes as X-Forwarded-Host
// from loopback; the edge's Host carries no port.
func csrfAllowedHosts(r *http.Request) csrfHosts {
	out := csrfHosts{}
	if r == nil {
		return out
	}
	out.add(r.Host)
	out.add(trustedForwardedHost(r))
	return out
}

// splitCanonicalHostPort lowercases host[:port] and drops a default port
// (80/443), which browsers leave out of Origin and Host alike.
func splitCanonicalHostPort(hostport string) (string, string) {
	hostport = strings.ToLower(strings.TrimSpace(hostport))
	if hostport == "" {
		return "", ""
	}
	host, port := hostport, ""
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	}
	host = strings.Trim(host, "[]")
	if port == "80" || port == "443" {
		port = ""
	}
	return host, port
}

func hostPortFromURL(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	if u.Host == "" {
		return "", "", errInvalidCSRFSource
	}
	host, port := splitCanonicalHostPort(u.Host)
	return host, port, nil
}

func trustedForwardedHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ""
	}
	xfh := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if xfh == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(xfh, ",")[0])
}

func hostOnly(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if strings.HasPrefix(hostport, "[") {
		h, _, err := net.SplitHostPort(hostport)
		if err == nil {
			return strings.Trim(strings.TrimSpace(h), "[]")
		}
		return strings.Trim(strings.TrimSpace(hostport), "[]")
	}
	if strings.Count(hostport, ":") == 0 {
		return hostport
	}
	h, _, err := net.SplitHostPort(hostport)
	if err == nil {
		return h
	}
	if strings.Count(hostport, ":") > 1 {
		return hostport
	}
	return hostport
}
