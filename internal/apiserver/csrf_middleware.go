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
// authentication happened through a browser session cookie.
//
// Notes:
//   - Bearer/scoped/embed-cookie auth is exempt (token-backed requests).
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
	return authnMechanismFromContext(r.Context()) == authnMechanismSession
}

func validateCSRFSameOrigin(r *http.Request) (bool, string) {
	allowed := csrfAllowedHosts(r)
	if len(allowed) == 0 {
		return false, "host_unavailable"
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		host, err := hostFromURL(origin)
		if err != nil {
			return false, "origin_invalid"
		}
		if _, ok := allowed[strings.ToLower(host)]; ok {
			return true, ""
		}
		return false, "origin_mismatch"
	}
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" {
		return false, "origin_missing"
	}
	host, err := hostFromURL(ref)
	if err != nil {
		return false, "referer_invalid"
	}
	if _, ok := allowed[strings.ToLower(host)]; ok {
		return true, ""
	}
	return false, "referer_mismatch"
}

func csrfAllowedHosts(r *http.Request) map[string]struct{} {
	out := map[string]struct{}{}
	if r == nil {
		return out
	}
	if h := strings.ToLower(hostOnly(r.Host)); h != "" {
		out[h] = struct{}{}
	}
	if h := strings.ToLower(hostOnly(trustedForwardedHost(r))); h != "" {
		out[h] = struct{}{}
	}
	return out
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

func hostFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", errInvalidCSRFSource
	}
	return hostOnly(u.Host), nil
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
