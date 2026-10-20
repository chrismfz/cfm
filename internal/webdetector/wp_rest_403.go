package webdetector

import (
	"net/url"
	"strings"
)

// isWPRestOrigin403 reports whether rec is a 403 the SITE's WordPress gave
// to a REST API call (/wp-json/… or the root ?rest_route=… form, at the site
// root or one directory down, e.g. a WordPress installed in /wordpress/).
//
// The 403 counters (403_flood and 40x_combo) skip these: WordPress answers a
// REST call the caller may not make with 403 (rest_forbidden), so a working
// client polling one endpoint crosses IP403_COUNT on the origin's own answers.
// Both cases the 2026-10-20 edge-ban read found were that: a WooCommerce stock
// sync whose API key lacks write access (84-89% 403 on /wp-json/wc/v3/…, mars)
// and a logged-in admin on the Site Kit dashboard (/wp-json/google-site-kit/v1/
// every ~5 s, orion). The request still counts in the IP's total, so it
// dilutes the 403 share instead of hiding it.
//
// Kept narrow so it cannot hide an attack:
//   - only the ORIGIN's 403 (rec.Upstream, and a cfm_apache* upstream where
//     the edge names one). The edge's own 403s on REST paths are the WAF
//     stopping scanners (Gravity SMTP mock-data, /wp-json/batch/v1, …: 99.7%
//     of speedhost's REST 403s, 10 IPs over the threshold in three days) and
//     keep counting. A line without upstream info (the Apache origin log)
//     counts too;
//   - not a route that takes credentials (token, login, auth, jwt, password):
//     JWT Auth answers a wrong password with 403, and rule 501 does not see
//     REST logins, so a brute force there must still reach 403_flood;
//   - the marker has to sit in the first or second path segment, behind an
//     install directory with no dot or escape in it; a path that climbs out
//     (`..`, `%2e`, `//`) or carries any escape after the marker never
//     matches, and rest_route counts only on the root page or a /wp-json
//     path, never on an arbitrary path such as /.env?rest_route=;
//   - a query rest_route is read as PHP and WordPress read it: it overrides
//     the /wp-json path, the last duplicate wins and "rest.route" is the
//     same key, so every such key must be clean (wpQueryRestRoute).
//
// Residual: WordPress also takes rest_route from a POST body, which the log
// line does not carry, so a POST to /wp-json/<plain route> whose body names a
// credential route is exempt. Rule 501 does not cover REST logins either.
func isWPRestOrigin403(rec LogRec) bool {
	if rec.Status != 403 || !rec.Upstream {
		return false
	}
	if rec.UpstreamName != "" && !strings.HasPrefix(rec.UpstreamName, "cfm_apache") {
		return false
	}
	route, ok := wpRestRoute(rec.URI)
	return ok && !wpRestCredentialRoute(route)
}

// wpRestRoute returns the REST route uri addresses ("/wc/v3/products/1"), or
// ok=false when uri is not a WordPress REST call (see isWPRestOrigin403).
func wpRestRoute(uri string) (string, bool) {
	path, query, _ := strings.Cut(uri, "?")
	if path == "" || path[0] != '/' {
		return "", false
	}
	lp := strings.ToLower(path)
	if strings.Contains(lp, "..") || strings.Contains(lp, "%2e") || strings.Contains(lp, "//") {
		return "", false
	}
	// "/wp-json…" or "/<dir>/wp-json…": strip at most one leading directory,
	// and only a plausible install directory (wpInstallDir).
	rest := lp
	if !strings.HasPrefix(rest, "/wp-json") {
		if i := strings.IndexByte(rest[1:], '/'); i >= 0 && wpInstallDir(rest[1:1+i]) {
			rest = rest[1+i:]
		}
	}
	// A rest_route in the query overrides the path route in WordPress
	// (WP::parse_request takes $_GET before the permalink's query vars), so the
	// query decides whenever it carries one.
	qroute, qok, qfound := wpQueryRestRoute(query)
	if qfound {
		if !qok {
			return "", false
		}
		if rest == "/wp-json" || strings.HasPrefix(rest, "/wp-json/") || isWPRootPage(lp) {
			return qroute, true
		}
		return "", false
	}
	if rest == "/wp-json" || strings.HasPrefix(rest, "/wp-json/") {
		route := strings.TrimPrefix(rest, "/wp-json")
		if strings.Contains(route, "%") {
			return "", false // an escaped route could spell a credential one
		}
		return route, true
	}
	return "", false
}

// wpQueryRestRoute reads the rest_route PHP would see in query: the LAST
// parameter whose key PHP maps to "rest_route" ('.' and ' ' become '_', the
// key url-decoded first). found reports any such key; ok=false when any of
// them fails to decode, climbs out ("..") or names a credential route, so
// no ordering trick (?rest_route=/wc/v3/x&rest.route=/jwt-auth/v1/token)
// passes a login off as a harmless call.
func wpQueryRestRoute(query string) (route string, ok, found bool) {
	if query == "" {
		return "", false, false
	}
	ok = true
	for _, kv := range strings.Split(query, "&") {
		k, v, _ := strings.Cut(kv, "=")
		key, err := url.QueryUnescape(k)
		if err != nil {
			key = k
		}
		key = strings.NewReplacer(".", "_", " ", "_").Replace(key)
		if !strings.EqualFold(key, "rest_route") {
			continue
		}
		found = true
		r, err := url.QueryUnescape(v)
		r = strings.ToLower(r)
		if err != nil || strings.Contains(r, "..") || wpRestCredentialRoute(r) {
			ok = false
		}
		route = r
	}
	return route, ok, found
}

// wpRestCredentialRoute: a route that takes a credential (JWT / application
// password / plugin login endpoints). Its 403s are a wrong password.
func wpRestCredentialRoute(route string) bool {
	for _, w := range []string{"token", "login", "auth", "jwt", "passw"} {
		if strings.Contains(route, w) {
			return true
		}
	}
	return false
}

// isWPRootPage: "/", "/index.php", "/<dir>/" or "/<dir>/index.php".
func isWPRootPage(lp string) bool {
	lp = strings.TrimSuffix(lp, "index.php")
	if lp == "/" {
		return true
	}
	if !strings.HasSuffix(lp, "/") || strings.Count(lp, "/") != 2 {
		return false
	}
	return wpInstallDir(lp[1 : len(lp)-1])
}

// wpInstallDir: a directory WordPress can be installed in, or index.php
// (PATH_INFO: /index.php/wp-json/…). No dot or escape in it, so a forbidden
// path (/.git/wp-json/…, /backup.zip/?rest_route=) never passes as REST.
func wpInstallDir(seg string) bool {
	if seg == "index.php" {
		return true
	}
	return seg != "" && !strings.ContainsAny(seg, ".%")
}
