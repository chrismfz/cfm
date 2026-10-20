package webdetector

import "strings"

// isWPRestAPIRequest reports whether uri ($request_uri, query included) is a
// WordPress REST API call: /wp-json/… or the root ?rest_route=… form, at the
// site root or one directory down (a WordPress installed in /wordpress/).
//
// The 403 counters (403_flood and 40x_combo) skip these: WordPress answers a
// REST call the caller may not make with 403 (rest_forbidden), so a working
// client polling one endpoint crosses IP403_COUNT on the origin's own answers.
// Both cases the 2026-10-20 edge-ban read found were that: a WooCommerce stock
// sync whose API key lacks write access (84-89% 403 on /wp-json/wc/v3/…, mars)
// and a logged-in admin on the Site Kit dashboard (/wp-json/google-site-kit/v1/
// every ~5 s, orion). Excluding them dropped none of the day's 193 403_flood
// IPs on mars, orion, titan and speedhost. The request still counts in the
// IP's total, so it dilutes the 403 share instead of hiding it.
//
// Kept narrow so it cannot be used to hide a probe: the marker has to sit in
// the first or second path segment, a path that climbs out of it (`..`,
// `%2e`, `//`) never matches, and rest_route counts only on the root page
// (`/`, `/index.php`), never on an arbitrary path such as /.env?rest_route=.
func isWPRestAPIRequest(uri string) bool {
	path, query, _ := strings.Cut(uri, "?")
	if path == "" || path[0] != '/' {
		return false
	}
	lp := strings.ToLower(path)
	if strings.Contains(lp, "..") || strings.Contains(lp, "%2e") || strings.Contains(lp, "//") {
		return false
	}
	// "/wp-json…" or "/<dir>/wp-json…": strip at most one leading directory,
	// and only a plausible install directory (wpInstallDir).
	rest := lp
	if !strings.HasPrefix(rest, "/wp-json") {
		if i := strings.IndexByte(rest[1:], '/'); i >= 0 && wpInstallDir(rest[1:1+i]) {
			rest = rest[1+i:]
		}
	}
	if rest == "/wp-json" || strings.HasPrefix(rest, "/wp-json/") {
		return true
	}
	if query == "" {
		return false
	}
	if !isWPRootPage(lp) {
		return false
	}
	for _, kv := range strings.Split(query, "&") {
		if k, _, _ := strings.Cut(kv, "="); strings.EqualFold(k, "rest_route") {
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
