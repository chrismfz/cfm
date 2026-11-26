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
	lp := strings.ToLower(path)
	// "/wp-json…" or "/<dir>/wp-json…": strip at most one leading directory,
	// and only a plausible install directory (wpInstallDir).
	_, rest, ok := wpStripInstall(lp, "/wp-json", true)
	if !ok {
		return "", false
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

// wpStripInstall checks lp (a lowercased path) for a climb or escape and, when
// it does not start with marker, strips one leading install directory
// (wpInstallDir; the index.php PATH_INFO pseudo-directory only when
// allowIndex). It returns the stripped prefix ("" or "/<dir>") and the rest.
// ok=false for a path that is not absolute, climbs out (`..`, `%2e`) or has
// an empty segment (`//`). The ONE copy of these guards: REST and admin-ajax
// both read paths through it.
func wpStripInstall(lp, marker string, allowIndex bool) (prefix, rest string, ok bool) {
	if lp == "" || lp[0] != '/' || strings.Contains(lp, "..") ||
		strings.Contains(lp, "%2e") || strings.Contains(lp, "//") {
		return "", "", false
	}
	if strings.HasPrefix(lp, marker) {
		return "", lp, true
	}
	if i := strings.IndexByte(lp[1:], '/'); i >= 0 {
		seg := lp[1 : 1+i]
		if wpInstallDir(seg) && (allowIndex || seg != "index.php") {
			return lp[:1+i], lp[1+i:], true
		}
	}
	return "", lp, true
}

// wpAjaxAppDenialMaxBytes: the largest admin-ajax 403 body read as the app's
// own answer (WordPress's "-1"/"0", a plugin's wp_send_json_error JSON: 6 and
// 110 bytes in the titan case). An origin WAF's block page is bigger (Apache's
// default 403 is ~200 bytes, LiteSpeed's ~1.2 KB, Wordfence's ~7 KB), and an
// EMPTY 403 there is a WAF's too (see isWPAjaxDenial).
const wpAjaxAppDenialMaxBytes = 128

// isWPAdminAjaxOrigin403 reports whether rec is a 403 the SITE's WordPress
// gave to an admin-ajax.php call made from the same site's wp-admin: the
// Referer is a /wp-admin/ page on rec.Host.
//
// The 403 counters skip these (skip403), as they skip isWPRestOrigin403: an
// open wp-admin tab polls admin-ajax every few seconds, and when the login
// cookie or a plugin's nonce expires WordPress (or the plugin) answers every
// poll with 403 until the tab is reloaded. On 2026-11-17 that nft-banned a
// shop's own admin on titan (Barcode Scanner's background indexing on
// edit.php?post_type=shop_order, 317 origin 403s in a few minutes,
// IP403_COUNT 250), and the ban took their second site with it. The request
// still counts in the IP's total, so it dilutes the 403 share.
//
// Kept narrow:
//   - only the ORIGIN's 403 (as isWPRestOrigin403): the edge's own 403s are
//     the WAF's and keep counting;
//   - only a small non-empty body (wpAjaxAppDenialMaxBytes): WordPress's or
//     a plugin's own answer, never an origin WAF's block page (ModSecurity,
//     Imunify, Wordfence refusing an admin-ajax exploit keep counting);
//   - only admin-ajax.php at the site root or one install directory down
//     (not the index.php PATH_INFO pseudo-directory, which is the front
//     controller);
//   - the Referer must be http(s), name the same host, and sit under the
//     SAME install's /wp-admin/;
//   - not when any action key names a credential (login, password, auth,
//     token, jwt): an AJAX login answered 403 is a wrong password.
//
// Residual: the Referer is the client's to write, so a client that forges a
// wp-admin Referer gets small app-answered admin-ajax 403s past the counters.
// What it gains is nothing the origin let through (each was refused), the WAF
// and the malicious-path counters still see the requests, and WordPress also
// takes action from a POST body, which the log line does not carry.
func isWPAdminAjaxOrigin403(rec LogRec) bool {
	if rec.Status != 403 || !rec.Upstream || rec.Bytes < 1 || rec.Bytes > wpAjaxAppDenialMaxBytes {
		return false
	}
	if rec.UpstreamName != "" && !strings.HasPrefix(rec.UpstreamName, "cfm_apache") {
		return false
	}
	// rec.URI and rec.Ref are lowercased by the parser.
	path, query, _ := strings.Cut(rec.URI, "?")
	prefix, rest, ok := wpStripInstall(path, "/wp-admin/", false)
	if !ok || rest != "/wp-admin/admin-ajax.php" {
		return false
	}
	if wpQueryActionCredential(query) {
		return false
	}
	return wpAdminReferer(rec.Ref, rec.Host, prefix)
}

// wpQueryActionCredential reports whether ANY key PHP could read as action
// names a credential, or fails to decode. The log line is lowercased, so key
// case (which PHP keeps) and order cannot tell which one PHP reads: any of
// them counts. Keys are read as PHP mangles them (leading spaces dropped,
// '.' and ' ' to '_', an "action[…]" array key is action too).
func wpQueryActionCredential(query string) bool {
	if query == "" {
		return false
	}
	mangle := strings.NewReplacer(".", "_", " ", "_")
	for _, kv := range strings.Split(query, "&") {
		k, v, _ := strings.Cut(kv, "=")
		key, err := url.QueryUnescape(k)
		if err != nil {
			key = k
		}
		key = mangle.Replace(strings.TrimLeft(key, " "))
		if key != "action" && !strings.HasPrefix(key, "action[") {
			continue
		}
		a, err := url.QueryUnescape(v)
		if err != nil || wpRestCredentialRoute(strings.ToLower(a)) {
			return true
		}
	}
	return false
}

// wpAdminReferer: ref is an http(s) URL on host (port ignored on both sides)
// whose path is under /wp-admin/ of the install at prefix ("" = the root).
func wpAdminReferer(ref, host, prefix string) bool {
	u, err := url.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return false
	}
	h := strings.ToLower(host)
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	if h == "" || strings.ToLower(u.Hostname()) != h {
		return false
	}
	rp, rest, ok := wpStripInstall(strings.ToLower(u.EscapedPath()), "/wp-admin/", false)
	return ok && rp == prefix && strings.HasPrefix(rest, "/wp-admin/")
}

// skip403 reports whether rec is a 403 the web detector's error counters
// (403_flood, 40x_combo and the per-IP CHALLENGE_RPS_4XX / ERR_RATIO
// challenge counters) do not count: the app's own answer to a client it
// knows (isWPRestOrigin403, isWPAdminAjaxOrigin403), the edge's refusal for
// a traffic rule's block (isRuleBlock403) or for a client the proxied IP
// filter refuses (isProxiedIPFilterBlock403). The ONE such predicate; a new
// counter of client-fault 4xx reads it too.
func skip403(rec LogRec) bool {
	return rec.Status == 403 &&
		(isWPRestOrigin403(rec) || isWPAdminAjaxOrigin403(rec) || isRuleBlock403(rec) || isProxiedIPFilterBlock403(rec))
}
