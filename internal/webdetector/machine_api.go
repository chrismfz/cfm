package webdetector

import "strings"

// isWooAdminAPIPath reports whether p (a request path, query already
// stripped) is a call to WooCommerce's authenticated REST API: /wp-json/wc/v1,
// v2 or v3, or the legacy /wc-api/v1-v3, at the site root or one install
// directory down (/shop/wp-json/wc/v3/…).
//
// The per-IP challenge triggers (CHALLENGE_UNIQPATHS_IP, CHALLENGE_ERR_RATIO,
// CHALLENGE_RPS_TOTAL, CHALLENGE_RPS_4XX/5XX, CHALLENGE_POST_RATIO) leave these
// requests out: they count toward no rate, ratio or path set, and leave the
// IP's total for those triggers (the IP's other requests decide alone). Their
// callers are server-to-server clients (ERP, stock and price sync, marketplace
// connectors) that cannot solve a challenge: on 2026-11-17 a product sync to
// kiamaia.gr (mars) POSTed ~13 requests a second to a new
// /wp-json/wc/v3/products/<id>/variations/<id> each, part of them answered 404
// by WooCommerce. CHALLENGE_ERR_RATIO and then CHALLENGE_UNIQPATHS_IP put the
// IP under a challenge, the challenge page answered its redirected requests
// with 403, and 403_flood banned it every 30 s for as long as the sync ran.
//
// Kept narrow, because it relaxes enforcement:
//   - only the authenticated API. The Store API (/wp-json/wc/store/…: cart and
//     checkout, no credentials) is what card-testing bots hit, so it keeps
//     every per-IP challenge, as does any other /wp-json route;
//   - the marker has to be the first or second path segment, behind a plain
//     install directory, and a path with "..", "%2e", "//" or any other escape
//     never matches (wpStripInstall, wpRestRoute), so a token placed mid-path
//     (/wp-login.php/wp-json/wc/v3/) does not exempt a request;
//   - a route that takes a credential (token, login, auth, jwt, password)
//     never matches;
//   - it only stops these requests from COUNTING toward a per-IP challenge.
//     It lifts no challenge or block already on the IP, and the WAF, the
//     403 / 404 / 40x_combo counters, agent_flood and the IP's requests to
//     any other path are unchanged.
func isWooAdminAPIPath(p string) bool {
	lp := strings.ToLower(p)
	if strings.ContainsRune(lp, '?') {
		return false
	}
	if route, ok := wpRestRoute(lp); ok {
		return wooVersionedRoute(route, "/wc/") && !wpRestCredentialRoute(route)
	}
	_, rest, ok := wpStripInstall(lp, "/wc-api/", true)
	if !ok || strings.Contains(rest, "%") || !strings.HasPrefix(rest, "/wc-api/") {
		return false
	}
	route := strings.TrimPrefix(rest, "/wc-api")
	return wooVersionedRoute("/wc"+route, "/wc/") && !wpRestCredentialRoute(route)
}

// wooVersionedRoute: route is <base>v1, v2 or v3, alone or followed by "/".
func wooVersionedRoute(route, base string) bool {
	if !strings.HasPrefix(route, base) {
		return false
	}
	rest := route[len(base):]
	for _, v := range []string{"v1", "v2", "v3"} {
		if rest == v || strings.HasPrefix(rest, v+"/") {
			return true
		}
	}
	return false
}
