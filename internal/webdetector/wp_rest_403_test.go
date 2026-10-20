package webdetector

import (
	"testing"
	"time"
)

func TestWPRestRoute(t *testing.T) {
	yes := []string{
		"/wp-json/wc/v3/products/14832/variations/14836?consumer_key=x&consumer_secret=y",
		"/wp-json/google-site-kit/v1/?_locale=user",
		"/wordpress/wp-json/google-site-kit/v1/?_locale=user",
		"/wp-json",
		"/wp-json/",
		"/WP-JSON/wp/v2/posts",
		"/?rest_route=/wp/v2/users",
		"/index.php?rest_route=%2Fwc%2Fv3%2Forders",
		"/blog/?foo=1&rest_route=/wp/v2/posts",
		"/blog/index.php?rest_route=/wp/v2/posts",
		"/index.php/wp-json/wp/v2/posts",
	}
	no := []string{
		"",
		"-",
		"/wp-login.php",
		"/wp-jsonx/",
		"/a/b/wp-json/wc/v3/products",       // too deep: not a WordPress root
		"/wp-json/../.env",                  // climbs out
		"/wp-json/%2e%2e/wp-config.php",     // encoded climb
		"/x//wp-json/",                      // empty segment
		"/.env?rest_route=/wp/v2/users",     // rest_route on a non-root path
		"/wp-admin/admin.php?rest_route=/x", // not the root page
		"/?not_rest_route=/x",
		"/?rest_routes=/x",
		"wp-json/",
		"/.git/wp-json/x", // a dot directory is not an install dir
		"/backup.zip/wp-json/x",
		"/%2egit/wp-json/x",
		"/.git/?rest_route=/x",
		"/wp-config.php.bak/?rest_route=/x",
	}
	for _, u := range yes {
		if _, ok := wpRestRoute(u); !ok {
			t.Errorf("wpRestRoute(%q) ok=false, want true", u)
		}
	}
	for _, u := range no {
		if _, ok := wpRestRoute(u); ok {
			t.Errorf("wpRestRoute(%q) ok=true, want false", u)
		}
	}
}

func TestIsWPRestOrigin403(t *testing.T) {
	origin := func(uri string) LogRec {
		return LogRec{URI: uri, Status: 403, Upstream: true, UpstreamName: "cfm_apache"}
	}
	if !isWPRestOrigin403(origin("/wp-json/wc/v3/products/1?consumer_key=ck&consumer_secret=cs")) {
		t.Fatal("a REST call with a non-route query must stay exempt")
	}
	if !isWPRestOrigin403(origin("/wp-json/x?rest_route=/wc/v3/orders")) {
		t.Fatal("query rest_route to a plain route on /wp-json: exempt")
	}
	if !isWPRestOrigin403(origin("/wp-json/wc/v3/products/1")) {
		t.Fatal("origin 403 on a REST route must be exempt")
	}
	if !isWPRestOrigin403(LogRec{URI: "/wp-json/wc/v3/products/1", Status: 403, Upstream: true}) {
		t.Fatal("an edge on the 12-column module names no upstream: still the origin")
	}
	for name, rec := range map[string]LogRec{
		"edge 403 (WAF)":           {URI: "/wp-json/gravitysmtp/v1/tests/mock-data", Status: 403},
		"challenge server 403":     {URI: "/wp-json/wc/v3/products/1", Status: 403, Upstream: true, UpstreamName: "cfm_challenge"},
		"404":                      {URI: "/wp-json/wc/v3/products/1", Status: 404, Upstream: true, UpstreamName: "cfm_apache"},
		"jwt token":                origin("/wp-json/jwt-auth/v1/token"),
		"login route":              origin("/wp-json/simple-jwt-login/v1/auth"),
		"rest_route jwt":           origin("/?rest_route=%2Fjwt-auth%2Fv1%2Ftoken"),
		"escaped credential":       origin("/wp-json/jwt-a%75th/v1/token"),
		"escaped rest_route":       origin("/?rest_route=/jwt-a%75th/v1/t%6fken"),
		"rest_route bad escape":    origin("/?rest_route=%zz"),
		"rest_route climbs out":    origin("/?rest_route=/../../.env"),
		"password reset route":     origin("/wp-json/wp/v2/users/lostpassword"),
		"duplicate key, last wins": origin("/?rest_route=/wc/v3/x&rest_route=/jwt-auth/v1/token"),
		"php key mangling (dot)":   origin("/?rest_route=/wc/v3/x&rest.route=/jwt-auth/v1/token"),
		"php key mangling (space)": origin("/?rest_route=/wc/v3/x&rest+route=/jwt-auth/v1/token"),
		"encoded key":              origin("/?rest_route=/wc/v3/x&rest%5Froute=/jwt-auth/v1/token"),
		"query overrides wp-json":  origin("/wp-json/wc/v3/products/1?rest_route=/jwt-auth/v1/token"),
		"rest_route on deep path":  origin("/shop/cart/?rest_route=/wc/v3/x"),
	} {
		if isWPRestOrigin403(rec) {
			t.Errorf("%s: %+v must not be exempt", name, rec)
		}
	}
}

func ipHasReasonPrefix(rows []IPSignals, ip, prefix string) bool {
	for _, r := range rows {
		if r.IP != ip {
			continue
		}
		for _, reason := range r.Reasons {
			if len(reason) >= len(prefix) && reason[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// The two false positives of the 2026-10-20 edge-ban read: an API client
// whose WooCommerce key lacks write access (most of its POSTs answered 403 by
// WordPress), and a logged-in admin whose Site Kit dashboard polls a REST
// route the origin 403s, next to admin-ajax 200s. Neither may reach
// 403_flood or 40x_combo; before this change both did.
func TestIP403Flood_WPRestAPIIgnored(t *testing.T) {
	e := NewEngine(Config{
		Every:                 1 * time.Second,
		Window:                2 * time.Minute,
		IP403Count:            5,
		IP40xComboCount:       5,
		IP40xComboUniquePaths: 3,
	})
	now := float64(time.Now().Unix())
	for i := 0; i < 20; i++ {
		e.ingest(LogRec{
			TS: now + float64(i), IP: "10.0.1.1", Host: "shop.example", Method: "post",
			URI:    "/wp-json/wc/v3/products/" + itoa(100+i) + "/variations/" + itoa(200+i) + "?consumer_key=ck&consumer_secret=cs",
			Status: 403, UA: "WooCommerce API Client-PHP/3.1.0", Upstream: true, UpstreamName: "cfm_apache",
		}, "raw")
	}
	for i := 0; i < 20; i++ {
		e.ingest(LogRec{
			TS: now + float64(i), IP: "10.0.1.2", Host: "news.example", Method: "get",
			URI: "/wordpress/wp-json/google-site-kit/v1/?_locale=user", Status: 403, UA: "Mozilla/5.0",
			Upstream: true, UpstreamName: "cfm_apache",
		}, "raw")
		e.ingest(LogRec{
			TS: now + float64(i), IP: "10.0.1.2", Host: "news.example", Method: "get",
			URI: "/wordpress/wp-admin/admin-ajax.php?action=rest-nonce", Status: 200, UA: "Mozilla/5.0",
		}, "raw")
	}
	rows := e.IPShort(0)
	for _, ip := range []string{"10.0.1.1", "10.0.1.2"} {
		if ipHasReasonPrefix(rows, ip, "403_flood") || ipHasReasonPrefix(rows, ip, "40x_combo") {
			t.Fatalf("%s: REST 403s must not count toward 403_flood / 40x_combo; rows=%+v", ip, rows)
		}
	}
}

// The exclusion must not open a hole: a wp-login brute force, probes that only
// dress up as REST calls, a REST scanner the edge's WAF refuses, and a JWT
// brute force the origin refuses all still trip 403_flood.
func TestIP403Flood_RESTLookalikesStillCount(t *testing.T) {
	cases := map[string][]string{
		"10.0.2.1": {"/wp-login.php"},
		"10.0.2.2": {"/.env?rest_route=/wp/v2/users", "/.git/config?rest_route=/x"},
		"10.0.2.3": {"/wp-json/../.env", "/a/b/wp-json/x", "/wp-json/%2e%2e/wp-config.php"},
		"10.0.2.4": {"/.git/wp-json/x", "/.env/?rest_route=/x"},
		"10.0.2.5": {"/wp-json/jwt-auth/v1/token", "/?rest_route=/jwt-auth/v1/token"},
	}
	// 10.0.2.6: the edge (WAF) refused these REST calls itself, no upstream.
	edgeOnly := map[string]bool{"10.0.2.6": true}
	cases["10.0.2.6"] = []string{"/wp-json/gravitysmtp/v1/tests/mock-data", "/wp-json/batch/v1"}
	e := NewEngine(Config{
		Every:      1 * time.Second,
		Window:     2 * time.Minute,
		IP403Count: 5,
	})
	now := float64(time.Now().Unix())
	for ip, uris := range cases {
		for i := 0; i < 6; i++ {
			e.ingest(LogRec{
				TS: now + float64(i), IP: ip, Host: "example.com", Method: "post",
				URI: uris[i%len(uris)], Status: 403, UA: "ua",
				Upstream: !edgeOnly[ip], UpstreamName: map[bool]string{true: "", false: "cfm_apache"}[edgeOnly[ip]],
			}, "raw")
		}
	}
	rows := e.IPShort(0)
	for ip := range cases {
		if !ipHas403FloodReason(rows, ip) {
			t.Errorf("%s: expected 403_flood; rows=%+v", ip, rows)
		}
	}
}
