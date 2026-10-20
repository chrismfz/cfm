package webdetector

import (
	"testing"
	"time"
)

func TestIsWPRestAPIRequest(t *testing.T) {
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
		if !isWPRestAPIRequest(u) {
			t.Errorf("isWPRestAPIRequest(%q) = false, want true", u)
		}
	}
	for _, u := range no {
		if isWPRestAPIRequest(u) {
			t.Errorf("isWPRestAPIRequest(%q) = true, want false", u)
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
			Status: 403, UA: "WooCommerce API Client-PHP/3.1.0",
		}, "raw")
	}
	for i := 0; i < 20; i++ {
		e.ingest(LogRec{
			TS: now + float64(i), IP: "10.0.1.2", Host: "news.example", Method: "get",
			URI: "/wordpress/wp-json/google-site-kit/v1/?_locale=user", Status: 403, UA: "Mozilla/5.0",
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

// The exclusion must not open a hole: a wp-login brute force, and probes that
// only dress up as REST calls, still trip 403_flood.
func TestIP403Flood_RESTLookalikesStillCount(t *testing.T) {
	cases := map[string][]string{
		"10.0.2.1": {"/wp-login.php"},
		"10.0.2.2": {"/.env?rest_route=/wp/v2/users", "/.git/config?rest_route=/x"},
		"10.0.2.3": {"/wp-json/../.env", "/a/b/wp-json/x", "/wp-json/%2e%2e/wp-config.php"},
		"10.0.2.4": {"/.git/wp-json/x", "/.env/?rest_route=/x"},
	}
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
