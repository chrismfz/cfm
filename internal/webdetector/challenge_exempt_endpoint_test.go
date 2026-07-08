package webdetector

import "testing"

// TestIsChallengeExemptEndpoint locks the NARROW enforcement carve-out: only
// verified non-browser machine endpoints are exempt from the vhost-wide
// challenge. A too-broad entry here is a challenge-bypass hole, so the negative
// cases matter as much as the positive ones.
func TestIsChallengeExemptEndpoint(t *testing.T) {
	exempt := []string{
		"/wp-json/wc/v3/orders/",  // WooCommerce REST (v-track order sync)
		"//wp-json/wc/v3/orders/", // double-slash form v-track actually sends
		"/wp-json/wc-blocks/products",
		"/wp-json/wc_stripe/foo",
		"/wc-api/v3/orders", // legacy Woo
		"/stripe/webhook",
		"/paypal/ipn",
		"/adyen/notify",
		"/checkout/webhook",
		"/payment/callback",
		"/ws_vtrack/json_v2.php", // v-track plugin endpoint (check_connection)
	}
	for _, u := range exempt {
		if !isChallengeExemptEndpoint(u) {
			t.Errorf("expected exempt, got not-exempt: %q", u)
		}
	}

	// Must STAY challengeable — these are either browser paths or too broad to
	// safely bypass enforcement on.
	notExempt := []string{
		"",
		"/",
		"/product-tag/set-petsetes-baniou-promise/",
		"/wp-json/",             // generic WP REST (user enumeration etc.)
		"/wp-json/wp/v2/users",  // enumeration target
		"/api",                  // too broad
		"/rest/v1/thing",        // too broad
		"/upload",               // too broad
		"/graphql",              // too broad
		"/checkout/",            // not the webhook subpath
		"/index.php?route=api/", // query-arg API (query is stripped upstream anyway)
	}
	for _, u := range notExempt {
		if isChallengeExemptEndpoint(u) {
			t.Errorf("expected not-exempt, got exempt: %q", u)
		}
	}
}
