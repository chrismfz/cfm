package webdetector

import (
	"strings"
	"testing"
	"time"
)

func has403FloodReason(reasons []string) bool {
	for _, reason := range reasons {
		if strings.HasPrefix(reason, "403_flood") {
			return true
		}
	}
	return false
}

func ipHas403FloodReason(rows []IPSignals, ip string) bool {
	for _, r := range rows {
		if r.IP == ip {
			return has403FloodReason(r.Reasons)
		}
	}
	return false
}

// Regression for the WEB/403 self-block: a customer browsing their own
// image-heavy WordPress/WooCommerce site whose origin (Apache/WordPress)
// returns 403 on static assets (hotlink protection, broken Elementor
// thumbnails, an origin security plugin) must NOT accumulate a 403_flood.
// A single Elementor page fans out to dozens of image requests, so counting
// static-asset 403s let legitimate first-party browsing cross IP403_COUNT.
// The 403 counter now mirrors the 404 / 40x-combo static-asset exclusion.
func TestIP403Flood_StaticAssetsIgnored(t *testing.T) {
	e := NewEngine(Config{
		Every:      1 * time.Second,
		Window:     2 * time.Minute,
		IP403Count: 5,
	})

	now := float64(time.Now().Unix())
	// Extensions taken straight from the real incident (jpg/png/gif).
	assets := []string{
		"/wp-content/uploads/elementor/thumbs/imgi_19_white.jpg",
		"/wp-content/plugins/flippingbook/flippingbook-icon.png",
		"/wp-includes/js/thickbox/loadingAnimation.gif",
		"/wp-admin/images/spinner.gif",
		"/wp-content/themes/woodmart/images/payments.png",
	}
	for i := 0; i < 4; i++ {
		for _, a := range assets {
			e.ingest(LogRec{
				TS:     now + float64(i),
				IP:     "10.0.0.1",
				Host:   "example.com",
				Method: "get",
				URI:    a,
				Status: 403,
				UA:     "ua",
			}, "raw")
		}
	}

	rows := e.IPShort(0)
	if ipHas403FloodReason(rows, "10.0.0.1") {
		t.Fatalf("did not expect 403_flood for static-asset 403s; rows=%+v", rows)
	}
}

// Guard against over-correction: forbidden non-static paths (the real
// 403-flood signal) must still trip the detector.
func TestIP403Flood_NonStaticCounts(t *testing.T) {
	e := NewEngine(Config{
		Every:      1 * time.Second,
		Window:     2 * time.Minute,
		IP403Count: 5,
	})

	now := float64(time.Now().Unix())
	paths := []string{
		"/wp-login.php",
		"/.git/config",
		"/wp-config.php.bak",
		"/admin/",
		"/.env",
		"/phpmyadmin/",
	}
	for i, p := range paths {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "10.0.0.2",
			Host:   "example.com",
			Method: "get",
			URI:    p,
			Status: 403,
			UA:     "ua",
		}, "raw")
	}

	rows := e.IPShort(0)
	if !ipHas403FloodReason(rows, "10.0.0.2") {
		t.Fatalf("expected 403_flood for non-static forbidden paths; rows=%+v", rows)
	}
}
