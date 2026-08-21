package webdetector

import (
	"testing"
	"time"
)

func TestMedianInt(t *testing.T) {
	cases := []struct {
		in   []int
		want float64
	}{
		{nil, 0},
		{[]int{5}, 5},
		{[]int{1, 3}, 2},        // even → mean of middle two
		{[]int{1, 2, 3}, 2},     // odd
		{[]int{3, 1, 2}, 2},     // unsorted
		{[]int{1, 1, 1, 62}, 1}, // e-vafeiadis-ish: dominated by the low mass
	}
	for _, c := range cases {
		if got := medianInt(c.in); got != c.want {
			t.Errorf("medianInt(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIPSkew(t *testing.T) {
	// concentrated: two big, many small → high skew.
	if s := ipSkew([]int{62, 62, 1, 1, 1, 1, 1}); s < 50 {
		t.Errorf("concentrated skew = %v, want ≥ 50", s)
	}
	// flat/distributed (e-athlos-ish): top only a few× median → low skew.
	if s := ipSkew([]int{43, 37, 25, 24, 24, 11, 11, 10, 10, 10, 10}); s >= 5 {
		t.Errorf("flat skew = %v, want < 5", s)
	}
	if s := ipSkew(nil); s != 0 {
		t.Errorf("empty skew = %v, want 0", s)
	}
}

func TestRateOutlier(t *testing.T) {
	cfg := shadowRateCfg{K: 20, Floor: 0.2, SkewMin: 5, MinReq: 20}
	win := 120.0

	// The e-vafeiadis IP: 62 reqs on a vhost with median 1 req, skew 62.
	medianRPS := 1.0 / win // 0.0083
	if !rateOutlier(62, 62/win, medianRPS, 62, cfg) {
		t.Errorf("concentrated 62× IP should be a rate outlier")
	}
	// A tiny-sample IP (1 req) on the same vhost is NOT an outlier.
	if rateOutlier(1, 1/win, medianRPS, 62, cfg) {
		t.Errorf("1-req IP must not be an outlier (MinReq gate)")
	}
	// e-athlos flat vhost: top IP 43 reqs, median 10, skew 4.3 (< SkewMin) → no.
	medFlat := 10.0 / win
	if rateOutlier(43, 43/win, medFlat, 4.3, cfg) {
		t.Errorf("flat/distributed top IP must NOT be an outlier (skew + K×median)")
	}
	// Above skew but below the absolute floor (slow idle vhost) → no.
	// median 1 req/120s, an IP with 10 reqs = 0.083 rps < Floor 0.2.
	if rateOutlier(10, 10/win, 1.0/win, 10, cfg) {
		t.Errorf("below the absolute floor must not be an outlier")
	}
}

func TestVerifiedGoodBot_NoDNSPaths(t *testing.T) {
	// Empty and non-good-bot PTRs return "" without touching DNS.
	if got := verifiedGoodBot("", "1.2.3.4"); got != "" {
		t.Errorf("empty PTR = %q, want \"\"", got)
	}
	if got := verifiedGoodBot("host.example.com", "1.2.3.4"); got != "" {
		t.Errorf("non-good-bot PTR = %q, want \"\"", got)
	}
	if got := verifiedGoodBot("ppp089044094244.access.hol.gr", "89.44.94.244"); got != "" {
		t.Errorf("residential PTR = %q, want \"\" (never exempt)", got)
	}
}

func TestShadowRateCfgDefaults(t *testing.T) {
	e := &Engine{}
	// All zero → sane defaults applied.
	c := e.shadowRateCfg()
	if c.K != 20 || c.Floor != 0.2 || c.SkewMin != 5 || c.MinReq != 20 {
		t.Errorf("defaults = %+v, want K20/Floor0.2/Skew5/MinReq20", c)
	}
	// Explicit values pass through.
	e.cfg.AbuseShadowRateK = 8
	e.cfg.AbuseShadowRateFloor = 0.5
	e.cfg.AbuseShadowRateSkewMin = 3
	e.cfg.AbuseShadowRateMinReq = 40
	c = e.shadowRateCfg()
	if c.K != 8 || c.Floor != 0.5 || c.SkewMin != 3 || c.MinReq != 40 {
		t.Errorf("explicit = %+v, want K8/Floor0.5/Skew3/MinReq40", c)
	}
}

// The 2026-08 false-positive fix: a human pageview on an asset-heavy theme pulls
// dozens of static files (css/js/fonts), which must NOT count toward Signal C's
// per-IP rate. ingest mirrors only DYNAMIC requests into bucketSW.ipsDyn (the
// map Signal C reads), while the enforced uniqIP path keeps counting all
// requests in ips. This asserts that split at the ingest layer.
func TestIngest_IpsDynExcludesStaticAssets(t *testing.T) {
	e := NewEngine(Config{Every: 1 * time.Second, Window: 2 * time.Minute})
	now := float64(time.Now().Unix())
	const ip, host = "5.203.174.86", "kirkikosmima.gr"

	// One human page load: 1 dynamic HTML request + a burst of static assets,
	// exactly the shape from the live access log that read as a 910× outlier.
	e.ingest(LogRec{TS: now, IP: ip, Host: host, Method: "get",
		URI: "/product-category/paidika-kosmimata/", Status: 200}, "raw")
	assets := []string{
		"/wp-content/themes/woodmart/css/parts/base.min.css?ver=8.4.1",
		"/wp-includes/css/dist/block-library/style.min.css?ver=7.1",
		"/wp-content/uploads/elementor/css/post-7.css?ver=1787293696",
		"/wp-content/plugins/elementor/assets/lib/font-awesome/fonts/fa-solid-900.woff2",
		"/wp-content/themes/woodmart/js/app.min.js?ver=8.4.1",
		"/wp-content/uploads/2024/01/logo.png",
	}
	for i, u := range assets {
		e.ingest(LogRec{TS: now + float64(i)*0.01, IP: ip, Host: host,
			Method: "get", URI: u, Status: 200}, "raw")
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	hs := e.hosts[host]
	if hs == nil {
		t.Fatalf("host %s not recorded", host)
	}
	var ipsTotal, ipsDyn int
	for i := range hs.buckets {
		ipsTotal += hs.buckets[i].ips[ip]
		ipsDyn += hs.buckets[i].ipsDyn[ip]
	}
	// ips counts every request (1 dynamic + 6 assets); ipsDyn counts the 1
	// dynamic only — so a shopper's asset fan-out can't inflate Signal C.
	if ipsTotal != 1+len(assets) {
		t.Errorf("ips (all requests) = %d, want %d", ipsTotal, 1+len(assets))
	}
	if ipsDyn != 1 {
		t.Errorf("ipsDyn (dynamic only) = %d, want 1 — static assets leaked into Signal C's counter", ipsDyn)
	}
}
