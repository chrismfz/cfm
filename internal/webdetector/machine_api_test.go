package webdetector

import (
	"fmt"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

func TestIsWooAdminAPIPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/wp-json/wc/v3/products/32945/variations/32947", true},
		{"/wp-json/wc/v3", true},
		{"/wp-json/wc/v2/orders", true},
		{"/wp-json/wc/v1/customers/1", true},
		{"/WP-JSON/WC/V3/products", true},
		{"/shop/wp-json/wc/v3/products", true},
		{"/wc-api/v3/products", true},
		{"/shop/wc-api/v2/orders", true},
		{"/index.php/wp-json/wc/v3/orders", true},
		{"/index.php/wc-api/v3/orders", true},

		// The Store API (cart / checkout, no credentials) keeps every challenge.
		{"/wp-json/wc/store/v1/checkout", false},
		{"/wp-json/wc/store/v1/batch", false},
		{"/wp-json/wc/store/cart", false},
		// Other routes and look-alikes.
		{"/wp-json/wc/v4/products", false},
		{"/wp-json/wc/v3x/products", false},
		{"/wp-json/wc-analytics/reports", false},
		{"/wp-json/wp/v2/users", false},
		{"/wp-json/wc/v3/auth/token", false},
		{"/wp-json/wc/v3/jwt-login", false},
		{"/wc-api/v4/products", false},
		{"/wc-api/v3/login", false},
		{"/", false},
		{"", false},
		// The marker mid-path, behind PATH_INFO or a deep directory.
		{"/wp-login.php/wp-json/wc/v3/products", false},
		{"/a/b/wp-json/wc/v3/products", false},
		{"/xmlrpc.php/wc-api/v3/products", false},
		// Traversal and escapes.
		{"/wp-json/wc/v3/../../wp-login.php", false},
		{"/wp-json/wc/v3/%2e%2e/x", false},
		{"//wp-json/wc/v3/products", false},
		{"/wp-json/wc/v3/products%2f1", false},
		{"/wc-api/v3/%2e%2e/x", false},
		{"/wp-json/wc/v3/products?x=1", false},
	}
	for _, c := range cases {
		if got := isWooAdminAPIPath(c.path); got != c.want {
			t.Errorf("isWooAdminAPIPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// The kiamaia.gr case: a product sync POSTs to a new variation path per
// request, a share of them 404. None of it may feed the per-IP challenge
// counters; the same traffic to the Store API, and a scanner's 404s, still do.
func TestWooAdminAPIRequestsSkipPerIPChallengeCounters(t *testing.T) {
	e := NewEngine(Config{
		Every: 1 * time.Second, Window: 2 * time.Minute,
		ChallengeIPErrRatioMin: 0.5, ChallengeIPPostRatioMin: 0.5,
		ChallengeIPUniqPathsEnabled: true, ChallengeIPUniqPathsMin: 5, ChallengeIPUniqPathsCap: 1000,
	})
	now := float64(time.Now().Unix())
	const sync, store, scan = "10.0.7.1", "10.0.7.2", "10.0.7.3"
	for i := 0; i < 20; i++ {
		st := 200
		if i%2 == 0 {
			st = 404
		}
		if i == 3 {
			st = 500
		}
		e.ingest(LogRec{TS: now, IP: sync, Host: "kiamaia.gr", Method: "post",
			URI:    fmt.Sprintf("/wp-json/wc/v3/products/%d/variations/%d?consumer_key=x", 100+i, 200+i),
			Status: st, Bytes: 50, Upstream: true, UpstreamName: "cfm_apache"}, "raw")
		e.ingest(LogRec{TS: now, IP: store, Host: "kiamaia.gr", Method: "post",
			URI:    fmt.Sprintf("/wp-json/wc/store/v1/checkout/%d", i),
			Status: st, Bytes: 50, UA: "mozilla", Upstream: true, UpstreamName: "cfm_apache"}, "raw")
		e.ingest(LogRec{TS: now, IP: scan, Host: "kiamaia.gr", Method: "get",
			URI:    fmt.Sprintf("/wp-login.php/wp-json/wc/v3/x%d", i),
			Status: 404, Bytes: 50, UA: "mozilla", Upstream: true, UpstreamName: "cfm_apache"}, "raw")
	}

	c4, c5, post, paths := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	e.mu.RLock()
	for _, hs := range e.hosts {
		for i := range hs.buckets {
			b := &hs.buckets[i]
			for ip, n := range b.ips4xx {
				c4[ip] += n
			}
			for ip, n := range b.ips5xx {
				c5[ip] += n
			}
			for ip, n := range b.ipsPOST {
				post[ip] += n
			}
			for ip, set := range b.ipUniqPaths {
				paths[ip] += len(set)
			}
		}
	}
	e.mu.RUnlock()

	if c4[sync] != 0 || c5[sync] != 0 || post[sync] != 0 || paths[sync] != 0 {
		t.Fatalf("WooCommerce REST calls fed the per-IP challenge counters: 4xx=%d 5xx=%d post=%d paths=%d",
			c4[sync], c5[sync], post[sync], paths[sync])
	}
	if c5[store] != 1 {
		t.Fatalf("a Store API 5xx must keep counting: %d", c5[store])
	}
	if c4[store] != 10 || post[store] != 20 || paths[store] != 20 {
		t.Fatalf("Store API calls must keep counting: 4xx=%d post=%d paths=%d", c4[store], post[store], paths[store])
	}
	if c4[scan] != 20 || paths[scan] != 20 {
		t.Fatalf("a mid-path marker must not exempt a request: 4xx=%d paths=%d", c4[scan], paths[scan])
	}
}

// End to end through the real tick: a WooCommerce sync gets no per-IP
// challenge from any trigger, CHALLENGE_RPS_TOTAL included (its requests leave
// the IP's total), while the same traffic to the Store API is challenged.
func TestWooAdminAPISyncGetsNoPerIPChallenge(t *testing.T) {
	e := NewEngine(Config{
		Every: time.Second, Window: 2 * time.Minute,
		OpenRestySock:               "/nonexistent/cfm_wooapi_test.sock",
		ChallengeIPRPSMin:           0.1, // 30 requests / 120 s = 0.25 req/s
		ChallengeIPErrRatioMin:      0.4,
		ChallengeIP4xxRPSMin:        0.1,
		ChallengeIPUniqPathsEnabled: true, ChallengeIPUniqPathsMin: 5, ChallengeIPUniqPathsCap: 1000,
	})
	now := float64(time.Now().Unix())
	const sync, store = "203.0.113.81", "203.0.113.82"
	for i := 0; i < 30; i++ {
		st := 200
		if i%2 == 0 {
			st = 404
		}
		e.ingest(LogRec{TS: now, IP: sync, Host: "kiamaia.gr", Method: "post",
			URI:    fmt.Sprintf("/wp-json/wc/v3/products/%d/variations/%d", 100+i, 200+i),
			Status: st, Bytes: 50, Upstream: true, UpstreamName: "cfm_apache"}, "raw")
		e.ingest(LogRec{TS: now, IP: store, Host: "kiamaia.gr", Method: "post",
			URI:    fmt.Sprintf("/wp-json/wc/store/v1/checkout/%d", i),
			Status: st, Bytes: 50, UA: "mozilla", Upstream: true, UpstreamName: "cfm_apache"}, "raw")
	}
	out := make(chan core.Alert, 64)
	e.emitIPChallenges(time.Now(), out)
	close(out)
	got := map[string]string{}
	for a := range out {
		if string(a.Kind) == "WEB/CHALLENGE" {
			got[a.Key] = a.Extra["rule"]
		}
	}
	if r, ok := got[sync]; ok {
		t.Fatalf("WooCommerce sync was challenged (%s)", r)
	}
	if _, ok := got[store]; !ok {
		t.Fatalf("the Store API client must still be challenged; alerts=%v", got)
	}
}
