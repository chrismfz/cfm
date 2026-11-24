package webdetector

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"cfm/internal/abuseshadow"
)

func TestOriginSeconds(t *testing.T) {
	cases := []struct {
		name string
		rec  LogRec
		want float64
	}{
		{"origin, urt", LogRec{Upstream: true, UpstreamName: "cfm_apache", URT: 2.5, RT: 2.6}, 2.5},
		{"origin tls upstream", LogRec{Upstream: true, UpstreamName: "cfm_apache_ssl", URT: 1}, 1},
		{"retried urt parses 0: rt stands in", LogRec{Upstream: true, UpstreamName: "cfm_apache", RT: 0.4}, 0.4},
		{"older edge, no upstream column", LogRec{Upstream: true, URT: 0.7}, 0.7},
		{"challenge server", LogRec{Upstream: true, UpstreamName: "cfm_challenge", URT: 0.1, RT: 0.1}, 0},
		{"edge answered itself", LogRec{Upstream: false, UpstreamName: "-", RT: 0.001}, 0},
		{"named non-origin", LogRec{Upstream: true, UpstreamName: "-", URT: 1}, 0},
	}
	for _, c := range cases {
		if got := originSeconds(c.rec); got != c.want {
			t.Errorf("%s: originSeconds = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRateCostTier(t *testing.T) {
	c := shadowRateCfg{Cost: 0.5}
	if !rateCostTier(0, 0.5, c) {
		t.Errorf("no static at the bar must be in the tier")
	}
	if rateCostTier(1, 3, c) {
		t.Errorf("one static asset in the window keeps it out")
	}
	if rateCostTier(0, 0.49, c) {
		t.Errorf("below the origin bar must stay out")
	}
	if got := (&Engine{}).shadowRateCfg().Cost; got != 0.5 {
		t.Errorf("default cost = %v, want 0.5", got)
	}
}

// End to end: ingest → the per-IP counters → the shadow line → the parser.
// A scraper of HTML pages (no static, 3 s of origin per page) reads tier=cost;
// an outlier as fast that also loads assets, and one whose pages cost the
// origin little, read tier=-; origin_busy is the node's origin time over the
// window.
func TestRateOutlierCostTierLine(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	prev := abuseShadowRateLogf
	abuseShadowRateLogf = func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	t.Cleanup(func() { abuseShadowRateLogf = prev })

	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute,
		AbuseShadow: true, AbuseShadowRateOutlier: true})
	now := float64(time.Now().Unix())
	const host = "shop.example.gr"
	origin := func(ip, uri string, urt float64, i int) {
		e.ingest(LogRec{TS: now + float64(i)*0.01, IP: ip, Host: host, Method: "get", URI: uri,
			Status: 200, Upstream: true, UpstreamName: "cfm_apache", URT: urt, RT: urt}, "raw")
	}
	for i := 0; i < 10; i++ { // the vhost's ordinary visitors: one page each
		origin(fmt.Sprintf("10.0.0.%d", i+1), "/", 0.2, i)
	}
	for i := 0; i < 40; i++ {
		origin("192.0.2.1", fmt.Sprintf("/shop/?filter_color=%d", i), 3, i)    // scraper
		origin("192.0.2.2", fmt.Sprintf("/shop/?filter_size=%d", i), 3, i)     // browser-like
		origin("192.0.2.3", fmt.Sprintf("/shop/?filter_brand=%d", i), 0.05, i) // cheap
	}
	for i := 0; i < 5; i++ {
		origin("192.0.2.2", "/wp-content/themes/x/style.css", 0, i)
	}
	// The challenge server's time is CFM's, not the origin's.
	e.ingest(LogRec{TS: now, IP: "192.0.2.9", Host: host, Method: "get", URI: "/__cfm_challenge",
		Status: 200, Upstream: true, UpstreamName: "cfm_challenge", URT: 50, RT: 50}, "raw")

	e.emitAbuseShadowRateOutliers(time.Now())

	got := map[string]abuseshadow.Entry{}
	for _, ln := range lines {
		en, ok := abuseshadow.Parse(ln)
		if !ok {
			t.Fatalf("unparsable line %q", ln)
		}
		got[en.IP] = en
	}
	// 10×0.2 + 40×3 + 40×3 + 40×0.05 = 244 origin seconds over 120 s.
	wantBusy := 244.0 / 120
	for ip, want := range map[string]struct {
		tier   string
		static int
		origin float64
	}{
		"192.0.2.1": {"cost", 0, 1.0},
		"192.0.2.2": {"", 5, 1.0},
		"192.0.2.3": {"", 0, 40 * 0.05 / 120},
	} {
		en, ok := got[ip]
		if !ok {
			t.Fatalf("no rate_outlier line for %s (lines: %q)", ip, lines)
		}
		if en.Verdict != "would_challenge" || en.Tier != want.tier || en.Static != want.static {
			t.Errorf("%s: verdict=%s tier=%q static=%d, want would_challenge/%q/%d", ip, en.Verdict, en.Tier, en.Static, want.tier, want.static)
		}
		if d := en.Origin - want.origin; d > 0.01 || d < -0.01 {
			t.Errorf("%s: origin=%v, want %.2f", ip, en.Origin, want.origin)
		}
		if d := en.OriginBusy - wantBusy; d > 0.1 || d < -0.1 {
			t.Errorf("%s: origin_busy=%v, want %.1f", ip, en.OriginBusy, wantBusy)
		}
	}
	for ip := range got {
		if strings.HasPrefix(ip, "10.0.0.") {
			t.Errorf("ordinary visitor %s logged as an outlier", ip)
		}
	}

	s := abuseshadow.Summarize(lines)
	if s.WouldChallengeCost != 1 || len(s.TopCostTier) != 1 || s.TopCostTier[0].IP != "192.0.2.1" {
		t.Errorf("summary cost tier = %d %+v, want 1 line for 192.0.2.1", s.WouldChallengeCost, s.TopCostTier)
	}
}
