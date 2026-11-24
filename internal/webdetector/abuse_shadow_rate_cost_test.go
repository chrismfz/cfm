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
		{"fast origin: never the request time", LogRec{Upstream: true, UpstreamName: "cfm_apache", RT: 0.4}, 0},
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

// A vhost that stopped logging keeps its buckets until its next line: they
// must not re-log an outlier that has stopped, nor feed origin_busy.
func TestRateOutlierIgnoresStaleBuckets(t *testing.T) {
	var lines []string
	prev := abuseShadowRateLogf
	abuseShadowRateLogf = func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	t.Cleanup(func() { abuseShadowRateLogf = prev })

	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute,
		AbuseShadow: true, AbuseShadowRateOutlier: true})
	old := float64(time.Now().Add(-10 * time.Minute).Unix())
	for i := 0; i < 10; i++ {
		e.ingest(LogRec{TS: old, IP: fmt.Sprintf("10.0.0.%d", i+1), Host: "quiet.example.gr", Method: "get",
			URI: "/", Status: 200, Upstream: true, UpstreamName: "cfm_apache", URT: 0.2}, "raw")
	}
	for i := 0; i < 40; i++ {
		e.ingest(LogRec{TS: old + float64(i)*0.01, IP: "192.0.2.1", Host: "quiet.example.gr", Method: "get",
			URI: fmt.Sprintf("/shop/?p=%d", i), Status: 200, Upstream: true, UpstreamName: "cfm_apache", URT: 3}, "raw")
	}
	e.emitAbuseShadowRateOutliers(time.Now())
	if len(lines) != 0 {
		t.Errorf("stale buckets logged %q", lines)
	}
}

func TestParseUpstreamTime(t *testing.T) {
	for in, want := range map[string]float64{
		"": 0, "-": 0, "0.000": 0, "1.250": 1.25,
		"0.100, 0.200": 0.3, "0.5 : 1.5": 2, "-, 0.4": 0.4, "x": 0,
		"-, -": 0, "-1": 0, "+Inf": 0, "NaN": 0,
	} {
		if got := parseUpstreamTime(in); got < want-1e-9 || got > want+1e-9 {
			t.Errorf("parseUpstreamTime(%q) = %v, want %v", in, got, want)
		}
	}
}

func captureRateLines(t *testing.T) *[]string {
	t.Helper()
	var lines []string
	prev := abuseShadowRateLogf
	abuseShadowRateLogf = func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	t.Cleanup(func() { abuseShadowRateLogf = prev })
	return &lines
}

// The tier is judged every tick: an IP that first crossed the rate bar cheap
// (tier=-, line throttled for the holddown) still logs its tier=cost line once
// it has cost the origin enough, and from then on ONE line per holddown, as
// any outlier: the plain key it logged under first must not open on its own
// clock and log the tier a second time.
func TestRateOutlierCostTierNotHeldByFirstLine(t *testing.T) {
	lines := captureRateLines(t)
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute,
		AbuseShadow: true, AbuseShadowRateOutlier: true,
		ChallengeSuspiciousHolddown: 30 * time.Second})
	t0 := time.Now()
	now := float64(t0.Unix())
	const host = "shop.example.gr"
	req := func(ip string, i int, urt float64) {
		e.ingest(LogRec{TS: now + float64(i)*0.01, IP: ip, Host: host, Method: "get", URI: fmt.Sprintf("/p/%d", i),
			Status: 200, Upstream: true, UpstreamName: "cfm_apache", URT: urt}, "raw")
	}
	for i := 0; i < 10; i++ {
		req(fmt.Sprintf("10.0.0.%d", i+1), i, 0.1)
	}
	for i := 0; i < 25; i++ {
		req("192.0.2.1", i, 1) // 25 s of origin: 0.21 of the window
	}
	e.emitAbuseShadowRateOutliers(t0)
	for i := 25; i < 100; i++ {
		req("192.0.2.1", i, 1) // now 100 s: 0.83
	}
	// The tier enters at +15s; the plain key would reopen at +30s and +60s,
	// the tier's own at +45s.
	for _, d := range []time.Duration{15, 30, 45, 60} {
		e.emitAbuseShadowRateOutliers(t0.Add(d * time.Second))
	}
	var tiers []string
	for _, ln := range *lines {
		en, _ := abuseshadow.Parse(ln)
		tiers = append(tiers, en.Tier)
	}
	if strings.Join(tiers, ",") != ",cost,cost" {
		t.Errorf("tiers = %q, want [\"\" cost cost] (lines %q)", tiers, *lines)
	}
}

// A log that reports no upstream (combined/Apache) measures no origin time:
// the line says "-", never 0, and never tier=cost. host_static is the
// vhost's own static share.
func TestRateOutlierUnmeasuredOrigin(t *testing.T) {
	lines := captureRateLines(t)
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute,
		AbuseShadow: true, AbuseShadowRateOutlier: true})
	now := float64(time.Now().Unix())
	const host = "apache.example.gr"
	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		e.ingest(LogRec{TS: now, IP: ip, Host: host, Method: "get", URI: "/", Status: 200, RT: 0.3}, "raw")
		e.ingest(LogRec{TS: now, IP: ip, Host: host, Method: "get", URI: "/a.css", Status: 200}, "raw")
	}
	for i := 0; i < 40; i++ {
		e.ingest(LogRec{TS: now + float64(i)*0.01, IP: "192.0.2.1", Host: host, Method: "get",
			URI: fmt.Sprintf("/p/%d", i), Status: 200, RT: 3}, "raw")
	}
	e.emitAbuseShadowRateOutliers(time.Now())
	if len(*lines) != 1 {
		t.Fatalf("lines = %q, want 1", *lines)
	}
	ln := (*lines)[0]
	if !strings.Contains(ln, " origin=- origin_busy=- tier=-") {
		t.Errorf("unmeasured origin must log '-': %q", ln)
	}
	en, _ := abuseshadow.Parse(ln)
	if d := en.HostStatic - 10.0/60; d > 0.01 || d < -0.01 {
		t.Errorf("host_static = %v, want %.2f", en.HostStatic, 10.0/60)
	}
}

// "Measured" is per vhost: a vhost whose lines report no upstream reads "-"
// even while another vhost on the node is measured (a log-source handover).
func TestRateOutlierMeasuredPerVhost(t *testing.T) {
	lines := captureRateLines(t)
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute,
		AbuseShadow: true, AbuseShadowRateOutlier: true})
	now := float64(time.Now().Unix())
	e.ingest(LogRec{TS: now, IP: "10.9.9.9", Host: "edge.example.gr", Method: "get", URI: "/",
		Status: 200, Upstream: true, UpstreamName: "cfm_apache", URT: 0.5}, "raw")
	const host = "apache.example.gr"
	for i := 0; i < 10; i++ {
		e.ingest(LogRec{TS: now, IP: fmt.Sprintf("10.0.0.%d", i+1), Host: host, Method: "get", URI: "/", Status: 200}, "raw")
	}
	for i := 0; i < 40; i++ {
		e.ingest(LogRec{TS: now + float64(i)*0.01, IP: "192.0.2.1", Host: host, Method: "get",
			URI: fmt.Sprintf("/p/%d", i), Status: 200, RT: 3}, "raw")
	}
	e.emitAbuseShadowRateOutliers(time.Now())
	if len(*lines) != 1 || !strings.Contains((*lines)[0], " origin=- origin_busy=0.0 tier=-") {
		t.Errorf("lines = %q, want one line with origin=- (vhost unmeasured) and the node's origin_busy", *lines)
	}
}
