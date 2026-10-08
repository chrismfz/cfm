package webdetector

import (
	"fmt"
	"testing"
	"time"
)

func TestParseTSV_Upstream(t *testing.T) {
	line := func(urt string) string {
		return "1791466170.6\t172.81.132.89\tvilladimitramykonos.com\tPOST\t/wp-admin/admin-ajax.php\tHTTP/1.1\t403\t7007\t0.065\t" + urt + "\t-\tMozilla/5.0"
	}
	cases := []struct {
		urt  string
		want bool
	}{
		{"0.064", true},
		{"0.000", true},    // a fast origin still answered
		{"0.1, 0.2", true}, // a retried upstream (URT parses as 0)
		{"-", false},       // answered at the edge
		{"", false},
	}
	for _, c := range cases {
		rec, ok := parseTSV(line(c.urt))
		if !ok {
			t.Fatalf("urt %q: line did not parse", c.urt)
		}
		if rec.Upstream != c.want {
			t.Errorf("urt %q: Upstream = %v, want %v", c.urt, rec.Upstream, c.want)
		}
	}
}

func TestIsOrigin403POST(t *testing.T) {
	base := LogRec{Method: "post", Status: 403, Upstream: true, Bytes: 7007}
	cases := []struct {
		name string
		mut  func(*LogRec)
		path string
		want bool
	}{
		{"Wordfence block page on admin-ajax", nil, "/wp-admin/admin-ajax.php", true},
		{"origin WAF with an empty body on another path", func(r *LogRec) { r.Bytes = 0 }, "/wp-json/batch/v1", true},
		{"origin WAF, 107 bytes", func(r *LogRec) { r.Bytes = 107 }, "/wp/", true},
		{"WordPress nonce refusal (-1) on admin-ajax", func(r *LogRec) { r.Bytes = 6 }, "/wp-admin/admin-ajax.php", false},
		{"WordPress refusal on admin-post", func(r *LogRec) { r.Bytes = 2 }, "/blog/wp-admin/admin-post.php", false},
		{"edge 403 (no upstream)", func(r *LogRec) { r.Upstream = false }, "/wp-admin/admin-ajax.php", false},
		{"CFM verify endpoint", nil, "/__cfm_verify", false},
		{"GET", func(r *LogRec) { r.Method = "get" }, "/wp-login.php", false},
		{"origin 200", func(r *LogRec) { r.Status = 200 }, "/wp-admin/admin-ajax.php", false},
	}
	for _, c := range cases {
		r := base
		if c.mut != nil {
			c.mut(&r)
		}
		if got := isOrigin403POST(r, c.path); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func newOrigin403Engine(on bool) *Engine {
	return NewEngine(Config{
		Every:                time.Second * 5,
		Window:               2 * time.Minute,
		AbuseShadow:          on,
		AbuseShadowOrigin403: on,
	})
}

func feedPOST403(e *Engine, t0 time.Time, ip, host, uri string, n int, bytes int64, upstream bool) {
	for i := 0; i < n; i++ {
		ts := t0.Add(time.Duration(i) * 500 * time.Millisecond)
		e.ingest(LogRec{
			TS: float64(ts.UnixNano()) / 1e9, IP: ip, Host: host, Method: "post", URI: uri,
			Status: 403, Bytes: bytes, URT: 0.06, Upstream: upstream, UA: "mozilla/5.0",
		}, "raw")
	}
}

func TestOrigin403Bursts(t *testing.T) {
	e := newOrigin403Engine(true)
	t0 := time.Unix(1791466170, 0)
	host := "villadimitramykonos.com"

	// The titan shape: 40 Wordfence-blocked POSTs in 20 s, plus 5 ordinary GETs.
	feedPOST403(e, t0, "172.81.132.89", host, "/wp-admin/admin-ajax.php", 40, 7007, true)
	for i := 0; i < 5; i++ {
		ts := t0.Add(time.Duration(i) * time.Second)
		e.ingest(LogRec{TS: float64(ts.Unix()), IP: "172.81.132.89", Host: host, Method: "get", URI: "/", Status: 200, Upstream: true}, "raw")
	}
	// A real visitor on a cached page with a stale nonce: WordPress's "-1".
	feedPOST403(e, t0, "85.75.103.60", host, "/wp-admin/admin-ajax.php", 60, 6, true)
	// CFM's own edge 403s (no upstream) and verify refusals.
	feedPOST403(e, t0, "203.0.113.5", host, "/wp-login.php", 60, 4000, false)
	feedPOST403(e, t0, "203.0.113.6", host, "/__cfm_verify", 60, 128, true)
	// Below the threshold.
	feedPOST403(e, t0, "203.0.113.7", host, "/xmlrpc.php", 20, 4000, true)
	// A scanner spraying paths on another vhost.
	for i := 0; i < 35; i++ {
		feedPOST403(e, t0.Add(time.Duration(i)*time.Second), "45.148.10.80", "meliasma.gr", fmt.Sprintf("/p%d/wp-json/batch/v1", i%4), 1, 0, true)
	}

	now := t0.Add(25 * time.Second)
	got := map[string]origin403Burst{}
	for _, b := range e.origin403Bursts(now, 30) {
		got[b.host+"|"+b.ip] = b
	}
	if len(got) != 2 {
		t.Fatalf("want 2 bursts, got %d: %+v", len(got), got)
	}
	b := got[host+"|172.81.132.89"]
	if b.post403 != 40 || b.paths != 1 || b.reqs != 45 {
		t.Errorf("titan burst = %+v, want post403=40 paths=1 reqs=45", b)
	}
	s := got["meliasma.gr|45.148.10.80"]
	if s.post403 != 35 || s.paths != 4 {
		t.Errorf("scanner burst = %+v, want post403=35 paths=4", s)
	}

	// Two minutes later the burst has left the one-minute window.
	if late := e.origin403Bursts(t0.Add(2*time.Minute), 30); len(late) != 0 {
		t.Errorf("a burst older than a minute must not count, got %+v", late)
	}

	// The emit runs without an enricher and throttles per (host, ip): it must
	// not panic, and a second tick inside the holddown logs nothing new.
	e.emitAbuseShadowOrigin403(now)
	if e.shouldLogVhostSuppress("abuseshadow:o403:"+host+"|172.81.132.89", now.Add(5*time.Second)) {
		t.Errorf("the first emit should have taken the throttle token for the titan burst")
	}
}

func TestOrigin403Gate(t *testing.T) {
	e := newOrigin403Engine(false)
	t0 := time.Unix(1791466170, 0)
	feedPOST403(e, t0, "172.81.132.89", "a.gr", "/wp-admin/admin-ajax.php", 40, 7007, true)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, hs := range e.hosts {
		for i := range hs.buckets {
			if hs.buckets[i].ipsOrigin403POST != nil {
				t.Fatal("the counter must stay nil with the shadow signal off (no hot-path cost)")
			}
		}
	}
}

func TestOrigin403PerMinDefault(t *testing.T) {
	e := &Engine{}
	if e.origin403PerMin() != 30 {
		t.Errorf("default per-minute threshold = %d, want 30", e.origin403PerMin())
	}
	e.cfg.AbuseShadowOrigin403PerMin = 50
	if e.origin403PerMin() != 50 {
		t.Errorf("configured threshold not applied")
	}
}
