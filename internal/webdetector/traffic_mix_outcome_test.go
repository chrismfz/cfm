package webdetector

import (
	"path/filepath"
	"testing"
	"time"
)

// The shapes of titan's edge log (2026-11-25, ~45 minutes): which upstream,
// status and URI each kind of edge answer carries, and what it reads as.
func TestTMOutcome(t *testing.T) {
	rec := func(up string, upstream bool, status int, uri string) LogRec {
		return LogRec{UpstreamName: up, Upstream: upstream, Status: status, URI: uri, URT: 0.2}
	}
	for _, tc := range []struct {
		name string
		rec  LogRec
		want int
	}{
		{"a page the origin answered", rec("cfm_apache", true, 200, "/p/1"), tmOutOrigin},
		{"the origin's own 429", rec("cfm_apache", true, 429, "/p/1"), tmOutOrigin},
		{"a static file from the origin", rec("cfm_apache_static", true, 200, "/a.css"), tmOutOrigin},
		{"a static cache hit (no upstream)", rec("cfm_apache_static", false, 200, "/a.css"), tmOutCached},
		{"a micro cache hit", rec("cfm_apache_micro", false, 200, "/"), tmOutCached},
		{"an edge rate limit (no upstream)", rec("cfm_apache", false, 429, "/p/1"), tmOutRateLimited},
		// Edge exits that never set $cfm_upstream keep cfm_apache: the status decides.
		{"a range from the cache", rec("cfm_apache_static", false, 206, "/v.mp4"), tmOutCached},
		{"a revalidation from the cache", rec("cfm_apache_static", false, 304, "/a.css"), tmOutCached},
		{"a UA emergency block (444)", rec("cfm_apache", false, 444, "/p/1"), tmOutBlocked},
		{"an edge 403 without an upstream name", rec("cfm_apache", false, 403, "/p/1"), tmOutBlocked},
		{"a challenge_resume redirect", rec("cfm_apache", false, 303, "/checkout"), tmOutOtherEdge},
		{"a client gone before the upstream", rec("cfm_apache", false, 499, "/p/1"), tmOutOtherEdge},
		{"a WAF block / ban", rec("cfm_block", false, 403, "/x"), tmOutBlocked},
		{"a traffic rule's block", rec("cfm_block_rule", false, 403, "/x"), tmOutRuleBlocked},
		{"sent to the challenge", rec("cfm_challenge", true, 302, "/p/1"), tmOutChallenge},
		// /__cfm_* bypass cfm.lua and keep the server default cfm_apache.
		{"the challenge page itself", rec("cfm_apache", true, 200, "/__cfm_challenge?next=%2f"), tmOutChallenge},
		{"a verify", rec("cfm_apache", true, 403, "/__cfm_verify"), tmOutChallenge},
		{"a panel port's challenge page", rec("cfm_panel_2083", true, 200, "/__cfm_challenge"), tmOutChallenge},
		{"another CFM location", rec("cfm_apache", true, 200, "/__cfm_pow.js"), tmOutOtherEdge},
		{"an edge redirect", rec("cfm_redirect", false, 301, "/"), tmOutRedirect},
		{"a panel proxy", rec("cfm_panel_2083", false, 307, "/"), tmOutOtherEdge},
		{"no upstream name (a file format without it)", rec("", true, 200, "/"), tmOutOrigin},
	} {
		if got := tmOutcome(tc.rec); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		status, want int
	}{{303, tmOutVerifyPass}, {403, tmOutVerifyFail}, {405, -1}} {
		if got := tmVerifyOutcome(LogRec{URI: "/__cfm_verify", Status: tc.status}); got != tc.want {
			t.Errorf("verify %d: %d, want %d", tc.status, got, tc.want)
		}
	}
	if got := tmVerifyOutcome(LogRec{URI: "/__cfm_challenge", Status: 303}); got != -1 {
		t.Errorf("a challenge page is not a verify: %d", got)
	}
}

// One client challenged and blocked, one visitor served: the outcomes add up
// per class, per vhost and per client, and the challenge server's time is
// never the origin's.
func TestTrafficMix_Outcomes(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	edge := func(ip, uri, up string, upstream bool, status int, urt float64) LogRec {
		r := tmOrigin(ip, "shop.gr", "GET", uri, tmMacChrome136, status, urt)
		r.UpstreamName, r.Upstream = up, upstream
		return r
	}
	for i, r := range []LogRec{
		edge("10.0.0.1", "/p/1", "cfm_challenge", true, 302, 0.001),
		edge("10.0.0.1", "/__cfm_challenge?next=%2fp%2f1", "cfm_apache", true, 200, 0.004),
		edge("10.0.0.1", "/__cfm_verify", "cfm_apache", true, 403, 0.002),
		edge("10.0.0.2", "/p/2", "cfm_challenge", true, 302, 0.001),
		edge("10.0.0.2", "/__cfm_verify", "cfm_apache", true, 303, 0.002),
		edge("10.0.0.3", "/wp-login.php", "cfm_block", false, 403, 0),
		edge("10.0.0.4", "/p/3", "cfm_apache", false, 429, 0),
		edge("10.0.0.5", "/a.css", "cfm_apache_static", false, 200, 0),
		edge("10.0.0.6", "/p/4", "cfm_apache", true, 200, 1.5),
	} {
		tmFeed(s, r, now.Add(time.Duration(i)*time.Second))
	}
	m := s.Snapshot(now.Add(time.Minute), time.Hour, "", false, 10, 10)
	want := TrafficMixOutcomes{Origin: 1, Cached: 1, Challenged: 5, Blocked: 1, RateLimited: 1, VerifySentOn: 1, VerifyRefused: 1}
	if got := tmClassOf(m, "human").Outcomes; got == nil || *got != want {
		t.Fatalf("class outcomes = %+v, want %+v", got, want)
	}
	if got := m.Total.Outcomes; got == nil || *got != want {
		t.Fatalf("total outcomes = %+v", got)
	}
	if o := tmClassOf(m, "human").OriginSec; o != 1.5 {
		t.Fatalf("origin time %.3f s, want only the one page the origin answered (1.5 s)", o)
	}
	if len(m.Hosts) == 0 || m.Hosts[0].Total.Outcomes == nil || *m.Hosts[0].Total.Outcomes != want {
		t.Fatalf("host outcomes = %+v", m.Hosts)
	}
	c := tmFindClient(m, tmMacChrome136)
	if c == nil || c.Outcomes == nil || *c.Outcomes != want {
		t.Fatalf("client outcomes = %+v", c)
	}

	// The vhost view reads its classes from the hosts: the same outcomes.
	hv := s.Snapshot(now.Add(time.Minute), time.Hour, "shop.gr", false, 10, 10)
	if got := tmClassOf(hv, "human").Outcomes; got == nil || *got != want {
		t.Fatalf("vhost view outcomes = %+v", got)
	}

	// And they survive a save and a reload.
	path := filepath.Join(t.TempDir(), "m.json.gz")
	if err := s.saveTo(path, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	dst := newTrafficMixStore()
	if _, err := dst.loadFrom(path, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := tmFindClient(dst.Snapshot(now.Add(time.Minute), time.Hour, "", false, 10, 10), tmMacChrome136).Outcomes; got == nil || *got != want {
		t.Fatalf("after a reload: %+v", got)
	}
}

// An entry that only ever reached the origin keeps no outcome counts (most of
// the ring's entries: they are allocated on the first edge outcome only).
func TestTrafficMix_OriginOnlyKeepsNoOutcomes(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	tmFeed(s, tmOrigin("10.0.0.6", "shop.gr", "GET", "/p/4", tmMacChrome136, 200, 0.3), now)
	s.mu.Lock()
	defer s.mu.Unlock()
	b := &s.buckets[(now.Unix()/tmBucketSec)%tmBuckets]
	if h := b.hosts["shop.gr"]; h == nil || h[tmHuman].Out != nil {
		t.Fatalf("an origin-only host entry holds outcome counts: %+v", h)
	}
	for _, cl := range b.clients[tmHuman] {
		if cl.Out != nil {
			t.Fatalf("an origin-only client holds outcome counts: %+v", cl.Out)
		}
	}
}

// A save copies the counts under the lock and encodes them after: it must not
// share them with the live entries that observe keeps adding to (-race).
func TestTrafficMix_SaveWhileObserving(t *testing.T) {
	s := newTrafficMixStore()
	now := time.Now()
	path := filepath.Join(t.TempDir(), "m.json.gz")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			r := tmOrigin("10.0.0.1", "shop.gr", "GET", "/p", tmMacChrome136, 403, 0)
			r.UpstreamName, r.Upstream = "cfm_block", false
			tmFeed(s, r, now)
		}
	}()
	for i := 0; i < 20; i++ {
		if err := s.saveTo(path, now); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}
