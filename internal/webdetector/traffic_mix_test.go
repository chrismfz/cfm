package webdetector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	tmChrome152 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
	tmMeta      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))"
)

// origin builds a request the site's origin answered in urt seconds.
func tmOrigin(ip, host, method, uri, ua string, status int, urt float64) LogRec {
	return LogRec{IP: ip, Host: host, Method: method, URI: uri, UA: ua, Status: status, Bytes: 1000, RT: urt, URT: urt, Upstream: true, UpstreamName: "cfm_apache"}
}

// tmBase is a minute boundary 4 hours ago: inside the 24 h ring, and every
// "+N seconds" of a test stays in one minute.
func tmBase() time.Time { return time.Now().Add(-4 * time.Hour).Truncate(time.Minute) }

func tmFeed(s *trafficMixStore, rec LogRec, at time.Time) {
	s.observe(rec, rec.Host, NormalizeUA(rec.UA), at)
}

func tmClassOf(m TrafficMix, key string) TrafficMixClass {
	for _, c := range m.Classes {
		if c.Key == key {
			return c
		}
	}
	return TrafficMixClass{}
}

// The four classes, titan's shapes: Meta's new Chrome-UA crawler, a tool, the
// Chrome/152 scraper (no static, no XHR, 30 pages a minute) and a person who
// loads a page with its assets and an XHR.
func TestTrafficMix_Classes(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()

	tmFeed(s, tmOrigin("57.141.20.42", "shop.example", "GET", "/p/1?add-to-cart=9", tmMeta, 200, 0.4), now)
	tmFeed(s, tmOrigin("203.0.113.9", "shop.example", "GET", "/", "curl/8.5.0", 200, 0.1), now)
	tmFeed(s, tmOrigin("203.0.113.10", "shop.example", "GET", "/", "", 200, 0.1), now)
	for i := 0; i < 30; i++ {
		tmFeed(s, tmOrigin("83.212.158.22", "shop.example", "GET", fmt.Sprintf("/shop/?per_page=%d", i), tmChrome152, 200, 1.0), now.Add(time.Duration(i)*time.Second))
	}
	human := "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1"
	tmFeed(s, tmOrigin("94.65.1.2", "shop.example", "GET", "/wp-content/themes/x/style.css", human, 200, 0.01), now)
	tmFeed(s, tmOrigin("94.65.1.2", "shop.example", "POST", "/?wc-ajax=get_refreshed_fragments", human, 200, 0.2), now)
	for i := 0; i < 30; i++ { // a fast human after evidence stays human
		tmFeed(s, tmOrigin("94.65.1.2", "shop.example", "GET", fmt.Sprintf("/p/%d", i), human, 200, 0.3), now.Add(time.Duration(i)*time.Second))
	}

	m := s.Snapshot(now.Add(time.Minute), time.Hour, "", false, 0, 0)
	if c := tmClassOf(m, "crawler"); c.Requests != 1 {
		t.Fatalf("crawler = %d, want Meta's 1", c.Requests)
	}
	if c := tmClassOf(m, "bot"); c.Requests != 2 {
		t.Fatalf("bot = %d, want curl + the empty UA", c.Requests)
	}
	// The scraper's first 19 requests of the minute count as human (a lower bound).
	if c := tmClassOf(m, "automation"); c.Requests != 30-(tmAutomationDynPerMin-1) {
		t.Fatalf("automation = %d, want %d", c.Requests, 30-(tmAutomationDynPerMin-1))
	}
	if c := tmClassOf(m, "human"); c.Requests != 32+(tmAutomationDynPerMin-1) {
		t.Fatalf("human = %d, want the person's 32 + the scraper's first %d", c.Requests, tmAutomationDynPerMin-1)
	}
	if m.Total.Requests != 65 {
		t.Fatalf("total = %d, want 65", m.Total.Requests)
	}
	// The automation client is the raw UA, with its IP.
	var auto *TrafficMixClient
	for i := range m.Clients {
		if m.Clients[i].Class == "automation" {
			auto = &m.Clients[i]
		}
	}
	if auto == nil || auto.Client != tmChrome152 || auto.IPs != 1 || len(auto.TopIPs) != 1 || auto.TopIPs[0].IP != "83.212.158.22" {
		t.Fatalf("automation client: %+v", auto)
	}
	// Its 11 one-second pages past the threshold are its origin time.
	if auto.OriginSec != 11 {
		t.Fatalf("automation origin %.1f s, want 11", auto.OriginSec)
	}
	// Clients are ranked by origin time.
	for i := 1; i < len(m.Clients); i++ {
		if m.Clients[i].OriginSec > m.Clients[i-1].OriginSec {
			t.Fatalf("clients not ranked by origin time: %+v", m.Clients)
		}
	}
}

// Human evidence expires after tmHumanEvidenceTTL; a new minute restarts the count.
func TestTrafficMix_EvidenceExpires(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	tmFeed(s, tmOrigin("94.65.1.3", "a.example", "GET", "/x.js", tmChrome152, 200, 0.01), now)
	later := now.Add(tmHumanEvidenceTTL + time.Minute)
	for i := 0; i < 25; i++ {
		tmFeed(s, tmOrigin("94.65.1.3", "a.example", "GET", fmt.Sprintf("/p/%d", i), tmChrome152, 200, 0.1), later)
	}
	m := s.Snapshot(later.Add(time.Second), 30*time.Minute, "", false, 0, 0)
	if c := tmClassOf(m, "automation"); c.Requests != 25-(tmAutomationDynPerMin-1) {
		t.Fatalf("after the evidence expired: automation = %d", c.Requests)
	}
}

// Origin seconds only for requests the site's origin answered; the edge's own
// answers (challenge server, cache, block) count as edge-served. Status mix.
func TestTrafficMix_OriginEdgeAndStatus(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	ua := "curl/8"
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", ua, 200, 1.5), now)
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", ua, 503, 2.0), now)
	ch := tmOrigin("203.0.113.1", "a.example", "GET", "/__cfm_challenge", ua, 302, 0.002)
	ch.UpstreamName = "cfm_challenge"
	tmFeed(s, ch, now)
	tmFeed(s, LogRec{IP: "203.0.113.1", Host: "a.example", Method: "GET", URI: "/", UA: ua, Status: 403}, now)
	tmFeed(s, LogRec{IP: "203.0.113.1", Host: "a.example", Method: "GET", URI: "/", UA: ua, Status: 429}, now)
	file := LogRec{IP: "203.0.113.1", Host: "a.example", Method: "GET", URI: "/", UA: ua, Status: 404, URT: 0.5, Upstream: true}
	tmFeed(s, file, now) // a format without the upstream name: any upstream is the origin
	retried := tmOrigin("203.0.113.1", "a.example", "GET", "/", ua, 200, 0)
	retried.RT = 3.0 // URT parsed as 0 ("0.1, 0.2"): RT, the client's transfer included, is not origin time
	tmFeed(s, retried, now)

	c := tmClassOf(s.Snapshot(now.Add(time.Second), time.Hour, "", false, 0, 0), "bot")
	if c.Requests != 7 || c.OriginSec != 4.0 || c.EdgeServed == nil || *c.EdgeServed != 3 || c.Status == nil {
		t.Fatalf("bot class: %+v, want 7 requests, 4.0 origin s, 3 edge-served", c)
	}
	if st := c.Status; st.S2xx != 2 || st.S3xx != 1 || st.S403 != 1 || st.S429 != 1 || st.S4xx != 1 || st.S5xx != 1 {
		t.Fatalf("status mix: %+v", st)
	}
}

// Vhosts ranked by origin time with their split; ?host= narrows every figure.
func TestTrafficMix_HostsAndHostFilter(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	tmFeed(s, tmOrigin("203.0.113.1", "cheap.example", "GET", "/", "curl/8", 200, 0.1), now)
	tmFeed(s, tmOrigin("203.0.113.1", "cheap.example", "GET", "/", "curl/8", 200, 0.1), now)
	tmFeed(s, tmOrigin("57.141.20.1", "dear.example", "GET", "/p", tmMeta, 200, 3.0), now)

	m := s.Snapshot(now.Add(time.Second), time.Hour, "", false, 0, 0)
	if len(m.Hosts) != 2 || m.Hosts[0].Host != "dear.example" || m.Hosts[0].Classes["crawler"].OriginSec != 3.0 {
		t.Fatalf("hosts: %+v", m.Hosts)
	}
	f := s.Snapshot(now.Add(time.Second), time.Hour, "CHEAP.example", false, 0, 0)
	if f.Total.Requests != 2 || tmClassOf(f, "crawler").Requests != 0 || len(f.Hosts) != 0 || len(f.Clients) != 0 {
		t.Fatalf("host filter: total %d, hosts %d, clients %d", f.Total.Requests, len(f.Hosts), len(f.Clients))
	}
	// Not kept per vhost: absent, never a fabricated zero.
	if c := tmClassOf(f, "bot"); c.Status != nil || c.EdgeServed != nil || f.Total.Status != nil {
		t.Fatalf("per-vhost view reports a status mix / edge count it does not keep: %+v", c)
	}
}

// Requests outside the window are not counted; the busiest minute is the peak.
func TestTrafficMix_WindowAndPeak(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0.1), now.Add(-2*time.Hour))
	for i := 0; i < 120; i++ {
		tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0.1), now.Add(-10*time.Minute))
	}
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0.1), now.Add(-5*time.Minute))
	c := tmClassOf(s.Snapshot(now, time.Hour, "", false, 0, 0), "bot")
	if c.Requests != 121 {
		t.Fatalf("in the hour: %d, want 121", c.Requests)
	}
	if c.RPSPeak != 2.0 || c.PeakAt != now.Add(-10*time.Minute).Unix()/60*60 {
		t.Fatalf("peak %.2f at %d, want 2.0 r/s at the -10m minute", c.RPSPeak, c.PeakAt)
	}
	if c := tmClassOf(s.Snapshot(now, 24*time.Hour, "", false, 0, 0), "bot"); c.Requests != 122 {
		t.Fatalf("in 24h: %d, want 122", c.Requests)
	}
}

// IPs are kept for the last hour only (memory bound), even when the buckets
// in between had no traffic; the client's totals stay.
func TestTrafficMix_IPsLastHourOnly(t *testing.T) {
	s := newTrafficMixStore()
	t0 := tmBase()
	tmFeed(s, tmOrigin("203.0.113.7", "a.example", "GET", "/", "python-requests/2.31", 200, 0.1), t0)
	// One later bucket only, 70 minutes on: the gap must not keep the IPs.
	tmFeed(s, tmOrigin("198.51.100.1", "a.example", "GET", "/", "curl/8", 200, 0.1), t0.Add(70*time.Minute))
	s.mu.Lock()
	ips := s.buckets[(t0.Unix()/tmBucketSec)%tmBuckets].clients[tmBot]["python-requests"].ips
	s.mu.Unlock()
	if ips != nil {
		t.Fatalf("the 70-minute-old bucket still holds IPs: %v", ips)
	}
	m := s.Snapshot(t0.Add(2*time.Hour), 24*time.Hour, "", false, 0, 50)
	for _, c := range m.Clients {
		if c.Client == "python-requests" {
			if c.Requests != 1 || c.IPs != 0 || len(c.TopIPs) != 0 {
				t.Fatalf("a 2h-old client: %+v, want its total and no IPs", c)
			}
			return
		}
	}
	t.Fatal("python-requests missing from the 24h clients")
}

// A record older than what its slot holds (replay, clock skew) never wipes the
// newer bucket; one older than the ring is dropped; a future one counts now.
func TestTrafficMix_OutOfOrderRecords(t *testing.T) {
	s := newTrafficMixStore()
	now := time.Now().Truncate(time.Minute)
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0.1), now)
	// Same slot, 24h earlier minus a bucket: older than the slot's bucket.
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0.1), now.Add(-tmBuckets*tmBucketSec*time.Second))
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0.1), now.Add(-25*time.Hour))
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0.1), now.Add(time.Hour))
	if c := tmClassOf(s.Snapshot(time.Now(), time.Hour, "", false, 0, 0), "bot"); c.Requests != 2 {
		t.Fatalf("bot = %d, want the current one + the future one counted now", c.Requests)
	}
}

// Every bucket of the window is a series point, empty ones as zeros; the peak
// says its window (60 s node-wide, 300 s for one vhost).
func TestTrafficMix_SeriesAndPeakWindow(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0.1), now)
	m := s.Snapshot(now.Add(time.Hour), time.Hour, "", false, 0, 0)
	if len(m.Series) < 12 {
		t.Fatalf("series has %d points for an hour, want one per bucket (>= 12)", len(m.Series))
	}
	zeros := 0
	for _, p := range m.Series {
		if v, ok := p.Classes["bot"]; ok && v == 0 {
			zeros++
		}
	}
	if zeros < 11 {
		t.Fatalf("empty buckets not reported as zeros: %d", zeros)
	}
	if c := tmClassOf(m, "bot"); c.PeakWindow != 60 {
		t.Fatalf("node-wide peak window %d", c.PeakWindow)
	}
	if c := tmClassOf(s.Snapshot(now.Add(time.Hour), time.Hour, "a.example", false, 0, 0), "bot"); c.PeakWindow != tmBucketSec {
		t.Fatalf("per-vhost peak window %d", c.PeakWindow)
	}
}

// Buckets older than an hour keep their top vhosts and clients; the rest is
// summed under _other, so every total stays exact.
func TestTrafficMix_CompactsOldBuckets(t *testing.T) {
	s := newTrafficMixStore()
	t0 := tmBase()
	n := tmOldMaxHosts + 40
	for i := 0; i < n; i++ {
		tmFeed(s, tmOrigin("203.0.113.1", fmt.Sprintf("h%03d.example", i), "GET", "/", fmt.Sprintf("tool%03d/1.0", i), 200, float64(i)/100), t0)
	}
	tmFeed(s, tmOrigin("203.0.113.1", "late.example", "GET", "/", "curl/8", 200, 0), t0.Add(70*time.Minute)) // compacts t0's bucket
	s.mu.Lock()
	b := &s.buckets[(t0.Unix()/tmBucketSec)%tmBuckets]
	hosts, clients, compact := len(b.hosts), len(b.clients[tmBot]), b.compact
	s.mu.Unlock()
	if !compact || hosts != tmOldMaxHosts || clients != tmOldMaxClients {
		t.Fatalf("compacted bucket: compact=%v hosts=%d clients=%d, want %d / %d", compact, hosts, clients, tmOldMaxHosts, tmOldMaxClients)
	}
	m := s.Snapshot(t0.Add(2*time.Hour), 24*time.Hour, "", false, 500, 500)
	if c := tmClassOf(m, "bot"); c.Requests != int64(n+1) {
		t.Fatalf("total after compaction: %d, want %d", c.Requests, n+1)
	}
	var sum int64
	for _, h := range m.Hosts {
		sum += h.Total.Requests
	}
	if sum != int64(n+1) {
		t.Fatalf("vhost rows sum to %d, want %d (the rest under _other)", sum, n+1)
	}
	first := ""
	for _, h := range m.Hosts {
		if h.Host != tmOtherKey { // _other (the summed tail) may be the biggest row
			first = h.Host
			break
		}
	}
	if first != fmt.Sprintf("h%03d.example", n-1) || m.Hosts[0].Host == tmOtherKey {
		t.Fatalf("top vhost after compaction: %s (row 0 %s), want the costliest named one first", first, m.Hosts[0].Host)
	}
	if m.Hosts[len(m.Hosts)-1].Host != tmOtherKey {
		t.Fatalf("_other is not the trailing row: %s", m.Hosts[len(m.Hosts)-1].Host)
	}
	if lim := s.Snapshot(t0.Add(2*time.Hour), 24*time.Hour, "", false, 5, 0); len(lim.Hosts) != 6 || lim.Hosts[5].Host != tmOtherKey {
		t.Fatalf("hosts=5: %d rows, want 5 named + the _other row", len(lim.Hosts))
	}
}

// The window starts on the boundary of the bucket holding since (rounded
// down) and reports that span; a short window just after a boundary still
// covers what was asked.
func TestTrafficMix_WindowStartsOnABucket(t *testing.T) {
	s := newTrafficMixStore()
	b := tmBase().Truncate(tmBucketSec * time.Second)
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0), b.Add(-time.Minute)) // before the window
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0), b.Add(time.Minute))
	tmFeed(s, tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0), b.Add(6*time.Minute))
	m := s.Snapshot(b.Add(17*time.Minute), 15*time.Minute, "", false, 0, 0)
	if c := tmClassOf(m, "bot"); c.Requests != 2 || m.Since != b.Unix() || m.WindowSec != 17*60 {
		t.Fatalf("requests %d, since %d, window %d s; want 2 from the bucket at b, a 17-minute span", c.Requests, m.Since, m.WindowSec)
	}
	// A 24h window never spans more buckets than the ring holds.
	if m := s.Snapshot(b.Add(17*time.Minute+5*time.Second), 24*time.Hour, "", false, 0, 0); len(m.Series) != tmBuckets || m.WindowSec > 24*3600 {
		t.Fatalf("24h: %d series points, %d s; want %d points, <= 24h", len(m.Series), m.WindowSec, tmBuckets)
	}
	// 5 seconds after a boundary, a 5m window still covers >= 5 minutes.
	if m := s.Snapshot(b.Add(10*time.Minute+5*time.Second), 5*time.Minute, "", false, 0, 0); m.WindowSec < 300 {
		t.Fatalf("a 5m window just after a boundary covers %d s", m.WindowSec)
	}
}

// merge_www counts example.com and www.example.com together.
func TestTrafficMix_MergeWWW(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	tmFeed(s, tmOrigin("203.0.113.1", "seedsworld.gr", "GET", "/", "curl/8", 200, 0), now)
	tmFeed(s, tmOrigin("203.0.113.1", "www.seedsworld.gr", "GET", "/", "curl/8", 200, 0), now)
	if m := s.Snapshot(now.Add(time.Minute), time.Hour, "seedsworld.gr", false, 0, 0); m.Total.Requests != 1 {
		t.Fatalf("without merge_www: %d", m.Total.Requests)
	}
	if m := s.Snapshot(now.Add(time.Minute), time.Hour, "www.seedsworld.gr", true, 0, 0); m.Total.Requests != 2 {
		t.Fatalf("with merge_www: %d, want both names", m.Total.Requests)
	}
}

// Every crawler family is a key NormalizeUA can produce, or it never matches.
func TestTrafficMix_CrawlerFamiliesAreUAKeys(t *testing.T) {
	for f := range knownCrawlerFamilies {
		if got := NormalizeUA(f + "/1.0"); got != f {
			t.Errorf("%q normalizes to %q: not a UA key", f, got)
		}
	}
}

// An IPv6 client is its /64 for the behaviour state: rotating the address
// does not reset the per-minute count.
func TestTrafficMix_IPv6Per64(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	for i := 0; i < 30; i++ {
		ip := fmt.Sprintf("2001:db8:1:2::%x", i+1)
		tmFeed(s, tmOrigin(ip, "a.example", "GET", fmt.Sprintf("/p/%d", i), tmChrome152, 200, 0.1), now)
	}
	if c := tmClassOf(s.Snapshot(now.Add(time.Second), time.Hour, "", false, 0, 0), "automation"); c.Requests != 30-(tmAutomationDynPerMin-1) {
		t.Fatalf("rotating inside one /64: automation = %d", c.Requests)
	}
}

// Hosts beyond the cap go to "_other", never dropped.
func TestTrafficMix_HostCap(t *testing.T) {
	s := newTrafficMixStore()
	now := tmBase()
	for i := 0; i < tmMaxHosts+5; i++ {
		tmFeed(s, tmOrigin("203.0.113.1", fmt.Sprintf("h%d.example", i), "GET", "/", "curl/8", 200, 0), now)
	}
	m := s.Snapshot(now.Add(time.Second), time.Hour, "", false, 500, 0)
	if m.Total.Requests != int64(tmMaxHosts+5) {
		t.Fatalf("total %d", m.Total.Requests)
	}
	s.mu.Lock()
	other := s.buckets[(now.Unix()/tmBucketSec)%tmBuckets].hosts[tmOtherKey]
	s.mu.Unlock()
	if other == nil || other[tmBot].Req != 5 {
		t.Fatalf("_other = %+v, want the 5 over the cap", other)
	}
}

func TestTrafficMix_HandlerAdminOnly(t *testing.T) {
	prev := trafficMix
	trafficMix = newTrafficMixStore()
	t.Cleanup(func() { trafficMix = prev })
	trafficMix.observe(tmOrigin("203.0.113.1", "a.example", "GET", "/", "curl/8", 200, 0.2), "a.example", "curl", time.Now())

	e := &Engine{}
	call := func(ctx context.Context, q string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		e.handleTrafficMix(rr, httptest.NewRequest(http.MethodGet, "/api/v1/webdet/traffic-mix"+q, nil).WithContext(ctx))
		return rr
	}
	scoped := context.WithValue(context.WithValue(context.Background(), CtxAuthnKey{}, true), CtxRoleKey{}, CtxRoleScoped)
	if rr := call(scoped, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped caller: %d, want 403", rr.Code)
	}
	admin := context.WithValue(context.WithValue(context.Background(), CtxAuthnKey{}, true), CtxRoleKey{}, CtxRoleAdmin)
	if rr := call(admin, "?window=bogus"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad window: %d, want 400", rr.Code)
	}
	rr := call(admin, "?window=15m")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin: %d %s", rr.Code, rr.Body.String())
	}
	var m TrafficMix
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Schema != "webdet.traffic_mix.v1" || m.WindowSec < 900 || m.WindowSec >= 1200 || tmClassOf(m, "bot").Requests != 1 || m.Note == "" {
		t.Fatalf("response: %+v", m)
	}
}

// BenchmarkTrafficMixObserve is the per-request cost added to ingest.
func BenchmarkTrafficMixObserve(b *testing.B) {
	s := newTrafficMixStore()
	now := tmBase()
	recs := []LogRec{
		tmOrigin("83.212.158.22", "shop.example", "GET", "/shop/?per_page=24", tmChrome152, 200, 0.8),
		tmOrigin("94.65.1.2", "shop.example", "GET", "/wp-content/x.css", tmChrome152, 200, 0.01),
		tmOrigin("57.141.20.42", "other.example", "GET", "/p/1", tmMeta, 200, 0.4),
	}
	nus := []string{NormalizeUA(recs[0].UA), NormalizeUA(recs[1].UA), NormalizeUA(recs[2].UA)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := recs[i%3]
		s.observe(r, r.Host, nus[i%3], now.Add(time.Duration(i)*time.Millisecond))
	}
}
