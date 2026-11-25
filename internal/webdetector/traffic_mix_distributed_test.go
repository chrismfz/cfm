package webdetector

import (
	"fmt"
	"testing"
	"time"
)

const (
	tmMacChrome136 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
	tmAndroid157   = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36"
	tmWin158       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
)

func tmFindClient(m TrafficMix, client string) *TrafficMixClient {
	for i := range m.Clients {
		if m.Clients[i].Client == client {
			return &m.Clients[i]
		}
	}
	return nil
}

// titan, 2026-11-24: the shapes the tell was written from.
func TestTrafficMix_DistributedTell(t *testing.T) {
	s := newTrafficMixStore()
	end := time.Now().Truncate(5 * time.Minute)
	start := end.Add(-time.Hour)
	at := func(i, n int) time.Time { return start.Add(time.Duration(i) * time.Hour / time.Duration(n)) }

	// The scraper: 460 residential IPs, 1-2 heavy pages each, nothing else.
	for i := 0; i < 460; i++ {
		ip := fmt.Sprintf("10.%d.%d.1", i/200, i%200)
		for j := 0; j <= i%2; j++ {
			tmFeed(s, tmOrigin(ip, fmt.Sprintf("shop%d.gr", i%60), "GET", fmt.Sprintf("/c/%d?f=%d", i, j), tmMacChrome136, 200, 4), at(i, 460))
		}
	}
	// Real visitors: 150 IPs browsing ~40 requests each, most of them static / XHR.
	for i := 0; i < 150; i++ {
		ip := fmt.Sprintf("172.16.%d.%d", i/200, i%200)
		for j := 0; j < 40; j++ {
			uri := "/wp-content/uploads/a.jpg"
			if j%4 == 0 {
				uri = fmt.Sprintf("/product/%d", j)
			}
			tmFeed(s, tmOrigin(ip, "shop1.gr", "GET", uri, tmAndroid157, 200, 0.1), at(i*40+j, 150*40))
		}
	}
	// A CDN-fronted site's visitors: no static reaches the edge, but many pages each.
	for i := 0; i < 80; i++ {
		ip := fmt.Sprintf("192.168.%d.%d", i/200, i%200)
		for j := 0; j < 20; j++ {
			tmFeed(s, tmOrigin(ip, "cdn.gr", "GET", fmt.Sprintf("/p/%d", j), tmWin158, 200, 0.2), at(i*20+j, 80*20))
		}
	}

	m := s.SnapshotSorted(end, time.Hour, "", false, 10, 50, TrafficMixSortRequests)
	scr := tmFindClient(m, tmMacChrome136)
	if scr == nil || scr.Class != "human" {
		t.Fatalf("scraper row = %+v (it is a browser UA under every per-IP limit: human class)", scr)
	}
	if scr.Distributed == nil {
		t.Fatalf("scraper not flagged: %+v ev=%v", scr, *scr.EvidenceShare)
	}
	if d := scr.Distributed; d.IPs < 400 || d.ReqPerIP > 2 || d.EvidenceShare != 0 {
		t.Fatalf("tell evidence = %+v", *d)
	}
	if d := scr.Distributed; d.EstIPs != d.IPs || d.Nets != 3 {
		t.Fatalf("under the IP cap the estimate is the count (%d vs %d); nets = %d, want the 3 /16s", d.EstIPs, d.IPs, d.Nets)
	}
	if h := scr.Distributed.Hosts; len(h) != tmDistTopHosts+1 || h[len(h)-1].Host != tmOtherKey || h[0].Requests < h[1].Requests {
		t.Fatalf("hosts = %+v, want the top %d by requests then _other", h, tmDistTopHosts)
	} else {
		var sum int64
		for _, x := range h {
			sum += x.Requests
		}
		if sum != scr.Distributed.Requests {
			t.Fatalf("hosts sum to %d of the hour's %d requests", sum, scr.Distributed.Requests)
		}
	}
	if len(scr.TopIPs) < 400 {
		t.Fatalf("flagged client lists %d IPs, want its addresses (up to %d) for a challenge", len(scr.TopIPs), manualIPChallengeMax)
	}
	for _, ua := range []string{tmAndroid157, tmWin158} {
		c := tmFindClient(m, ua)
		if c == nil || c.Distributed != nil {
			t.Fatalf("%s: %+v, want unflagged", ua, c)
		}
		if len(c.TopIPs) != 0 || c.IPs == 0 {
			t.Fatalf("%s: visitors' addresses listed (%d) or no count (%d)", ua, len(c.TopIPs), c.IPs)
		}
	}
	if c := tmFindClient(m, tmAndroid157); c.EvidenceShare == nil || *c.EvidenceShare < 0.7 {
		t.Fatalf("visitors' evidence share = %v", c.EvidenceShare)
	}
}

// A population past the per-bucket IP cap is still read right: requests per
// IP come from the addresses kept, not all requests over a capped count.
func TestTrafficMix_DistributedTellPastTheIPCap(t *testing.T) {
	s := newTrafficMixStore()
	end := time.Now().Truncate(5 * time.Minute)
	start := end.Add(-time.Hour)
	for i := 0; i < 2400; i++ { // 200 new addresses per 5 minutes, one page each
		tmFeed(s, tmOrigin(fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256), "a.gr", "GET", fmt.Sprintf("/x/%d", i), tmMacChrome136, 200, 3),
			start.Add(time.Duration(i)*time.Hour/2400))
	}
	c := tmFindClient(s.SnapshotSorted(end, time.Hour, "", false, 10, 10, ""), tmMacChrome136)
	if c == nil || c.Distributed == nil || c.Distributed.ReqPerIP != 1 {
		t.Fatalf("a population past the cap: %+v", c)
	}
	// rigel, 2026-11-25: 767 kept of 18,078. The count is the sample; the
	// estimate is the pool.
	// (The hour is the window's last 12 buckets: 2200 of the 2400 here.)
	if d := c.Distributed; d.IPs > tmIPBuckets*tmMaxHumanClientIPs || int64(d.EstIPs) != d.Requests || d.EstIPs <= 2*d.IPs {
		t.Fatalf("kept %d, estimated %d of the hour's %d one-request addresses", d.IPs, d.EstIPs, d.Requests)
	}
	if h := c.Distributed.Hosts; len(h) != 1 || h[0] != (TrafficMixClientHost{Host: "a.gr", Requests: c.Distributed.Requests}) {
		t.Fatalf("hosts = %+v", h)
	}
}

// sort=ips ranks a distributed pool by its estimate, not by the sample its
// buckets kept: ~2,200 one-request addresses outrank 840 visitors.
func TestTrafficMix_SortByIPsUsesTheEstimate(t *testing.T) {
	s := newTrafficMixStore()
	end := time.Now().Truncate(5 * time.Minute)
	start := end.Add(-time.Hour)
	for i := 0; i < 2400; i++ {
		tmFeed(s, tmOrigin(fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256), "a.gr", "GET", fmt.Sprintf("/x/%d", i), tmMacChrome136, 200, 1),
			start.Add(time.Duration(i)*time.Hour/2400))
	}
	// 840 visitors (70 a bucket: their kept count saturates like the pool's)
	// with more origin time: by kept count they tie the pool and win on
	// origin time; by the pool's estimate they do not.
	for i := 0; i < 840; i++ {
		ip := fmt.Sprintf("172.20.%d.%d", i/256, i%256)
		for j := 0; j < 4; j++ {
			tmFeed(s, tmOrigin(ip, "b.gr", "GET", "/wp-content/a.css", tmAndroid157, 200, 3), start.Add(time.Duration(i*4+j)*time.Hour/3360))
		}
	}
	m := s.SnapshotSorted(end, time.Hour, "", false, 10, 10, TrafficMixSortIPs)
	var order []string
	for _, c := range m.Clients {
		order = append(order, c.Client)
	}
	if len(m.Clients) < 2 || m.Clients[0].Client != tmMacChrome136 || m.Clients[0].IPs > tmFindClient(m, tmAndroid157).IPs {
		t.Fatalf("order %q: want the pool first, ranked by its estimate over a bigger kept count", order)
	}
}

// A client past the per-bucket vhost cap counts the rest under _other, and
// the hour still adds up.
func TestTrafficMix_DistributedHostsPastTheCap(t *testing.T) {
	s := newTrafficMixStore()
	end := time.Now().Truncate(5 * time.Minute)
	start := end.Add(-time.Hour)
	for i := 0; i < 600; i++ {
		host := fmt.Sprintf("v%d.gr", i%40) // 40 vhosts, more than a bucket keeps
		if i%2 == 0 {
			host = "big.gr"
		}
		tmFeed(s, tmOrigin(fmt.Sprintf("10.9.%d.%d", i/256, i%256), host, "GET", "/p", tmMacChrome136, 200, 1), start.Add(time.Duration(i)*time.Hour/600))
	}
	c := tmFindClient(s.SnapshotSorted(end, time.Hour, "", false, 10, 10, ""), tmMacChrome136)
	if c == nil || c.Distributed == nil {
		t.Fatalf("not flagged: %+v", c)
	}
	d := c.Distributed
	h := d.Hosts
	if h[0].Host != "big.gr" || h[0].Requests*2 != d.Requests || h[len(h)-1].Host != tmOtherKey {
		t.Fatalf("hosts = %+v of %d", h, d.Requests)
	}
	var sum int64
	for _, x := range h {
		sum += x.Requests
	}
	if sum != d.Requests {
		t.Fatalf("hosts sum to %d, want the hour's %d", sum, d.Requests)
	}
}

// The cap is on NAMED vhosts: "_other" does not take one of the 16.
func TestTMCountHostCap(t *testing.T) {
	m := map[string]int64{}
	for i := 0; i < tmMaxHumanClientHosts+5; i++ {
		tmCountHost(m, fmt.Sprintf("h%d.gr", i), 1)
	}
	tmCountHost(m, "late.gr", 1)
	if len(m) != tmMaxHumanClientHosts+1 || m[tmOtherKey] != 6 {
		t.Fatalf("%d keys, _other=%d: want %d named + _other holding 6", len(m), m[tmOtherKey], tmMaxHumanClientHosts)
	}
}

func TestTMNetCount(t *testing.T) {
	ips := map[string]int64{
		"10.1.2.3": 1, "10.1.9.9": 1, // one /16
		"10.2.0.1":         1,
		"::ffff:10.1.7.7":  1, // the mapped form of the first /16
		"2a02:587:1::1":    1,
		"2a02:587:ffff::1": 1, // the same /32
		"2a02:588::1":      1,
		"not-an-ip":        1,
	}
	if n := tmNetCount(ips); n != 4 {
		t.Fatalf("nets = %d, want 4", n)
	}
}

func TestDistributedTellThresholds(t *testing.T) {
	for _, tc := range []struct {
		ips            int
		sampled, r, ev int64
		want           bool
	}{
		{460, 600, 600, 0, true},
		{460, 600, 600, 59, true},   // < 10% evidence
		{460, 600, 600, 60, false},  // 10%
		{460, 1400, 1400, 0, false}, // 3 req/IP
		{49, 60, 600, 0, false},     // too few addresses
		{60, 70, 199, 0, false},     // too few requests
	} {
		if got := distributedTell(tc.ips, tc.sampled, tc.r, tc.ev) != nil; got != tc.want {
			t.Errorf("%+v: %v, want %v", tc, got, tc.want)
		}
	}
}

// A busy visitor population saturates the per-bucket IP cap, so its sampled
// requests per IP read low; its evidence share keeps it unflagged.
func TestTrafficMix_DistributedTellBusyVisitors(t *testing.T) {
	s := newTrafficMixStore()
	end := time.Now().Truncate(5 * time.Minute)
	start := end.Add(-time.Hour)
	n := 0
	for b := 0; b < 12; b++ { // 150 new visitors every 5 minutes, 40 requests each, 3 in 4 static
		for v := 0; v < 150; v++ {
			ip := fmt.Sprintf("10.%d.%d.9", b, v)
			for j := 0; j < 40; j++ {
				uri := "/wp-content/x.css"
				if j%4 == 0 {
					uri = fmt.Sprintf("/p/%d", j)
				}
				tmFeed(s, tmOrigin(ip, "a.gr", "GET", uri, tmAndroid157, 200, 0.1), start.Add(time.Duration(b)*5*time.Minute+time.Duration(n%290)*time.Second))
				n++
			}
		}
	}
	c := tmFindClient(s.SnapshotSorted(end, time.Hour, "", false, 10, 10, ""), tmAndroid157)
	if c == nil || c.Distributed != nil {
		t.Fatalf("busy visitors flagged: %+v", c)
	}
}
