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
