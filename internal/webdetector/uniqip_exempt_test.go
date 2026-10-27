package webdetector

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// appleExcludeBridge carries the shipped Apple exclude rule (asn=as714;
// action=skip), shaped like the detectors matcher: AS714 for 17.x, a Greek
// ISP otherwise.
func appleExcludeBridge(t *testing.T) *NginxBridge {
	t.Helper()
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.chalExcludeASNFn = func(ip string) uint32 {
		if strings.HasPrefix(ip, "17.") {
			return 714
		}
		return 6799
	}
	b.ChalExcludeHot = func(host, ua string, asn, ptr func() string, rule string) (string, string, bool) {
		if rule != "CHALLENGE_VHOST" {
			return "", "", false
		}
		return "skip", "asn=as714; action=skip", asn() == "AS714"
	}
	return b
}

func TestParseSocketTSV_BypassColumn(t *testing.T) {
	base := "1791466170.6\t17.166.20.62\ta.gr\tGET\t/\tHTTP/2.0\t200\t7\t0.002\t0.001\t-\tMozilla/5.0"
	cases := []struct {
		tail     string
		upName   string
		bypass   bool
		ua       string
		describe string
	}{
		{"\tcfm_apache\t1", "cfm_apache", true, "mozilla/5.0", "14 columns, on the bypass list"},
		{"\tcfm_apache\t0", "cfm_apache", false, "mozilla/5.0", "14 columns, not on it"},
		{"\tcfm_apache\t-", "cfm_apache", false, "mozilla/5.0", "14 columns, a conf without the geo"},
		{"\tcfm_apache", "cfm_apache", false, "mozilla/5.0", "13 columns (older module)"},
		{"", "", false, "mozilla/5.0", "12 columns (older module)"},
	}
	for _, c := range cases {
		rec, ok := parseSocketTSV(base + c.tail)
		if !ok || rec.UpstreamName != c.upName || rec.Bypass != c.bypass || rec.UA != c.ua {
			t.Errorf("%s: ok=%v up=%q bypass=%v ua=%q", c.describe, ok, rec.UpstreamName, rec.Bypass, rec.UA)
		}
	}
	// A file TSV never carries the column: past 11 is the UA.
	if rec, ok := parseTSV(base + "\tcfm_apache\t1"); !ok || rec.Bypass || rec.UA != "mozilla/5.0\tcfm_apache\t1" {
		t.Errorf("file TSV: ok=%v bypass=%v ua=%q", ok, rec.Bypass, rec.UA)
	}
}

func TestCountedUniqueIPs(t *testing.T) {
	counts := map[string]int{"a": 3, "b": 2, "c": 1, "d": 4}
	if got := countedUniqueIPs(counts, nil); got != 4 {
		t.Errorf("no exempt: got %d, want 4", got)
	}
	// b fully exempt, d partly exempt (one request could be challenged).
	if got := countedUniqueIPs(counts, map[string]int{"b": 2, "d": 3}); got != 3 {
		t.Errorf("b exempt, d partly: got %d, want 3", got)
	}
	if got := countedUniqueIPs(counts, map[string]int{"a": 3, "b": 2, "c": 1, "d": 4}); got != 0 {
		t.Errorf("all exempt: got %d, want 0", got)
	}
}

func TestVhostChallengeExemptClient(t *testing.T) {
	now := time.Now()
	b := appleExcludeBridge(t)
	b.enr = stubPageEnricher{
		"66.249.66.1": {ASN: 15169, PTR: "crawl-66-249-66-1.googlebot.com"},
	}
	b.goodBotExempt = true
	b.goodBot.store("66.249.66.1", "googlebot", now)

	cases := []struct {
		ip, ua   string
		bypass   bool
		want     bool
		describe string
	}{
		{"84.54.49.1", "mozilla/5.0", true, true, "bypass list (edge flag)"},
		{"17.166.20.62", "mozilla/5.0 (applebot/0.1)", false, true, "exclude file asn=as714"},
		{"17.166.20.62", "mozilla/5.0 (macintosh)", false, true, "exclude file: the asn rule needs no UA"},
		{"66.249.66.1", "mozilla/5.0 (compatible; googlebot/2.1)", false, true, "verified good bot, crawler UA"},
		{"66.249.66.1", "mozilla/5.0 (linux; android)", false, true, "verified good bot, browser UA (the edge exempts the IP)"},
		{"79.129.88.110", "mozilla/5.0 (windows nt 10.0)", false, false, "a human"},
		{"79.129.88.111", "mozilla/5.0 (compatible; googlebot/2.1)", false, false, "a spoofed crawler UA, not verified"},
	}
	for _, c := range cases {
		if got := b.vhostChallengeExemptClient(c.ip, "shop.gr", c.ua, c.bypass, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.describe, got, c.want)
		}
	}

	// A stale positive (expired, inside the edge's grace) still exempts, as
	// the edge serves it: the edge refreshes verdicts only while it serves a
	// challenge, so a fresh-only count would re-arm the challenge ~30 min
	// after it went off. Past the grace it counts.
	b.goodBot.store("66.249.66.9", "googlebot", now.Add(-goodBotIPPosTTL-time.Minute))
	if !b.vhostChallengeExemptClient("66.249.66.9", "shop.gr", "mozilla/5.0 (compatible; googlebot/2.1)", false, now) {
		t.Error("a stale good-bot verdict inside the grace must exempt")
	}
	b.goodBot.store("66.249.66.10", "googlebot", now.Add(-goodBotIPPosTTL-goodBotIPStaleGrace-time.Minute))
	if b.vhostChallengeExemptClient("66.249.66.10", "shop.gr", "mozilla/5.0 (compatible; googlebot/2.1)", false, now) {
		t.Error("a verdict past the stale grace must not exempt")
	}
	// The count side never asks the enricher for a PTR (no reverse lookup):
	// a ptr= rule cannot match, so its client counts.
	b.ChalExcludeHot = func(host, ua string, asn, ptr func() string, rule string) (string, string, bool) {
		return "skip", "asn=as15169; ptr=*.googlezip.net", ptr() != ""
	}
	if b.vhostChallengeExemptClient("66.249.80.1", "shop.gr", "mozilla/5.0", false, now) {
		t.Error("a ptr= rule must not exempt on the count side")
	}
	b.ChalExcludeHot = appleExcludeBridge(t).ChalExcludeHot

	// CHALLENGE_GOODBOT_EXEMPT=0: the edge challenges a verified crawler, so it counts.
	b.goodBotExempt = false
	if b.vhostChallengeExemptClient("66.249.66.1", "shop.gr", "mozilla/5.0 (compatible; googlebot/2.1)", false, now) {
		t.Error("good-bot exemption off: a verified crawler must count")
	}
	// No exclude file loaded: Apple counts again (the operator dropped the rule).
	b.ChalExcludeHot = nil
	if b.vhostChallengeExemptClient("17.166.20.62", "shop.gr", "mozilla/5.0 (applebot/0.1)", false, now) {
		t.Error("no exclude rule: Apple must count")
	}
	// The bypass flag needs no bridge state at all.
	var nb *NginxBridge
	if !nb.vhostChallengeExemptClient("1.2.3.4", "shop.gr", "", true, now) || nb.vhostChallengeExemptClient("1.2.3.4", "shop.gr", "", false, now) {
		t.Error("nil bridge: only the bypass flag may exempt")
	}
}

// TestUniqIPExemptCount reproduces qualityweb (2026-10-27): a crawl from
// hundreds of Apple IPs on a shop must not push the vhost uniqIP over the
// threshold, while the humans on it still count; with the kill switch off the
// old count comes back.
func TestUniqIPExemptCount(t *testing.T) {
	for _, on := range []bool{true, false} {
		e := NewEngine(Config{
			Every:                           time.Second,
			Window:                          2 * time.Minute,
			ChallengeSuspiciousUniqIPExempt: on,
		})
		ab := appleExcludeBridge(t)
		e.nginxBridge.chalExcludeASNFn = ab.chalExcludeASNFn
		e.nginxBridge.ChalExcludeHot = ab.ChalExcludeHot
		e.nginxBridge.enr = stubPageEnricher{}

		e.nginxBridge.goodBotExempt = true
		e.nginxBridge.goodBot.store("66.249.66.1", "googlebot", time.Now())

		// Spread over the window so the count spans several buckets.
		t0 := float64(time.Now().Add(-90 * time.Second).Unix())
		n := 0
		rec := func(ip, ua string, bypass bool) LogRec {
			n++
			return LogRec{TS: t0 + float64(n%90), IP: ip, Host: "www.trimel.gr", Method: "get", URI: "/", Status: 200, UA: ua, Bypass: bypass}
		}
		e.ingest(rec("66.249.66.1", "mozilla/5.0 (compatible; googlebot/2.1)", false), "raw") // verified good bot
		for i := 0; i < 300; i++ {                                                            // Applebot through the exclude file
			e.ingest(rec(fmt.Sprintf("17.166.%d.%d", i/250, i%250+1), "mozilla/5.0 (applebot/0.1)", false), "raw")
		}
		for i := 0; i < 50; i++ { // a bypass-listed crawler range
			e.ingest(rec(fmt.Sprintf("40.77.167.%d", i+1), "mozilla/5.0 (compatible; bingbot/2.0)", true), "raw")
		}
		for i := 0; i < 40; i++ { // humans
			e.ingest(rec(fmt.Sprintf("79.129.88.%d", i+1), "mozilla/5.0 (windows nt 10.0)", false), "raw")
		}
		// An Apple IP that also browses outside the rule's reach would count;
		// here the asn rule covers every UA, so it stays exempt.
		e.ingest(rec("17.166.0.1", "mozilla/5.0 (macintosh)", false), "raw")

		e.mu.Lock()
		m := e.snapshotMiniLocked(time.Now())["www.trimel.gr"]
		e.mu.Unlock()
		want := 391
		if on {
			want = 40
		}
		if m.UniqueIPs != want {
			t.Errorf("exempt=%v: UniqueIPs = %d, want %d", on, m.UniqueIPs, want)
		}
	}
}

// TestUniqIPExemptInjectObserved: a WAF hit re-fed through InjectObserved
// applies the same exemption, so an exempt crawler that trips the WAF stays
// out of the count while a human who does still counts.
func TestUniqIPExemptInjectObserved(t *testing.T) {
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, ChallengeSuspiciousUniqIPExempt: true})
	ab := appleExcludeBridge(t)
	e.nginxBridge.chalExcludeASNFn = ab.chalExcludeASNFn
	e.nginxBridge.ChalExcludeHot = ab.ChalExcludeHot

	ts := float64(time.Now().Unix())
	e.ingest(LogRec{TS: ts, IP: "17.166.20.62", Host: "shop.gr", Method: "get", URI: "/", Status: 200, UA: "mozilla/5.0 (applebot/0.1)"}, "raw")
	e.InjectObserved("17.166.20.62", "shop.gr", "/?x=<script>", "GET", 403, "WAF_XSS", 302, "Mozilla/5.0 (Applebot/0.1)")
	e.ingest(LogRec{TS: ts, IP: "79.129.88.110", Host: "shop.gr", Method: "get", URI: "/", Status: 200, UA: "mozilla/5.0"}, "raw")
	e.InjectObserved("79.129.88.110", "shop.gr", "/?x=<script>", "GET", 403, "WAF_XSS", 302, "Mozilla/5.0")

	e.mu.Lock()
	m := e.snapshotMiniLocked(time.Now())["shop.gr"]
	e.mu.Unlock()
	if m.UniqueIPs != 1 {
		t.Errorf("UniqueIPs = %d, want 1 (the human; Apple stays exempt through its WAF hit)", m.UniqueIPs)
	}
}
