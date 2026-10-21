package webdetector

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func assertNoStoreForCDN(t *testing.T, what string, h http.Header) {
	t.Helper()
	for _, k := range []string{"Cache-Control", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control"} {
		if h.Get(k) != "no-store" {
			t.Fatalf("%s: %s = %q, want no-store", what, k, h.Get(k))
		}
	}
}

// mars, anastasiadi.gr, 2026-10-19: the challenge server answered a challenged
// "/" with the page itself, and a Cloudflare rule overriding the origin's
// Cache-Control cached it for the whole homepage: every visitor got another
// visitor's token and no cfm_chal cookie. The page now lives only at
// /__cfm_challenge; "/" redirects there like every other content URL.
func TestChallengePage_RootRedirectsToTheChallengePath(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	base, _ := startVerifyServer(t)
	resetThrottleStores(t)
	get := func(path string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:158.0) Gecko/20100101 Firefox/158.0")
		req.Header.Set("X-Real-IP", "87.202.177.128")
		req.Header.Set("X-Forwarded-Host", "anastasiadi.gr")
		resp, err := noFollow().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	for _, tc := range []struct{ path, next string }{
		{"/", "/"},
		{"/?utm_source=fb", "/?utm_source=fb"},
		{"/shop/?a=1", "/shop/?a=1"},
		// The old "/?next=X" page form is not read any more: a tenant
		// homepage's own next parameter stays the target's query.
		{"/?next=" + url.QueryEscape("/account"), "/?next=" + url.QueryEscape("/account")},
		// ... whatever it holds: it is a query value, never the target.
		{"/?next=" + url.QueryEscape("//evil.example/x"), "/?next=" + url.QueryEscape("//evil.example/x")},
	} {
		r := get(tc.path)
		want := challengePath + "?next=" + url.QueryEscape(tc.next)
		if r.StatusCode != http.StatusFound || r.Header.Get("Location") != want {
			t.Fatalf("GET %s: %d %q, want 302 to %q", tc.path, r.StatusCode, r.Header.Get("Location"), want)
		}
		assertNoStoreForCDN(t, "GET "+tc.path, r.Header)
	}
	r := get(challengePath + "?next=%2F")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("the challenge path: %d, want the page", r.StatusCode)
	}
	assertNoStoreForCDN(t, "the challenge page", r.Header)
}

func TestCDNBustNext(t *testing.T) {
	// Empty pairs too: the edge strips only the cfm_nc pairs again, and the
	// origin must get the original query back (cfm.lua strip_cdn_bust_arg).
	for _, next := range []string{"/", "/shop/", "/?a=1&b=%2F", "/wp-admin/post.php?post=7&cfm_rt=abc", "/x?a=1&&b=", "/x?a=1&"} {
		got := cdnBustNext(next)
		sep := "?"
		if strings.Contains(next, "?") {
			sep = "&"
		}
		if !strings.HasPrefix(got, next+sep+cdnBustParam+"=") || len(got) != len(next)+len(sep)+len(cdnBustParam)+1+12 {
			t.Fatalf("cdnBustNext(%q) = %q, want next kept byte for byte plus %s%s=<12 hex>", next, got, sep, cdnBustParam)
		}
		// An already busted next (a bookmarked or shared URL a CDN may have
		// cached too) gets a FRESH value: the old one is replaced, not kept.
		again := cdnBustNext(got)
		if again == got || strings.Count(again, cdnBustParam+"=") != 1 || !strings.HasPrefix(again, next+sep+cdnBustParam+"=") {
			t.Fatalf("cdnBustNext(%q) = %q, want next with one fresh %s", got, again, cdnBustParam)
		}
	}
	// The bound is the result's length: one byte under it still busts.
	room := maxNextLen - len("?"+cdnBustParam+"=") - 12
	if got := cdnBustNext("/" + strings.Repeat("a", room-1)); len(got) != maxNextLen {
		t.Fatalf("a next that busts to exactly maxNextLen gave %d bytes, want %d", len(got), maxNextLen)
	}
	if got := cdnBustNext("/" + strings.Repeat("a", room)); got != "" {
		t.Fatalf("a next one byte past the bound busted to %d bytes", len(got))
	}
	if a, b := cdnBustNext("/"), cdnBustNext("/"); a == b {
		t.Fatalf("two busts gave the same URL %q: a cache could hold it", a)
	}
	// A fragment (a cfm_nc after '#' never reaches the server) and a result
	// past maxNextLen (the bounce would normalize to "/") are refused too.
	for _, bad := range []string{"", "shop", "//evil.example/x", "/\\evil.example", "/foo#x", "/foo?a=1#x",
		"/" + strings.Repeat("a", maxNextLen-10)} {
		if got := cdnBustNext(bad); got != "" {
			t.Fatalf("cdnBustNext(%q) = %q, want \"\"", bad, got)
		}
	}
}

func TestCDNCachedChallengeHosts(t *testing.T) {
	resetCDNCachedChallengeForTest()
	t.Cleanup(resetCDNCachedChallengeForTest)
	t0 := time.Date(2026, 10, 19, 9, 48, 0, 0, time.UTC)
	// One client bouncing many times is ONE IP: the Host header is its own, so
	// it must not be able to make a host look like a CDN casualty.
	for i := 0; i < 5; i++ {
		noteCDNCachedChallenge("www.anastasiadi.gr", "87.202.177.128", t0.Add(time.Duration(i)*time.Second))
	}
	noteCDNCachedChallenge("www.anastasiadi.gr", "94.65.1.2", t0.Add(time.Minute))
	noteCDNCachedChallenge("www.anastasiadi.gr", "2a02:587::1", t0.Add(2*time.Minute))
	noteCDNCachedChallenge("Shop.Example.com ", "203.0.113.5", t0)
	noteCDNCachedChallenge("", "203.0.113.5", t0)
	noteCDNCachedChallenge("x.gr", "", t0)
	hs := CDNCachedChallengeHosts(t0.Add(time.Hour))
	if len(hs) != 2 || hs[0].Host != "www.anastasiadi.gr" || hs[0].IPs != 3 || hs[0].Bounces != 7 ||
		!hs[0].First.Equal(t0) || !hs[0].Last.Equal(t0.Add(2*time.Minute)) ||
		hs[1].Host != "shop.example.com" || hs[1].IPs != 1 {
		t.Fatalf("hosts = %+v", hs)
	}
	// A real 24 h window per IP: one stray bounce a day does not add up.
	noteCDNCachedChallenge("www.anastasiadi.gr", "198.51.100.9", t0.Add(23*time.Hour))
	if hs := CDNCachedChallengeHosts(t0.Add(24*time.Hour + 30*time.Minute)); len(hs) != 1 || hs[0].IPs != 1 {
		t.Fatalf("after 24.5 h: %+v, want only the IP seen at 23 h", hs)
	}
	if hs := CDNCachedChallengeHosts(t0.Add(48 * time.Hour)); len(hs) != 0 {
		t.Fatalf("after 48 h: %+v, want none", hs)
	}
	// One IPv6 subscriber holds a whole /64: its addresses are ONE client.
	resetCDNCachedChallengeForTest()
	for _, a := range []string{"2a02:587:1:2::1", "2a02:587:1:2::2", "2a02:587:1:2:aaaa::9"} {
		noteCDNCachedChallenge("v6.gr", a, t0)
	}
	noteCDNCachedChallenge("v6.gr", "2a02:587:1:3::1", t0)
	noteCDNCachedChallenge("v6.gr", "::ffff:203.0.113.7", t0)
	if hs := CDNCachedChallengeHosts(t0); len(hs) != 1 || hs[0].IPs != 3 || hs[0].Bounces != 5 {
		t.Fatalf("IPv6 per /64: %+v, want 3 clients (one /64, another /64, one mapped IPv4) over 5 bounces", hs)
	}
	// The host is the client's own Host header: cut to 120 bytes.
	resetCDNCachedChallengeForTest()
	noteCDNCachedChallenge(strings.Repeat("a", 300)+".gr", "203.0.113.5", t0)
	if hs := CDNCachedChallengeHosts(t0); len(hs) != 1 || len(hs[0].Host) != 120 {
		t.Fatalf("a long Host kept %d bytes, want 120", len(hs[0].Host))
	}
	// A host keeps at most cdnSuspectMaxIPsHost addresses.
	resetCDNCachedChallengeForTest()
	for i := 0; i < cdnSuspectMaxIPsHost+10; i++ {
		noteCDNCachedChallenge("big.gr", "10.0.0."+strconv.Itoa(i), t0)
	}
	if hs := CDNCachedChallengeHosts(t0); hs[0].IPs != cdnSuspectMaxIPsHost {
		t.Fatalf("%d IPs kept, want the cap %d", hs[0].IPs, cdnSuspectMaxIPsHost)
	}
	// Bounded: past the cap the stalest host makes room.
	resetCDNCachedChallengeForTest()
	for i := 0; i < cdnSuspectMaxHosts+5; i++ {
		noteCDNCachedChallenge("h"+strconv.Itoa(i)+".gr", "203.0.113.1", t0.Add(time.Duration(i)*time.Second))
	}
	hs = CDNCachedChallengeHosts(t0.Add(time.Hour))
	if len(hs) != cdnSuspectMaxHosts {
		t.Fatalf("%d hosts tracked, want the cap %d", len(hs), cdnSuspectMaxHosts)
	}
	for _, h := range hs {
		if h.Host == "h0.gr" {
			t.Fatal("the stalest host was kept past the cap")
		}
	}
}

// The panel listeners sit behind no CDN: a cleared bounce there is a validator
// disagreement, so it gets the page as before and is never counted.
func TestChallengePage_PanelBounceIsNotACDN(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	base, _ := startVerifyServer(t)
	resetThrottleStores(t)
	resetCDNCachedChallengeForTest()
	t.Cleanup(resetCDNCachedChallengeForTest)
	const ip, host = "203.0.113.79", "cpanel.example.com"
	hdr := map[string]string{"X-CFM-Panel-Port": "2083", "X-Forwarded-Port": "2083"}
	clr := &http.Cookie{Name: "cfm_clearance_p2083", Value: issueClearanceToken(ip, host, "panel:2083", time.Now().Add(time.Hour))}
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	if r := doChallengePage(t, http.MethodGet, base, ip, host, ua, "/cpsess1/frontend/", hdr, clr); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("first: %d, want 303", r.StatusCode)
	}
	if r := doChallengePage(t, http.MethodGet, base, ip, host, ua, "/cpsess1/frontend/", hdr, clr); r.StatusCode != http.StatusOK {
		t.Fatalf("second panel bounce: %d %q, want the page (no cache-bust on a panel port)", r.StatusCode, r.Header.Get("Location"))
	}
	if hs := CDNCachedChallengeHosts(time.Now()); len(hs) != 0 {
		t.Fatalf("a panel bounce was counted as a CDN: %+v", hs)
	}
}

// edge_health reads ChallengeServerServing to tell "nothing bounced" from
// "nothing could bounce": Start raises it, Stop lowers it again.
func TestChallengeServerServing(t *testing.T) {
	before := challengeHTTPServing.Load()
	srv := NewChallengeServer(nil)
	if err := srv.Start(context.Background(), "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !ChallengeServerServing() || challengeHTTPServing.Load() != before+1 {
		t.Fatalf("after Start: serving=%d, want %d", challengeHTTPServing.Load(), before+1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Serve returns asynchronously after Shutdown.
	for deadline := time.Now().Add(2 * time.Second); challengeHTTPServing.Load() != before; {
		if time.Now().After(deadline) {
			t.Fatalf("after Stop: serving=%d, want %d", challengeHTTPServing.Load(), before)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// orion, 2026-10-21: edge_health named www.mathematica.gr, a vhost with no
// CDN at all. Every bounce was a PDF opened on Android: the download leaves the
// tab on /__cfm_challenge?next=…pdf, and each re-tap reaches the page as a
// cleared client for the same target. Only a relayed bounce for a page counts
// for the warning (and one from an edge conf that sends no header, as before);
// a direct page bounce and a relayed download go to lists edge_health only
// shows; a direct download is not counted. The cache-bust redirect itself is unchanged in every case.
func TestChallengePage_DirectBounceNotCountedAsCDN(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	base, _ := startVerifyServer(t)
	ua := "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36"
	bounce := func(ip, host, next string, hdr map[string]string) {
		t.Helper()
		clr := &http.Cookie{Name: "cfm_clearance", Value: issueClearanceToken(ip, host, "web", time.Now().Add(time.Hour))}
		if r := doChallengePage(t, http.MethodGet, base, ip, host, ua, next, hdr, clr); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != next {
			t.Fatalf("%s first: %d %q, want 303 to next", ip, r.StatusCode, r.Header.Get("Location"))
		}
		sep := "?"
		if strings.Contains(next, "?") {
			sep = "&"
		}
		if r := doChallengePage(t, http.MethodGet, base, ip, host, ua, next, hdr, clr); r.StatusCode != http.StatusSeeOther || !strings.HasPrefix(r.Header.Get("Location"), next+sep+"cfm_nc=") {
			t.Fatalf("%s second: %d %q, want the one cache-bust (unchanged)", ip, r.StatusCode, r.Header.Get("Location"))
		}
	}
	count := func(list []CDNCacheSuspect, host string) int {
		for _, s := range list {
			if s.Host == host {
				return s.IPs
			}
		}
		return 0
	}
	relayed := map[string]string{cdnRelayedHeader: "1"}
	direct := map[string]string{cdnRelayedHeader: "0"}

	resetThrottleStores(t)
	resetCDNCachedChallengeForTest()
	t.Cleanup(resetCDNCachedChallengeForTest)
	// mathematica.gr as it happened: direct, PDFs. Counted nowhere.
	for _, ip := range []string{"94.46.1.1", "87.228.1.1", "109.242.1.1"} {
		bounce(ip, "www.mathematica.gr", "/forum/oldfiles/mk_285_1.pdf", direct)
	}
	// The same download behind Cloudflare: listed apart, never a suspect (a
	// phone re-tapping it, or a CDN rule caching file extensions only).
	for _, ip := range []string{"62.74.2.1", "62.74.2.2", "62.74.2.3"} {
		bounce(ip, "cf-pdfs.example", "/files/Report.PDF?v=2", relayed)
	}
	// A page bounced directly: listed, not a CDN suspect.
	for _, ip := range []string{"198.51.100.11", "198.51.100.12", "198.51.100.13"} {
		bounce(ip, "direct-page.example", "/shop/", direct)
	}
	// rigel's amabilecreations.com: "/" through Cloudflare. A suspect.
	for _, ip := range []string{"2a02:587:1::1", "62.74.1.1", "186.247.1.1"} {
		bounce(ip, "www.amabilecreations.com", "/", relayed)
	}
	// An edge conf from before the header: counted as before.
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		bounce(ip, "old-conf.example", "/", nil)
	}
	now := time.Now()
	sus, dir, dl := CDNCachedChallengeHosts(now), DirectClearedBounceHosts(now), RelayedDownloadBounceHosts(now)
	for host, want := range map[string][3]int{
		"www.mathematica.gr":       {0, 0, 0},
		"cf-pdfs.example":          {0, 0, 3},
		"direct-page.example":      {0, 3, 0},
		"www.amabilecreations.com": {3, 0, 0},
		"old-conf.example":         {2, 0, 0},
	} {
		if got := [3]int{count(sus, host), count(dir, host), count(dl, host)}; got != want {
			t.Errorf("%s: (suspect, direct, download) clients = %v, want %v", host, got, want)
		}
	}
}

func TestCDNDownloadTarget(t *testing.T) {
	for _, next := range []string{
		"/forum/oldfiles/mk_285_1.pdf", "/a/B.PDF", "/x.zip?dl=1", "/docs/file%2Epdf",
		"/x.docx#page=2", "/x.pdf?cfm_nc=ab", "/media/v.mp4",
	} {
		if !cdnDownloadTarget(next) {
			t.Errorf("cdnDownloadTarget(%q) = false, want true", next)
		}
	}
	for _, next := range []string{
		"/", "/shop/", "/product/x.html", "/index.php?file=x.pdf", "/v1.2/page",
		"/pdf", "/x.pdf/", "/wp-admin/admin-ajax.php", "/?s=a.zip",
	} {
		if cdnDownloadTarget(next) {
			t.Errorf("cdnDownloadTarget(%q) = true, want false", next)
		}
	}
}

func TestCDNRelayedHeaderValues(t *testing.T) {
	for v, want := range map[string]bool{"0": false, " 0 ": false, "1": true, "": true, "yes": true} {
		if got := cdnRelayedCounts(v); got != want {
			t.Errorf("cdnRelayedCounts(%q) = %v, want %v", v, got, want)
		}
	}
	for v, want := range map[string]string{"0": "0", "1": "1", "": "-", "x\" note=forged": "?"} {
		if got := cdnRelayedLogValue(v); got != want {
			t.Errorf("cdnRelayedLogValue(%q) = %q, want %q", v, got, want)
		}
	}
}
