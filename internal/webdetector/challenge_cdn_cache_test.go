package webdetector

import (
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
		// The legacy "/?next=X" form keeps its target.
		{"/?next=" + url.QueryEscape("/wp-admin/post.php?post=7"), "/wp-admin/post.php?post=7"},
		// ... normalized like every next: never another origin.
		{"/?next=" + url.QueryEscape("//evil.example/x"), "/"},
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
	for _, next := range []string{"/", "/shop/", "/?a=1&b=%2F", "/wp-admin/post.php?post=7&cfm_rt=abc"} {
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
	if a, b := cdnBustNext("/"), cdnBustNext("/"); a == b {
		t.Fatalf("two busts gave the same URL %q: a cache could hold it", a)
	}
	for _, bad := range []string{"", "shop", "//evil.example/x", "/\\evil.example"} {
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
