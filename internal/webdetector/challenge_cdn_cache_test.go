package webdetector

import (
	"net/http"
	"net/url"
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
		if again := cdnBustNext(got); again != "" {
			t.Fatalf("cdnBustNext of an already busted next = %q, want \"\" (one try only)", again)
		}
	}
	if a, b := cdnBustNext("/"), cdnBustNext("/"); a == b {
		t.Fatalf("two busts gave the same URL %q: a cache could hold it", a)
	}
	for _, bad := range []string{"", "shop", "//evil.example/x"} {
		if got := cdnBustNext(bad); got != "" && !strings.HasPrefix(bad, "/") {
			t.Fatalf("cdnBustNext(%q) = %q, want \"\"", bad, got)
		}
	}
}

func TestCDNCachedChallengeHosts(t *testing.T) {
	resetCDNCachedChallengeForTest()
	t.Cleanup(resetCDNCachedChallengeForTest)
	t0 := time.Date(2026, 10, 19, 9, 48, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		noteCDNCachedChallenge("www.anastasiadi.gr", t0.Add(time.Duration(i)*time.Minute))
	}
	noteCDNCachedChallenge("Shop.Example.com ", t0)
	noteCDNCachedChallenge("", t0)
	hs := CDNCachedChallengeHosts(t0.Add(time.Hour))
	if len(hs) != 2 || hs[0].Host != "www.anastasiadi.gr" || hs[0].Count != 3 ||
		!hs[0].First.Equal(t0) || !hs[0].Last.Equal(t0.Add(2*time.Minute)) ||
		hs[1].Host != "shop.example.com" || hs[1].Count != 1 {
		t.Fatalf("hosts = %+v", hs)
	}
	// Past the 24 h window a host drops out, and a new bounce starts afresh.
	if hs := CDNCachedChallengeHosts(t0.Add(25 * time.Hour)); len(hs) != 0 {
		t.Fatalf("after 25 h: %+v, want none", hs)
	}
	noteCDNCachedChallenge("www.anastasiadi.gr", t0.Add(26*time.Hour))
	if hs := CDNCachedChallengeHosts(t0.Add(26 * time.Hour)); len(hs) != 1 || hs[0].Count != 1 {
		t.Fatalf("a bounce after the window: %+v, want a fresh count of 1", hs)
	}
	// Bounded: past the cap the stalest host makes room.
	resetCDNCachedChallengeForTest()
	for i := 0; i < cdnSuspectMaxHosts+5; i++ {
		noteCDNCachedChallenge("h"+string(rune('a'+i%26))+strings.Repeat("x", i/26)+".gr", t0.Add(time.Duration(i)*time.Second))
	}
	hs = CDNCachedChallengeHosts(t0.Add(time.Hour))
	if len(hs) != cdnSuspectMaxHosts {
		t.Fatalf("%d hosts tracked, want the cap %d", len(hs), cdnSuspectMaxHosts)
	}
	for _, h := range hs {
		if h.Host == "ha.gr" {
			t.Fatal("the stalest host was kept past the cap")
		}
	}
}
