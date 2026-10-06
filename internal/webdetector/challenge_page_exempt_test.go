package webdetector

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"cfm/internal/enrich"
)

// stubPageEnricher is the bridge's enrich source for the challenge-page
// exemption tests: a fixed record per IP, no mmdb, no DNS.
type stubPageEnricher map[string]enrich.Result

func (s stubPageEnricher) Lookup(ip string) enrich.Result              { return s[ip] }
func (s stubPageEnricher) LookupCachedOrAsync(ip string) enrich.Result { return s[ip] }

const (
	readAloudIP   = "66.102.8.73"
	readAloudUA   = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)"
	pageBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
)

// exemptPageBridge is a bridge carrying the shipped Read-Aloud exclude rule
// (asn=as15169; ua=*google-read-aloud*; action=skip), shaped like the
// detectors matcher: the rule needs the UA and the "AS<n>" string.
func exemptPageBridge(t *testing.T) *NginxBridge {
	t.Helper()
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.chalExcludeASNFn = func(ip string) uint32 {
		if strings.HasPrefix(ip, "66.102.") {
			return 15169
		}
		return 6799
	}
	b.ChalExcludeHot = func(host, ua string, asn, ptr func() string, rule string) (string, string, bool) {
		if rule != "CHALLENGE_VHOST" || !strings.Contains(strings.ToLower(ua), "google-read-aloud") {
			return "", "", false
		}
		return "skip", "asn=as15169; ua=*google-read-aloud*; action=skip", asn() == "AS15169"
	}
	b.enr = stubPageEnricher{
		readAloudIP:   {CountryISO: "US", ASN: 15169},
		"66.249.66.1": {CountryISO: "US", ASN: 15169, PTR: "crawl-66-249-66-1.googlebot.com"},
	}
	return b
}

func getChallengePage(t *testing.T, base, ip, host, ua, next string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+challengePath+"?next="+url.QueryEscape(next), nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Forwarded-Host", host)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := noFollow().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// rigel, 2026-10-04: Read-Aloud fetched the challenge page's own URL (the
// visitor's address bar) and got the PoW although the #1539 exclude rule had
// loaded: /__cfm_challenge bypasses cfm.lua, so the rule never ran. The page
// now sends an exclude-file match to next, without the visitor's cfm_rt.
func TestChallengePage_ExcludedFetcherGoesToNext(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetFPPolicies(t)
	b := exemptPageBridge(t)
	base, _ := startVerifyServerWithBridge(t, b)
	resetThrottleStores(t)
	const host = "karol.gr"
	next := "/product/pomolo-portas-a42/?srsltid=AU7g&cfm_rt=0123456789abcdef"

	r := getChallengePage(t, base, readAloudIP, host, readAloudUA, next, nil)
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("excluded fetcher: %d, want 303 to next", r.StatusCode)
	}
	if loc := r.Header.Get("Location"); loc != "/product/pomolo-portas-a42/?srsltid=AU7g" {
		t.Fatalf("Location = %q, want next without the visitor's cfm_rt", loc)
	}
	// The same fetcher bounced straight back for the same target: the breaker
	// serves the page instead of a redirect loop.
	if r := getChallengePage(t, base, readAloudIP, host, readAloudUA, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("second redirect for the same target within 10 s: %d, want the page", r.StatusCode)
	}

	resetThrottleStores(t)
	if r := getChallengePage(t, base, readAloudIP, host, pageBrowserUA, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("browser UA from the same IP: %d, want the page", r.StatusCode)
	}
	if r := getChallengePage(t, base, "203.0.113.5", host, readAloudUA, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("Read-Aloud UA off Google's ASN: %d, want the page", r.StatusCode)
	}
	// Panel scope: the exclude file governs the web decision only.
	panel := map[string]string{"X-CFM-Panel-Port": "2083", "X-Forwarded-Port": "2083"}
	if r := getChallengePage(t, base, readAloudIP, host, readAloudUA, next, panel); r.StatusCode != http.StatusOK {
		t.Fatalf("panel-scope request: %d, want the page", r.StatusCode)
	}
}

// The exclude file lifts a vhost-wide challenge only: with a per-IP challenge
// (an ipState entry, or the geo floor) the edge would challenge next again, so
// the page is served. A per-IP block exempts nothing.
func TestChallengePage_ExcludeNeverLiftsAPerIPChallenge(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetFPPolicies(t)
	b := exemptPageBridge(t)
	base, _ := startVerifyServerWithBridge(t, b)
	const host, next = "karol.gr", "/product/x/"
	setIP := func(action string) {
		b.mu.Lock()
		if action == "" {
			delete(b.ipState, readAloudIP)
		} else {
			b.ipState[readAloudIP] = bridgeIPEntry{Action: action, Expires: time.Now().Add(time.Minute)}
		}
		b.mu.Unlock()
	}
	for _, action := range []string{"challenge", "block"} {
		resetThrottleStores(t)
		setIP(action)
		if r := getChallengePage(t, base, readAloudIP, host, readAloudUA, next, nil); r.StatusCode != http.StatusOK {
			t.Fatalf("per-IP %s: %d, want the page", action, r.StatusCode)
		}
	}
	setIP("")

	// The geo floor is a per-IP challenge the file never governed.
	resetThrottleStores(t)
	SetFingerprintPolicies([]FingerprintPolicy{{ID: "US", Kind: "country", Action: "challenge"}})
	if r := getChallengePage(t, base, readAloudIP, host, readAloudUA, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("geo-floored client: %d, want the page", r.StatusCode)
	}
	SetFingerprintPolicies(nil)
	resetThrottleStores(t)
	if r := getChallengePage(t, base, readAloudIP, host, readAloudUA, next, nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("geo policy gone: %d, want 303", r.StatusCode)
	}
}

// A verified good bot (CHALLENGE_GOODBOT_EXEMPT) is exempt from a per-IP and a
// vhost challenge alike, so it goes to next even under a per-IP challenge or
// the geo floor; never under a block, never with the exemption off.
func TestChallengePage_VerifiedGoodBotGoesToNext(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetFPPolicies(t)
	// Every bridge field the handler reads is set before its server starts.
	goodBotBridge := func(exempt bool) (*NginxBridge, string) {
		b := exemptPageBridge(t)
		b.ChalExcludeHot = nil // the good-bot exemption alone
		b.goodBotExempt = exempt
		b.goodBot.verify = func(ptr, ip string) (string, bool) { return "", true } // no DNS
		b.goodBot.store("66.249.66.1", "googlebot", time.Now())
		base, _ := startVerifyServerWithBridge(t, b)
		return b, base
	}
	b, base := goodBotBridge(true)
	const host, next = "shop.example.com", "/category/a/"
	const ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	setIP := func(action string) {
		b.mu.Lock()
		if action == "" {
			delete(b.ipState, "66.249.66.1")
		} else {
			b.ipState["66.249.66.1"] = bridgeIPEntry{Action: action, Expires: time.Now().Add(time.Minute)}
		}
		b.mu.Unlock()
	}

	resetThrottleStores(t)
	if r := getChallengePage(t, base, "66.249.66.1", host, ua, next, nil); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != next {
		t.Fatalf("verified googlebot: %d %q, want 303 to next", r.StatusCode, r.Header.Get("Location"))
	}
	setIP("challenge")
	SetFingerprintPolicies([]FingerprintPolicy{{ID: "US", Kind: "country", Action: "challenge"}})
	resetThrottleStores(t)
	if r := getChallengePage(t, base, "66.249.66.1", host, ua, next, nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("verified googlebot under a per-IP challenge and the geo floor: %d, want 303", r.StatusCode)
	}
	SetFingerprintPolicies(nil)
	setIP("block")
	resetThrottleStores(t)
	if r := getChallengePage(t, base, "66.249.66.1", host, ua, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("blocked googlebot: %d, want the page", r.StatusCode)
	}
	setIP("")
	// An unverified IP claiming Googlebot is not exempt.
	resetThrottleStores(t)
	if r := getChallengePage(t, base, "203.0.113.9", host, ua, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("unverified Googlebot UA: %d, want the page", r.StatusCode)
	}

	_, offBase := goodBotBridge(false)
	resetThrottleStores(t)
	if r := getChallengePage(t, offBase, "66.249.66.1", host, ua, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("good-bot exemption off: %d, want the page", r.StatusCode)
	}
}

func TestWithoutResumeToken(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/p/?cfm_rt=abc", "/p/"},
		{"/p/?a=1&cfm_rt=abc&b=2", "/p/?a=1&b=2"},
		{"/p/?a=1", "/p/?a=1"},
		{"/p/", "/p/"},
		{"/%CF%80/?cfm_rt=abc&x=%CE%B1", "/%CF%80/?x=%CE%B1"},
	} {
		if got := withoutResumeToken(c.in); got != c.want {
			t.Errorf("withoutResumeToken(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Whatever it returns stays on this origin.
	for _, in := range []string{"/%2F%2Fevil.com/?cfm_rt=x", "/.//evil.com?cfm_rt=x"} {
		got := withoutResumeToken(normalizeChallengeNext(in))
		if strings.HasPrefix(got, "//") || strings.Contains(got, "\\") || !strings.HasPrefix(got, "/") {
			t.Errorf("withoutResumeToken(%q) = %q leaves the origin", in, got)
		}
	}
}
