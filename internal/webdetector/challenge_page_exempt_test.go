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

// geoResolverUS answers the live geo lookup (GeoPolicyActionForIP) for the
// tests: every IP is in the US, on Google's network.
func geoResolverUS(t *testing.T) {
	t.Helper()
	SetFingerprintPolicyGeoResolver(func(string) (string, uint64) { return "US", 15169 })
	t.Cleanup(func() { SetFingerprintPolicyGeoResolver(nil) })
}

func doChallengePage(t *testing.T, method, base, ip, host, ua, next string, hdr map[string]string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, base+challengePath+"?next="+url.QueryEscape(next), nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Forwarded-Host", host)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noFollow().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func getChallengePage(t *testing.T, base, ip, host, ua, next string, hdr map[string]string) *http.Response {
	t.Helper()
	return doChallengePage(t, http.MethodGet, base, ip, host, ua, next, hdr)
}

// rigel, 2026-10-04: Read-Aloud fetched the challenge page's own URL (the
// visitor's address bar) and got the PoW although the #1539 exclude rule had
// loaded: /__cfm_challenge bypasses cfm.lua, so the rule never ran. The page
// now sends an exclude-file match to next.
func TestChallengePage_ExcludedFetcherGoesToNext(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetFPPolicies(t)
	b := exemptPageBridge(t)
	base, _ := startVerifyServerWithBridge(t, b)
	resetThrottleStores(t)
	const host = "karol.gr"
	next := "/product/pomolo-portas-a42/?srsltid=AU7g"

	r := getChallengePage(t, base, readAloudIP, host, readAloudUA, next, nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != next {
		t.Fatalf("excluded fetcher: %d %q, want 303 to next", r.StatusCode, r.Header.Get("Location"))
	}
	if n := b.snapshotBridgeStats(0, 0).ChallengePageExemptRedirects; n != 1 {
		t.Fatalf("ChallengePageExemptRedirects = %d, want 1", n)
	}
	// The edge still challenges the target (a reason no exemption lifts):
	// it proxies the request to the challenge server, whose catch-all sends
	// it back to the page. Follow that real bounce: the breaker then serves
	// the page instead of a redirect loop.
	bounce := func(path string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		req.Header.Set("User-Agent", readAloudUA)
		req.Header.Set("X-Real-IP", readAloudIP)
		req.Header.Set("X-Forwarded-Host", host)
		resp, err := noFollow().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	back := bounce(r.Header.Get("Location"))
	if back.StatusCode != http.StatusFound || !strings.HasPrefix(back.Header.Get("Location"), challengePath+"?next=") {
		t.Fatalf("edge-challenged target: %d %q, want 302 back to the page", back.StatusCode, back.Header.Get("Location"))
	}
	if r := bounce(back.Header.Get("Location")); r.StatusCode != http.StatusOK {
		t.Fatalf("bounced straight back within 10 s: %d, want the page (loop broken)", r.StatusCode)
	}
	// A HEAD then a GET of the same page is not a loop.
	resetThrottleStores(t)
	for _, m := range []string{http.MethodHead, http.MethodGet} {
		if r := doChallengePage(t, m, base, readAloudIP, host, readAloudUA, next, nil); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s after a fresh window: %d, want 303", m, r.StatusCode)
		}
	}

	resetThrottleStores(t)
	if r := getChallengePage(t, base, readAloudIP, host, pageBrowserUA, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("browser UA from the same IP: %d, want the page", r.StatusCode)
	}
	if r := getChallengePage(t, base, "203.0.113.5", host, readAloudUA, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("Read-Aloud UA off Google's ASN: %d, want the page", r.StatusCode)
	}
	// Panel scope: the exemptions govern the web decision only.
	panel := map[string]string{"X-CFM-Panel-Port": "2083", "X-Forwarded-Port": "2083"}
	if r := getChallengePage(t, base, readAloudIP, host, readAloudUA, next, panel); r.StatusCode != http.StatusOK {
		t.Fatalf("panel-scope request: %d, want the page", r.StatusCode)
	}
	// A cfm_rt is minted only after the full decision, exemptions included,
	// challenged that POST: the exemption cannot clear it, and the owner (an
	// exclude rule can cover a whole network) would lose the POST.
	withRT := next + "&cfm_rt=0123456789abcdef"
	if r := getChallengePage(t, base, readAloudIP, host, readAloudUA, withRT, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("next carrying cfm_rt: %d, want the page", r.StatusCode)
	}
	if n := b.snapshotBridgeStats(0, 0).ChallengePageExemptRedirects; n != 3 {
		t.Fatalf("ChallengePageExemptRedirects = %d, want 3 (one GET, then HEAD + GET)", n)
	}
}

// A cleared client keeps its cfm_rt (the edge replays its POST), even when it
// is also exempt; the exempt path never counts it.
func TestChallengePage_ClearedWinsOverExempt(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetFPPolicies(t)
	b := exemptPageBridge(t)
	base, _ := startVerifyServerWithBridge(t, b)
	resetThrottleStores(t)
	const host = "karol.gr"
	next := "/wp-admin/post.php?post=1&action=edit&cfm_rt=0123456789abcdef"
	clr := &http.Cookie{Name: "cfm_clearance", Value: issueClearanceToken(readAloudIP, host, "web", time.Now().Add(time.Hour))}
	r := doChallengePage(t, http.MethodGet, base, readAloudIP, host, readAloudUA, next, nil, clr)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != next {
		t.Fatalf("cleared and exempt: %d %q, want 303 to next with cfm_rt", r.StatusCode, r.Header.Get("Location"))
	}
	if n := b.snapshotBridgeStats(0, 0).ChallengePageExemptRedirects; n != 0 {
		t.Fatalf("a cleared redirect counted as exempt: %d", n)
	}
}

// The exclude path needs no enricher: the ASN comes from the inline mmdb read.
func TestChallengePage_ExcludeWithoutEnricher(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetFPPolicies(t)
	b := exemptPageBridge(t)
	b.enr = nil
	base, _ := startVerifyServerWithBridge(t, b)
	resetThrottleStores(t)
	if r := getChallengePage(t, base, readAloudIP, "karol.gr", readAloudUA, "/p/", nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("exclude match with no enricher: %d, want 303", r.StatusCode)
	}
}

// The exclude file lifts a vhost-wide challenge only: with a per-IP challenge
// (an ipState entry, or a country/ASN policy) the edge would challenge next
// again, so the page is served. A per-IP block exempts nothing.
func TestChallengePage_ExcludeNeverLiftsAPerIPChallenge(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetFPPolicies(t)
	geoResolverUS(t)
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

	// A country policy is a per-IP challenge the file never governed.
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
// a country policy; never under a block, never with the exemption off.
func TestChallengePage_VerifiedGoodBotGoesToNext(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetFPPolicies(t)
	geoResolverUS(t)
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
		t.Fatalf("verified googlebot under a per-IP challenge and a country policy: %d, want 303", r.StatusCode)
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

// A Challenge Access-Control entry (the operator allow-list) lifts a per-IP
// and a vhost challenge alike, matched against next as the request.
func TestChallengePage_AccessControlEntryGoesToNext(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	resetFPPolicies(t)
	b := exemptPageBridge(t)
	b.ChalExcludeHot = nil
	var seen []ChallengeAccessInput
	b.ChallengeAccessExempt = func(in ChallengeAccessInput, asn func() uint32) bool {
		seen = append(seen, in)
		return strings.Contains(in.UA, "UptimeRobot") && in.Path == "/στάτους/" && asn() == 6799
	}
	base, _ := startVerifyServerWithBridge(t, b)
	const host, ip = "shop.example.com", "203.0.113.20"
	const ua = "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)"
	next := "/%CF%83%CF%84%CE%AC%CF%84%CE%BF%CF%85%CF%82/?a=1"

	resetThrottleStores(t)
	if r := getChallengePage(t, base, ip, host, ua, next, nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("access-control match: %d, want 303", r.StatusCode)
	}
	if len(seen) != 1 || seen[0].Host != host || seen[0].IP != ip || seen[0].Method != http.MethodGet || seen[0].QueryString != "a=1" {
		t.Fatalf("access-control input: %+v, want the request's host/IP, GET, the decoded next path and its raw query", seen)
	}
	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: time.Now().Add(time.Minute)}
	b.mu.Unlock()
	resetThrottleStores(t)
	if r := getChallengePage(t, base, ip, host, ua, next, nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("access-control match under a per-IP challenge: %d, want 303", r.StatusCode)
	}
	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "block", Expires: time.Now().Add(time.Minute)}
	b.mu.Unlock()
	resetThrottleStores(t)
	if r := getChallengePage(t, base, ip, host, ua, next, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("access-control match under a block: %d, want the page", r.StatusCode)
	}
	b.mu.Lock()
	delete(b.ipState, ip)
	b.mu.Unlock()
	resetThrottleStores(t)
	if r := getChallengePage(t, base, ip, host, ua, "/other/", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("another path: %d, want the page", r.StatusCode)
	}
}

func TestCarriesResumeToken(t *testing.T) {
	for in, want := range map[string]bool{
		"/p/?cfm_rt=abc":         true,
		"/p/?a=1&cfm_rt=abc&b=2": true,
		"/p/?cfm_rt=":            true,
		"/p/?a=1":                false,
		"/p/":                    false,
		"/p/?xcfm_rt=1":          false,
		"/p/?a=cfm_rt":           false,
		"/p/?a=1%26cfm_rt%3Dabc": false,
	} {
		if got := carriesResumeToken(in); got != want {
			t.Errorf("carriesResumeToken(%q) = %v, want %v", in, got, want)
		}
	}
}
