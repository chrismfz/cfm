package webdetector

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ligaapola.gr on mars, 2026-09-30: two wp-admin products opened with
// ctrl+click, both tabs challenged. The first verify expired cfm_chal, the
// second tab's verify failed with "missing cookie" (silently), and the page's
// retry went to "/?next=…", which WordPress served as the homepage because the
// browser was cleared by then.

// solvedVerifyRequest builds one genuine verify for a tab sharing cookie.
func solvedVerifyRequest(t *testing.T, base, clientIP, host, ua, cookie, next string) *http.Request {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	bind := powBind(ua, cookie)
	cfg := defaultPowConfig()
	powTok, err := issuePowChallenge(powSecretKey(), time.Now().UTC(), cfg.Difficulty, nonce, bind)
	if err != nil {
		t.Fatalf("issuePowChallenge: %v", err)
	}
	sol := ""
	for i := 0; i < 1<<26; i++ {
		if cand := strconv.Itoa(i); verifyPowSolution(nonce, bind, cand, cfg.Difficulty) {
			sol = cand
			break
		}
	}
	if sol == "" {
		t.Fatal("could not solve the PoW")
	}
	req, _ := http.NewRequest(http.MethodPost, base+verifyPath+"?next="+url.QueryEscape(next), strings.NewReader(`{"v":1}`))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-Real-IP", clientIP)
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-CFM-Token", issueToken(clientIP, ua, cookie))
	req.Header.Set("X-CFM-Pow", powTok)
	req.Header.Set("X-CFM-Sol", sol)
	req.AddCookie(&http.Cookie{Name: "cfm_chal", Value: cookie})
	return req
}

func noFollow() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func TestVerify_SecondTabStillVerifiesAfterTheFirstSolves(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	base, _ := startVerifyServer(t)
	const (
		ip   = "203.0.113.77"
		host = "shop.example.com"
		ua   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	)
	cookie := randomCookieValue() // shared by both tabs: set only when missing
	tabA := "/wp-admin/post.php?post=68591&action=edit"
	tabB := "/wp-admin/post.php?post=66091&action=edit"

	respA, err := noFollow().Do(solvedVerifyRequest(t, base, ip, host, ua, cookie, tabA))
	if err != nil {
		t.Fatal(err)
	}
	respA.Body.Close()
	if respA.StatusCode != http.StatusSeeOther || respA.Header.Get("Location") != tabA {
		t.Fatalf("tab A: %d %q, want 303 to its product", respA.StatusCode, respA.Header.Get("Location"))
	}
	for _, c := range respA.Cookies() {
		if c.Name == "cfm_chal" && c.MaxAge < 0 {
			t.Fatal("the first solve expired cfm_chal: every other open tab's verify then fails")
		}
	}

	respB, err := noFollow().Do(solvedVerifyRequest(t, base, ip, host, ua, cookie, tabB))
	if err != nil {
		t.Fatal(err)
	}
	respB.Body.Close()
	if respB.StatusCode != http.StatusSeeOther || respB.Header.Get("Location") != tabB {
		t.Fatalf("tab B: %d %q, want 303 to its own product", respB.StatusCode, respB.Header.Get("Location"))
	}
	var clr string
	for _, c := range respB.Cookies() {
		if c.Name == "cfm_clearance" {
			clr = c.Value
		}
	}
	if !verifyClearanceToken(clr, ip, host, "web", time.Now()) {
		t.Fatal("tab B's 303 carries no usable clearance")
	}
}

func TestChallengePage_ClearedClientGoesStraightToNext(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	base, _ := startVerifyServer(t)
	const (
		ip   = "203.0.113.78"
		host = "shop.example.com"
		ua   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
	)
	next := "/wp-admin/post.php?post=66091&action=edit&cfm_rt=abc"
	resetThrottleStores(t)
	get := func(clientIP, cookieHost string, withCookie bool) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, base+challengePath+"?next="+url.QueryEscape(next), nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("X-Forwarded-Host", host)
		if withCookie {
			tok := issueClearanceToken(ip, cookieHost, "web", time.Now().Add(time.Hour))
			req.AddCookie(&http.Cookie{Name: "cfm_clearance", Value: tok})
		}
		resp, err := noFollow().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	if r := get(ip, host, true); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != next {
		t.Fatalf("cleared: %d %q, want 303 to next (cfm_rt kept, so the edge replays the POST)", r.StatusCode, r.Header.Get("Location"))
	}
	if r := get(ip, host, false); r.StatusCode != http.StatusOK {
		t.Fatalf("no clearance: %d, want the challenge page", r.StatusCode)
	}
	if r := get("203.0.113.99", host, true); r.StatusCode != http.StatusOK {
		t.Fatalf("clearance for another IP: %d, want the challenge page", r.StatusCode)
	}
	if r := get(ip, "other.example.com", true); r.StatusCode != http.StatusOK {
		t.Fatalf("clearance for another host: %d, want the challenge page", r.StatusCode)
	}
	// Loop breaker: the edge bounced the cleared client straight back (its
	// validator disagrees) — the second redirect within the window serves the
	// page instead of ping-ponging into ERR_TOO_MANY_REDIRECTS.
	if r := get(ip, host, true); r.StatusCode != http.StatusOK {
		t.Fatalf("second cleared redirect for the same next within 10 s: %d, want the page", r.StatusCode)
	}
}

func TestChallengePage_PanelScopeUsesThePanelClearance(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	base, _ := startVerifyServer(t)
	resetThrottleStores(t)
	const ip, host = "203.0.113.79", "cpanel.example.com"
	get := func(cookieName, scope string) int {
		req, _ := http.NewRequest(http.MethodGet, base+challengePath+"?next=%2Fcpsess1%2Ffrontend%2F", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-CFM-Panel-Port", "2083")
		req.Header.Set("X-Forwarded-Port", "2083")
		req.AddCookie(&http.Cookie{Name: cookieName, Value: issueClearanceToken(ip, host, scope, time.Now().Add(time.Hour))})
		resp, err := noFollow().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("cfm_clearance", "web"); code != http.StatusOK {
		t.Fatalf("a WEB clearance on the 2083 page: %d, want the challenge page", code)
	}
	if code := get("cfm_clearance_p2083", "panel:2083"); code != http.StatusSeeOther {
		t.Fatalf("the 2083 clearance on the 2083 page: %d, want 303", code)
	}
}

func resetThrottleStores(t *testing.T) {
	t.Helper()
	reset := func() {
		for _, st := range []*pairTTLStore[struct{}]{&clearedRedirects, &verifyRejects} {
			st.mu.Lock()
			st.m = map[string]time.Time{}
			st.fullWarn = false
			st.mu.Unlock()
		}
	}
	reset()
	t.Cleanup(reset)
}

// The page's retry must go through the challenge server, never "/?next=".
func TestChallengePage_RetryGoesThroughTheChallengeServer(t *testing.T) {
	html := challengeHTML()
	if strings.Contains(html, `"/?next="`) {
		t.Fatal(`the page still retries via "/?next=", which a cleared browser gets as the site's homepage`)
	}
	if !strings.Contains(html, `"/__cfm_challenge?next=" + encodeURIComponent(next)`) {
		t.Fatal("the page's retry no longer goes through /__cfm_challenge")
	}
}

func TestNormalizeChallengeNext_RefusesOtherOrigins(t *testing.T) {
	for _, in := range []string{
		"//evil.com/x",
		"/\\evil.com",
		"/\\/evil.com",
		"%2F%2Fevil.com",
		"%2f%5cevil.com",
		"/\t/evil.com",
		"/\n/evil.com",
		"/x\x00y",
		"/__cfm_challenge?next=%2F%2Fevil.com",
	} {
		if got := normalizeChallengeNext(in); got != "/" {
			t.Errorf("normalizeChallengeNext(%q) = %q, want \"/\"", in, got)
		}
	}
	for _, in := range []string{"/wp-admin/post.php?post=1&action=edit", "/%2Fx", "/a//b", "/?next=/x"} {
		if got := normalizeChallengeNext(in); got == "/" && in != "/" {
			t.Errorf("normalizeChallengeNext(%q) = %q, want it kept", in, got)
		}
	}
}

func TestPutIfAbsent_WindowAndFullStore(t *testing.T) {
	st := pairTTLStore[struct{}]{m: map[string]time.Time{}, ttl: time.Minute, maxKeys: 2, fullMsg: "full %d"}
	t0 := time.Unix(1000, 0)
	add := func(k string, at time.Time) bool { return st.putIfAbsent(k, struct{}{}, at) }
	if !add("a", t0) || add("a", t0.Add(59*time.Second)) {
		t.Fatal("a first sighting is new, a repeat within the TTL is not")
	}
	if !add("a", t0.Add(2*time.Minute)) {
		t.Fatal("after the TTL the key is new again")
	}
	add("b", t0.Add(2*time.Minute))
	// Full of live keys: a newcomer cannot be recorded and reads as seen, so
	// the caller takes its conservative branch (no log line, serve the page).
	if add("c", t0.Add(2*time.Minute)) {
		t.Fatal("a key the full store cannot record must read as seen")
	}
}

// putIfAbsent is one atomic test-and-set: racing callers on one key, exactly
// one wins (the breaker and the log throttle must not both fire twice).
func TestPairTTLStore_PutIfAbsentIsAtomic(t *testing.T) {
	st := pairTTLStore[struct{}]{m: map[string]time.Time{}, ttl: time.Minute, maxKeys: 16, fullMsg: "full %d"}
	now := time.Now()
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st.putIfAbsent("k", struct{}{}, now) {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d winners, want exactly 1", wins)
	}
}

// A challenged POST's next is the original URI plus cfm_rt: a long admin/ajax
// URI must survive normalization, or the client lands on "/" (the homepage)
// and the stash is never replayed.
func TestNormalizeChallengeNext_KeepsALongResumeTarget(t *testing.T) {
	next := "/wp-admin/admin-ajax.php?action=x&data=" + strings.Repeat("a", 2500) + "&cfm_rt=tok"
	if got := normalizeChallengeNext(next); got != next {
		t.Fatalf("a %d-byte resume target was not kept (got %d bytes)", len(next), len(got))
	}
	if got := normalizeChallengeNext("/" + strings.Repeat("a", maxNextLen+1)); got != "/" {
		t.Fatal("over maxNextLen must still fall back to /")
	}
}

// The retry logic runs for real in node: extracted from the page between its
// markers and exercised with a fake sessionStorage. Skipped without node
// (CI has it: make test-js).
func TestChallengePage_RetryTargetLogic(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	html := challengeHTML()
	begin := strings.Index(html, "// BEGIN cfmRetryTarget")
	end := strings.Index(html, "// END cfmRetryTarget")
	if begin < 0 || end < 0 {
		t.Fatal("cfmRetryTarget markers not found in the challenge page")
	}
	fn := html[begin:end]
	script := fn + `
const assert = require("assert");
function mem() { const m = {}; return { get: k => (k in m ? m[k] : null), set: (k, v) => { m[k] = v; }, del: k => { delete m[k]; }, m }; }
const next = "/wp-admin/post.php?post=66091&action=edit&cfm_rt=T";
const via = "/__cfm_challenge?next=" + encodeURIComponent(next);

// 1-2 failures: through the challenge server; the 3rd in a row: the edge, cfm_rt KEPT.
let s = mem(), t0 = 1000000;
assert.strictEqual(cfmRetryTarget(next, false, s, t0), via);
assert.strictEqual(cfmRetryTarget(next, false, s, t0 + 1000), via);
assert.strictEqual(cfmRetryTarget(next, false, s, t0 + 2000), next);
// ...and the count starts over after the fallback.
assert.strictEqual(cfmRetryTarget(next, false, s, t0 + 3000), via);

// A different next does not inherit the count (a new challenge in the same tab).
s = mem();
cfmRetryTarget(next, false, s, t0); cfmRetryTarget(next, false, s, t0 + 1);
assert.strictEqual(cfmRetryTarget("/other", false, s, t0 + 2), "/__cfm_challenge?next=%2Fother");

// A v2 reject resets it: the failures must be in a row.
s = mem();
cfmRetryTarget(next, false, s, t0); cfmRetryTarget(next, false, s, t0 + 1);
assert.strictEqual(cfmRetryTarget(next, true, s, t0 + 2), via);
assert.strictEqual(cfmRetryTarget(next, false, s, t0 + 3), via);

// The count expires after 2 minutes of quiet.
s = mem();
cfmRetryTarget(next, false, s, t0); cfmRetryTarget(next, false, s, t0 + 1);
assert.strictEqual(cfmRetryTarget(next, false, s, t0 + 120001), via);

// A next with a "|" is compared whole.
s = mem();
const pipe = "/a|b?x=1";
cfmRetryTarget(pipe, false, s, t0); cfmRetryTarget(pipe, false, s, t0 + 1);
assert.strictEqual(cfmRetryTarget(pipe, false, s, t0 + 2), pipe);

// Never another origin: the page only ever sees a server-normalized next
// (normalizeChallengeNext, pinned by the Location tests), and below 3
// failures the target is always the challenge server.
s = mem();
assert.ok(cfmRetryTarget("/x", false, s, t0).startsWith("/__cfm_challenge?next="));
// No usable sessionStorage (private mode: the page's cfmSession wrapper then
// reads null and drops writes): every retry goes through the challenge server.
const none = { get: () => null, set: () => {}, del: () => {} };
for (let i = 0; i < 5; i++) assert.strictEqual(cfmRetryTarget(next, false, none, t0 + i), via);
console.log("ok");
`
	out, err := exec.Command(node, "-e", script).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
}

// Keyed on next's decoded path: another page from the same browser within the
// window is not a loop, while the edge's bounce (next rebuilt, same path) is.
func TestChallengePage_BreakerIsPerPath(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	base, _ := startVerifyServer(t)
	resetThrottleStores(t)
	const ip, host = "203.0.113.82", "shop.example.com"
	get := func(rawNextQuery string) int {
		req, _ := http.NewRequest(http.MethodGet, base+challengePath+"?next="+rawNextQuery, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")
		req.Header.Set("X-Real-IP", ip)
		req.Header.Set("X-Forwarded-Host", host)
		req.AddCookie(&http.Cookie{Name: "cfm_clearance", Value: issueClearanceToken(ip, host, "web", time.Now().Add(time.Hour))})
		resp, err := noFollow().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := get(url.QueryEscape("/προϊόν/ένα?x=1")); c != http.StatusSeeOther {
		t.Fatalf("first cleared visit: %d, want 303", c)
	}
	if c := get(url.QueryEscape("/wp-admin/post.php?post=68591&action=edit")); c != http.StatusSeeOther {
		t.Fatalf("another page within the window: %d, want 303 (not a loop)", c)
	}
	// The incident's second tab: same path, another ?post= — another target.
	if c := get(url.QueryEscape("/wp-admin/post.php?post=66091&action=edit")); c != http.StatusSeeOther {
		t.Fatalf("same path, other query: %d, want 303 (not a loop)", c)
	}
	// The bounce: the same target, rebuilt (percent-encoded path, reordered query).
	if c := get(url.QueryEscape("/%CF%80%CF%81%CE%BF%CF%8A%CF%8C%CE%BD/%CE%AD%CE%BD%CE%B1?x=1")); c != http.StatusOK {
		t.Fatalf("same target back within the window: %d, want the page (loop broken)", c)
	}
}

// The open-redirect check must hold for the Location http.Redirect actually
// emits: it path.Clean()s after normalizeChallengeNext.
func TestChallengeNext_LocationNeverLeavesTheOrigin(t *testing.T) {
	for _, in := range []string{
		"//evil.com/x", "/\\evil.com", "/./\\evil.com", "/x/../\\evil.com", "/.//evil.com",
		"/a/..//evil.com", "%2F%2Fevil.com", "%2F.%2F%5Cevil.com", "/\t/evil.com",
		"/__cfm_challenge?next=%2F.%2F%5Cevil.com",
	} {
		next := normalizeChallengeNext(in)
		w := httptest.NewRecorder()
		http.Redirect(w, httptest.NewRequest(http.MethodPost, verifyPath, nil), next, http.StatusSeeOther)
		loc := w.Header().Get("Location")
		u, err := url.Parse(strings.ReplaceAll(loc, "\\", "/"))
		if err != nil || u.Host != "" || strings.HasPrefix(strings.ReplaceAll(loc, "\\", "/"), "//") {
			t.Errorf("next %q -> Location %q leaves the origin", in, loc)
		}
	}
}

// The cleared-client check runs only on /__cfm_challenge (its location stamps
// the host and scope headers), never on a challenge proxied through `/`.
func TestChallengePage_ClearedCheckOnlyOnTheChallengePath(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
	base, _ := startVerifyServer(t)
	resetThrottleStores(t)
	const ip, host = "203.0.113.80", "shop.example.com"
	req, _ := http.NewRequest(http.MethodGet, base+"/?next=%2Fwp-admin%2F", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Forwarded-Host", host)
	req.AddCookie(&http.Cookie{Name: "cfm_clearance", Value: issueClearanceToken(ip, host, "web", time.Now().Add(time.Hour))})
	resp, err := noFollow().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / (proxied challenge, unstamped headers): %d, want the page", resp.StatusCode)
	}
}

// Every page re-sets cfm_chal with a full MaxAge, keeping its value (tabs
// share it): a reused cookie near its end must not expire mid-PoW.
func TestChallengePage_RefreshesTheSharedChallengeCookie(t *testing.T) {
	base, _ := startVerifyServer(t)
	resetThrottleStores(t)
	req, _ := http.NewRequest(http.MethodGet, base+challengePath+"?next=%2F", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")
	req.Header.Set("X-Real-IP", "203.0.113.81")
	req.Header.Set("X-Forwarded-Host", "shop.example.com")
	req.AddCookie(&http.Cookie{Name: "cfm_chal", Value: "shared-by-tabs"})
	resp, err := noFollow().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "cfm_chal" {
			if c.Value != "shared-by-tabs" || c.MaxAge != 300 {
				t.Fatalf("cfm_chal re-set as %q MaxAge=%d, want the same value with a full 300", c.Value, c.MaxAge)
			}
			return
		}
	}
	t.Fatal("the page did not refresh cfm_chal")
}
