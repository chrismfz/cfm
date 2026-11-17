package webdetector

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cfm/internal/enrich"
)

// withConfirm sets the confirm knobs and the under-attack read for one test.
func withConfirm(t *testing.T, mode, audience string, attack func(host string) (bool, bool)) {
	t.Helper()
	challengeConfirm.mu.RLock()
	prevMode, prevAud, prevAttack := challengeConfirm.mode, challengeConfirm.audience, challengeConfirm.attack
	challengeConfirm.mu.RUnlock()
	ConfigureChallengeV2Confirm(mode, audience)
	SetUnderAttackConfirmState(attack)
	t.Cleanup(func() {
		challengeConfirm.mu.Lock()
		challengeConfirm.mode, challengeConfirm.audience, challengeConfirm.attack = prevMode, prevAud, prevAttack
		challengeConfirm.mu.Unlock()
	})
}

func manualOn(hosts ...string) func(string) (bool, bool) {
	return func(h string) (bool, bool) {
		for _, x := range hosts {
			if h == x {
				return true, false
			}
		}
		return false, false
	}
}

func TestConfirmToken(t *testing.T) {
	t.Setenv("CFM_CHALLENGE_SECRET", "confirm-token-secret")
	now := time.Now().UTC()
	tok := issueConfirmToken("203.0.113.5", "Shop.Example.com", "POWTOK", now)

	at, ok := verifyConfirmToken(tok, "203.0.113.5", "shop.example.com", "POWTOK", now.Add(time.Minute))
	if !ok || at.UnixMilli() != now.UnixMilli() {
		t.Fatalf("genuine token refused: ok=%v at=%v", ok, at)
	}
	cases := []struct {
		name          string
		tok, ip, host string
		pow           string
		at            time.Time
	}{
		{"other ip", tok, "203.0.113.6", "shop.example.com", "POWTOK", now},
		{"other host", tok, "203.0.113.5", "other.example.com", "POWTOK", now},
		{"other pow", tok, "203.0.113.5", "shop.example.com", "POWTOK2", now},
		{"expired", tok, "203.0.113.5", "shop.example.com", "POWTOK", now.Add(confirmTokenTTL + time.Second)},
		{"from the future", tok, "203.0.113.5", "shop.example.com", "POWTOK", now.Add(-time.Minute)},
		{"tampered", tok[:len(tok)-2] + "AA", "203.0.113.5", "shop.example.com", "POWTOK", now},
		{"garbage", "not-a-token", "203.0.113.5", "shop.example.com", "POWTOK", now},
		{"empty", "", "203.0.113.5", "shop.example.com", "POWTOK", now},
	}
	for _, c := range cases {
		if _, ok := verifyConfirmToken(c.tok, c.ip, c.host, c.pow, c.at); ok {
			t.Errorf("%s: token accepted", c.name)
		}
	}
}

func TestParseConfirmKnobs(t *testing.T) {
	for in, want := range map[string]string{
		"": confirmModeManual, "manual": confirmModeManual, "typo": confirmModeManual,
		"off": confirmModeOff, "0": confirmModeOff, "OFF": confirmModeOff,
		"auto": confirmModeAuto, "all": confirmModeAuto,
	} {
		if got := parseConfirmMode(in); got != want {
			t.Errorf("mode %q = %q, want %q", in, got, want)
		}
	}
	if a := parseConfirmAudience(""); !a["GR"] || !a["CY"] || len(a) != 2 {
		t.Errorf("default audience = %v", a)
	}
	if a := parseConfirmAudience("none"); len(a) != 0 {
		t.Errorf("none = %v", a)
	}
	if a := parseConfirmAudience(" gr, de ,"); !a["GR"] || !a["DE"] || len(a) != 2 {
		t.Errorf("list = %v", a)
	}
}

func TestConfirmRequired(t *testing.T) {
	zero := 0
	one := 1
	noInput := &humanitySignals{PTR: &zero, TCH: &zero, KEY: &zero}
	base := ChallengeSolve{Host: "shop.example.com", Scope: "web", CountryISO: "US", ASN: 7922, ASNName: "Comcast Cable Communications, LLC"}

	withConfirm(t, "manual", "GR,CY", manualOn("shop.example.com"))
	if !confirmRequired(base, noInput) {
		t.Fatal("no-input solve from outside the audience under a manual attack: want confirm")
	}
	if !confirmRequired(base, nil) {
		t.Error("a solve with no payload at all: want confirm")
	}
	if !confirmRequired(base, &humanitySignals{}) {
		t.Error("unreported counts read as no input: want confirm")
	}

	mut := func(f func(*ChallengeSolve)) ChallengeSolve { s := base; f(&s); return s }
	no := []struct {
		name string
		s    ChallengeSolve
		sig  *humanitySignals
	}{
		{"pointer input", base, &humanitySignals{PTR: &one, TCH: &zero, KEY: &zero}},
		{"touch input", base, &humanitySignals{PTR: &zero, TCH: &one, KEY: &zero}},
		{"key input", base, &humanitySignals{PTR: &zero, TCH: &zero, KEY: &one}},
		{"audience", mut(func(s *ChallengeSolve) { s.CountryISO = "GR"; s.ASNName = "OTEnet S.A." }), noInput},
		{"audience, lower case", mut(func(s *ChallengeSolve) { s.CountryISO = "cy" }), noInput},
		{"country unresolved", mut(func(s *ChallengeSolve) { s.CountryISO = "" }), noInput},
		{"panel scope", mut(func(s *ChallengeSolve) { s.Scope = "panel:2083" }), noInput},
		{"waived good bot", mut(func(s *ChallengeSolve) { s.V2Waived = "googlebot" }), noInput},
		{"host not under attack", mut(func(s *ChallengeSolve) { s.Host = "other.example.com" }), noInput},
	}
	for _, c := range no {
		if confirmRequired(c.s, c.sig) {
			t.Errorf("%s: confirm required, want none", c.name)
		}
	}

	// A datacenter network inside the audience is outside it.
	dc := mut(func(s *ChallengeSolve) { s.CountryISO = "GR"; s.ASN = 14061; s.ASNName = "DigitalOcean, LLC" })
	if !confirmRequired(dc, noInput) {
		t.Error("GR datacenter: want confirm")
	}
	// The host is looked up normalized.
	if !confirmRequired(mut(func(s *ChallengeSolve) { s.Host = "SHOP.example.com:443" }), noInput) {
		t.Error("host with case and port: want confirm")
	}

	// Modes.
	withConfirm(t, "off", "GR,CY", manualOn("shop.example.com"))
	if confirmRequired(base, noInput) {
		t.Error("mode off: want none")
	}
	autoOnly := func(string) (bool, bool) { return false, true }
	withConfirm(t, "manual", "GR,CY", autoOnly)
	if confirmRequired(base, noInput) {
		t.Error("mode manual, automatic entry only: want none")
	}
	withConfirm(t, "auto", "GR,CY", autoOnly)
	if !confirmRequired(base, noInput) {
		t.Error("mode auto, automatic entry: want confirm")
	}
	withConfirm(t, "manual", "none", manualOn("shop.example.com"))
	if !confirmRequired(mut(func(s *ChallengeSolve) { s.CountryISO = "GR" }), noInput) {
		t.Error("audience none: a GR client sees it too")
	}
	withConfirm(t, "manual", "GR,CY", nil)
	if confirmRequired(base, noInput) {
		t.Error("unwired: want none")
	}
}

func TestVhostAttackKind(t *testing.T) {
	e := &Engine{attack: newUnderAttackTracker()}
	e.cfg.UnderAttack = true
	now := time.Now()

	if m, a := e.vhostAttackKind("x.example", now); m || a {
		t.Fatalf("unknown host: %v %v", m, a)
	}
	e.SetVhostAttackOverride("x.example", true, now, 0)
	if m, a := e.vhostAttackKind("x.example", now); !m || a {
		t.Errorf("forced on: manual=%v auto=%v", m, a)
	}
	e.SetVhostAttackOverride("y.example", true, now, time.Minute)
	if m, _ := e.vhostAttackKind("y.example", now.Add(2*time.Minute)); m {
		t.Error("an expired TTL-bound override still reads manual")
	}
	e.attack.hosts["z.example"] = &attackVhost{on: true}
	if m, a := e.vhostAttackKind("z.example", now); m || !a {
		t.Errorf("automatic state: manual=%v auto=%v", m, a)
	}
	e.SetVhostAttackOverride("z.example", false, now, 0)
	if m, a := e.vhostAttackKind("z.example", now); m || a {
		t.Errorf("forced off: manual=%v auto=%v", m, a)
	}
	e.cfg.UnderAttack = false
	if m, a := e.vhostAttackKind("x.example", now); m || a {
		t.Error("detector off: the override must not read")
	}
}

// verifyPoster solves ONE PoW (issued at issuedAt) and returns a function that
// posts it, so a test can re-post the same solve as the page's confirm click does.
func verifyPoster(t *testing.T, base, clientIP, host, ua string, issuedAt time.Time) func(body string, hdr map[string]string) *http.Response {
	t.Helper()
	cookie := randomCookieValue()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	bind := powBind(ua, cookie)
	cfg := defaultPowConfig()
	powTok, err := issuePowChallenge(powSecretKey(), issuedAt, cfg.Difficulty, nonce, bind)
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
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return func(body string, hdr map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, base+verifyPath+"?next=/", strings.NewReader(body))
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Real-IP", clientIP)
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-CFM-Token", issueToken(clientIP, ua, cookie))
		req.Header.Set("X-CFM-Pow", powTok)
		req.Header.Set("X-CFM-Sol", sol)
		req.AddCookie(&http.Cookie{Name: "cfm_chal", Value: cookie})
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("verify POST: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
}

const confirmUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

func TestVerify_ConfirmStepThenClickPasses(t *testing.T) {
	base, capt := startVerifyServer(t)
	setSolveEnricher(t, func(ip string) enrich.Result {
		return enrich.Result{Country: "United States", CountryISO: "US", ASN: 6079, ASNName: "RCN"}
	})
	const ip, host = "198.51.100.20", "www.ventus.example"
	withConfirm(t, "manual", "GR,CY", manualOn(host))

	// The farm's hs-0 profile: a hardware renderer, 8 cores, no input.
	body := `{"v":1,"wd":false,"ptr":0,"tch":0,"key":0,"mv":0,"hc":8,"ow":1440,"oh":900}`
	post := verifyPoster(t, base, ip, host, confirmUA, time.Now().UTC())

	resp := post(body, nil)
	tok := resp.Header.Get(confirmHeader)
	if resp.StatusCode != http.StatusForbidden || tok == "" {
		t.Fatalf("first POST: status=%d %s=%q, want 403 + a token", resp.StatusCode, confirmHeader, tok)
	}
	if resp.Header.Get("X-CFM-V2") != "" {
		t.Error("a confirm must not read as a v2 reject (the page would back off)")
	}
	if solved, rejects := capt.counts(); solved != 0 || rejects != 0 {
		t.Fatalf("a confirm cleared or rejected something: solved=%d rejects=%d", solved, rejects)
	}

	// The click re-posts the same solve, now with the approach to the button.
	resp = post(`{"v":1,"wd":false,"ptr":9,"tch":0,"key":0,"mv":240,"hc":8,"ow":1440,"oh":900}`, map[string]string{confirmHeader: tok})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirmed re-post: status=%d, want 303", resp.StatusCode)
	}
	solved, _ := capt.counts()
	if solved != 1 {
		t.Fatalf("solved=%d, want 1", solved)
	}
	s := capt.solved[0]
	if s.V2Confirm != confirmClicked || s.V2ConfirmMS < 0 {
		t.Errorf("solve not marked: confirm=%q ms=%d", s.V2Confirm, s.V2ConfirmMS)
	}
	if !strings.Contains(s.HumanitySuffix(), " v2_confirm=clicked v2_confirm_ms=") {
		t.Errorf("solve line lacks the confirm fields: %q", s.HumanitySuffix())
	}

	// A forged or foreign token is ignored: the solve is asked again.
	post2 := verifyPoster(t, base, ip, host, confirmUA, time.Now().UTC())
	resp = post2(body, map[string]string{confirmHeader: tok})
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(confirmHeader) == "" {
		t.Errorf("another solve's token: status=%d, want a fresh confirm", resp.StatusCode)
	}
}

func TestVerify_ConfirmSparesInputAudienceAndCalmVhosts(t *testing.T) {
	base, capt := startVerifyServer(t)
	const ip, host = "198.51.100.21", "shop.example"
	noInput := `{"v":1,"wd":false,"ptr":0,"tch":0,"key":0,"mv":0,"hc":8,"ow":1440,"oh":900}`

	// The audience (the default enricher in startVerifyServer is GR / OTEnet).
	withConfirm(t, "manual", "GR,CY", manualOn(host))
	if resp := verifyPoster(t, base, ip, host, confirmUA, time.Now().UTC())(noInput, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GR client: status=%d, want 303 without a confirm", resp.StatusCode)
	}

	setSolveEnricher(t, func(ip string) enrich.Result {
		return enrich.Result{CountryISO: "US", ASN: 6079, ASNName: "RCN"}
	})
	// Real input.
	if resp := verifyPoster(t, base, ip, host, confirmUA, time.Now().UTC())(`{"v":1,"wd":false,"ptr":12,"tch":0,"key":0,"mv":400}`, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("client with input: status=%d, want 303", resp.StatusCode)
	}
	// A vhost no operator holds under attack.
	withConfirm(t, "manual", "GR,CY", manualOn("elsewhere.example"))
	if resp := verifyPoster(t, base, ip, host, confirmUA, time.Now().UTC())(noInput, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("calm vhost: status=%d, want 303", resp.StatusCode)
	}
	if solved, _ := capt.counts(); solved != 3 {
		t.Errorf("solved=%d, want 3", solved)
	}
}

// The PoW of a confirm re-post is checked as of the confirm, so a visitor who
// clicks after the PoW's own 2-minute TTL is not sent back to solve again.
func TestVerify_ConfirmOutlivesThePowTTL(t *testing.T) {
	base, capt := startVerifyServer(t)
	setSolveEnricher(t, func(ip string) enrich.Result {
		return enrich.Result{CountryISO: "US", ASN: 6079, ASNName: "RCN"}
	})
	const ip, host = "198.51.100.22", "slow.example"
	withConfirm(t, "manual", "GR,CY", manualOn(host))
	noInput := `{"v":1,"wd":false,"ptr":0,"tch":0,"key":0,"mv":0}`

	// Issued 1.5 s short of the TTL: fresh at the first POST, stale 2 s later.
	post := verifyPoster(t, base, ip, host, confirmUA, time.Now().UTC().Add(-defaultPowTTL+1500*time.Millisecond))
	resp := post(noInput, nil)
	tok := resp.Header.Get(confirmHeader)
	if tok == "" {
		t.Fatalf("first POST: status=%d, want a confirm", resp.StatusCode)
	}
	time.Sleep(2 * time.Second)
	if resp := post(noInput, nil); resp.StatusCode != http.StatusForbidden || resp.Header.Get(confirmHeader) != "" {
		t.Fatalf("control: the stale PoW alone must fail verify, got status=%d", resp.StatusCode)
	}
	if resp := post(noInput, map[string]string{confirmHeader: tok}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirmed re-post after the PoW TTL: status=%d, want 303", resp.StatusCode)
	}
	if solved, _ := capt.counts(); solved != 1 {
		t.Errorf("solved=%d, want 1", solved)
	}
}

func TestConfirmLine(t *testing.T) {
	s := ChallengeSolve{IP: "198.51.100.1", Host: "h.example", URI: "/", HumanityScored: true, UA: "ua", Scope: "web",
		V2Grain: "vhost", V2Via: "auto:under_attack", CountryISO: "US"}
	line := s.ConfirmLine()
	for _, want := range []string{"result=v2_confirm", "hs=0", "v2=vhost", "v2_via=auto:under_attack", "scope=web", `ua="ua"`} {
		if !strings.Contains(line, want) {
			t.Errorf("confirm line %q lacks %q", line, want)
		}
	}
	s.V2Grain, s.V2Via = "", ""
	if !strings.Contains(s.ConfirmLine(), " v2=- ") {
		t.Errorf("an unarmed confirm must say v2=-: %q", s.ConfirmLine())
	}
}

// The page's whole script must parse once rendered, and its confirm branch
// must only take a 403 that carries a token.
func TestChallengePage_ConfirmToken(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI for the challenge-page confirm test")
		}
		t.Skip("node not installed")
	}
	page := fmt.Sprintf(challengeHTML(), htmlEscape("h.example"), jsStringLiteral("TOK"), jsStringLiteral("POW"), jsStringLiteral("/"), 16)
	if strings.Contains(page, "%!") {
		t.Fatalf("the page template has a bad verb: %q", page[strings.Index(page, "%!"):][:40])
	}
	i, j := strings.Index(page, "<script>"), strings.Index(page, "</script>")
	if i < 0 || j < i {
		t.Fatal("no script in the page")
	}
	dir := t.TempDir()
	whole := filepath.Join(dir, "page.js")
	if err := os.WriteFile(whole, []byte(page[i+len("<script>"):j]), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, "--check", whole).CombinedOutput(); err != nil {
		t.Fatalf("the rendered page script does not parse: %v\n%s", err, out)
	}

	begin, end := strings.Index(page, "// BEGIN cfmConfirmToken"), strings.Index(page, "// END cfmConfirmToken")
	if begin < 0 || end < begin {
		t.Fatal("cfmConfirmToken markers not found")
	}
	script := page[begin:end] + `
const assert = require("assert");
assert.strictEqual(cfmConfirmToken(403, "T"), "T");
assert.strictEqual(cfmConfirmToken(403, null), "");
assert.strictEqual(cfmConfirmToken(403, ""), "");
assert.strictEqual(cfmConfirmToken(200, "T"), "");
assert.strictEqual(cfmConfirmToken(429, "T"), "");
`
	fn := filepath.Join(dir, "confirm.js")
	if err := os.WriteFile(fn, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, fn).CombinedOutput(); err != nil {
		t.Fatalf("cfmConfirmToken: %v\n%s", err, out)
	}
}
