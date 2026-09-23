package webdetector

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// setV2GoodBot installs fn as the D5 gate's good-bot waiver for one test.
func setV2GoodBot(t *testing.T, fn func(ctx context.Context, ip, ptr string) string) {
	t.Helper()
	challengeV2.mu.RLock()
	prev := challengeV2.goodBot
	challengeV2.mu.RUnlock()
	SetChallengeV2GoodBot(fn)
	t.Cleanup(func() { SetChallengeV2GoodBot(prev) })
}

// setV2HostArmed installs fn as the vhost-arm lookup for one test.
func setV2HostArmed(t *testing.T, fn func(host string) bool) {
	t.Helper()
	challengeV2.mu.RLock()
	prev := challengeV2.hostArmed
	challengeV2.mu.RUnlock()
	SetChallengeV2HostArmed(fn)
	t.Cleanup(func() { SetChallengeV2HostArmed(prev) })
}

// An FCrDNS-verified good bot is waived at the D5 gate instead of rejected —
// under the grains the decision path's good-bot exemption already softens.
// Seen on the fleet: Google-Read-Aloud (rotating Google fetcher IPs) scores 140
// (sw_renderer,touch_lie,no_input) on ad-click landings and would be rejected
// on any armed shop. Everyone else, and every explicit rule/WAF arm, stays
// strict; and the waiver is never even consulted for a solve that would pass.
func TestVerify_V2GateWaivesAVerifiedGoodBot(t *testing.T) {
	base, capt := startVerifyServer(t)
	const (
		armedHost   = "shop.example.com"
		unarmedHost = "blog.example.com"
		markHost    = "forum.example.com"
		humanIP     = "203.0.113.9"
		readAloud   = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)"
		desktop     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
		failing     = `{"v":1,"wd":true,"ptr":0,"tch":0,"key":0}`
		passing     = `{"v":1,"wd":false,"ptr":7,"tch":0,"key":2}`
	)
	setV2HostArmed(t, func(host string) bool { return host == armedHost })
	var calls atomic.Int32
	var askedPTR atomic.Value
	setV2GoodBot(t, func(_ context.Context, ip, ptr string) string {
		calls.Add(1)
		askedPTR.Store(ptr)
		if strings.HasPrefix(ip, "66.249.") {
			return "google"
		}
		return ""
	})

	// Vhost-armed, failing, verified bot → waived: the normal solved path,
	// clearance cookie and redirect included.
	resp := postVerify(t, base, "66.249.81.200", armedHost, readAloud, failing)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a verified good bot was not waived: status=%d X-CFM-V2=%q", resp.StatusCode, resp.Header.Get("X-CFM-V2"))
	}
	// The clearance cookie is SET (its value is empty here only because the
	// test has no bridge token file to sign with); the reject path sets none.
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == "cfm_clearance" && c.MaxAge > 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("a waived solve must take the clearance path, cookies=%v", resp.Cookies())
	}
	solved, rejects := capt.counts()
	if solved != 1 || rejects != 0 || calls.Load() != 1 {
		t.Fatalf("waived solve: solved=%d rejects=%d waiver calls=%d, want 1/0/1", solved, rejects, calls.Load())
	}
	s := capt.solved[0]
	if s.V2Waived != "google" || s.V2Grain != v2GrainVhost || s.HumanityScore < defaultV2FailScore {
		t.Fatalf("waived solve not attributed: waived=%q grain=%q hs=%d", s.V2Waived, s.V2Grain, s.HumanityScore)
	}
	if !strings.Contains(s.HumanitySuffix(), " v2=vhost v2_waived=google") {
		t.Errorf("solve line does not show the waiver: %q", s.HumanitySuffix())
	}
	if got, _ := askedPTR.Load().(string); got != "ppp.otenet.gr" {
		t.Errorf("the waiver was not given the solve's resolved PTR: %q", got)
	}

	// Not a verified bot → rejected exactly as before.
	resp = postVerify(t, base, humanIP, armedHost, readAloud, failing)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-CFM-V2") != "reject" {
		t.Fatalf("unverified failing solve: status=%d X-CFM-V2=%q, want 403 + reject", resp.StatusCode, resp.Header.Get("X-CFM-V2"))
	}
	if _, rejects = capt.counts(); rejects != 1 || calls.Load() != 2 {
		t.Fatalf("rejects=%d waiver calls=%d, want 1/2", rejects, calls.Load())
	}

	// The waiver is consulted ONLY for a solve about to be rejected: never
	// for an armed solve that passes, nor for a failing solve with no arm.
	if resp = postVerify(t, base, "66.249.81.201", armedHost, desktop, passing); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("passing armed solve: status=%d", resp.StatusCode)
	}
	if resp = postVerify(t, base, "66.249.81.202", unarmedHost, readAloud, failing); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unarmed failing solve: status=%d", resp.StatusCode)
	}
	if calls.Load() != 2 {
		t.Fatalf("the waiver ran for a solve that was never going to be rejected: calls=%d", calls.Load())
	}

	// An explicit traffic-rule / WAF mark stays strict for a verified bot —
	// alone, or on top of a vhost arm — and the waiver isn't consulted.
	MarkChallengeV2("66.249.81.203", markHost)
	MarkChallengeV2("66.249.81.204", armedHost)
	for _, c := range []struct{ ip, host string }{{"66.249.81.203", markHost}, {"66.249.81.204", armedHost}} {
		resp = postVerify(t, base, c.ip, c.host, readAloud, failing)
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-CFM-V2") != "reject" {
			t.Fatalf("%s on %s under a mark: status=%d, want 403 + reject", c.ip, c.host, resp.StatusCode)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("the waiver ran under a mark: calls=%d", calls.Load())
	}

	// Waiver unwired (CHALLENGE_GOODBOT_EXEMPT off) → the bot is rejected too.
	SetChallengeV2GoodBot(nil)
	resp = postVerify(t, base, "66.249.81.205", armedHost, readAloud, failing)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("with no waiver wired the bot must be rejected, got %d", resp.StatusCode)
	}
}

// Only the grains the decision-time good-bot exemption softens (the geo floor,
// the vhost challenge) are waivable, and only without a mark on top.
func TestChallengeV2Waivable(t *testing.T) {
	resetChallengeV2Marks(t)
	const ip, host = "66.249.81.200", "shop.example.com"
	for grain, want := range map[string]bool{
		v2GrainGeo: true, v2GrainVhost: true, v2GrainFP: false, v2GrainMark: false, "": false,
	} {
		if got := challengeV2Waivable(grain, ip, host); got != want {
			t.Errorf("challengeV2Waivable(%q) = %v, want %v", grain, got, want)
		}
	}
	MarkChallengeV2(ip, host)
	for _, grain := range []string{v2GrainGeo, v2GrainVhost} {
		if challengeV2Waivable(grain, ip, host) {
			t.Errorf("grain %q with a traffic-rule/WAF mark on top must stay strict", grain)
		}
	}
	if !challengeV2Waivable(v2GrainVhost, ip, "other.example.com") {
		t.Errorf("a mark on another host must not affect this one")
	}
}

// NewEngine wires the waiver to the bridge's FCrDNS verdict cache under
// CHALLENGE_GOODBOT_EXEMPT — forward-confirming a first-seen candidate
// inline — and clears it when the exemption is off.
func TestNewEngineWiresTheV2GoodBotWaiver(t *testing.T) {
	setV2GoodBot(t, nil) // restores the previous waiver afterwards
	prevSolve := challengeSolveEnricher.Load()
	challengeV2.mu.RLock()
	prevHostArmed := challengeV2.hostArmed
	challengeV2.mu.RUnlock()
	t.Cleanup(func() {
		challengeSolveEnricher.Store(prevSolve)
		SetChallengeV2HostArmed(prevHostArmed)
	})
	const (
		cachedIP = "66.249.81.200"
		freshIP  = "66.102.9.41" // first seen
		freshPTR = "google-proxy-66-102-9-41.google.com"
		humanIP  = "203.0.113.9"
	)
	ctx := context.Background()

	e := NewEngine(Config{Every: time.Second, Window: time.Minute, ChallengeGoodBotExempt: true})
	gb := e.nginxBridge.goodBot
	gb.mu.Lock()
	gb.cache[cachedIP] = goodBotIPVerdict{name: "google", until: time.Now().Add(time.Hour)}
	gb.mu.Unlock()
	var verified []string
	gb.verify = func(ptr, ip string) (string, bool) {
		verified = append(verified, ip)
		if ip == freshIP && ptr == freshPTR {
			return "google", true
		}
		return "", true
	}

	if got := challengeV2GoodBot(ctx, cachedIP, ""); got != "google" {
		t.Fatalf("waiver with a cached FCrDNS verdict = %q, want google", got)
	}
	if got := challengeV2GoodBot(ctx, freshIP, freshPTR); got != "google" {
		t.Fatalf("a first-seen Google fetcher must be forward-confirmed inline, got %q", got)
	}
	if got := challengeV2GoodBot(ctx, humanIP, "ppp.otenet.gr"); got != "" {
		t.Fatalf("an unverified IP was waived: %q", got)
	}
	if got := challengeV2GoodBot(ctx, "66.102.9.42", ""); got != "" {
		t.Fatalf("with no known PTR the waiver is cache-only, got %q", got)
	}
	if len(verified) != 1 || verified[0] != freshIP {
		t.Fatalf("forward-confirms run = %v, want only the first-seen candidate", verified)
	}

	_ = NewEngine(Config{Every: time.Second, Window: time.Minute, ChallengeGoodBotExempt: false})
	if got := challengeV2GoodBot(ctx, cachedIP, ""); got != "" {
		t.Fatalf("with CHALLENGE_GOODBOT_EXEMPT off the waiver must be unwired, got %q", got)
	}
}

// verifiedBeforeReject answers from the cache when it can and forward-confirms
// a first-seen candidate inline (the Read-Aloud case: rotating IPs never have a
// verdict yet). It never does a reverse lookup, and costs no DNS and no slot
// for a solve whose PTR is unknown or not a crawler's — a solver farm's rejects
// stay cheap, and a client can't point the lookup at a zone it controls.
func TestGoodBotState_VerifiedBeforeReject(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	s := newBridgeGoodBotState()
	var verifies []string
	s.verify = func(ptr, ip string) (string, bool) {
		verifies = append(verifies, ip)
		switch ptr {
		case "google-proxy-66-249-81-200.google.com":
			return "google", true
		case "flaky.googlebot.com":
			return "", false // resolver failure
		}
		return "", true // spoofed: resolved, no match
	}
	const readAloudPTR = "google-proxy-66-249-81-200.google.com"

	// First seen, candidate PTR → forward-confirmed inline, then cached.
	if got := s.verifiedBeforeReject(ctx, "66.249.81.200", readAloudPTR, now); got != "google" {
		t.Fatalf("first-seen verified fetcher = %q, want google", got)
	}
	if got := s.verified("66.249.81.200", nil, now); got != "google" {
		t.Fatalf("the inline verdict must be cached for the decision path, got %q", got)
	}
	n := len(verifies)
	if got := s.verifiedBeforeReject(ctx, "66.249.81.200", "", now); got != "google" || len(verifies) != n {
		t.Fatalf("cached verdict: got %q, verifies %d→%d", got, n, len(verifies))
	}

	// Known non-crawler PTR, or no PTR known → "" with no DNS at all.
	if got := s.verifiedBeforeReject(ctx, "203.0.113.9", "ppp.otenet.gr", now); got != "" || len(verifies) != n {
		t.Fatalf("non-candidate PTR: got %q, verifies %d→%d", got, n, len(verifies))
	}
	if got := s.verifiedBeforeReject(ctx, "203.0.113.10", "", now); got != "" || len(verifies) != n {
		t.Fatalf("unknown PTR: got %q, verifies %d→%d", got, n, len(verifies))
	}

	// Spoofed candidate → "" and a cached negative (no second forward-confirm).
	for i := 0; i < 2; i++ {
		if got := s.verifiedBeforeReject(ctx, "198.51.100.7", "x.googlebot.com", now); got != "" {
			t.Fatalf("spoofed candidate waived: %q", got)
		}
	}
	if len(verifies) != n+1 {
		t.Fatalf("a spoofed candidate must be forward-confirmed once, then cached: verifies=%d", len(verifies)-n)
	}
	// Resolver failure → no waiver, nothing cached.
	if got := s.verifiedBeforeReject(ctx, "198.51.100.8", "flaky.googlebot.com", now); got != "" {
		t.Fatalf("transient failure must not waive, got %q", got)
	}
	s.mu.RLock()
	_, cached := s.cache["198.51.100.8"]
	s.mu.RUnlock()
	if cached {
		t.Fatalf("a transient failure must not be cached")
	}

	// A stale positive: kept with no PTR known, dropped when the known PTR is
	// no longer a crawler's (the IP was reassigned).
	stale := func(ip string) {
		s.mu.Lock()
		s.cache[ip] = goodBotIPVerdict{name: "google", until: now.Add(-time.Minute)}
		s.mu.Unlock()
	}
	stale("66.249.90.1")
	if got := s.verifiedBeforeReject(ctx, "66.249.90.1", "", now); got != "google" {
		t.Fatalf("stale positive with no known PTR = %q, want google", got)
	}
	stale("66.249.90.2")
	if got := s.verifiedBeforeReject(ctx, "66.249.90.2", "home.example.net", now); got != "" {
		t.Fatalf("stale positive with a reassigned PTR = %q, want \"\"", got)
	}

	// Slots all taken (a burst of inline verifies):
	for i := 0; i < goodBotSyncMaxInflight; i++ {
		s.syncSem <- struct{}{}
	}
	// ...a known non-crawler PTR still answers at once: it never waits on one;
	start := time.Now()
	if got := s.verifiedBeforeReject(ctx, "203.0.113.11", "cpe.example.net", now); got != "" || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("non-candidate PTR with slots full: got %q after %v, want \"\" at once", got, time.Since(start))
	}
	// ...a candidate whose client gives up gets no waiver, promptly — unless a
	// stale positive stands, which is honoured as verified() would.
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	start = time.Now()
	if got := s.verifiedBeforeReject(short, "66.249.81.9", readAloudPTR, now); got != "" {
		t.Fatalf("no slot: got %q, want no waiver", got)
	}
	stale("66.249.90.3")
	if got := s.verifiedBeforeReject(short, "66.249.90.3", readAloudPTR, now); got != "google" {
		t.Fatalf("no slot, stale positive: got %q, want google", got)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("a cancelled wait must return promptly")
	}
}

func TestRecordChallengeSolved_PersistsV2Waived(t *testing.T) {
	e := newSolveTestEngine(t)
	e.RecordChallengeSolved(ChallengeSolve{
		IP: "66.249.81.200", Host: "shop.example.com", URI: "/",
		HumanityScored: true, HumanityScore: 140, V2Grain: v2GrainGeo, V2Waived: "google",
	})
	p := latestSolveEvent(t, e).Payload
	if p["v2"] != v2GrainGeo || p["v2_waived"] != "google" {
		t.Fatalf("history payload v2=%v v2_waived=%v, want geo/google", p["v2"], p["v2_waived"])
	}
}
