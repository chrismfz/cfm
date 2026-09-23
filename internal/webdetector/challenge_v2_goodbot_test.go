package webdetector

import (
	"context"
	"net/http"
	"strings"
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

// An FCrDNS-verified good bot is waived at the D5 gate instead of rejected —
// the same exemption CHALLENGE_GOODBOT_EXEMPT grants at decision time. Seen on
// the fleet: Google-Read-Aloud (rotating Google fetcher IPs) scores 140
// (sw_renderer,touch_lie,no_input) on ad-click landings and would be rejected
// on any armed vhost. Everyone else is still rejected.
func TestVerify_V2GateWaivesAVerifiedGoodBot(t *testing.T) {
	base, capt := startVerifyServer(t)
	const (
		botIP   = "66.249.81.200"
		humanIP = "203.0.113.9"
		host    = "shop.example.com"
		ua      = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 (compatible; Google-Read-Aloud; +https://support.google.com/webmasters/answer/1061943)"
		failing = `{"v":1,"wd":true,"ptr":0,"tch":0,"key":0}`
	)
	var askedPTR string
	setV2GoodBot(t, func(_ context.Context, ip, ptr string) string {
		askedPTR = ptr
		if ip == botIP {
			return "google"
		}
		return ""
	})
	MarkChallengeV2(botIP, host)
	MarkChallengeV2(humanIP, host)

	resp := postVerify(t, base, botIP, host, ua, failing)
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("a verified good bot was rejected: X-CFM-V2=%q", resp.Header.Get("X-CFM-V2"))
	}
	solved, rejects := capt.counts()
	if solved != 1 || rejects != 0 {
		t.Fatalf("waived solve: solved=%d rejects=%d, want 1/0", solved, rejects)
	}
	s := capt.solved[0]
	if s.V2Waived != "google" || s.V2Grain != v2GrainMark || s.HumanityScore < defaultV2FailScore {
		t.Fatalf("waived solve not attributed: waived=%q grain=%q hs=%d", s.V2Waived, s.V2Grain, s.HumanityScore)
	}
	if !strings.Contains(s.HumanitySuffix(), " v2=mark v2_waived=google") {
		t.Errorf("solve line does not show the waiver: %q", s.HumanitySuffix())
	}
	if askedPTR != "ppp.otenet.gr" {
		t.Errorf("the waiver was not given the solve's resolved PTR: %q", askedPTR)
	}

	// Not a verified bot → rejected exactly as before.
	resp = postVerify(t, base, humanIP, host, ua, failing)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-CFM-V2") != "reject" {
		t.Fatalf("unverified failing solve: status=%d X-CFM-V2=%q, want 403 + reject", resp.StatusCode, resp.Header.Get("X-CFM-V2"))
	}
	if _, rejects = capt.counts(); rejects != 1 {
		t.Fatalf("rejects=%d, want 1", rejects)
	}

	// Waiver unwired (CHALLENGE_GOODBOT_EXEMPT off) → the bot is rejected too.
	SetChallengeV2GoodBot(nil)
	resp = postVerify(t, base, botIP, host, ua, failing)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("with no waiver wired the bot must be rejected, got %d", resp.StatusCode)
	}
}

// NewEngine wires the waiver to the bridge's FCrDNS verdict cache under
// CHALLENGE_GOODBOT_EXEMPT — verifying a first-seen IP inline — and clears it
// when the exemption is off.
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
		freshIP  = "66.102.9.41" // first seen, PTR not in the enrich cache yet
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
		if ip == freshIP && ptr == "google-proxy-66-102-9-41.google.com" {
			return "google", true
		}
		return "", true
	}
	e.simulatePTRFn = func(ip string) (string, bool) {
		if ip == freshIP {
			return "google-proxy-66-102-9-41.google.com", true
		}
		return "", true
	}

	if got := challengeV2GoodBot(ctx, cachedIP, ""); got != "google" {
		t.Fatalf("waiver with a cached FCrDNS verdict = %q, want google", got)
	}
	if got := challengeV2GoodBot(ctx, freshIP, ""); got != "google" {
		t.Fatalf("a first-seen Google fetcher must be verified inline, got %q", got)
	}
	if got := challengeV2GoodBot(ctx, humanIP, "ppp.otenet.gr"); got != "" {
		t.Fatalf("an unverified IP was waived: %q", got)
	}
	if len(verified) != 1 || verified[0] != freshIP {
		t.Fatalf("forward-confirms run = %v, want only the first-seen candidate", verified)
	}

	_ = NewEngine(Config{Every: time.Second, Window: time.Minute, ChallengeGoodBotExempt: false})
	if got := challengeV2GoodBot(ctx, cachedIP, ""); got != "" {
		t.Fatalf("with CHALLENGE_GOODBOT_EXEMPT off the waiver must be unwired, got %q", got)
	}
}

// verifiedBeforeReject answers from the cache when it can, verifies a
// first-seen candidate inline (the Read-Aloud case: rotating IPs never have a
// verdict yet), and costs no DNS and no slot for a solve whose PTR is already
// known not to be a crawler's — a solver farm's rejects stay cheap.
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
	lookups := 0
	lookup := func(ptr string, ok bool) func() (string, bool) {
		return func() (string, bool) { lookups++; return ptr, ok }
	}
	noLookup := func() (string, bool) { t.Fatal("reverse lookup must not run when the PTR is known"); return "", false }

	// First seen, PTR already known and a candidate → verified inline, cached.
	if got := s.verifiedBeforeReject(ctx, "66.249.81.200", "google-proxy-66-249-81-200.google.com", noLookup, now); got != "google" {
		t.Fatalf("first-seen verified fetcher = %q, want google", got)
	}
	if got := s.verified("66.249.81.200", nil, now); got != "google" {
		t.Fatalf("the inline verdict must be cached for the decision path, got %q", got)
	}
	// Cached now: no second forward-confirm.
	n := len(verifies)
	if got := s.verifiedBeforeReject(ctx, "66.249.81.200", "", nil, now); got != "google" || len(verifies) != n {
		t.Fatalf("cached verdict: got %q, verifies %d→%d", got, n, len(verifies))
	}

	// Known non-crawler PTR → "" with no DNS at all.
	if got := s.verifiedBeforeReject(ctx, "203.0.113.9", "ppp.otenet.gr", noLookup, now); got != "" || len(verifies) != n {
		t.Fatalf("non-candidate PTR: got %q, verifies %d→%d", got, n, len(verifies))
	}

	// PTR not known yet → reverse lookup inline, then forward-confirm.
	if got := s.verifiedBeforeReject(ctx, "198.51.100.7", "", lookup("x.googlebot.com", true), now); got != "" || lookups != 1 || len(verifies) != n+1 {
		t.Fatalf("spoofed candidate: got %q lookups=%d verifies=%d", got, lookups, len(verifies))
	}
	// Resolver failure → no waiver, nothing cached.
	if got := s.verifiedBeforeReject(ctx, "198.51.100.8", "flaky.googlebot.com", noLookup, now); got != "" {
		t.Fatalf("transient failure must not waive, got %q", got)
	}
	s.mu.RLock()
	_, cached := s.cache["198.51.100.8"]
	s.mu.RUnlock()
	if cached {
		t.Fatalf("a transient failure must not be cached")
	}

	// A stale positive: kept when the PTR can't be learned (PTR enrichment
	// off), dropped when the known PTR is no longer a crawler's.
	stale := func(ip string) {
		s.mu.Lock()
		s.cache[ip] = goodBotIPVerdict{name: "google", until: now.Add(-time.Minute)}
		s.mu.Unlock()
	}
	stale("66.249.90.1")
	if got := s.verifiedBeforeReject(ctx, "66.249.90.1", "", nil, now); got != "google" {
		t.Fatalf("stale positive with no PTR resolver = %q, want google", got)
	}
	stale("66.249.90.2")
	if got := s.verifiedBeforeReject(ctx, "66.249.90.2", "home.example.net", noLookup, now); got != "" {
		t.Fatalf("stale positive with a reassigned PTR = %q, want \"\"", got)
	}

	// Slots all taken (a flood of inline verifies) and the client gives up:
	// no waiver, promptly — the solve is rejected as before.
	for i := 0; i < goodBotSyncMaxInflight; i++ {
		s.syncSem <- struct{}{}
	}
	// ...a known non-crawler PTR still answers at once: it never waits on one.
	start := time.Now()
	if got := s.verifiedBeforeReject(ctx, "203.0.113.10", "cpe.example.net", noLookup, now); got != "" || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("non-candidate PTR with slots full: got %q after %v, want \"\" at once", got, time.Since(start))
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	start = time.Now()
	if got := s.verifiedBeforeReject(short, "66.249.81.9", "google-proxy-66-249-81-200.google.com", noLookup, now); got != "" {
		t.Fatalf("no slot: got %q, want no waiver", got)
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
