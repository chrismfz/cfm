package webdetector

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLooksLikeGoodBotPTR(t *testing.T) {
	cases := map[string]bool{
		"crawl-66-249-74-1.googlebot.com": true,
		"host.fbsv.net":                   true, // Meta
		"foo.search.msn.com":              true, // Bing
		"5.bl.bot.semrush.com":            false,
		"":                                false,
		"c-73-1-2-3.hsd1.wa.comcast.net":  false,
		"EVIL.GOOGLEBOT.COM.":             true, // case + trailing dot normalised (candidate only)
	}
	for ptr, want := range cases {
		if got := looksLikeGoodBotPTR(ptr); got != want {
			t.Errorf("looksLikeGoodBotPTR(%q) = %v, want %v", ptr, got, want)
		}
	}
}

func TestGoodBotDowngrade(t *testing.T) {
	cases := []struct {
		name            string
		ipIn, vhIn, bot string
		ipWant, vhWant  string
	}{
		{"empty bot is a no-op", "challenge", "challenge", "", "challenge", "challenge"},
		{"vhost challenge downgraded", "allow", "challenge", "googlebot", "allow", "allow"},
		{"ip challenge downgraded", "challenge", "allow", "bingbot", "allow", "allow"},
		{"both downgraded", "challenge", "challenge", "meta", "allow", "allow"},
		{"block is NEVER softened", "block", "challenge", "googlebot", "block", "allow"},
		{"allow stays allow", "allow", "allow", "googlebot", "allow", "allow"},
	}
	for _, c := range cases {
		gotIP, gotVH := goodBotDowngrade(c.ipIn, c.vhIn, c.bot)
		if gotIP != c.ipWant || gotVH != c.vhWant {
			t.Errorf("%s: goodBotDowngrade(%q,%q,%q) = (%q,%q), want (%q,%q)",
				c.name, c.ipIn, c.vhIn, c.bot, gotIP, gotVH, c.ipWant, c.vhWant)
		}
	}
}

// A cached positive verdict is served O(1) until it expires; after posTTL it is
// gone and a re-check would be needed.
func TestGoodBotState_VerifiedCacheHit(t *testing.T) {
	s := newBridgeGoodBotState()
	s.verify = func(ptr, ip string) (string, bool) { return "", true } // no real DNS on the post-expiry re-kick
	base := time.Unix(1_700_000_000, 0)
	s.store("66.249.74.1", "googlebot", base)

	ptrFn := func() string { return "x.googlebot.com" }
	if got := s.verified("66.249.74.1", ptrFn, base.Add(time.Minute)); got != "googlebot" {
		t.Fatalf("fresh positive verdict: got %q, want googlebot", got)
	}
	// After posTTL the positive is STALE: it is still served (within the grace)
	// while an async re-verify is kicked, so a crawler never loses its verdict
	// for one request per TTL. Beyond the grace it is a plain miss.
	if got := s.verified("66.249.74.1", ptrFn, base.Add(goodBotIPPosTTL+time.Minute)); got != "googlebot" {
		t.Fatalf("stale positive within grace must still be served, got %q", got)
	}
	if got := s.verified("66.249.74.1", ptrFn, base.Add(goodBotIPPosTTL+goodBotIPStaleGrace+time.Minute)); got != "" {
		t.Fatalf("positive beyond the stale grace must not be served, got %q", got)
	}
	// A stale NEGATIVE is never served: it is a miss that re-verifies.
	n := newBridgeGoodBotState()
	n.verify = func(ptr, ip string) (string, bool) { return "", true }
	n.store("5.5.5.5", "", base)
	if got := n.verified("5.5.5.5", func() string { return "spoof.googlebot.com" }, base.Add(goodBotIPNegTTL+time.Minute)); got != "" {
		t.Fatalf("expired negative must not be served as anything, got %q", got)
	}
}

// A non-candidate PTR (no good-bot suffix) must never enter the verify path or
// the cache — the common attacker-IP case stays cheap and leaves no state.
func TestGoodBotState_NonCandidateNoVerify(t *testing.T) {
	var calls int
	s := newBridgeGoodBotState()
	s.verify = func(ptr, ip string) (string, bool) { calls++; return "", true }

	ptrFn := func() string { return "c-1-2-3-4.hsd1.wa.comcast.net" }
	if got := s.verified("1.2.3.4", ptrFn, time.Unix(1_700_000_000, 0)); got != "" {
		t.Fatalf("non-candidate: got %q, want empty", got)
	}
	// give any (erroneous) goroutine a moment
	time.Sleep(20 * time.Millisecond)
	if calls != 0 {
		t.Fatalf("verify called %d times for a non-candidate PTR, want 0", calls)
	}
	s.mu.Lock()
	n := len(s.cache)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("non-candidate left %d cache entries, want 0", n)
	}
}

// resolveInto forward-confirms and stores: a positive gets posTTL, a negative
// (spoofed / not a bot) gets the short negTTL so a spoofer isn't re-verified
// every request but a transient failure recovers soon.
func TestGoodBotState_ResolveIntoStores(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	pos := newBridgeGoodBotState()
	pos.verify = func(ptr, ip string) (string, bool) { return "googlebot", true }
	pos.resolveInto("66.249.74.1", "x.googlebot.com", base)
	if got := pos.verified("66.249.74.1", func() string { return "x.googlebot.com" }, base.Add(goodBotIPNegTTL+time.Second)); got != "googlebot" {
		t.Fatalf("positive verdict should survive past negTTL, got %q", got)
	}

	neg := newBridgeGoodBotState()
	neg.verify = func(ptr, ip string) (string, bool) { return "", true } // forward-confirm resolved, no match (spoofed) -> cacheable negative
	neg.resolveInto("9.9.9.9", "evil.googlebot.com", base)
	// within negTTL: cached negative → verified returns "" WITHOUT re-verifying.
	// ptrFn must not even be consulted on a fresh cache hit, so fail if it is.
	neg.verify = func(ptr, ip string) (string, bool) { t.Fatal("must not re-verify within negTTL"); return "", true }
	ptrFn := func() string { t.Fatal("ptrFn must not run on a cache hit"); return "" }
	if got := neg.verified("9.9.9.9", ptrFn, base.Add(time.Minute)); got != "" {
		t.Fatalf("spoofed PTR must not be exempt, got %q", got)
	}
}

// The async path: a cache miss for a candidate kicks a background verify that
// populates the cache for the crawler's next request.
func TestGoodBotState_AsyncKickPopulates(t *testing.T) {
	done := make(chan struct{})
	var once sync.Once
	s := newBridgeGoodBotState()
	s.verify = func(ptr, ip string) (string, bool) {
		once.Do(func() { close(done) })
		return "meta", true
	}

	ptrFn := func() string { return "x.fbsv.net" }
	// First call: miss + candidate → returns "" now, kicks async verify.
	if got := s.verified("57.141.20.1", ptrFn, time.Now()); got != "" {
		t.Fatalf("first call should not block/return a verdict, got %q", got)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("async verify never ran")
	}
	// Poll for the verdict to land (store happens right after verify returns).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := s.verified("57.141.20.1", ptrFn, time.Now()); got == "meta" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("verdict never populated the cache")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// store bounds cache growth: at the cap it prunes expired entries first.
func TestGoodBotState_StorePrunesAtCap(t *testing.T) {
	s := newBridgeGoodBotState()
	base := time.Unix(1_700_000_000, 0)
	// Fill with entries that are already expired relative to a later "now".
	for i := 0; i < goodBotIPCacheCap; i++ {
		s.cache[ipKeyForTest(i)] = goodBotIPVerdict{name: "", until: base.Add(time.Second)}
	}
	// A store far in the future should prune the expired ones and admit the new.
	future := base.Add(time.Hour)
	s.store("new.ip", "googlebot", future)
	s.mu.Lock()
	_, ok := s.cache["new.ip"]
	n := len(s.cache)
	s.mu.Unlock()
	if !ok {
		t.Fatal("new entry not admitted after prune")
	}
	if n > goodBotIPCacheCap {
		t.Fatalf("cache grew past cap: %d", n)
	}
}

// A transient (inconclusive) verify result must NOT be cached, so a real crawler
// whose forward-confirm hit a DNS blip is re-verified next request rather than
// pinned as "not a bot" for negTTL.
func TestGoodBotState_TransientNotCached(t *testing.T) {
	s := newBridgeGoodBotState()
	s.verify = func(ptr, ip string) (string, bool) { return "", false } // inconclusive
	base := time.Unix(1_700_000_000, 0)
	s.resolveInto("66.249.74.1", "x.googlebot.com", base)
	s.mu.RLock()
	_, cached := s.cache["66.249.74.1"]
	s.mu.RUnlock()
	if cached {
		t.Fatal("inconclusive (transient) result must not be cached")
	}
}

// A positive verdict must be admitted even when the cache is full of (cheap)
// negatives — a fake-PTR flood of negatives must not disable the exemption.
func TestGoodBotState_PositiveEvictsNegativeAtCap(t *testing.T) {
	s := newBridgeGoodBotState()
	future := time.Unix(1_700_000_000, 0).Add(time.Hour)
	// Fill to cap with UNEXPIRED negatives (until far in the future).
	for i := 0; i < goodBotIPCacheCap; i++ {
		s.cache[ipKeyForTest(i)] = goodBotIPVerdict{name: "", until: future.Add(time.Hour)}
	}
	s.store("66.249.74.1", "googlebot", future) // a positive
	s.mu.RLock()
	v, ok := s.cache["66.249.74.1"]
	n := len(s.cache)
	s.mu.RUnlock()
	if !ok || v.name != "googlebot" {
		t.Fatal("positive verdict was not admitted by evicting a negative")
	}
	if n > goodBotIPCacheCap {
		t.Fatalf("cache grew past cap: %d", n)
	}
}

func ipKeyForTest(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
}

// TestGoodBotState_VerifiedSync: the simulate-API variant resolves inline —
// a candidate PTR is verified now (not on a later request), a non-candidate
// PTR costs no verify, a cached verdict is served, and an inconclusive verify
// (transient DNS failure) leaves nothing cached.
func TestGoodBotState_VerifiedSync(t *testing.T) {
	now := time.Now()
	calls := 0
	s := newBridgeGoodBotState()
	s.verify = func(ptr, ip string) (string, bool) {
		calls++
		if ip == "66.249.66.1" {
			return "googlebot", true
		}
		if ip == "9.9.9.9" {
			return "", false // transient
		}
		return "", true
	}
	ptrCalls := 0
	ptr := func(v string) func() string { return func() string { ptrCalls++; return v } }
	if got, why := s.verifiedSync(context.Background(), "66.249.66.1", ptr("crawl-66-249-66-1.googlebot.com."), now); got != "googlebot" || why != "" {
		t.Fatalf("sync verify: got %q", got)
	}
	if calls != 1 || ptrCalls != 1 {
		t.Fatalf("expected one verify + one PTR call, got verify=%d ptr=%d", calls, ptrCalls)
	}
	// Cached now: neither verified() nor verifiedSync() resolves the PTR again.
	if got := s.verified("66.249.66.1", func() string { t.Errorf("ptrFn must not run on a cache hit"); return "" }, now); got != "googlebot" {
		t.Fatalf("cache hit: got %q", got)
	}
	if got, _ := s.verifiedSync(context.Background(), "66.249.66.1", func() string { t.Errorf("ptrFn must not run on a cache hit"); return "" }, now); got != "googlebot" {
		t.Fatalf("sync cache hit: got %q", got)
	}
	if got, why := s.verifiedSync(context.Background(), "1.2.3.4", ptr("1-2-3-4.some-isp.example."), now); got != "" || why != "" || calls != 1 {
		t.Fatalf("non-candidate PTR must not verify: got %q calls=%d", got, calls)
	}
	if got, why := s.verifiedSync(context.Background(), "9.9.9.9", ptr("x.googlebot.com."), now); got != "" || why != verifiedInconclusiveTransient || calls != 2 {
		t.Fatalf("transient: got %q calls=%d", got, calls)
	}
	s.mu.RLock()
	_, cached := s.cache["9.9.9.9"]
	s.mu.RUnlock()
	if cached {
		t.Fatalf("inconclusive verify must not be cached")
	}
	if got, why := s.verifiedSync(context.Background(), "5.5.5.5", ptr("spoof.googlebot.com."), now); got != "" || why != "" {
		t.Fatalf("spoofed PTR must not verify: %q", got)
	}
	// The verdict is reported from the verifier, not re-read from a cache that
	// may have dropped the insert at its cap.
	full := newBridgeGoodBotState()
	full.verify = func(ptr, ip string) (string, bool) { return "googlebot", true }
	for i := 0; i < goodBotIPCacheCap; i++ {
		full.store(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "googlebot", now)
	}
	if got, _ := full.verifiedSync(context.Background(), "66.249.99.9", ptr("x.googlebot.com."), now); got != "googlebot" {
		t.Fatalf("verdict must survive a full cache: got %q", got)
	}
	// Verify slots are bounded: with every slot taken, verifiedSync waits
	// (bounded by ctx) instead of fanning out, proceeds once a slot frees, and
	// gives up — returning inconclusive — when the caller's context ends.
	bounded := newBridgeGoodBotState()
	bounded.verify = func(ptr, ip string) (string, bool) { return "googlebot", true }
	for i := 0; i < goodBotIPMaxInflight; i++ {
		bounded.sem <- struct{}{}
	}
	done := make(chan string, 1)
	go func() {
		n, _ := bounded.verifiedSync(context.Background(), "66.249.77.7", ptr("x.googlebot.com."), now)
		done <- n
	}()
	select {
	case got := <-done:
		t.Fatalf("verifiedSync must wait for a slot, returned %q", got)
	case <-time.After(50 * time.Millisecond):
	}
	<-bounded.sem
	select {
	case got := <-done:
		if got != "googlebot" {
			t.Fatalf("after a slot freed: got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("verifiedSync did not proceed after a slot freed")
	}
	// slots full again + a client that gives up: returns promptly, no verdict.
	bounded.sem <- struct{}{}
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	ptrCallsBefore := ptrCalls
	if got, why := bounded.verifiedSync(short, "66.249.88.8", ptr("y.googlebot.com."), now); got != "" || why != verifiedInconclusiveTimeout {
		t.Fatalf("cancelled wait must be inconclusive/timeout, got %q/%q", got, why)
	}
	if ptrCalls != ptrCallsBefore {
		t.Fatalf("the reverse lookup must not run before a slot is held")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("cancelled wait must return promptly")
	}
}

// TestGoodBotState_StaleDroppedWhenPTRChanged: a stale positive is served only
// while the IP still LOOKS like a crawler. A resolved PTR that no longer has a
// good-bot suffix is definitive evidence of reassignment: the stale verdict is
// dropped on the spot (both hot path and simulate). An empty PTR (enrich cache
// miss) is not evidence, so the stale positive stands.
func TestGoodBotState_StaleDroppedWhenPTRChanged(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	expired := base.Add(goodBotIPPosTTL + time.Minute)
	s := newBridgeGoodBotState()
	s.verify = func(ptr, ip string) (string, bool) { return "", true }
	s.store("66.249.74.1", "googlebot", base)
	// empty PTR → still stale-served
	if got := s.verified("66.249.74.1", func() string { return "" }, expired); got != "googlebot" {
		t.Fatalf("empty PTR must keep the stale positive, got %q", got)
	}
	// reassigned: PTR is some ISP now → dropped, and gone for good
	if got := s.verified("66.249.74.1", func() string { return "dyn-1.some-isp.example." }, expired); got != "" {
		t.Fatalf("non-candidate PTR must drop the stale positive, got %q", got)
	}
	s.mu.RLock()
	_, still := s.cache["66.249.74.1"]
	s.mu.RUnlock()
	if still {
		t.Fatalf("stale entry must be deleted once the PTR changed")
	}
	if got := s.verified("66.249.74.1", func() string { return "" }, expired.Add(time.Second)); got != "" {
		t.Fatalf("dropped verdict must not come back, got %q", got)
	}
	// verifiedSync on a stale candidate re-verifies inline and reports NOW's answer.
	s2 := newBridgeGoodBotState()
	s2.verify = func(ptr, ip string) (string, bool) { return "", true } // spoofed now
	s2.store("66.249.74.2", "googlebot", base)
	if got, why := s2.verifiedSync(context.Background(), "66.249.74.2", func() string { return "x.googlebot.com." }, expired); got != "" || why != "" {
		t.Fatalf("simulate must re-verify a stale candidate inline and report the current verdict, got %q/%q", got, why)
	}
}

// TestGoodBotState_PruneKeepsStalePositives: at the cache cap, pruning drops
// expired negatives but keeps an expired positive that is still inside the
// stale grace — otherwise a fake-PTR flood (cheap negatives) would evict a real
// crawler's verdict while starving its re-verify, and the stale grace would be
// worthless exactly when it matters.
func TestGoodBotState_PruneKeepsStalePositives(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	s := newBridgeGoodBotState()
	s.store("66.249.74.1", "googlebot", base) // positive, expires at +posTTL
	s.store("5.5.5.5", "", base)              // negative, expires at +negTTL
	later := base.Add(goodBotIPPosTTL + time.Minute)
	s.mu.Lock()
	s.pruneLocked(later)
	_, posKept := s.cache["66.249.74.1"]
	_, negKept := s.cache["5.5.5.5"]
	s.mu.Unlock()
	if !posKept || negKept {
		t.Fatalf("prune: expired positive within grace kept=%v (want true), expired negative kept=%v (want false)", posKept, negKept)
	}
	s.mu.Lock()
	s.pruneLocked(base.Add(goodBotIPPosTTL + goodBotIPStaleGrace + time.Minute))
	_, posKept = s.cache["66.249.74.1"]
	s.mu.Unlock()
	if posKept {
		t.Fatalf("positive past the stale grace must be pruned")
	}
}
