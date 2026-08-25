package webdetector

import (
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
	// After posTTL the verdict is stale; verified() no longer returns it (it would
	// re-kick a verify, which returns "" immediately on the hot path).
	if got := s.verified("66.249.74.1", ptrFn, base.Add(goodBotIPPosTTL+time.Minute)); got != "" {
		t.Fatalf("expired verdict must not be served, got %q", got)
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
