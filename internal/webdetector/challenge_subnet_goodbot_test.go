package webdetector

import (
	"testing"
	"time"
)

// A /24 whose sampled members all reverse to *.fbsv.net and forward-confirm
// must be exempt — the live 2026-08-21 FP (CHALLENGE_SUBNET challenging Meta's
// crawler fleet on a shop vhost).
func TestSubnetGoodBotCore_MetaFleetExempt(t *testing.T) {
	ips := map[string]struct{}{
		"57.141.20.2": {}, "57.141.20.9": {}, "57.141.20.29": {}, "57.141.20.30": {},
		"57.141.20.6": {}, "57.141.20.26": {},
	}
	ptrOf := func(ip string) string { return "fwdproxy-atn-020.fbsv.net" }
	verify := func(ptr, ip string) string { return "meta" } // FCrDNS passes
	budget := 20
	name, ok, complete := subnetGoodBotCore(ips, &budget, ptrOf, verify)
	if !ok || name != "meta" || !complete {
		t.Fatalf("Meta fleet: got (%q,%v,complete=%v), want (meta,true,true)", name, ok, complete)
	}
}

// A botnet /24 has no PTRs (or random residential ones) — never exempt.
func TestSubnetGoodBotCore_NoPTRsNotExempt(t *testing.T) {
	ips := map[string]struct{}{"1.2.3.4": {}, "1.2.3.5": {}, "1.2.3.6": {}, "1.2.3.7": {}}
	budget := 20
	if name, ok, complete := subnetGoodBotCore(ips, &budget, func(string) string { return "" }, func(string, string) string { return "should-not-run" }); ok || !complete {
		t.Fatalf("no-PTR subnet exempted as %q (complete=%v)", name, complete)
	}
}

// A spoofed PTR that fails forward-confirm earns nothing (verify returns "").
func TestSubnetGoodBotCore_SpoofedPTRNotExempt(t *testing.T) {
	ips := map[string]struct{}{"1.2.3.4": {}, "1.2.3.5": {}, "1.2.3.6": {}, "1.2.3.7": {}}
	ptrOf := func(ip string) string { return "crawl-fake.googlebot.com" }
	verify := func(ptr, ip string) string { return "" } // forward-confirm fails
	budget := 20
	if _, ok, _ := subnetGoodBotCore(ips, &budget, ptrOf, verify); ok {
		t.Fatal("spoofed-PTR subnet exempted")
	}
}

// Fewer than subnetGoodBotMinVerified verifications is not enough, even if the
// ones that verify are genuine — a couple of good-bot IPs parked in a hostile
// /24 must not shield it.
func TestSubnetGoodBotCore_MinorityNotEnough(t *testing.T) {
	ips := map[string]struct{}{"1.2.3.4": {}, "1.2.3.5": {}, "1.2.3.6": {}, "1.2.3.7": {}}
	calls := 0
	verify := func(ptr, ip string) string {
		calls++
		if calls <= subnetGoodBotMinVerified-1 {
			return "meta"
		}
		return ""
	}
	budget := 20
	if _, ok, _ := subnetGoodBotCore(ips, &budget, func(string) string { return "x.fbsv.net" }, verify); ok {
		t.Fatal("minority verification exempted the subnet")
	}
}

// Budget is counted per sampled IP, and a subnet whose budget runs out before a
// decision returns complete=false (so the caller does not cache it).
func TestSubnetGoodBotCore_BudgetPerIPAndTruncation(t *testing.T) {
	ips := map[string]struct{}{"1.2.3.4": {}, "1.2.3.5": {}, "1.2.3.6": {}, "1.2.3.7": {}}
	// 1) A full, non-matching sample spends one unit per member (up to the sample cap).
	budget := 20
	if _, ok, complete := subnetGoodBotCore(ips, &budget, func(string) string { return "" }, func(string, string) string { return "" }); ok || !complete {
		t.Fatalf("full non-match: ok=%v complete=%v want false,true", ok, complete)
	}
	if spent := 20 - budget; spent != subnetGoodBotSample {
		t.Fatalf("budget spent=%d, want one unit per sampled IP (%d)", spent, subnetGoodBotSample)
	}
	// 2) Budget exhausted immediately → no decision, complete=false.
	zero := 0
	if _, ok, complete := subnetGoodBotCore(ips, &zero, func(string) string { return "x.fbsv.net" }, func(string, string) string { return "meta" }); ok || complete {
		t.Fatalf("zero budget: ok=%v complete=%v want false,false (truncated)", ok, complete)
	}
}

// The engine method is nil-safe: no enricher (as in tests) never exempts.
func TestSubnetVerifiedGoodBot_NilEnrSafe(t *testing.T) {
	e := &Engine{}
	budget := 5
	if _, ok := e.subnetVerifiedGoodBot("1.2.3.0/24", map[string]struct{}{"1.2.3.4": {}}, &budget, time.Now()); ok {
		t.Fatal("nil enricher must never exempt")
	}
}

// The cache logic of subnetGoodBotState.verdict, exercised with a stub resolve
// so no DNS runs: a fresh verdict is served from cache (resolve not re-called)
// within TTL and reports fresh=false; a non-cacheable (budget-truncated) resolve
// is not cached (re-tried next tick); an expired verdict re-resolves fresh.
func TestSubnetGoodBotState_VerdictCacheAndFreshness(t *testing.T) {
	var st subnetGoodBotState
	now := time.Unix(1_700_000_000, 0)
	calls := 0
	resolve := func() (string, bool, bool) { calls++; return "meta", true, true }

	// 1) cold miss → resolve runs, caches positive (30m), fresh.
	if name, ok, fresh := st.verdict("a/24", now, resolve); !ok || name != "meta" || !fresh {
		t.Fatalf("cold: (%q,%v,fresh=%v) want (meta,true,true)", name, ok, fresh)
	}
	if calls != 1 {
		t.Fatalf("cold: calls=%d, want 1", calls)
	}
	// 2) within posTTL → served from cache, resolve NOT re-called, fresh=false
	// (the F1 invariant: the caller must not re-log this).
	if name, ok, fresh := st.verdict("a/24", now.Add(10*time.Minute), resolve); !ok || name != "meta" || fresh {
		t.Fatalf("cached: (%q,%v,fresh=%v) want (meta,true,false)", name, ok, fresh)
	}
	if calls != 1 {
		t.Fatalf("cache hit re-resolved: calls=%d", calls)
	}
	// 3) budget-truncated resolve (cacheable=false) → not cached, not fresh.
	truncated := func() (string, bool, bool) { calls++; return "", false, false }
	if _, ok, fresh := st.verdict("b/24", now, truncated); ok || fresh {
		t.Fatalf("truncated: ok=%v fresh=%v want false,false", ok, fresh)
	}
	if _, present := st.cache["b/24"]; present {
		t.Fatal("budget-truncated resolve must NOT be cached (must re-try next tick)")
	}
	// 4) after posTTL expiry → re-resolves, fresh again.
	if _, ok, fresh := st.verdict("a/24", now.Add(subnetGoodBotPosTTL+time.Second), resolve); !ok || !fresh {
		t.Fatalf("expired verdict should re-resolve fresh (ok=%v fresh=%v)", ok, fresh)
	}
	if calls != 3 {
		t.Fatalf("expiry did not re-resolve: calls=%d", calls)
	}
}

// At the cache cap, a new insert prunes expired entries inline so the map does
// not grow without bound between the periodic prunes.
func TestSubnetGoodBotState_VerdictCapPrunesExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	st := subnetGoodBotState{cache: make(map[string]subnetGoodBotVerdict, subnetGoodBotCacheCap)}
	// Fill to the cap with already-expired negative verdicts.
	for i := 0; i < subnetGoodBotCacheCap; i++ {
		st.cache[string(rune(i))+"/24"] = subnetGoodBotVerdict{until: now.Add(-time.Minute)}
	}
	resolve := func() (string, bool, bool) { return "meta", true, true }
	if _, ok, _ := st.verdict("fresh/24", now, resolve); !ok {
		t.Fatal("verdict at cap should still resolve")
	}
	if len(st.cache) > subnetGoodBotCacheCap {
		t.Fatalf("cache grew past cap without pruning: len=%d cap=%d", len(st.cache), subnetGoodBotCacheCap)
	}
	if _, present := st.cache["fresh/24"]; !present {
		t.Fatal("fresh verdict not stored after cap prune")
	}
}

// prune drops expired verdicts, keeps fresh ones.
func TestSubnetGoodBotState_Prune(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	st := subnetGoodBotState{cache: map[string]subnetGoodBotVerdict{
		"fresh/24": {name: "meta", until: now.Add(time.Minute)},
		"stale/24": {name: "", until: now.Add(-time.Minute)},
	}}
	st.prune(now)
	if _, ok := st.cache["stale/24"]; ok {
		t.Fatal("stale verdict not pruned")
	}
	if _, ok := st.cache["fresh/24"]; !ok {
		t.Fatal("fresh verdict wrongly pruned")
	}
}

// The Meta PTR suffix is registered so the REAL verifier suffix-gates it (the
// forward-confirm itself is not exercised here — no DNS in unit tests).
func TestGoodBotSuffixes_MetaRegistered(t *testing.T) {
	if goodBotPTRSuffixes[".fbsv.net"] != "meta" {
		t.Fatalf("goodBotPTRSuffixes missing .fbsv.net → meta: %v", goodBotPTRSuffixes)
	}
}
