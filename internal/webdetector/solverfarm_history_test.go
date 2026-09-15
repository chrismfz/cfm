package webdetector

import (
	"testing"
	"time"
)

// goodBotsFor builds the sparse {ip: name} good-bot map that RecordSolverFarmFinding
// attaches to a finding. It must tag ONLY forward-confirmed crawlers, never the
// farm's ordinary addresses, and must not fan out DNS for an IP whose verdict is
// already cached (the finding's IPs are edge-seen, so most are warm).
func TestGoodBotsFor_TagsOnlyConfirmedCrawlers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	gb := newBridgeGoodBotState()
	gb.store("66.249.66.1", "googlebot", now) // pre-confirmed crawler (cache hit)
	gb.store("13.66.139.1", "bingbot", now)

	// A cache hit must NOT trigger a PTR resolve; a plain farm IP has no good-bot PTR.
	ptrCalls := map[string]int{}
	ptrOf := func(ip string) string {
		ptrCalls[ip]++
		return "" // farm IPs: nothing that looks like a crawler
	}

	ips := []string{"66.249.66.1", "203.0.113.9", "13.66.139.1", "203.0.113.10"}
	out := goodBotsFor(ips, ptrOf, gb, nil, 0, now) // no operator file

	if len(out) != 2 {
		t.Fatalf("want 2 tagged crawlers, got %d: %v", len(out), out)
	}
	if out["66.249.66.1"] != "googlebot" || out["13.66.139.1"] != "bingbot" {
		t.Fatalf("wrong good-bot names: %v", out)
	}
	if _, ok := out["203.0.113.9"]; ok {
		t.Fatalf("an ordinary farm address must never be tagged: %v", out)
	}
	// A cached-verdict IP is claimed by the verdict cache without resolving a PTR at
	// all (lazy + memoized), and the file layer is never reached for it.
	if ptrCalls["66.249.66.1"] != 0 || ptrCalls["13.66.139.1"] != 0 {
		t.Fatalf("a cached-verdict IP must not resolve its PTR: %v", ptrCalls)
	}
}

// A finding with no good bots (the common case) yields a nil map, so the caller
// omits the `good_bots` payload key entirely rather than shipping an empty object.
func TestGoodBotsFor_NoCrawlersYieldsNilMap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	gb := newBridgeGoodBotState()

	if out := goodBotsFor(nil, func(string) string { return "" }, gb, nil, 0, now); out != nil {
		t.Fatalf("no IPs → nil, got %v", out)
	}
	if out := goodBotsFor([]string{"203.0.113.1", "198.51.100.2"}, func(string) string { return "" }, gb, nil, 0, now); out != nil {
		t.Fatalf("no good bots → nil (not empty map), got %v", out)
	}
	// Defensive nil guards mirror goodBotsForFinding's (nil enricher / cache).
	if out := goodBotsFor([]string{"1.2.3.4"}, nil, gb, nil, 0, now); out != nil {
		t.Fatalf("nil ptrOf → nil, got %v", out)
	}
	if out := goodBotsFor([]string{"1.2.3.4"}, func(string) string { return "" }, nil, nil, 0, now); out != nil {
		t.Fatalf("nil cache → nil, got %v", out)
	}
}

// The operator-file layer (chalGoodBotFunc) tags crawlers the canonical map doesn't
// know, but only for an IP the canonical cache didn't already claim and only when a
// PTR is present. Canonical always wins.
func TestGoodBotsFor_FileLayerTagsBeyondCanonical(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	gb := newBridgeGoodBotState()
	gb.store("66.249.66.1", "googlebot", now) // canonical, cache hit — file layer must be skipped

	ptr := map[string]string{
		"66.249.66.1":  "crawl.googlebot.com",
		"5.5.5.1":      "bot.ahrefs.com",        // operator-file crawler
		"5.5.5.2":      "spider.semrush.com",    // operator-file crawler
		"203.0.113.9":  "pool.badproxy.example", // neither
		"203.0.113.10": "",                      // no PTR → file layer skipped
	}
	ptrOf := func(ip string) string { return ptr[ip] }

	// Fake matcher standing in for ChallengeExclude.VerifiedGoodBotName: a
	// registrable-domain name for the two operator crawlers, spending the shared
	// budget per candidate (no budget spent for a non-candidate PTR).
	fileFn := func(ip, p string, budget *int) (string, bool) {
		name := map[string]string{"bot.ahrefs.com": "ahrefs.com", "spider.semrush.com": "semrush.com"}[p]
		if name == "" {
			return "", false // not a glob candidate → no DNS, no budget
		}
		if budget != nil {
			if *budget <= 0 {
				return "", false
			}
			*budget--
		}
		return name, true
	}

	ips := []string{"66.249.66.1", "5.5.5.1", "5.5.5.2", "203.0.113.9", "203.0.113.10"}
	out := goodBotsFor(ips, ptrOf, gb, fileFn, maxFindingFileConfirm, now)

	want := map[string]string{"66.249.66.1": "googlebot", "5.5.5.1": "ahrefs.com", "5.5.5.2": "semrush.com"}
	if len(out) != len(want) {
		t.Fatalf("want %v, got %v", want, out)
	}
	for ip, n := range want {
		if out[ip] != n {
			t.Fatalf("ip %s: want %q, got %q (full: %v)", ip, n, out[ip], out)
		}
	}
	if _, ok := out["203.0.113.10"]; ok {
		t.Fatalf("a no-PTR IP is never offered to the file layer: %v", out)
	}
}

// A canonical-suffix PTR (even a spoofed one) is the ASYNC canonical path's job and
// must never reach the SYNCHRONOUS file layer — that keeps an attacker's guessable
// *.googlebot.com PTRs off the blocking forward-confirm.
func TestGoodBotsFor_CanonicalPTRBypassesFileLayer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	gb := newBridgeGoodBotState()
	gb.verify = func(string, string) (string, bool) { return "", true } // stub: no real DNS on the async kick

	ptrOf := func(string) string { return "crawl.googlebot.com" } // canonical suffix
	fileCalled := 0
	fileFn := func(ip, p string, budget *int) (string, bool) { fileCalled++; return "googlebot.com", true }

	out := goodBotsFor([]string{"1.2.3.4"}, ptrOf, gb, fileFn, maxFindingFileConfirm, now)
	if fileCalled != 0 {
		t.Fatalf("a canonical-suffix PTR must not reach the file layer, got %d call(s)", fileCalled)
	}
	if len(out) != 0 {
		t.Fatalf("canonical miss + no file confirm → no tag, got %v", out)
	}
}

// The file budget is shared across the whole finding, so a pathological sample full
// of operator-crawler PTRs can never spend more than the cap in forward-confirms.
func TestGoodBotsFor_FileBudgetCapsConfirms(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	gb := newBridgeGoodBotState()
	ptrOf := func(string) string { return "bot.ahrefs.com" } // every IP is a candidate

	confirms := 0
	fileFn := func(ip, p string, budget *int) (string, bool) {
		if budget != nil {
			if *budget <= 0 {
				return "", false
			}
			*budget--
		}
		confirms++
		return "ahrefs.com", true
	}

	ips := []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"}
	out := goodBotsFor(ips, ptrOf, gb, fileFn, 2, now) // budget of 2

	if confirms != 2 {
		t.Fatalf("budget of 2 must cap forward-confirms at 2, got %d", confirms)
	}
	if len(out) != 2 {
		t.Fatalf("only the 2 budgeted IPs are tagged, got %d: %v", len(out), out)
	}
}
