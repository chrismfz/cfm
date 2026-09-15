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
	out := goodBotsFor(ips, ptrOf, gb, now)

	if len(out) != 2 {
		t.Fatalf("want 2 tagged crawlers, got %d: %v", len(out), out)
	}
	if out["66.249.66.1"] != "googlebot" || out["13.66.139.1"] != "bingbot" {
		t.Fatalf("wrong good-bot names: %v", out)
	}
	if _, ok := out["203.0.113.9"]; ok {
		t.Fatalf("an ordinary farm address must never be tagged: %v", out)
	}
	// The two confirmed IPs resolve from the verdict cache → ptrOf is never called
	// for them (no per-finding DNS storm on the common, already-warm case).
	if ptrCalls["66.249.66.1"] != 0 || ptrCalls["13.66.139.1"] != 0 {
		t.Fatalf("a cached-verdict IP must not resolve its PTR: %v", ptrCalls)
	}
}

// A finding with no good bots (the common case) yields a nil map, so the caller
// omits the `good_bots` payload key entirely rather than shipping an empty object.
func TestGoodBotsFor_NoCrawlersYieldsNilMap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	gb := newBridgeGoodBotState()

	if out := goodBotsFor(nil, func(string) string { return "" }, gb, now); out != nil {
		t.Fatalf("no IPs → nil, got %v", out)
	}
	if out := goodBotsFor([]string{"203.0.113.1", "198.51.100.2"}, func(string) string { return "" }, gb, now); out != nil {
		t.Fatalf("no good bots → nil (not empty map), got %v", out)
	}
	// Defensive nil guards mirror goodBotsForFinding's (nil enricher / cache).
	if out := goodBotsFor([]string{"1.2.3.4"}, nil, gb, now); out != nil {
		t.Fatalf("nil ptrOf → nil, got %v", out)
	}
	if out := goodBotsFor([]string{"1.2.3.4"}, func(string) string { return "" }, nil, now); out != nil {
		t.Fatalf("nil cache → nil, got %v", out)
	}
}
