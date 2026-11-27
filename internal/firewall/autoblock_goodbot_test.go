package firewall

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	cfgpkg "cfm/internal/config"
)

func TestAutoblockGoodBot(t *testing.T) {
	ptrs := map[string]string{
		"69.63.184.14":  "fwdproxy-ncg-014.fbsv.net",
		"198.51.100.7":  "spoof.fbsv.net",
		"198.51.100.8":  "host.example.net",
		"198.51.100.9":  "",
		"198.51.100.10": "flaky.fbsv.net",
	}
	calls := map[string]int{}
	restore := SetAutoblockGoodBotForTest(
		func(ip string) string { return ptrs[ip] },
		func(ptr, ip string) (string, bool) {
			calls[ip]++
			switch ip {
			case "69.63.184.14":
				return "meta", true
			case "198.51.100.10":
				return "", false // resolver timeout
			}
			return "", true // forward-confirm failed: spoofed
		})
	defer restore()

	skip := func(ip string, off bool) bool { s, _ := AutoblockGoodBot(nil, ip, off); return s }
	if !skip("69.63.184.14", false) {
		t.Errorf("verified Meta proxy not skipped")
	}
	if _, why := AutoblockGoodBot(nil, "69.63.184.14", false); why != "FCrDNS-verified good bot meta" || calls["69.63.184.14"] != 1 {
		t.Errorf("second crossing: why=%q after %d verifies, want the cached verdict (1 verify)", why, calls["69.63.184.14"])
	}
	if skip("69.63.184.14", true) {
		t.Errorf("THROTTLE_GOODBOT_EXEMPT=0 still skipped the Meta proxy")
	}
	if skip("198.51.100.7", false) {
		t.Errorf("spoofed suffix PTR skipped")
	}
	for _, ip := range []string{"198.51.100.8", "198.51.100.9"} {
		if skip(ip, false) || calls[ip] != 0 {
			t.Errorf("%s (PTR %q) skipped or verified (%d), want a ban with no DNS", ip, ptrs[ip], calls[ip])
		}
	}
	// Inconclusive: a crossing is skipped (one DNS blip must not ban a real
	// crawler) and re-verified next time, but a run that never resolves bans
	// on the third crossing: the PTR is the address owner's to set.
	if !skip("198.51.100.10", false) || !skip("198.51.100.10", false) {
		t.Errorf("inconclusive: first two crossings not skipped")
	}
	if skip("198.51.100.10", false) {
		t.Errorf("inconclusive: third crossing in a row still skipped, want the ban")
	}
	if calls["198.51.100.10"] != 3 {
		t.Errorf("inconclusive: %d verifies, want 3 (never cached)", calls["198.51.100.10"])
	}
	if !skip("198.51.100.10", false) {
		t.Errorf("inconclusive: a new run after the ban should skip again")
	}
}

// Verdicts expire: a positive after 30 min, a negative after 5, and an old
// inconclusive run (an hour) starts again.
func TestAutoblockGoodBotExpiry(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	oldNow := autoblockGoodBotNow
	autoblockGoodBotNow = func() time.Time { return now }
	defer func() { autoblockGoodBotNow = oldNow }()
	verdict := map[string]string{"192.0.2.1": "meta", "192.0.2.2": ""}
	inconclusive := false
	calls := map[string]int{}
	restore := SetAutoblockGoodBotForTest(
		func(string) string { return "x.fbsv.net" },
		func(_, ip string) (string, bool) {
			calls[ip]++
			if inconclusive {
				return "", false
			}
			return verdict[ip], true
		})
	defer restore()

	AutoblockGoodBot(nil, "192.0.2.1", false)
	AutoblockGoodBot(nil, "192.0.2.2", false)
	now = now.Add(4 * time.Minute)
	AutoblockGoodBot(nil, "192.0.2.1", false)
	AutoblockGoodBot(nil, "192.0.2.2", false)
	if calls["192.0.2.1"] != 1 || calls["192.0.2.2"] != 1 {
		t.Fatalf("within both TTLs: verifies %v, want 1 each", calls)
	}
	now = now.Add(2 * time.Minute) // 6 min: the negative expired
	AutoblockGoodBot(nil, "192.0.2.2", false)
	AutoblockGoodBot(nil, "192.0.2.1", false)
	if calls["192.0.2.2"] != 2 || calls["192.0.2.1"] != 1 {
		t.Errorf("at 6 min: verifies %v, want the negative re-verified only", calls)
	}
	now = now.Add(25 * time.Minute) // 31 min: the positive expired
	if s, _ := AutoblockGoodBot(nil, "192.0.2.1", false); !s || calls["192.0.2.1"] != 2 {
		t.Errorf("at 31 min: skip=%t after %d verifies, want a re-verified positive", s, calls["192.0.2.1"])
	}

	inconclusive = true
	AutoblockGoodBot(nil, "192.0.2.3", false)
	AutoblockGoodBot(nil, "192.0.2.3", false)
	now = now.Add(2 * time.Hour) // the run is stale: this is crossing 1 again
	if s, _ := AutoblockGoodBot(nil, "192.0.2.3", false); !s {
		t.Errorf("an inconclusive run older than an hour was not restarted")
	}
}

// The verdict cache is bounded: at the cap expired entries go first, and a
// cache full of live ones is reset rather than grown.
func TestAutoblockGoodBotCacheCap(t *testing.T) {
	restore := SetAutoblockGoodBotForTest(
		func(string) string { return "x.fbsv.net" },
		func(string, string) (string, bool) { return "meta", true })
	defer restore()
	for i := 0; i < autoblockGoodBotCap+10; i++ {
		AutoblockGoodBot(nil, fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), false)
	}
	autoblockGoodBotMu.Lock()
	n := len(autoblockGoodBotCache)
	autoblockGoodBotMu.Unlock()
	if n > autoblockGoodBotCap {
		t.Errorf("cache holds %d verdicts, cap %d", n, autoblockGoodBotCap)
	}
}

func TestPruneSeen(t *testing.T) {
	m := map[string]time.Time{}
	for i := 0; i < seenCap; i++ {
		m[fmt.Sprintf("old%d", i)] = time.Now().Add(-time.Hour)
	}
	m["fresh"] = time.Now()
	PruneSeen(m, 90*time.Second)
	if len(m) != 1 || m["fresh"].IsZero() {
		t.Errorf("after prune: %d entries, want only the fresh one", len(m))
	}
	small := map[string]time.Time{"old": time.Now().Add(-time.Hour)}
	PruneSeen(small, 90*time.Second)
	if len(small) != 1 {
		t.Errorf("pruned a map below the cap")
	}
}

// Forward-confirms spend a resolver-time budget per window: past it an
// uncached candidate is banned (not exempted on a guess), a cached verdict
// still holds, and the next window has a fresh budget.
func TestAutoblockGoodBotBudget(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	oldNow := autoblockGoodBotNow
	autoblockGoodBotNow = func() time.Time { return now }
	defer func() { autoblockGoodBotNow = oldNow }()
	calls := 0
	restore := SetAutoblockGoodBotForTest(
		func(string) string { return "x.googlebot.com" },
		func(_, ip string) (string, bool) {
			calls++
			now = now.Add(2 * time.Second) // a slow resolver
			if ip == "192.0.2.1" {
				return "googlebot", true
			}
			return "", false // timing out
		})
	defer restore()

	if s, _ := AutoblockGoodBot(nil, "192.0.2.1", false); !s {
		t.Fatal("verified crawler not skipped")
	}
	// 2 s per lookup against a 5 s budget: 192.0.2.1 (2 s), .2 (4 s) and .3
	// (6 s) look up; the budget is spent before .4.
	for i := 2; i <= 4; i++ {
		AutoblockGoodBot(nil, fmt.Sprintf("192.0.2.%d", i), false)
	}
	if calls != 3 {
		t.Fatalf("%d lookups before the budget refused, want 3 (the one past 4 s still runs)", calls)
	}
	before := calls
	if s, _ := AutoblockGoodBot(nil, "192.0.2.50", false); s || calls != before {
		t.Errorf("past the budget: skip=%t, %d new lookups; want a ban with no lookup", s, calls-before)
	}
	if s, _ := AutoblockGoodBot(nil, "192.0.2.1", false); !s || calls != before {
		t.Errorf("past the budget the cached crawler lost its verdict (skip=%t)", s)
	}
	now = now.Add(time.Minute)
	if AutoblockGoodBot(nil, "192.0.2.50", false); calls != before+1 {
		t.Errorf("the next window did not verify again (%d lookups)", calls-before)
	}
}

// A full inconclusive-run map is never wiped (that restarted every address's
// count): stale runs go first, and with none, a new address is banned.
func TestAutoblockGoodBotInconclusiveCap(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	oldNow := autoblockGoodBotNow
	autoblockGoodBotNow = func() time.Time { return now }
	defer func() { autoblockGoodBotNow = oldNow }()
	restore := SetAutoblockGoodBotForTest(
		func(string) string { return "x.googlebot.com" },
		func(string, string) (string, bool) { return "", false })
	defer restore()

	autoblockGoodBotMu.Lock()
	for i := 0; i < autoblockGoodBotCap; i++ {
		autoblockGoodBotInconclusive[fmt.Sprintf("10.0.%d.%d", i>>8, i&255)] = autoblockGoodBotRun{n: 1, last: now}
	}
	autoblockGoodBotInconclusive["10.0.0.0"] = autoblockGoodBotRun{n: 2, last: now} // one short of the ban
	autoblockGoodBotMu.Unlock()

	if s, _ := AutoblockGoodBot(nil, "198.51.100.1", false); s {
		t.Error("a new address with the run map full of live runs was skipped uncounted")
	}
	if s, _ := AutoblockGoodBot(nil, "10.0.0.0", false); s {
		t.Error("a full map reset the count of an address one crossing from its ban")
	}

	now = now.Add(2 * time.Hour) // every run is stale now
	if s, _ := AutoblockGoodBot(nil, "198.51.100.2", false); !s {
		t.Error("stale runs were not pruned to make room")
	}
}

// The port scanner's config carries the good-bot kill switch (it runs the
// same autoBlockAction), and its PS_MODE / PS_TTL / PS_INTERVAL.
func TestPortscanThrottleConfig(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.Portscan = cfgpkg.PortscanConfig{Interval: 30, TTLSeconds: 600, Mode: "permanent"}
	cfg.Throttle.GoodBotExemptOff = true
	tc := PortscanThrottleConfig(cfg)
	if !tc.GoodBotExemptOff || tc.Mode != "permanent" || tc.Hits != 1 || tc.WindowSec != 30 || tc.TTLSeconds != 600 {
		t.Errorf("PortscanThrottleConfig = %+v", tc)
	}
	cfg.Portscan.Mode, cfg.Throttle.GoodBotExemptOff = "temporary", false
	if tc := PortscanThrottleConfig(cfg); tc.GoodBotExemptOff || tc.Mode != "ttl" {
		t.Errorf("PortscanThrottleConfig(temporary, exempt on) = %+v", tc)
	}
}

// An expired positive is honoured (24 h grace) when it cannot be re-verified
// now, and replaced by a completed re-verify.
func TestAutoblockGoodBotStaleGrace(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	oldNow := autoblockGoodBotNow
	autoblockGoodBotNow = func() time.Time { return now }
	defer func() { autoblockGoodBotNow = oldNow }()
	answer := func() (string, bool) { return "meta", true }
	restore := SetAutoblockGoodBotForTest(
		func(string) string { return "fwdproxy-frc-011.fbsv.net" },
		func(string, string) (string, bool) { return answer() })
	defer restore()
	spend := func() { // the budget is spent for this window
		autoblockGoodBotMu.Lock()
		autoblockGoodBotBudgetStart, autoblockGoodBotBudgetSpent = now, autoblockGoodBotBudget
		autoblockGoodBotMu.Unlock()
	}

	AutoblockGoodBot(nil, "173.252.127.11", false) // verified at 12:00
	now = now.Add(31 * time.Minute)
	spend()
	if s, why := AutoblockGoodBot(nil, "173.252.127.11", false); !s {
		t.Errorf("expired positive with the budget spent: banned (%q), want the earlier verdict", why)
	}
	if s, _ := AutoblockGoodBot(nil, "198.51.100.9", false); s {
		t.Error("a never-verified address skipped with the budget spent")
	}

	now = now.Add(time.Minute) // a new window: the re-verify runs, inconclusively
	answer = func() (string, bool) { return "", false }
	if s, _ := AutoblockGoodBot(nil, "173.252.127.11", false); !s {
		t.Error("expired positive with an inconclusive re-verify: banned, want the earlier verdict")
	}

	now = now.Add(25 * time.Hour) // past the grace
	spend()
	if s, _ := AutoblockGoodBot(nil, "173.252.127.11", false); s {
		t.Error("a positive past its 24 h grace still honoured with the budget spent")
	}

	// A completed negative re-verify replaces a stale positive.
	now = now.Add(time.Minute)
	answer = func() (string, bool) { return "meta", true }
	AutoblockGoodBot(nil, "173.252.127.12", false)
	now = now.Add(31 * time.Minute)
	answer = func() (string, bool) { return "", true }
	if s, _ := AutoblockGoodBot(nil, "173.252.127.12", false); s {
		t.Error("a definitive negative re-verify did not replace the stale positive")
	}
}

// A full verdict cache never drops a positive for a negative.
func TestAutoblockGoodBotCacheKeepsPositives(t *testing.T) {
	verdicts := map[string]string{}
	calls := map[string]int{}
	restore := SetAutoblockGoodBotForTest(
		func(string) string { return "x.fbsv.net" },
		func(_, ip string) (string, bool) { calls[ip]++; return verdicts[ip], true })
	defer restore()

	verdicts["173.252.127.11"] = "meta"
	AutoblockGoodBot(nil, "173.252.127.11", false)
	for i := 0; i < autoblockGoodBotCap+50; i++ { // fake-PTR addresses: negatives
		AutoblockGoodBot(nil, fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), false)
	}
	if s, _ := AutoblockGoodBot(nil, "173.252.127.11", false); !s || calls["173.252.127.11"] != 1 {
		t.Errorf("after the cache filled with negatives: skip=%t after %d verifies, want the cached positive (1)", s, calls["173.252.127.11"])
	}
	autoblockGoodBotMu.Lock()
	n := len(autoblockGoodBotCache)
	autoblockGoodBotMu.Unlock()
	if n > autoblockGoodBotCap {
		t.Errorf("cache holds %d verdicts, cap %d", n, autoblockGoodBotCap)
	}
}

// A trusted proxy's own address is never banned by the flood / portscan
// autoblock, even with THROTTLE_GOODBOT_EXEMPT = 0 and no PTR at all.
func TestAutoblockSparesATrustedProxy(t *testing.T) {
	restore := SetAutoblockGoodBotForTest(func(string) string { return "" }, func(string, string) (string, bool) { return "", false })
	defer restore()
	cf := netip.MustParsePrefix("172.64.0.0/13")
	SetClientNetExempt("trusted_proxies", func(p netip.Prefix) bool { return cf.Overlaps(p) })
	t.Cleanup(func() { SetClientNetExempt("trusted_proxies", nil) })
	for _, off := range []bool{false, true} {
		if skip, why := AutoblockGoodBot(nil, "172.71.172.97", off); !skip || why == "" {
			t.Errorf("off=%v: skip=%v why=%q", off, skip, why)
		}
		if skip, _ := AutoblockGoodBot(nil, "198.51.100.9", off); skip {
			t.Errorf("off=%v: an ordinary address was spared", off)
		}
	}
}
