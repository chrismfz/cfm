package firewall

import (
	"fmt"
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
	for i := 2; i <= 4; i++ { // 2 s each: 8 s spent after the third lookup
		AutoblockGoodBot(nil, fmt.Sprintf("192.0.2.%d", i), false)
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
