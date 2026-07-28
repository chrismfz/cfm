package solverfarm

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"

type harness struct {
	d     *Detector
	clock time.Time
	out   chan core.Alert
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{clock: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC), out: make(chan core.Alert, 64)}
	h.d = New(cfg)
	h.d.nowFn = func() time.Time { return h.clock }
	return h
}

func (h *harness) solve(host, ip, ua string) {
	h.d.Enqueue(core.InputEvent{When: h.clock, Scope: host, SrcIP: ip, UserAgent: ua, Source: "challenge"})
}

// farmBurst simulates the observed shape: one solve per fresh address, each in
// its own /24, all within the window.
func (h *harness) farmBurst(host string, n int, ua func(i int) string) {
	for i := 0; i < n; i++ {
		h.solve(host, fmt.Sprintf("203.0.%d.%d", i%256, i/256+1), ua(i))
	}
}

func (h *harness) run(t *testing.T) []core.Alert {
	t.Helper()
	if err := h.d.RunOnce(context.Background(), h.out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	var got []core.Alert
	for {
		select {
		case a := <-h.out:
			got = append(got, a)
		default:
			return got
		}
	}
}

func TestFarmShapeAlerts(t *testing.T) {
	h := newHarness(t, Config{})
	h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Key != "shop.example.com" {
		t.Errorf("Key = %q, want the vhost", a.Key)
	}
	if a.Kind != "Challenge/SolverFarm" {
		t.Errorf("Kind = %q", a.Kind)
	}
	if a.Count != 80 {
		t.Errorf("Count = %d, want 80 distinct subnets", a.Count)
	}
	if a.Extra["solves_per_ip"] != "1.00" {
		t.Errorf("solves_per_ip = %q, want 1.00", a.Extra["solves_per_ip"])
	}
	if a.Extra["top_ua"] != chromeUA || a.Extra["top_ua_share"] != "100%" {
		t.Errorf("UA evidence = %q / %q", a.Extra["top_ua"], a.Extra["top_ua_share"])
	}
}

// The alert must never reach the sink's IP-picking path: at ~1 solve per IP a
// per-IP ban cannot work, and the pool is residential, so banning an address
// risks a real customer. enforcement=observe makes the sink notify and return.
func TestAlertIsObserveOnly(t *testing.T) {
	h := newHarness(t, Config{})
	h.farmBurst("shop.example.com", 60, func(int) string { return chromeUA })

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if got := alerts[0].Extra["enforcement"]; got != "observe" {
		t.Errorf("enforcement = %q, want %q — the sink would otherwise block on a BLOCK policy", got, "observe")
	}
}

// The alert quotes the User-Agents it observed, and its Key is a vhost. Without
// declaring host scope the sink resolves a source IP by scanning Samples for
// anything IP-shaped, letting a client name its own address via its UA — which
// the global ignore list then uses to drop the alert silently.
func TestAlertDeclaresHostScope(t *testing.T) {
	h := newHarness(t, Config{})
	h.farmBurst("shop.example.com", 60, func(int) string { return chromeUA })

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if got := alerts[0].Extra[core.ExtraIPScope]; got != core.IPScopeHost {
		t.Errorf("%s = %q, want %q — the sink would otherwise scrape a source IP out of a quoted User-Agent",
			core.ExtraIPScope, got, core.IPScopeHost)
	}
	if _, ok := alerts[0].Extra["ip"]; ok {
		t.Error(`Extra["ip"] must stay absent: this finding is about a vhost, not an address`)
	}
}

// The detection key is deliberately UA-agnostic. A farm that randomises its
// User-Agent per request must still be caught, otherwise the detector is
// defeated by a header the attacker controls.
func TestUARandomisationDoesNotEvade(t *testing.T) {
	h := newHarness(t, Config{})
	h.farmBurst("shop.example.com", 80, func(i int) string {
		return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/%d.0.%d.0 Safari/537.36", 100+i%40, i)
	})

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts with a randomised UA, want 1 — detection must not depend on the UA", len(alerts))
	}
	if alerts[0].Count != 80 {
		t.Errorf("Count = %d, want 80", alerts[0].Count)
	}
}

// A self-contradictory UA corroborates a finding but must never be part of the
// threshold — a farm can send a perfectly well-formed UA whenever it likes.
func TestImpossibleUAIsEvidenceNotThreshold(t *testing.T) {
	t.Run("reported when present", func(t *testing.T) {
		h := newHarness(t, Config{})
		for i := 0; i < 80; i++ {
			ev := core.InputEvent{
				When: h.clock, Scope: "shop.example.com",
				SrcIP: fmt.Sprintf("203.0.%d.1", i), UserAgent: chromeUA, Source: "challenge",
			}
			if i%4 == 0 {
				ev.Signal = "ios_with_blink_webkit"
			}
			h.d.Enqueue(ev)
		}
		alerts := h.run(t)
		if len(alerts) != 1 {
			t.Fatalf("got %d alerts, want 1", len(alerts))
		}
		if got := alerts[0].Extra["impossible_ua"]; got != "20" {
			t.Errorf("impossible_ua = %q, want 20", got)
		}
	})

	t.Run("absence does not suppress the alert", func(t *testing.T) {
		h := newHarness(t, Config{})
		h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })
		alerts := h.run(t)
		if len(alerts) != 1 {
			t.Fatalf("got %d alerts with entirely well-formed UAs, want 1", len(alerts))
		}
		if got := alerts[0].Extra["impossible_ua"]; got != "0" {
			t.Errorf("impossible_ua = %q, want 0", got)
		}
	})
}

func TestLegitimateShapesDoNotAlert(t *testing.T) {
	t.Run("normal audience: few subnets, repeat visitors", func(t *testing.T) {
		h := newHarness(t, Config{})
		for i := 0; i < 200; i++ {
			h.solve("blog.example.com", fmt.Sprintf("198.51.100.%d", i%12+1), chromeUA)
		}
		if alerts := h.run(t); len(alerts) != 0 {
			t.Fatalf("got %d alerts for a normal audience, want 0", len(alerts))
		}
	})

	t.Run("concentrated attacker: many solves, few subnets", func(t *testing.T) {
		// This is a per-IP rate problem, not a distributed farm. Must not fire.
		h := newHarness(t, Config{})
		for i := 0; i < 500; i++ {
			h.solve("forum.example.com", fmt.Sprintf("192.0.2.%d", i%20+1), chromeUA)
		}
		if alerts := h.run(t); len(alerts) != 0 {
			t.Fatalf("got %d alerts for a concentrated source, want 0", len(alerts))
		}
	})

	t.Run("wide spread but below MIN_SOLVES", func(t *testing.T) {
		h := newHarness(t, Config{MinSubnets: 40, MinSolves: 100})
		h.farmBurst("quiet.example.com", 60, func(int) string { return chromeUA })
		if alerts := h.run(t); len(alerts) != 0 {
			t.Fatalf("got %d alerts below MIN_SOLVES, want 0", len(alerts))
		}
	})
}

// Two bursts of DISJOINT subnets, far enough apart that the first has expired.
// Each is below MinSubnets on its own; their union is comfortably above it. If
// the window stopped expiring, the second evaluation would see 50 subnets and
// alert — so this fails if the prune is removed, which the previous version of
// this test did not (it reused the same 30 subnets for both bursts, so the union
// was still 30 and the assertion held for the wrong reason).
func TestSlidingWindowExpiresSolves(t *testing.T) {
	// Each burst is 25 subnets but 50 solves, so MIN_SOLVES is satisfied by ONE
	// burst alone. That matters: if the burst were solve-starved, MIN_SOLVES
	// would suppress the alert and the test would pass without the subnet set
	// ever having to expire — which is exactly how the first version of this
	// test managed to prove nothing.
	burst := func(h *harness, from int) {
		for i := from; i < from+25; i++ {
			ip := fmt.Sprintf("203.0.%d.1", i)
			h.solve("shop.example.com", ip, chromeUA)
			h.solve("shop.example.com", ip, chromeUA)
		}
	}

	h := newHarness(t, Config{Window: time.Minute, MinSubnets: 40, MinSolves: 40})
	burst(h, 0)
	if got := h.run(t); len(got) != 0 {
		t.Fatalf("first burst alone (25 subnets, 50 solves): got %d alerts, want 0", len(got))
	}

	h.clock = h.clock.Add(90 * time.Second) // first burst is now outside the window
	burst(h, 100)                           // disjoint /24s, another 50 solves
	if got := h.run(t); len(got) != 0 {
		t.Fatalf("got %d alerts, want 0 — 25 + 25 disjoint subnets 90s apart must not sum to 50", len(got))
	}

	// The same two bursts INSIDE one window do cross the threshold, proving the
	// fixture can alert at all and that expiry is what suppressed it above.
	h2 := newHarness(t, Config{Window: time.Minute, MinSubnets: 40, MinSolves: 40})
	burst(h2, 0)
	h2.clock = h2.clock.Add(10 * time.Second)
	burst(h2, 100)
	if got := h2.run(t); len(got) != 1 {
		t.Fatalf("both bursts within the window: got %d alerts, want 1", len(got))
	}
}

// The alert's Count, distinct_ips and subnets are three different numbers; every
// other fixture makes them coincide, so a Count: len(subnets) -> len(ips) swap
// would pass unnoticed. Pin them apart.
func TestCountsAreDistinguishable(t *testing.T) {
	h := newHarness(t, Config{MinSubnets: 40, MinSolves: 40})
	// 45 subnets, 90 addresses (2 per subnet), 180 solves (2 per address).
	for i := 0; i < 45; i++ {
		for a := 1; a <= 2; a++ {
			ip := fmt.Sprintf("203.0.%d.%d", i, a)
			h.solve("shop.example.com", ip, chromeUA)
			h.solve("shop.example.com", ip, chromeUA)
		}
	}
	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Count != 45 {
		t.Errorf("Count = %d, want 45 (distinct subnets)", a.Count)
	}
	if a.Extra["subnets"] != "45" {
		t.Errorf("subnets = %q, want 45", a.Extra["subnets"])
	}
	if a.Extra["distinct_ips"] != "90" {
		t.Errorf("distinct_ips = %q, want 90", a.Extra["distinct_ips"])
	}
	if a.Extra["solves"] != "180" {
		t.Errorf("solves = %q, want 180", a.Extra["solves"])
	}
	if a.Extra["solves_per_ip"] != "2.00" {
		t.Errorf("solves_per_ip = %q, want 2.00", a.Extra["solves_per_ip"])
	}
}

// Exact-threshold behaviour: MinSubnets is a floor that must be reached, not
// exceeded. Without this, flipping `<` to `<=` passes every other test.
func TestThresholdBoundaries(t *testing.T) {
	burst := func(t *testing.T, subnets int) int {
		t.Helper()
		h := newHarness(t, Config{MinSubnets: 40, MinSolves: 40})
		for i := 0; i < subnets; i++ {
			h.solve("shop.example.com", fmt.Sprintf("203.0.%d.1", i), chromeUA)
		}
		return len(h.run(t))
	}
	if got := burst(t, 39); got != 0 {
		t.Errorf("39 subnets: got %d alerts, want 0", got)
	}
	if got := burst(t, 40); got != 1 {
		t.Errorf("40 subnets (exactly MinSubnets): got %d alerts, want 1", got)
	}
}

// MinSolves counts every solve seen in the window, including ones the evidence
// cap dropped — otherwise a flood could stay under the floor by overflowing it.
func TestMinSolvesCountsTruncatedSolves(t *testing.T) {
	h := newHarness(t, Config{MinSubnets: 40, MinSolves: 100, MaxTrackedPerHost: 50})
	for i := 0; i < 120; i++ {
		h.solve("shop.example.com", fmt.Sprintf("203.0.%d.1", i), chromeUA)
	}
	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 — 120 solves must satisfy MIN_SOLVES=100 despite a 50-record cap", len(alerts))
	}
	if alerts[0].Extra["solves"] != "120" {
		t.Errorf("solves = %q, want 120", alerts[0].Extra["solves"])
	}
}

// The evidence cap must never suppress detection: a cheap flood from one subnet
// fills the buffer, but the farm's spread still has to be visible.
func TestFloodCannotMaskFarm(t *testing.T) {
	h := newHarness(t, Config{MinSubnets: 40, MinSolves: 40, MaxTrackedPerHost: 100})
	// Flood arrives first and exhausts the evidence buffer from a single /24.
	for i := 0; i < 500; i++ {
		h.solve("shop.example.com", "198.51.100.7", chromeUA)
	}
	// The farm's solves land after the buffer is already full.
	for i := 0; i < 60; i++ {
		h.solve("shop.example.com", fmt.Sprintf("203.0.%d.1", i), chromeUA)
	}
	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 — a flood must not hide the farm behind the evidence cap", len(alerts))
	}
	if alerts[0].Count != 61 {
		t.Errorf("Count = %d, want 61 distinct subnets (60 farm + 1 flood)", alerts[0].Count)
	}
}

// Every > Window would prune away a slice of the stream unexamined every tick.
func TestEveryIsClampedToWindow(t *testing.T) {
	d := New(Config{Window: 60 * time.Second, Every: 120 * time.Second})
	if d.Every() != 60*time.Second {
		t.Errorf("Every() = %v, want it clamped to Window (60s); a longer interval discards unexamined solves", d.Every())
	}
}

func TestCooldownSuppressesRepeatAlerts(t *testing.T) {
	h := newHarness(t, Config{Cooldown: 30 * time.Minute})
	h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })
	if got := h.run(t); len(got) != 1 {
		t.Fatalf("first scan: got %d alerts, want 1", len(got))
	}

	h.clock = h.clock.Add(5 * time.Minute)
	h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })
	if got := h.run(t); len(got) != 0 {
		t.Fatalf("within cooldown: got %d alerts, want 0", len(got))
	}

	h.clock = h.clock.Add(30 * time.Minute)
	h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })
	if got := h.run(t); len(got) != 1 {
		t.Fatalf("after cooldown: got %d alerts, want 1", len(got))
	}
}

func TestAllowLists(t *testing.T) {
	t.Run("host", func(t *testing.T) {
		h := newHarness(t, Config{AllowHosts: []string{"Shop.Example.com"}})
		h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })
		if got := h.run(t); len(got) != 0 {
			t.Fatalf("got %d alerts for an allowed host, want 0", len(got))
		}
	})
	t.Run("ua substring", func(t *testing.T) {
		h := newHarness(t, Config{AllowUAContains: []string{"claudebot"}})
		h.farmBurst("shop.example.com", 80, func(int) string {
			return "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
		})
		if got := h.run(t); len(got) != 0 {
			t.Fatalf("got %d alerts for an allowed UA, want 0", len(got))
		}
	})
	t.Run("net", func(t *testing.T) {
		h := newHarness(t, Config{AllowNets: []string{"203.0.0.0/16"}})
		h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })
		if got := h.run(t); len(got) != 0 {
			t.Fatalf("got %d alerts for an allowed net, want 0", len(got))
		}
	})
}

func TestSubnetOf(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"203.0.113.7", "203.0.113.0/24"},
		{"203.0.113.250", "203.0.113.0/24"},
		{"2001:db8:abcd:1234::5", "2001:db8:abcd::/48"},
		{"2001:db8:abcd:9999::1", "2001:db8:abcd::/48"},
		{"not-an-ip", ""},
	}
	for _, tc := range tests {
		if got := subnetOf(tc.ip, 24, 48); got != tc.want {
			t.Errorf("subnetOf(%q) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

// A single residential customer can hold many /64s, so IPv6 must aggregate at
// /48 — otherwise one legitimate subscriber looks like a farm.
func TestIPv6CustomerIsOneSubnet(t *testing.T) {
	h := newHarness(t, Config{})
	for i := 0; i < 200; i++ {
		h.solve("shop.example.com", fmt.Sprintf("2001:db8:abcd:%x::1", i), chromeUA)
	}
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts, want 0 — many /64s of one /48 customer are one subnet", len(alerts))
	}
}

// Truncation must be reported, never silent: a capped window would otherwise
// read as a complete count.
func TestTruncationIsReported(t *testing.T) {
	h := newHarness(t, Config{MaxTrackedPerHost: 50})
	h.farmBurst("shop.example.com", 200, func(int) string { return chromeUA })

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	found := false
	for _, s := range alerts[0].Samples {
		if strings.Contains(s, "were not sampled") && strings.Contains(s, "MAX_TRACKED_PER_HOST") {
			found = true
		}
	}
	if !found {
		t.Errorf("truncation not reported in samples: %v", alerts[0].Samples)
	}
}

func TestParseAction(t *testing.T) {
	tests := []struct {
		raw      string
		want     Action
		wantNote bool
	}{
		{"", ActionObserve, false}, // absent: backward compatible
		{"observe", ActionObserve, false},
		{"  OBSERVE ", ActionObserve, false}, // tolerant of case and spacing
		{"logonly", ActionLogonly, false},
		// Reserved values must fall back to observe AND say why, never silently.
		{"deny", ActionObserve, true},
		{"block", ActionObserve, true},
		{"nonsense", ActionObserve, true},
	}
	for _, tc := range tests {
		got, note := ParseAction(tc.raw)
		if got != tc.want {
			t.Errorf("ParseAction(%q) = %q, want %q", tc.raw, got, tc.want)
		}
		if (note != "") != tc.wantNote {
			t.Errorf("ParseAction(%q) note = %q, wantNote=%v", tc.raw, note, tc.wantNote)
		}
	}
}

// logonly must keep the detector-log record and drop only the notification.
func TestActionLogonlySuppressesNotificationOnly(t *testing.T) {
	h := newHarness(t, Config{Action: ActionLogonly})
	h.farmBurst("shop.example.com", 60, func(int) string { return chromeUA })

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 — logonly must still raise the alert", len(alerts))
	}
	if got := alerts[0].Extra[core.ExtraNotify]; got != core.NotifyNo {
		t.Errorf("%s = %q, want %q", core.ExtraNotify, got, core.NotifyNo)
	}
	if got := alerts[0].Extra["action"]; got != string(ActionLogonly) {
		t.Errorf("action = %q, want logonly", got)
	}
}

// observe (and the zero value) must not carry the notify-suppression key.
func TestActionObserveNotifies(t *testing.T) {
	for _, cfg := range []Config{{}, {Action: ActionObserve}} {
		h := newHarness(t, cfg)
		h.farmBurst("shop.example.com", 60, func(int) string { return chromeUA })
		alerts := h.run(t)
		if len(alerts) != 1 {
			t.Fatalf("got %d alerts, want 1", len(alerts))
		}
		if _, ok := alerts[0].Extra[core.ExtraNotify]; ok {
			t.Errorf("observe must not set %s (absent means notify)", core.ExtraNotify)
		}
		if got := alerts[0].Extra["action"]; got != string(ActionObserve) {
			t.Errorf("action = %q, want observe", got)
		}
	}
}

// The badge the WebUI draws must mean "farmed right now", which is NOT what the
// alert means: the alert is suppressed for COOLDOWN (30m by default) because a
// farm runs for hours. A hook that fired with the alert would let the badge blink
// off mid-attack, so it fires on every over-threshold evaluation instead.
func TestFarmHookFiresThroughTheAlertCooldown(t *testing.T) {
	h := newHarness(t, Config{Window: time.Minute, Cooldown: 30 * time.Minute})
	var marks []string
	var ttls []time.Duration
	h.d.SetFarmHook(func(host string, ttl time.Duration) {
		marks = append(marks, host)
		ttls = append(ttls, ttl)
	})

	h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })
	if alerts := h.run(t); len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if len(marks) != 1 {
		t.Fatalf("got %d marks on the alerting pass, want 1", len(marks))
	}

	// Second pass, well inside the cooldown: no alert, but the vhost is still
	// being farmed and must still be marked.
	h.clock = h.clock.Add(30 * time.Second)
	h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts inside the cooldown, want 0", len(alerts))
	}
	if len(marks) != 2 {
		t.Fatalf("got %d marks total, want 2 — the badge would have gone dark while the farm ran", len(marks))
	}
	for _, m := range marks {
		if m != "shop.example.com" {
			t.Errorf("marked %q, want the vhost", m)
		}
	}
	// The TTL must outlive the gap between evaluations, or the badge flickers
	// between passes even while the farm is continuous.
	for _, ttl := range ttls {
		if ttl <= h.d.Every() {
			t.Errorf("mark TTL %s is not longer than the evaluation interval %s", ttl, h.d.Every())
		}
		if ttl < h.d.cfg.Window {
			t.Errorf("mark TTL %s is shorter than the window it was derived from (%s)", ttl, h.d.cfg.Window)
		}
	}
}

// Below threshold there is nothing to badge.
func TestFarmHookSilentBelowThreshold(t *testing.T) {
	h := newHarness(t, Config{MinSubnets: 40, MinSolves: 40})
	fired := 0
	h.d.SetFarmHook(func(string, time.Duration) { fired++ })
	h.farmBurst("shop.example.com", 20, func(int) string { return chromeUA })
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts below threshold", len(alerts))
	}
	if fired != 0 {
		t.Fatalf("hook fired %d times below threshold, want 0", fired)
	}
}

// An allowlisted vhost must not be badged either — the allowlist is how an
// operator says "this spread is legitimate", and a badge would keep asserting
// the opposite.
func TestFarmHookRespectsAllowlist(t *testing.T) {
	h := newHarness(t, Config{AllowHosts: []string{"shop.example.com"}})
	fired := 0
	h.d.SetFarmHook(func(string, time.Duration) { fired++ })
	h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA })
	h.run(t)
	if fired != 0 {
		t.Fatalf("hook fired %d times for an allowlisted vhost, want 0", fired)
	}
}
