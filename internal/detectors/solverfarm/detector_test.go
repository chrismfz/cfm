package solverfarm

import (
	"context"
	"fmt"
	"net"
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

// ── Fingerprint-concentration track (the low-and-slow farm) ──────────────────

func (h *harness) solveFP(host, ip, ua, fp string) {
	h.d.Enqueue(core.InputEvent{When: h.clock, Scope: host, SrcIP: ip, UserAgent: ua, Fingerprint: fp, Source: "challenge"})
}

var fpTestCountries = []string{
	"BR", "MX", "AR", "NP", "SY", "VN", "ZA", "NG", "UA", "KZ",
	"BD", "OM", "CO", "RU", "ES", "TR", "PK", "CL", "PY", "KE",
}

// ipCountry maps 203.0.N.x to the N-th test country, so a test controls a solve's
// country through its /24 — a stand-in for the GeoIP enricher's countryFn.
func ipCountry(ip string) string {
	v := net.ParseIP(ip).To4()
	if v == nil {
		return ""
	}
	return fpTestCountries[int(v[2])%len(fpTestCountries)]
}

// The c28caa00 shape: ~8/min, well below MIN_SUBNETS(40)/MIN_SOLVES(40) so the
// subnet-spread track stays silent, but one fingerprint spans many subnets AND
// many countries. The concentration track must catch it — this is the whole gap.
func TestFPConcentrationLowAndSlowFarm(t *testing.T) {
	h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
	h.d.countryFn = ipCountry
	for i := 0; i < 12; i++ {
		h.solveFP("techking.example", fmt.Sprintf("203.0.%d.1", i),
			fmt.Sprintf("Mozilla/5.0 Chrome/%d.0.0.0 Safari/537.36", 135+i%15), "c28caa00")
	}
	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 — 12 subnets/12 countries under one fingerprint is a low-and-slow farm", len(alerts))
	}
	a := alerts[0]
	if a.Kind != "Challenge/SolverFarm" {
		t.Errorf("Kind = %q", a.Kind)
	}
	if a.Extra["fp_track"] != "1" {
		t.Errorf("fp_track = %q, want 1", a.Extra["fp_track"])
	}
	if a.Extra["tracks"] != "fp_concentration" {
		t.Errorf("tracks = %q, want fp_concentration only (subnet-spread must NOT fire at 12<40 subnets)", a.Extra["tracks"])
	}
	if a.Extra["top_fp"] != "c28caa00" {
		t.Errorf("top_fp = %q, want c28caa00 (the grouping fingerprint, reported as evidence)", a.Extra["top_fp"])
	}
	if a.Extra["fp_subnets"] != "12" || a.Extra["fp_countries"] != "12" {
		t.Errorf("fp evidence = %q subnets / %q countries, want 12 / 12", a.Extra["fp_subnets"], a.Extra["fp_countries"])
	}
	if a.Extra["enforcement"] != "observe" {
		t.Errorf("enforcement = %q, want observe (alert-only like the parent track)", a.Extra["enforcement"])
	}
	// As of the 2026-09-11 promotion (clean weekday burn-in) an fp-only finding
	// NOTIFIES — ExtraNotify absent means notify. The throttle is NotifyCooldown,
	// not a blanket suppression; this is the first alert so it is not throttled.
	if _, ok := a.Extra[core.ExtraNotify]; ok {
		t.Errorf("%s must be absent — an fp-only finding notifies after the burn-in promotion", core.ExtraNotify)
	}
}

// A COMBINED finding — the high-rate subnet-spread AND fingerprint concentration
// both fire on one vhost — is a confirmed farm and DOES notify (as does an fp-only
// finding since the 2026-09-11 promotion).
func TestFPConcentrationCombinedWithSubnetSpreadNotifies(t *testing.T) {
	h := newHarness(t, Config{FPTrack: true, MinSubnets: 40, MinSolves: 40, MinFPSubnets: 8, MinFPCountries: 6})
	h.d.countryFn = ipCountry
	for i := 0; i < 40; i++ { // 40 /24s (>= MinSubnets), all one fingerprint, 20 countries
		h.solveFP("techking.example", fmt.Sprintf("203.0.%d.1", i), chromeUA, "c28caa00")
	}
	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if got := a.Extra["tracks"]; got != "subnet_spread+fp_concentration" {
		t.Errorf("tracks = %q, want subnet_spread+fp_concentration", got)
	}
	if _, ok := a.Extra[core.ExtraNotify]; ok {
		t.Errorf("a combined confirmed-farm finding must notify — %s must be absent", core.ExtraNotify)
	}
}

func TestFPConcentrationCountryGuardAndDiversity(t *testing.T) {
	// A legit shared-fingerprint population (corporate fleet / carrier CGNAT):
	// many subnets, ONE fingerprint, but ONE country. The country guard excludes
	// it — this is the real 'ba6b4aad' near-FP (17 /24s, 2 countries) shape.
	t.Run("single-country shared fingerprint is not a farm", func(t *testing.T) {
		h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
		h.d.countryFn = func(string) string { return "GR" }
		for i := 0; i < 20; i++ {
			h.solveFP("office.example", fmt.Sprintf("203.0.%d.1", i), chromeUA, "ba6b4aad")
		}
		if got := h.run(t); len(got) != 0 {
			t.Fatalf("got %d alerts for 20 subnets of ONE country under one fingerprint, want 0", len(got))
		}
	})
	// A real global audience: many subnets, many countries, but a DISTINCT
	// fingerprint per solver. No single fingerprint concentrates → no farm.
	t.Run("fingerprint diversity is not a farm", func(t *testing.T) {
		h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
		h.d.countryFn = ipCountry
		for i := 0; i < 20; i++ {
			h.solveFP("shop.example", fmt.Sprintf("203.0.%d.1", i), chromeUA, fmt.Sprintf("fp%04d", i))
		}
		if got := h.run(t); len(got) != 0 {
			t.Fatalf("got %d alerts for 20 diverse fingerprints, want 0", len(got))
		}
	})
}

// The two thresholds are AND'd and are floors, not ceilings. The country floor is
// load-bearing: a legit group can clear the subnet floor (the ba6b4aad case) yet
// stay under the country floor.
func TestFPConcentrationThresholds(t *testing.T) {
	fire := func(t *testing.T, subnets, countries int) int {
		t.Helper()
		h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
		h.d.countryFn = func(ip string) string {
			v := net.ParseIP(ip).To4()
			return fpTestCountries[int(v[2])%countries]
		}
		for i := 0; i < subnets; i++ {
			h.solveFP("x.example", fmt.Sprintf("203.0.%d.1", i), chromeUA, "onefp")
		}
		return len(h.run(t))
	}
	if got := fire(t, 8, 6); got != 1 {
		t.Errorf("8 subnets / 6 countries (exactly at both floors): got %d, want 1", got)
	}
	if got := fire(t, 7, 6); got != 0 {
		t.Errorf("7 subnets (below MinFPSubnets=8): got %d, want 0", got)
	}
	if got := fire(t, 12, 5); got != 0 {
		t.Errorf("5 countries (below MinFPCountries=6, subnets fine): got %d, want 0 — the country floor is load-bearing", got)
	}
}

// An empty fingerprint (older edge, plain HTTP, DNAT) must NEVER be a group key:
// pooling every no-fingerprint solver would manufacture a phantom farm.
func TestFPConcentrationEmptyFingerprintNeverGroups(t *testing.T) {
	h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
	h.d.countryFn = ipCountry
	for i := 0; i < 20; i++ {
		h.solveFP("shop.example", fmt.Sprintf("203.0.%d.1", i), chromeUA, "")
	}
	if got := h.run(t); len(got) != 0 {
		t.Fatalf("got %d alerts, want 0 — an empty fingerprint must never group", len(got))
	}
}

// ALLOW_FPS exempts a known-legitimate shared fingerprint, case-insensitively.
func TestFPConcentrationAllowFP(t *testing.T) {
	h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6, AllowFPs: []string{"C28CAA00"}})
	h.d.countryFn = ipCountry
	for i := 0; i < 12; i++ {
		h.solveFP("shop.example", fmt.Sprintf("203.0.%d.1", i), chromeUA, "c28caa00")
	}
	if got := h.run(t); len(got) != 0 {
		t.Fatalf("got %d alerts for an allow-listed fingerprint, want 0", len(got))
	}
}

// With no enricher wired (countryFn nil) the country dimension is unavailable, so
// the track must stay silent — it must never fall back to firing on subnets alone.
func TestFPConcentrationOffWithoutGeo(t *testing.T) {
	h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
	// countryFn deliberately left nil (no SetEnricher / no geodb).
	for i := 0; i < 20; i++ {
		h.solveFP("shop.example", fmt.Sprintf("203.0.%d.1", i), chromeUA, "c28caa00")
	}
	if got := h.run(t); len(got) != 0 {
		t.Fatalf("got %d alerts with no geo enricher, want 0 — the country guard must fail safe (off)", len(got))
	}
}

// FPTrack on must not perturb the original high-rate subnet-spread track: a
// classic farm carrying no fingerprint still fires, tagged subnet_spread.
func TestFPConcentrationLeavesSubnetSpreadIntact(t *testing.T) {
	h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
	h.d.countryFn = ipCountry
	h.farmBurst("shop.example.com", 80, func(int) string { return chromeUA }) // no fingerprint
	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 — the high-rate track must be unaffected by FPTrack", len(alerts))
	}
	if got := alerts[0].Extra["tracks"]; got != "subnet_spread" {
		t.Errorf("tracks = %q, want subnet_spread (no fingerprint present)", got)
	}
	if got := alerts[0].Extra["fp_track"]; got != "0" {
		t.Errorf("fp_track = %q, want 0", got)
	}
}

// ── cross-host track (Phase 2) ────────────────────────────────────────────────

// xhCountry maps 10.b.c.x to a country by BOTH octets so a spread across hosts
// (b) AND subnets (c) produces many distinct countries — the cross-host shape.
func xhCountry(ip string) string {
	v := net.ParseIP(ip).To4()
	if v == nil {
		return ""
	}
	return fpTestCountries[(int(v[1])*6+int(v[2]))%len(fpTestCountries)]
}

func xhCfg() Config {
	return Config{
		XHTrack: true, FPTrack: true,
		MinFPSubnets: 8, MinFPCountries: 6, // per-host stays silent at 6 subnets/host
		MinXHHosts: 4, MinXHCountries: 12, MinXHSubnets: 30, MinXHHostShare: 0.5,
	}
}

// The thin farm: one fingerprint on 6 subnets per vhost across 6 vhosts — under
// the per-host bar on every host (6 < MIN_FP_SUBNETS 8), yet node-wide it spans
// 36 subnets / 20 countries under one dominant fingerprint. The cross-host track
// must flag it and mark EVERY contributing vhost; per-host must stay silent.
func TestCrossHostThinFarmFlagsEveryVhost(t *testing.T) {
	h := newHarness(t, xhCfg())
	h.d.countryFn = xhCountry
	hosts := []string{"a.shop", "b.shop", "c.shop", "d.shop", "e.shop", "f.shop"}
	for hi, host := range hosts {
		for s := 0; s < 6; s++ {
			h.solveFP(host, fmt.Sprintf("10.%d.%d.1", hi+1, s), chromeUA, "95070673")
		}
	}
	alerts := h.run(t)
	if len(alerts) != len(hosts) {
		t.Fatalf("got %d alerts, want %d — every farmed vhost is marked", len(alerts), len(hosts))
	}
	seen := map[string]bool{}
	for _, a := range alerts {
		seen[a.Key] = true
		if a.Extra["xh_track"] != "1" {
			t.Errorf("%s: xh_track = %q, want 1", a.Key, a.Extra["xh_track"])
		}
		if a.Extra["tracks"] != "cross_host" {
			t.Errorf("%s: tracks = %q, want cross_host only (per-host silent at 6<8 subnets)", a.Key, a.Extra["tracks"])
		}
		if a.Extra["xh_fp"] != "95070673" {
			t.Errorf("%s: xh_fp = %q, want the grouping fingerprint", a.Key, a.Extra["xh_fp"])
		}
		if a.Extra["xh_host_share"] != "100%" {
			t.Errorf("%s: xh_host_share = %q, want 100%% (fp is the only solver)", a.Key, a.Extra["xh_host_share"])
		}
		// cross-host-only is LOG-ONLY through its burn-in.
		if got := a.Extra[core.ExtraNotify]; got != core.NotifyNo {
			t.Errorf("%s: %s = %q, want %q — a cross-host-only finding is log-only through burn-in", a.Key, core.ExtraNotify, got, core.NotifyNo)
		}
	}
	if len(seen) != len(hosts) {
		t.Errorf("distinct flagged vhosts = %d, want %d", len(seen), len(hosts))
	}
}

// The share pre-gate is the primary guard: a globally-distributed shared browser
// (the 19877aeb shape — many hosts, many countries, ~1 solve/IP) that is a MINORITY
// of every vhost must never enter the cross-host pool. Here the "farm" fp is 1 of 5
// fingerprints on each host (20% share < 50%), so no host qualifies.
func TestCrossHostMinorityBrowserIsNotPooled(t *testing.T) {
	h := newHarness(t, xhCfg())
	h.d.countryFn = xhCountry
	hosts := []string{"a.shop", "b.shop", "c.shop", "d.shop", "e.shop", "f.shop"}
	for hi, host := range hosts {
		for s := 0; s < 6; s++ {
			// the shared fp on one /24 …
			h.solveFP(host, fmt.Sprintf("10.%d.%d.1", hi+1, s), chromeUA, "19877aeb")
			// … drowned by 4 other fingerprints on the same /24 (distinct IPs), so
			// 19877aeb is 20% of the vhost's fingerprinted solves.
			for k := 0; k < 4; k++ {
				h.solveFP(host, fmt.Sprintf("10.%d.%d.%d", hi+1, s, 10+k), chromeUA, fmt.Sprintf("other%d", k))
			}
		}
	}
	if got := h.run(t); len(got) != 0 {
		t.Fatalf("got %d alerts for a 20%%-share shared browser, want 0 — the share pre-gate must empty the pool", len(got))
	}
}

// solves_per_ip is NOT a gate: a farm at s/ip = 1.1 (repeat solves from some IPs)
// still flags. The burn-in showed s/ip does not separate farm from legit, so it is
// evidence only. Here each vhost has the fp on 6 /24s but a couple of IPs solve
// twice, pushing s/ip above 1.0 — the flag must be unaffected.
func TestCrossHostSolvesPerIPIsNotAGate(t *testing.T) {
	h := newHarness(t, xhCfg())
	h.d.countryFn = xhCountry
	hosts := []string{"a.shop", "b.shop", "c.shop", "d.shop", "e.shop", "f.shop"}
	for hi, host := range hosts {
		for s := 0; s < 6; s++ {
			h.solveFP(host, fmt.Sprintf("10.%d.%d.1", hi+1, s), chromeUA, "95070673")
		}
		// two repeat solves from already-seen addresses on this host
		h.solveFP(host, fmt.Sprintf("10.%d.0.1", hi+1), chromeUA, "95070673")
		h.solveFP(host, fmt.Sprintf("10.%d.1.1", hi+1), chromeUA, "95070673")
	}
	alerts := h.run(t)
	if len(alerts) != len(hosts) {
		t.Fatalf("got %d alerts, want %d — s/ip>1 must not suppress the cross-host flag", len(alerts), len(hosts))
	}
	if spi := alerts[0].Extra["xh_solves_per_ip"]; spi == "" || spi == "1.00" {
		t.Errorf("xh_solves_per_ip = %q, want >1.00 carried as evidence", spi)
	}
}

// Fail-safe: with no enricher (countryFn nil) the cross-host track — like the
// per-host one — must stay silent rather than fire on subnet/host spread alone.
func TestCrossHostOffWithoutGeo(t *testing.T) {
	h := newHarness(t, xhCfg())
	// countryFn deliberately nil.
	for hi := 0; hi < 6; hi++ {
		for s := 0; s < 6; s++ {
			h.solveFP(fmt.Sprintf("h%d.shop", hi), fmt.Sprintf("10.%d.%d.1", hi+1, s), chromeUA, "95070673")
		}
	}
	if got := h.run(t); len(got) != 0 {
		t.Fatalf("got %d alerts with no geo enricher, want 0 — cross-host must fail safe (off)", len(got))
	}
}

// XH_TRACK off leaves only the per-host tracks; a thin cross-host farm goes
// unflagged (each host is under the per-host bar).
func TestCrossHostOffByFlag(t *testing.T) {
	cfg := xhCfg()
	cfg.XHTrack = false
	h := newHarness(t, cfg)
	h.d.countryFn = xhCountry
	for hi := 0; hi < 6; hi++ {
		for s := 0; s < 6; s++ {
			h.solveFP(fmt.Sprintf("h%d.shop", hi), fmt.Sprintf("10.%d.%d.1", hi+1, s), chromeUA, "95070673")
		}
	}
	if got := h.run(t); len(got) != 0 {
		t.Fatalf("got %d alerts with XHTrack off, want 0", len(got))
	}
}

// NotifyCooldown throttles the MAIL for a persistent farm while COOLDOWN still
// governs the logged alert and the mark: the first notifying alert stamps the
// notify clock, and the next alert after COOLDOWN (but within NotifyCooldown) is
// logged with NotifyNo. A subnet-spread farm (which notifies) exercises this.
func TestNotifyCooldownThrottlesMailNotLog(t *testing.T) {
	h := newHarness(t, Config{Cooldown: 30 * time.Minute, NotifyCooldown: 6 * time.Hour})
	// pass 1: farm fires and notifies (ExtraNotify absent).
	h.farmBurst("shop.example.com", 60, func(int) string { return chromeUA })
	a1 := h.run(t)
	if len(a1) != 1 {
		t.Fatalf("pass 1: got %d alerts, want 1", len(a1))
	}
	if _, ok := a1[0].Extra[core.ExtraNotify]; ok {
		t.Fatalf("pass 1: first alert must notify (ExtraNotify absent)")
	}
	// advance past COOLDOWN but well within NotifyCooldown, and re-run the farm.
	h.clock = h.clock.Add(31 * time.Minute)
	h.farmBurst("shop.example.com", 60, func(int) string { return chromeUA })
	a2 := h.run(t)
	if len(a2) != 1 {
		t.Fatalf("pass 2: got %d alerts, want 1 (logged past COOLDOWN)", len(a2))
	}
	if got := a2[0].Extra[core.ExtraNotify]; got != core.NotifyNo {
		t.Errorf("pass 2: %s = %q, want %q — logged but not mailed within NotifyCooldown", core.ExtraNotify, got, core.NotifyNo)
	}
	// advance past NotifyCooldown: mail is allowed again.
	h.clock = h.clock.Add(6 * time.Hour)
	h.farmBurst("shop.example.com", 60, func(int) string { return chromeUA })
	a3 := h.run(t)
	if len(a3) != 1 {
		t.Fatalf("pass 3: got %d alerts, want 1", len(a3))
	}
	if _, ok := a3[0].Extra[core.ExtraNotify]; ok {
		t.Errorf("pass 3: alert past NotifyCooldown must notify again (ExtraNotify absent)")
	}
}

// A PULSING farm — active, then quiet past COOLDOWN, then active again within
// NotifyCooldown — must not bypass the mail throttle. The hostState (which holds
// lastNotify) must survive the idle gap, or the next burst mails again far inside
// NotifyCooldown. This is the reclamation-bypass the review flagged.
func TestNotifyCooldownSurvivesIdleReclamation(t *testing.T) {
	h := newHarness(t, Config{Cooldown: 30 * time.Minute, NotifyCooldown: 6 * time.Hour})
	// pass 1: fires and notifies.
	h.farmBurst("shop.example.com", 60, func(int) string { return chromeUA })
	if a := h.run(t); len(a) != 1 {
		t.Fatalf("pass 1: got %d alerts, want 1", len(a))
	}
	// pass 2: fully idle and past COOLDOWN — the host must NOT be reclaimed (its
	// lastNotify is still within NotifyCooldown).
	h.clock = h.clock.Add(31 * time.Minute)
	if a := h.run(t); len(a) != 0 {
		t.Fatalf("pass 2 (idle): got %d alerts, want 0", len(a))
	}
	if _, ok := h.d.hosts["shop.example.com"]; !ok {
		t.Fatalf("host was reclaimed during the idle gap — lastNotify is lost, the throttle can be bypassed")
	}
	// pass 3: the farm returns ~1h later, still within NotifyCooldown → logged, not
	// mailed (proves lastNotify survived).
	h.clock = h.clock.Add(30 * time.Minute)
	h.farmBurst("shop.example.com", 60, func(int) string { return chromeUA })
	a3 := h.run(t)
	if len(a3) != 1 {
		t.Fatalf("pass 3: got %d alerts, want 1", len(a3))
	}
	if got := a3[0].Extra[core.ExtraNotify]; got != core.NotifyNo {
		t.Errorf("pass 3: %s = %q, want %q — a pulsing farm must not re-mail within NotifyCooldown", core.ExtraNotify, got, core.NotifyNo)
	}
}

// ── durable finding sink (Phase A: node persists the finding to detection_history) ──

// An emitted finding fires the durable sink once, carrying the resolved evidence
// (the grouping fingerprint, tracks, spread) — the record cfm-web ingests.
func TestFindingSinkFiresWithEvidence(t *testing.T) {
	var got []Finding
	SetFindingSink(func(f Finding) { got = append(got, f) })
	t.Cleanup(func() { SetFindingSink(nil) })

	h := newHarness(t, Config{FPTrack: true, MinFPSubnets: 8, MinFPCountries: 6})
	h.d.countryFn = ipCountry
	for i := 0; i < 12; i++ {
		h.solveFP("techking.example", fmt.Sprintf("203.0.%d.1", i), chromeUA, "c28caa00")
	}
	if a := h.run(t); len(a) != 1 {
		t.Fatalf("alerts=%d, want 1", len(a))
	}
	if len(got) != 1 {
		t.Fatalf("finding sink fired %d times, want 1 (once per emitted alert)", len(got))
	}
	f := got[0]
	if f.Host != "techking.example" {
		t.Errorf("Host=%q", f.Host)
	}
	if f.Fingerprint != "c28caa00" {
		t.Errorf("Fingerprint=%q, want the grouping fp (evidence, not a signature)", f.Fingerprint)
	}
	if f.Tracks != "fp_concentration" {
		t.Errorf("Tracks=%q, want fp_concentration", f.Tracks)
	}
	// Subnets is the fp's own /24 count on this vhost (loFPSubs), matching the
	// fp's country count — not the vhost-wide subnet total.
	if f.Subnets != 12 || f.Countries != 12 {
		t.Errorf("subnets=%d countries=%d, want 12 / 12", f.Subnets, f.Countries)
	}
	if !(f.Countries <= f.Subnets && f.Subnets <= f.DistinctIPs) {
		t.Errorf("finding countries=%d subnets=%d ips=%d must satisfy countries<=subnets<=ips",
			f.Countries, f.Subnets, f.DistinctIPs)
	}
	if f.Solves != 12 || f.Hosts != 1 {
		t.Errorf("Solves=%d Hosts=%d, want 12 / 1 (per-host finding)", f.Solves, f.Hosts)
	}
}

// The durable finding must fire even when the alert is LOG-ONLY: the memory is
// not throttled by the mail decision. A cross-host-only finding (log-only through
// its burn-in) still records, with the cross-host evidence resolved.
func TestFindingSinkFiresEvenWhenLogOnly(t *testing.T) {
	var got []Finding
	SetFindingSink(func(f Finding) { got = append(got, f) })
	t.Cleanup(func() { SetFindingSink(nil) })

	h := newHarness(t, xhCfg())
	h.d.countryFn = xhCountry
	for hi := 0; hi < 6; hi++ {
		for s := 0; s < 6; s++ {
			h.solveFP(fmt.Sprintf("h%d.shop", hi), fmt.Sprintf("10.%d.%d.1", hi+1, s), chromeUA, "95070673")
		}
	}
	alerts := h.run(t)
	if len(alerts) == 0 {
		t.Fatal("expected cross-host alerts")
	}
	for _, a := range alerts {
		if a.Extra[core.ExtraNotify] != core.NotifyNo {
			t.Fatal("cross-host-only alerts must be log-only")
		}
	}
	if len(got) != len(alerts) {
		t.Fatalf("findings=%d alerts=%d — the sink must fire once per emitted alert even when log-only", len(got), len(alerts))
	}
	f := got[0]
	if f.Tracks != "cross_host" || f.Fingerprint != "95070673" {
		t.Errorf("finding tracks=%q fp=%q, want cross_host / 95070673", f.Tracks, f.Fingerprint)
	}
	if f.Hosts < 4 {
		t.Errorf("cross-host finding Hosts=%d, want >= 4 (node-wide dominated vhosts)", f.Hosts)
	}
	if f.HostShare == 0 {
		t.Errorf("cross-host finding HostShare=0, want the per-vhost dominance carried as evidence")
	}
	// The spread must be the fp's NODE-WIDE footprint (6 vhosts × 6 /24s = 36),
	// not this one vhost's slice (6) — otherwise distinct_subnets would be a
	// thin-per-vhost number while distinct_countries is node-wide, and the two
	// would describe different populations in the same fleet-store row.
	if f.Subnets < 30 {
		t.Errorf("cross-host finding Subnets=%d, want the node-wide fp subnet spread (>=30), not this vhost's slice", f.Subnets)
	}
	// Evidence integrity: one set of solvers satisfies countries ≤ subnets ≤ ips.
	if !(f.Countries <= f.Subnets && f.Subnets <= f.DistinctIPs) {
		t.Errorf("cross-host finding countries=%d subnets=%d ips=%d must satisfy countries<=subnets<=ips",
			f.Countries, f.Subnets, f.DistinctIPs)
	}
}
