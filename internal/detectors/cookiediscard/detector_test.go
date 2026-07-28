package cookiediscard

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
	h := &harness{clock: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC), out: make(chan core.Alert, 128)}
	h.d = New(cfg)
	h.d.nowFn = func() time.Time { return h.clock }
	return h
}

func (h *harness) solve(ip, host, path, ua string) {
	h.d.Enqueue(core.InputEvent{
		When: h.clock, Scope: host, SrcIP: ip, Path: path, UserAgent: ua, Source: "challenge",
	})
}

// resolveBurst is the observed shape: one address solving the same vhost over
// and over, each solve a few seconds apart.
func (h *harness) resolveBurst(ip string, n int, gap time.Duration) {
	for i := 0; i < n; i++ {
		h.solve(ip, "forum.example.com", "/forum/ucp.php?mode=register", chromeUA)
		h.clock = h.clock.Add(gap)
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

func TestReSolverAlerts(t *testing.T) {
	h := newHarness(t, Config{})
	h.resolveBurst("198.51.100.7", 30, 4*time.Second)

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if a.Key != "198.51.100.7" {
		t.Errorf("Key = %q, want the client address", a.Key)
	}
	if a.Kind != "Challenge/CookieDiscard" {
		t.Errorf("Kind = %q", a.Kind)
	}
	if a.Count != 30 {
		t.Errorf("Count = %d, want 30 solves", a.Count)
	}
	if a.Extra["ip"] != "198.51.100.7" {
		t.Errorf("Extra[ip] = %q, want the client address", a.Extra["ip"])
	}
	if a.Extra["top_vhost"] != "forum.example.com" {
		t.Errorf("Extra[top_vhost] = %q", a.Extra["top_vhost"])
	}
	if a.Extra["top_ua_share"] != "100%" {
		t.Errorf("Extra[top_ua_share] = %q, want 100%%", a.Extra["top_ua_share"])
	}
}

// The threshold must not fire on the traffic shape challenge_solver_farm exists
// for: many addresses, one solve each. The two detectors do not overlap, and a
// regression that made this one count per-vhost instead of per-IP would light up
// on every farmed vhost.
func TestFarmShapeDoesNotAlert(t *testing.T) {
	h := newHarness(t, Config{})
	for i := 0; i < 500; i++ {
		h.solve(fmt.Sprintf("203.0.%d.%d", i%256, i/256+1), "shop.example.com", "/", chromeUA)
	}
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts on one-solve-per-address traffic, want 0", len(alerts))
	}
}

// A tab burst is the documented legitimate shape: one real browser challenged in
// several tabs at once, before any cookie is set. It must stay below threshold.
func TestLegitimateTabBurstDoesNotAlert(t *testing.T) {
	h := newHarness(t, Config{})
	for i := 0; i < 4; i++ {
		h.solve("198.51.100.9", "shop.example.com", "/", chromeUA)
	}
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts for 4 simultaneous solves, want 0 (calibration says legitimate repeaters top out at 4)", len(alerts))
	}
}

func TestBelowThresholdStaysQuiet(t *testing.T) {
	h := newHarness(t, Config{MinSolves: 8})
	h.resolveBurst("198.51.100.7", 7, time.Second)
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts at 7 solves with MIN_SOLVES=8, want 0", len(alerts))
	}
}

// The window must actually slide. Two bursts, each below threshold, separated by
// more than Window: if pruning were dropped the combined count would cross it.
// Each burst is deliberately MinSolves-1 so the test fails the moment expiry
// stops working, rather than being masked by a second threshold.
func TestSlidingWindowExpiresSolves(t *testing.T) {
	h := newHarness(t, Config{Window: 10 * time.Minute, MinSolves: 8})

	h.resolveBurst("198.51.100.7", 7, time.Second)
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("first burst alerted (%d), want 0", len(alerts))
	}

	h.clock = h.clock.Add(11 * time.Minute)
	h.resolveBurst("198.51.100.7", 7, time.Second)
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("second burst alerted (%d) — expired solves from the first are still being counted", len(alerts))
	}
}

func TestCooldownSuppressesRepeats(t *testing.T) {
	h := newHarness(t, Config{Window: 10 * time.Minute, MinSolves: 8, Cooldown: 30 * time.Minute})

	h.resolveBurst("198.51.100.7", 12, time.Second)
	if alerts := h.run(t); len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}

	h.clock = h.clock.Add(time.Minute)
	h.resolveBurst("198.51.100.7", 12, time.Second)
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts inside the cooldown, want 0", len(alerts))
	}

	h.clock = h.clock.Add(31 * time.Minute)
	h.resolveBurst("198.51.100.7", 12, time.Second)
	if alerts := h.run(t); len(alerts) != 1 {
		t.Fatalf("got %d alerts after the cooldown expired, want 1", len(alerts))
	}
}

// State for an address that has gone quiet must be reclaimed, but never while
// its cooldown is still suppressing a repeat alert.
func TestQuietAddressStateIsReclaimedAfterCooldown(t *testing.T) {
	h := newHarness(t, Config{Window: time.Minute, MinSolves: 8, Cooldown: 5 * time.Minute})
	h.resolveBurst("198.51.100.7", 10, time.Second)
	if alerts := h.run(t); len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}

	h.clock = h.clock.Add(2 * time.Minute)
	h.run(t)
	if len(h.d.ips) != 1 {
		t.Fatalf("state reclaimed while the cooldown was still active (%d entries) — the next burst would alert early", len(h.d.ips))
	}

	h.clock = h.clock.Add(10 * time.Minute)
	h.run(t)
	if len(h.d.ips) != 0 {
		t.Fatalf("quiet address still tracked after the cooldown (%d entries)", len(h.d.ips))
	}
}

// The evidence cap costs detail, never detection: records it drops are still
// counted toward the solve total.
func TestEvidenceCapStillCountsSolves(t *testing.T) {
	h := newHarness(t, Config{Window: 10 * time.Minute, MinSolves: 8, MaxTrackedPerIP: 5})
	h.resolveBurst("198.51.100.7", 20, time.Second)

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 — the evidence cap must not suppress the count", len(alerts))
	}
	if alerts[0].Count != 20 {
		t.Errorf("Count = %d, want all 20 solves counted despite the cap", alerts[0].Count)
	}
	if !hasSample(alerts[0], "MAX_TRACKED_PER_IP") {
		t.Error("truncation was not reported on the alert — a silent cap reads as complete evidence")
	}
}

// Reaching MaxTrackedIPs must not erase a finding already accumulating: new
// addresses are refused, tracked ones keep counting.
func TestAddressCapDoesNotEraseInProgressFinding(t *testing.T) {
	h := newHarness(t, Config{Window: 10 * time.Minute, MinSolves: 8, MaxTrackedIPs: 3})

	// Three addresses admitted, one of them already re-solving.
	h.resolveBurst("198.51.100.7", 4, time.Second)
	h.solve("198.51.100.8", "a.example.com", "/", chromeUA)
	h.solve("198.51.100.9", "a.example.com", "/", chromeUA)
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts, want 0 so far", len(alerts))
	}

	// A flood of fresh addresses is refused by the cap...
	for i := 0; i < 200; i++ {
		h.solve(fmt.Sprintf("203.0.%d.%d", i%256, i/256+1), "a.example.com", "/", chromeUA)
	}
	// ...while the address already tracked keeps counting past the threshold.
	h.resolveBurst("198.51.100.7", 6, time.Second)

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 — the address cap must not drop an in-progress finding", len(alerts))
	}
	if alerts[0].Key != "198.51.100.7" {
		t.Errorf("Key = %q", alerts[0].Key)
	}
}

func TestAllowlistsExempt(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"ip", Config{MinSolves: 8, AllowIPs: []string{"198.51.100.7"}}},
		{"net", Config{MinSolves: 8, AllowNets: []string{"198.51.100.0/24"}}},
		{"host", Config{MinSolves: 8, AllowHosts: []string{"forum.example.com"}}},
		{"ua", Config{MinSolves: 8, AllowUAContains: []string{"chrome/118"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.cfg)
			h.resolveBurst("198.51.100.7", 30, time.Second)
			if alerts := h.run(t); len(alerts) != 0 {
				t.Fatalf("got %d alerts for an allowlisted client, want 0", len(alerts))
			}
		})
	}
}

// A non-address SrcIP must never create state — the map key is client-facing
// and an unbounded set of junk keys is a memory bug waiting to happen.
func TestMalformedAddressIsIgnored(t *testing.T) {
	h := newHarness(t, Config{MinSolves: 2})
	for i := 0; i < 10; i++ {
		h.solve("not-an-ip", "a.example.com", "/", chromeUA)
	}
	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts for a malformed address, want 0", len(alerts))
	}
	if len(h.d.ips) != 0 {
		t.Fatalf("malformed address created %d state entries", len(h.d.ips))
	}
}

// EVERY longer than WINDOW would prune part of the stream away before it was
// ever examined, so New clamps it.
func TestEveryClampedToWindow(t *testing.T) {
	d := New(Config{Every: 5 * time.Minute, Window: time.Minute})
	if d.Every() != time.Minute {
		t.Fatalf("Every() = %s, want it clamped to Window (1m)", d.Every())
	}
}

// The samples quote client-controlled text (User-Agents, URIs), so the alert
// must hand the sink an authoritative address rather than let it scan for one:
// the sink's fallback takes the first IP-shaped string it finds, and
// "Chrome/118.0.0.0" is IP-shaped.
func TestAuthoritativeIPBeatsIPShapedUserAgent(t *testing.T) {
	h := newHarness(t, Config{MinSolves: 8})
	for i := 0; i < 12; i++ {
		h.solve("198.51.100.7", "a.example.com", "/10.0.0.1/", "Mozilla/5.0 Chrome/10.0.0.1 Safari/537.36")
		h.clock = h.clock.Add(time.Second)
	}
	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if got := alerts[0].Extra["ip"]; got != "198.51.100.7" {
		t.Fatalf("Extra[ip] = %q, want the real client address", got)
	}
	if net.ParseIP(alerts[0].Key) == nil {
		t.Fatalf("Key = %q is not an address; the sink resolves per-IP alerts from it", alerts[0].Key)
	}
}

func hasSample(a core.Alert, substr string) bool {
	for _, s := range a.Samples {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
