package solverfarm

import (
	"context"
	"fmt"
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

func TestSlidingWindowExpiresSolves(t *testing.T) {
	h := newHarness(t, Config{Window: time.Minute})
	h.farmBurst("shop.example.com", 30, func(int) string { return chromeUA })
	h.clock = h.clock.Add(90 * time.Second) // first burst falls out of the window
	h.farmBurst("shop.example.com", 30, func(int) string { return chromeUA })

	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts, want 0 — two 30-subnet bursts 90s apart must not sum", len(alerts))
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
		if len(s) > 0 && containsAll(s, "not tracked", "lower bound") {
			found = true
		}
	}
	if !found {
		t.Errorf("truncation not reported in samples: %v", alerts[0].Samples)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
