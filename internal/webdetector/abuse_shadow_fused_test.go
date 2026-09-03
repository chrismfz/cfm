package webdetector

import (
	"math"
	"testing"
	"time"
)

// The security-critical freeze invariant: a corroborated vhost (≥2 signals) must
// NOT be folded into its own baseline (an active flood can't train itself in),
// while an uncorroborated one keeps learning.
func TestFuseObserveOrFreeze(t *testing.T) {
	bl := newVhostBaseline(vhostBaselineConfig{Window: 60, MinSamples: 3})
	now := time.Now()

	// Corroborated (facet + shadow) → frozen: no observation, no ring created.
	if observed := fuseObserveOrFreeze(bl, "flood", 9784, 0, 0, 19, now); observed {
		t.Errorf("corroborated vhost was observed — must be frozen")
	}
	if _, n := bl.RobustZ("flood", "facet", 9784, fusedFacetFloor); n != 0 {
		t.Errorf("frozen vhost has %d facet samples, want 0 (never trained)", n)
	}
	if bl.hostCount() != 0 {
		t.Errorf("frozen vhost created a baseline entry (hostCount=%d, want 0)", bl.hostCount())
	}

	// Uncorroborated (facet alone) → observed across ticks; the ring fills.
	for i := 0; i < 4; i++ {
		if observed := fuseObserveOrFreeze(bl, "quiet", 300, 0, 0, 0, now); !observed {
			t.Fatalf("uncorroborated vhost was frozen — must learn")
		}
	}
	if _, n := bl.RobustZ("quiet", "facet", 300, fusedFacetFloor); n != 4 {
		t.Errorf("uncorroborated vhost trained %d samples, want 4", n)
	}
}

func TestActiveSignals(t *testing.T) {
	cases := []struct {
		f, c, d, s int
		want       int
	}{
		{0, 0, 0, 0, 0},
		{402, 0, 0, 0, 1}, // planetgym: facet alone
		{0, 0, 52, 0, 1},  // dc alone
		{326, 0, 52, 0, 2},
		{9784, 0, 0, 19, 2},
		{100, 20, 90, 3, 4},
	}
	for _, tc := range cases {
		if got := activeSignals(tc.f, tc.c, tc.d, tc.s); got != tc.want {
			t.Errorf("activeSignals(%d,%d,%d,%d)=%d, want %d", tc.f, tc.c, tc.d, tc.s, got, tc.want)
		}
	}
}

func TestFusedDelta_ClampAndCap(t *testing.T) {
	// Negative / zero z contribute nothing.
	if d := fusedDelta(-5, 0, 0, 0); d != 0 {
		t.Errorf("negative z delta=%v, want 0", d)
	}
	// One saturated signal: fusedWeight * min(z, zClamp) = 0.02 * 8 = 0.16.
	if d := fusedDelta(100, 0, 0, 0); math.Abs(d-0.16) > 1e-9 {
		t.Errorf("one saturated signal delta=%v, want 0.16", d)
	}
	// Two saturated: 0.02*(8+8)=0.32 → capped at fusedGroupCap 0.25.
	if d := fusedDelta(100, 100, 0, 0); d != fusedGroupCap {
		t.Errorf("two saturated delta=%v, want cap %v", d, fusedGroupCap)
	}
	// A modest single z scales linearly: 0.02*4 = 0.08.
	if d := fusedDelta(4, 0, 0, 0); math.Abs(d-0.08) > 1e-9 {
		t.Errorf("modest z delta=%v, want 0.08", d)
	}
}

// The corroboration gate is the planetgym guard: a single strong signal (facet
// alone, or dc alone) must NEVER move the fused score, no matter how large its z.
func TestFusedVerdict_SingleSignalNeverArms(t *testing.T) {
	on := 0.70
	// facet alone, huge z, a base already near the line — still must not arm.
	active, delta, fused, arm := fusedVhostVerdict(0.68, 9784, 0, 0, 0, 100, 0, 0, 0, on)
	if active != 1 || delta != 0 || arm {
		t.Errorf("facet-alone: active=%d delta=%v fused=%v arm=%v, want 1/0/…/false", active, delta, fused, arm)
	}
	if !approx(fused, 0.68, 1e-9) {
		t.Errorf("facet-alone fused=%v, want base 0.68 unchanged", fused)
	}
	// dc alone (datacenter-ASN alone never decides).
	if _, _, _, arm := fusedVhostVerdict(0.69, 0, 0, 100, 0, 0, 0, 100, 0, on); arm {
		t.Errorf("dc-alone armed, must never")
	}
}

// Two co-firing signals CAN lift a mid base over the line — the net-new catch.
func TestFusedVerdict_CorroboratedArms(t *testing.T) {
	on := 0.70
	// base 0.55, facet+shadow both saturated → delta capped 0.25 → fused 0.80 ≥ on.
	active, delta, fused, arm := fusedVhostVerdict(0.55, 9784, 0, 0, 19, 100, 0, 0, 100, on)
	if active != 2 || delta != fusedGroupCap || !arm {
		t.Errorf("corroborated: active=%d delta=%v fused=%v arm=%v, want 2/cap/…/true", active, delta, fused, arm)
	}
	if !approx(fused, 0.80, 1e-9) {
		t.Errorf("fused=%v, want 0.80", fused)
	}
	// Same two signals but a low base: delta can't manufacture an arm from nothing.
	if _, _, fused, arm := fusedVhostVerdict(0.20, 9784, 0, 0, 19, 100, 0, 0, 100, on); arm || fused >= on {
		t.Errorf("low base still armed (fused=%v) — Δ must not fabricate an arm", fused)
	}
}

// clamp01 keeps the fused score in range even if base+Δ overshoots.
func TestFusedVerdict_ClampsToOne(t *testing.T) {
	if _, _, fused, _ := fusedVhostVerdict(0.95, 9784, 20, 90, 3, 100, 100, 100, 100, 0.70); fused != 1.0 {
		t.Errorf("fused=%v, want clamped 1.0", fused)
	}
}
