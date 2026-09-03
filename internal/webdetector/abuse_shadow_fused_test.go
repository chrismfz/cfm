package webdetector

import (
	"math"
	"testing"
	"time"
)

// Corroboration is over the VHOST-LEVEL shapes {facet, cost, dc} only — rate-outlier
// (shadow) is excluded, because one aggressive IP trips both facet and rate-outlier.
func TestCorroboratingSignals(t *testing.T) {
	cases := []struct {
		f, c, d int
		want    int
	}{
		{0, 0, 0, 0},
		{402, 0, 0, 1}, // planetgym: facet alone
		{0, 0, 52, 1},  // dc alone
		{326, 0, 52, 2},
		{100, 20, 90, 3},
	}
	for _, tc := range cases {
		if got := corroboratingSignals(tc.f, tc.c, tc.d); got != tc.want {
			t.Errorf("corroboratingSignals(%d,%d,%d)=%d, want %d", tc.f, tc.c, tc.d, got, tc.want)
		}
	}
}

func TestFusedDelta_ClampAndCap(t *testing.T) {
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
	if d := fusedDelta(4, 0, 0, 0); math.Abs(d-0.08) > 1e-9 {
		t.Errorf("modest z delta=%v, want 0.08", d)
	}
}

const testMinUniq = 5 // stand-in for ChallengeSuspiciousMinUniqIP in the pure tests

// The corroboration gate is the planetgym guard: a single vhost shape (facet alone,
// or dc alone) must never move the fused score — even paired with a huge rate-outlier
// z, since rate-outlier does not count toward corroboration.
func TestFusedVerdict_SingleShapeNeverArms(t *testing.T) {
	on := 0.70
	// facet alone (huge facet z AND huge shadow z), base near the line, plenty of IPs.
	corrob, delta, fused, verdict := fusedVhostVerdict(0.68, 9784, 0, 0, 200, testMinUniq, 100, 0, 0, 100, on)
	if corrob != 1 || delta != 0 || verdict != "" {
		t.Errorf("facet+shadow single-shape: corrob=%d delta=%v verdict=%q, want 1/0/\"\"", corrob, delta, verdict)
	}
	if !approx(fused, 0.68, 1e-9) {
		t.Errorf("single-shape fused=%v, want base 0.68 unchanged", fused)
	}
	// dc alone.
	if _, _, _, v := fusedVhostVerdict(0.69, 0, 0, 100, 200, testMinUniq, 0, 0, 100, 0, on); v != "" {
		t.Errorf("dc-alone verdict=%q, must never arm", v)
	}
}

// Two vhost shapes CAN lift a mid base over the line — the net-new catch — but only
// when the uniqIP floor is met (mirrors the live arm).
func TestFusedVerdict_CorroboratedArms(t *testing.T) {
	on := 0.70
	// base 0.55, facet+dc both saturated → delta capped 0.25 → fused 0.80 ≥ on, uniq ok.
	corrob, delta, fused, verdict := fusedVhostVerdict(0.55, 9784, 0, 90, 200, testMinUniq, 100, 0, 100, 0, on)
	if corrob != 2 || delta != fusedGroupCap || verdict != "would_arm" {
		t.Errorf("corroborated: corrob=%d delta=%v verdict=%q, want 2/cap/would_arm", corrob, delta, verdict)
	}
	if !approx(fused, 0.80, 1e-9) {
		t.Errorf("fused=%v, want 0.80", fused)
	}
	// Same, but below the uniqIP floor → not a real catch → no verdict.
	if _, _, _, v := fusedVhostVerdict(0.55, 9784, 0, 90, 2, testMinUniq, 100, 0, 100, 0, on); v != "" {
		t.Errorf("low-uniqIP verdict=%q, want \"\" (can't actually arm)", v)
	}
	// base already ≥ on → confirm, not would_arm.
	if _, _, _, v := fusedVhostVerdict(0.72, 9784, 0, 90, 200, testMinUniq, 100, 0, 100, 0, on); v != "confirm" {
		t.Errorf("already-armed verdict=%q, want confirm", v)
	}
	// Δ can't manufacture an arm from a low base.
	if _, _, fused, v := fusedVhostVerdict(0.20, 9784, 0, 90, 200, testMinUniq, 100, 0, 100, 0, on); v != "" || fused >= on {
		t.Errorf("low base armed (fused=%v verdict=%q) — Δ must not fabricate an arm", fused, v)
	}
}

func TestFusedVerdict_ClampsToOne(t *testing.T) {
	if _, _, fused, _ := fusedVhostVerdict(0.95, 9784, 20, 90, 200, testMinUniq, 100, 100, 100, 100, 0.70); fused != 1.0 {
		t.Errorf("fused=%v, want clamped 1.0", fused)
	}
}

// The security-critical freeze invariant + the sustained-flood Touch: a corroborated
// vhost must NOT train its own baseline, but must be Touch()'d so a long flood is not
// pruned; an uncorroborated vhost keeps learning.
func TestFuseLearnOrFreeze(t *testing.T) {
	bl := newVhostBaseline(vhostBaselineConfig{Window: 60, MinSamples: 3})
	t0 := time.Now()

	// First, an uncorroborated pass fills the baseline (learning "normal").
	for i := 0; i < 4; i++ {
		if corr := fuseLearnOrFreeze(bl, "h", 100, 0, 0, 0, t0); corr {
			t.Fatalf("single-shape vhost reported corroborated")
		}
	}
	if _, n := bl.RobustZ("h", "facet", 100, fusedFacetFloor); n != 4 {
		t.Errorf("uncorroborated vhost trained %d samples, want 4", n)
	}

	// Now it becomes corroborated (facet+dc): frozen — no new samples — but Touch'd.
	later := t0.Add(time.Hour)
	if corr := fuseLearnOrFreeze(bl, "h", 9784, 0, 90, 19, later); !corr {
		t.Fatalf("facet+dc vhost not reported corroborated")
	}
	if _, n := bl.RobustZ("h", "facet", 9784, fusedFacetFloor); n != 4 {
		t.Errorf("frozen vhost gained samples (n=%d, want 4) — flood trained itself in", n)
	}
	// Touch advanced lastSeen, so a prune at the original time does not drop it.
	if removed := bl.Prune(t0.Add(30 * time.Minute)); removed != 0 || bl.hostCount() != 1 {
		t.Errorf("sustained corroborated host pruned: removed=%d hostCount=%d, want 0/1", removed, bl.hostCount())
	}

	// A never-seen corroborated host is not created (Touch is a no-op on unknown).
	if corr := fuseLearnOrFreeze(bl, "fresh-flood", 9784, 0, 90, 0, later); !corr {
		t.Fatalf("fresh corroborated host not reported corroborated")
	}
	if bl.hostCount() != 1 {
		t.Errorf("Touch created an entry for an unknown corroborated host (hostCount=%d, want 1)", bl.hostCount())
	}
}
