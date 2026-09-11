package webdetector

import (
	"fmt"
	"testing"
	"time"
)

func newTestMarks(now *time.Time) *farmMarks {
	m := newFarmMarks()
	m.nowFn = func() time.Time { return *now }
	return m
}

func TestMarkExpiresOnItsOwn(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	m := newTestMarks(&now)

	m.mark("shop.example.com", 90*time.Second)
	if !m.active("shop.example.com") {
		t.Fatal("a fresh mark must be active")
	}

	now = now.Add(89 * time.Second)
	if !m.active("shop.example.com") {
		t.Fatal("the mark expired before its TTL")
	}

	// Expiry is the only way a mark clears — there is no unmark path, so a
	// detector that stops firing must not leave a vhost badged forever.
	now = now.Add(2 * time.Second)
	if m.active("shop.example.com") {
		t.Fatal("the mark outlived its TTL")
	}
}

func TestMarkRefreshExtends(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	m := newTestMarks(&now)

	m.mark("shop.example.com", 90*time.Second)
	now = now.Add(60 * time.Second)
	m.mark("shop.example.com", 90*time.Second)

	now = now.Add(60 * time.Second)
	if !m.active("shop.example.com") {
		t.Fatal("a refreshed mark expired on the original deadline")
	}
}

func TestMarkNormalisesHost(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	m := newTestMarks(&now)

	m.mark("  SHOP.Example.COM ", time.Minute)
	if !m.active("shop.example.com") {
		t.Error("mark did not normalise case/whitespace on write")
	}
	if !m.active("Shop.Example.com") {
		t.Error("active did not normalise case on read")
	}
	if m.active("") || m.active("   ") {
		t.Error("an empty host must never be active")
	}
}

func TestMarkIgnoresNonPositiveTTL(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	m := newTestMarks(&now)
	m.mark("shop.example.com", 0)
	m.mark("other.example.com", -time.Minute)
	if m.active("shop.example.com") || m.active("other.example.com") {
		t.Fatal("a non-positive TTL must not create a mark")
	}
}

// Expired entries must be reclaimed, not merely reported inactive: the map key
// comes from the Host header, so a long-running process would otherwise
// accumulate one entry per vhost ever farmed.
func TestExpiredMarksAreReclaimed(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	m := newTestMarks(&now)

	for i := 0; i < 50; i++ {
		m.mark(fmt.Sprintf("host%d.example.com", i), time.Minute)
	}
	now = now.Add(2 * time.Minute)
	m.mark("fresh.example.com", time.Minute)

	m.mu.RLock()
	n := len(m.hosts)
	m.mu.RUnlock()
	if n != 1 {
		t.Fatalf("%d entries retained after expiry, want 1", n)
	}
}

// The key is client-influenced, so the store must be bounded — but a vhost
// already marked must keep being refreshable past the bound, or a flood of junk
// Host headers could freeze a real finding's badge.
func TestMarkStoreIsBounded(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	m := newTestMarks(&now)

	for i := 0; i < maxFarmMarks; i++ {
		m.mark(fmt.Sprintf("host%d.example.com", i), time.Hour)
	}
	m.mark("overflow.example.com", time.Hour)
	if m.active("overflow.example.com") {
		t.Error("an entry past the bound was admitted")
	}
	m.mark("host0.example.com", 2*time.Hour)
	if !m.active("host0.example.com") {
		t.Error("a known host could not be refreshed once the bound was reached")
	}
}

func TestResetDropsEverything(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	m := newTestMarks(&now)
	m.mark("shop.example.com", time.Hour)
	m.reset()
	if m.active("shop.example.com") {
		t.Fatal("reset left a mark behind")
	}
}

// The package-level entry points are what the detector and the API handlers
// use, so exercise them end to end — including the row decorators, which are
// the only thing standing between a mark and a badge.
func TestPackageLevelMarkAndDecorate(t *testing.T) {
	ResetSolverFarmMarks()
	t.Cleanup(ResetSolverFarmMarks)

	MarkSolverFarm("farmed.example.com", time.Hour)
	if !IsSolverFarm("farmed.example.com") {
		t.Fatal("IsSolverFarm = false right after MarkSolverFarm")
	}
	if IsSolverFarm("quiet.example.com") {
		t.Fatal("an unmarked host reported as farmed")
	}

	short := decorateSolverFarmShort([]ShortRow{
		{Host: "farmed.example.com"},
		{Host: "quiet.example.com"},
	})
	if !short[0].SolverFarm || short[1].SolverFarm {
		t.Errorf("short rows decorated wrong: %v / %v", short[0].SolverFarm, short[1].SolverFarm)
	}

	susp := decorateSolverFarmSuspicious([]SuspiciousRow{
		{Host: "farmed.example.com"},
		{Host: "quiet.example.com"},
	})
	if !susp[0].SolverFarm || susp[1].SolverFarm {
		t.Errorf("suspicious rows decorated wrong: %v / %v", susp[0].SolverFarm, susp[1].SolverFarm)
	}
}

// The fingerprint-level marks are a separate instance of the same TTL store, so
// they don't collide with the vhost marks, and ResetSolverFarmMarks clears both.
func TestPackageLevelFingerprintMark(t *testing.T) {
	ResetSolverFarmMarks()
	t.Cleanup(ResetSolverFarmMarks)

	MarkSolverFarmFingerprint("c28caa00", time.Hour)
	if !IsSolverFarmFingerprint("c28caa00") {
		t.Fatal("IsSolverFarmFingerprint = false right after MarkSolverFarmFingerprint")
	}
	if IsSolverFarmFingerprint("deadbeef") {
		t.Fatal("an unmarked fingerprint reported as convicted")
	}
	// The fingerprint and vhost stores are independent — a fingerprint mark is not
	// a vhost mark and vice-versa.
	if IsSolverFarm("c28caa00") {
		t.Error("fingerprint mark leaked into the vhost store")
	}
	MarkSolverFarm("farmed.example.com", time.Hour)
	if IsSolverFarmFingerprint("farmed.example.com") {
		t.Error("vhost mark leaked into the fingerprint store")
	}
	// One reset clears both.
	ResetSolverFarmMarks()
	if IsSolverFarmFingerprint("c28caa00") || IsSolverFarm("farmed.example.com") {
		t.Fatal("ResetSolverFarmMarks left a mark behind")
	}
}
