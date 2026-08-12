package lvestat

import (
	"testing"
	"time"
)

func TestLimitCores(t *testing.T) {
	cases := map[int64]float64{0: 0, -5: 0, 10000: 1, 60000: 6, 155000: 15.5, 5000: 0.5}
	for in, want := range cases {
		if got := LimitCores(in); got != want {
			t.Errorf("LimitCores(%d) = %v, want %v", in, got, want)
		}
	}
}

func snap(entries ...LVE) Snapshot { return Snapshot{Version: 10, Entries: entries} }

func TestDiff_RatesAndSort(t *testing.T) {
	prev := snap(
		LVE{Reseller: 0, UID: 1004, CPUUsage: 1_000, LimitCPU: 20000, NumCPU: 2},
		LVE{Reseller: 0, UID: 1010, CPUUsage: 5_000, LimitCPU: 30000, NumCPU: 3},
	)
	cur := snap(
		LVE{Reseller: 0, UID: 1004, CPUUsage: 3_000, LimitCPU: 20000, NumCPU: 2, EP: 1, NProc: 43}, // +2000 / 10s = 200/s
		LVE{Reseller: 0, UID: 1010, CPUUsage: 5_500, LimitCPU: 30000, NumCPU: 3},                   // +500 / 10s = 50/s
	)
	got := Diff(prev, cur, 10*time.Second)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	// Hottest first: 1004 (200/s) before 1010 (50/s).
	if got[0].UID != 1004 || got[0].CPURate != 200 {
		t.Errorf("got[0] = uid %d rate %v, want 1004/200", got[0].UID, got[0].CPURate)
	}
	if got[1].UID != 1010 || got[1].CPURate != 50 {
		t.Errorf("got[1] = uid %d rate %v, want 1010/50", got[1].UID, got[1].CPURate)
	}
	// Passthrough fields come from cur.
	if got[0].LimitCPU != 20000 || got[0].NumCPU != 2 || got[0].EP != 1 || got[0].NProc != 43 {
		t.Errorf("passthrough wrong: %+v", got[0])
	}
}

func TestDiff_NewTenantAndCounterResetAreZero(t *testing.T) {
	prev := snap(LVE{Reseller: 0, UID: 1004, CPUUsage: 10_000})
	cur := snap(
		LVE{Reseller: 0, UID: 1004, CPUUsage: 500},   // counter went BACKWARDS (reset) → rate 0
		LVE{Reseller: 0, UID: 2000, CPUUsage: 9_999}, // not in prev → rate 0
	)
	got := Diff(prev, cur, 5*time.Second)
	for _, s := range got {
		if s.CPURate != 0 {
			t.Errorf("uid %d rate = %v, want 0 (reset / new tenant)", s.UID, s.CPURate)
		}
	}
}

func TestDiff_NonPositiveElapsed(t *testing.T) {
	prev := snap(LVE{UID: 1, CPUUsage: 1})
	cur := snap(LVE{UID: 1, CPUUsage: 100})
	if got := Diff(prev, cur, 0); got != nil {
		t.Fatalf("elapsed 0 → got %v, want nil", got)
	}
	if got := Diff(prev, cur, -time.Second); got != nil {
		t.Fatalf("negative elapsed → got %v, want nil", got)
	}
}

func approx(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-6
}

// Cores = ΔCPU_ns / (Δt × 1e9); PctOfLimit = Cores / (lCPU/10000) × 100.
func TestDiff_CoresAndPctOfLimit(t *testing.T) {
	prev := snap(
		LVE{Reseller: 0, UID: 1, CPUUsage: 0, LimitCPU: 60000}, // 6-core cap
		LVE{Reseller: 0, UID: 2, CPUUsage: 0, LimitCPU: 10000}, // 1-core cap
		LVE{Reseller: 0, UID: 3, CPUUsage: 0, LimitCPU: 0},     // unlimited
	)
	cur := snap(
		LVE{Reseller: 0, UID: 1, CPUUsage: 9_300_000_000, LimitCPU: 60000},  // 0.93 cores
		LVE{Reseller: 0, UID: 2, CPUUsage: 10_000_000_000, LimitCPU: 10000}, // 1.0 core == 100% of cap
		LVE{Reseller: 0, UID: 3, CPUUsage: 5_000_000_000, LimitCPU: 0},      // 0.5 cores, no cap
	)
	got := Diff(prev, cur, 10*time.Second)
	by := map[int64]CPUSample{}
	for _, s := range got {
		by[s.UID] = s
	}
	if !approx(by[1].Cores, 0.93) || !approx(by[1].PctOfLimit, 15.5) {
		t.Errorf("uid1 = %.4f cores / %.4f%%, want 0.93 / 15.5", by[1].Cores, by[1].PctOfLimit)
	}
	if !approx(by[2].Cores, 1.0) || !approx(by[2].PctOfLimit, 100) {
		t.Errorf("uid2 = %.4f cores / %.4f%%, want 1.0 / 100 (at cap)", by[2].Cores, by[2].PctOfLimit)
	}
	if !approx(by[3].Cores, 0.5) || by[3].PctOfLimit != 0 {
		t.Errorf("uid3 = %.4f cores / %.4f%%, want 0.5 / 0 (unlimited)", by[3].Cores, by[3].PctOfLimit)
	}
	// Hottest-first ordering is by rate: uid2 (1.0) > uid1 (0.93) > uid3 (0.5).
	if got[0].UID != 2 || got[1].UID != 1 || got[2].UID != 3 {
		t.Errorf("order = %d,%d,%d, want 2,1,3", got[0].UID, got[1].UID, got[2].UID)
	}
}

// Reseller is part of the match key: same uid under different resellers are
// distinct tenants and must not cross-match.
func TestDiff_ResellerScopedMatch(t *testing.T) {
	prev := snap(LVE{Reseller: 0, UID: 1004, CPUUsage: 1_000})
	cur := snap(LVE{Reseller: 7, UID: 1004, CPUUsage: 9_000}) // different reseller, same uid
	got := Diff(prev, cur, 10*time.Second)
	if len(got) != 1 || got[0].Reseller != 7 {
		t.Fatalf("got %+v, want one entry reseller 7", got)
	}
	if got[0].CPURate != 0 {
		t.Errorf("cross-reseller must not match prev → rate %v, want 0", got[0].CPURate)
	}
}
