package webdetector

import (
	"math"
	"sort"
	"sync"
	"testing"
	"time"
)

func approx(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

// A flat baseline yields MAD 0, so the madFloor sets the scale: z is a clean
// (x-median)/floor scaled by 0.6745.
func TestRobustZ_FlatBaselineUsesMadFloor(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 60, MinSamples: 8})
	now := time.Now()
	for i := 0; i < 20; i++ {
		b.Observe("h", "dc", 5, now)
	}
	// median = 5, MAD = 0, floor = 5 → z = 0.6745*(25-5)/5 = 2.698
	z, n := b.RobustZ("h", "dc", 25, 5)
	if n != 20 {
		t.Fatalf("n=%d, want 20", n)
	}
	if !approx(z, 2.698, 1e-3) {
		t.Errorf("z=%v, want ~2.698", z)
	}
	// x == median → z = 0 regardless of floor.
	if z0, _ := b.RobustZ("h", "dc", 5, 5); z0 != 0 {
		t.Errorf("z at median = %v, want 0", z0)
	}
	// Below baseline → negative (sign preserved).
	if zn, _ := b.RobustZ("h", "dc", 0, 5); zn >= 0 {
		t.Errorf("z below baseline = %v, want negative", zn)
	}
}

// Cold start: below MinSamples the store must not emit a z (it would be noise
// off 1–2 points), and it reports the real sample count so the caller can log.
func TestRobustZ_ColdStart(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 60, MinSamples: 8})
	now := time.Now()
	for i := 0; i < 5; i++ {
		b.Observe("h", "facet", 100, now)
	}
	z, n := b.RobustZ("h", "facet", 9000, 50)
	if z != 0 || n != 5 {
		t.Errorf("cold start z=%v n=%d, want 0/5", z, n)
	}
	// Unknown host / feature → 0/0.
	if z, n := b.RobustZ("nope", "facet", 1, 1); z != 0 || n != 0 {
		t.Errorf("unknown host = %v/%d, want 0/0", z, n)
	}
	if z, n := b.RobustZ("h", "nope", 1, 1); z != 0 || n != 0 {
		t.Errorf("unknown feature = %v/%d, want 0/0", z, n)
	}
}

// The whole point of MAD: a handful of huge spikes in the window must NOT poison
// the baseline. A mean/σ estimator would be dragged up and mask the next spike;
// median/MAD stays put.
func TestRobustZ_OutlierRobust(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 60, MinSamples: 8})
	now := time.Now()
	for i := 0; i < 18; i++ {
		b.Observe("h", "cost", 0.02, now) // quiet 5xx fraction
	}
	b.Observe("h", "cost", 0.95, now) // two earlier bursts already in the window
	b.Observe("h", "cost", 0.90, now)

	// median is still ~0.02 (18 of 20), MAD tiny → a fresh benign 0.02 reads ~0…
	if z, _ := b.RobustZ("h", "cost", 0.02, 0.05); math.Abs(z) > 0.5 {
		t.Errorf("benign value against outlier-laced window z=%v, want ~0", z)
	}
	// …while a real spike still lights up strongly.
	zSpike, _ := b.RobustZ("h", "cost", 0.80, 0.05)
	if zSpike < 5 {
		t.Errorf("spike z=%v, want strongly positive", zSpike)
	}
	// Sanity: the poisoned-mean baseline (mean ≈ 0.11) would have made 0.80 look
	// far less anomalous than the robust one does — assert the robust z is big.
}

// Odd/even median correctness through the public API (via a floor of 0 so MAD
// alone drives the scale).
func TestRobustZ_MedianOddEven(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 60, MinSamples: 3})
	now := time.Now()
	// samples 1,2,3,4 → median 2.5, deviations {1.5,0.5,0.5,1.5} → MAD 1.0
	for _, v := range []float64{1, 2, 3, 4} {
		b.Observe("h", "f", v, now)
	}
	z, n := b.RobustZ("h", "f", 2.5, 0)
	if n != 4 || z != 0 {
		t.Errorf("z at median 2.5 = %v (n=%d), want 0", z, n)
	}
	// x = 4.0 → 0.6745*(4.0-2.5)/1.0 = 1.01175
	if z, _ := b.RobustZ("h", "f", 4.0, 0); !approx(z, 1.01175, 1e-4) {
		t.Errorf("z=%v, want ~1.01175", z)
	}

	// odd window, non-flat: 1,2,3,4,5 → median 3, deviations {2,1,0,1,2} → MAD 1.
	// x=5 → 0.6745*(5-3)/1 = 1.349
	for _, v := range []float64{1, 2, 3, 4, 5} {
		b.Observe("odd", "f", v, now)
	}
	if z, n := b.RobustZ("odd", "f", 5, 0); n != 5 || !approx(z, 1.349, 1e-4) {
		t.Errorf("odd-window z=%v (n=%d), want ~1.349 / 5", z, n)
	}
}

// The recency window aged samples out for RobustZ, but median/MAD is robust to a
// MINORITY of leaked stale samples, so that test can't lock exact eviction. This
// white-box test asserts the ring holds EXACTLY the last Window pushes — catching
// any partial-eviction / off-by-one that the robust-z path would mask.
func TestRing_EvictsExactLastWindow(t *testing.T) {
	r := &featureRing{buf: make([]float64, 4)}
	for i := 0; i < 10; i++ {
		r.push(float64(i)) // 0..9; only 6,7,8,9 should survive
	}
	got := r.appendSamples(nil)
	if len(got) != 4 {
		t.Fatalf("ring kept %d samples, want 4", len(got))
	}
	sort.Float64s(got)
	for i, want := range []float64{6, 7, 8, 9} {
		if got[i] != want {
			t.Errorf("ring contents = %v, want [6 7 8 9]", got)
			break
		}
	}
	// Also assert the unfilled case: 2 pushes into a size-4 ring keep exactly both.
	r2 := &featureRing{buf: make([]float64, 4)}
	r2.push(11)
	r2.push(22)
	got2 := r2.appendSamples(nil)
	sort.Float64s(got2)
	if len(got2) != 2 || got2[0] != 11 || got2[1] != 22 {
		t.Errorf("unfilled ring = %v, want [11 22]", got2)
	}
}

// A non-finite sample must never enter a window (it would poison median/MAD), and
// a non-finite query value must never yield a non-finite z into security scoring.
func TestRobustZ_NonFiniteGuard(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 60, MinSamples: 8})
	now := time.Now()
	for i := 0; i < 12; i++ {
		b.Observe("h", "f", 10, now)
	}
	b.Observe("h", "f", math.NaN(), now)  // dropped
	b.Observe("h", "f", math.Inf(1), now) // dropped
	if z, n := b.RobustZ("h", "f", 10, 1); z != 0 || n != 12 {
		t.Errorf("non-finite samples leaked: z=%v n=%d, want 0/12", z, n)
	}
	// Non-finite query value → 0, never NaN/Inf.
	if z, _ := b.RobustZ("h", "f", math.NaN(), 1); z != 0 {
		t.Errorf("NaN query z=%v, want 0", z)
	}
	if z, _ := b.RobustZ("h", "f", math.Inf(1), 1); z != 0 {
		t.Errorf("Inf query z=%v, want 0", z)
	}
	// A non-finite madFloor must not slip a NaN z out (Max(mad, NaN) = NaN passes
	// the scale<=0 guard) — the output finiteness backstop catches it.
	if z, _ := b.RobustZ("h", "f", 25, math.NaN()); z != 0 || math.IsNaN(z) {
		t.Errorf("NaN madFloor z=%v, want 0", z)
	}
	// An absurdly tiny madFloor overflows z to +Inf on a large deviation; the
	// backstop returns 0 rather than a non-finite score.
	if z, _ := b.RobustZ("h", "f", 1e300, 1e-309); z != 0 || math.IsInf(z, 0) {
		t.Errorf("tiny-madFloor overflow z=%v, want 0", z)
	}
}

// A transient non-finite sample must NOT cost an existing vhost its rolling window
// via a prune/LRU: Observe refreshes lastSeen for a known host even when it drops
// the bad value, and does not create a brand-new host from a non-finite sample.
func TestObserve_NonFiniteRefreshesLastSeen(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 10, MinSamples: 3})
	t0 := time.Now()
	b.Observe("h", "f", 10, t0)                        // creates host, lastSeen = t0
	b.Observe("h", "f", math.NaN(), t0.Add(time.Hour)) // dropped, but lastSeen → t0+1h
	// Prune with a cutoff between t0 and t0+1h: the host must survive because its
	// lastSeen advanced past the bad sample.
	if got := b.Prune(t0.Add(30 * time.Minute)); got != 0 {
		t.Errorf("pruned %d, want 0 — lastSeen should have advanced on the NaN tick", got)
	}
	if b.hostCount() != 1 {
		t.Errorf("hostCount=%d, want 1 (host kept)", b.hostCount())
	}
	// A brand-new host whose first-ever sample is non-finite is not created.
	b.Observe("nan-only", "f", math.Inf(1), t0)
	if b.hostCount() != 1 {
		t.Errorf("hostCount=%d, want 1 — a NaN/Inf first sample must not create a host", b.hostCount())
	}
}

// The ring is a recency window: after more than Window observations only the last
// Window survive, so the baseline tracks recent behaviour and old regimes age out.
func TestRing_RecencyWindow(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 10, MinSamples: 3})
	now := time.Now()
	for i := 0; i < 10; i++ { // fill with 1000
		b.Observe("h", "f", 1000, now)
	}
	for i := 0; i < 10; i++ { // overwrite the whole ring with 3
		b.Observe("h", "f", 3, now)
	}
	// Baseline is now all 3s (the 1000s aged out): median 3, MAD 0.
	z, n := b.RobustZ("h", "f", 3, 1)
	if n != 10 || z != 0 {
		t.Errorf("recency z=%v n=%d, want 0/10 (old regime gone)", z, n)
	}
}

// RobustZ must not fold the queried value into its own baseline.
func TestRobustZ_DoesNotIncludeQueryValue(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 60, MinSamples: 3})
	now := time.Now()
	for i := 0; i < 10; i++ {
		b.Observe("h", "f", 10, now)
	}
	// Querying a huge x repeatedly must not change subsequent z (x isn't stored).
	_, _ = b.RobustZ("h", "f", 9999, 1)
	z, _ := b.RobustZ("h", "f", 10, 1)
	if z != 0 {
		t.Errorf("query value leaked into baseline: z=%v, want 0", z)
	}
}

func TestPrune(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 10, MinSamples: 3})
	t0 := time.Now()
	b.Observe("old", "f", 1, t0)
	b.Observe("new", "f", 1, t0.Add(time.Hour))
	if got := b.Prune(t0.Add(30 * time.Minute)); got != 1 {
		t.Fatalf("pruned %d, want 1", got)
	}
	if b.hostCount() != 1 {
		t.Errorf("hostCount=%d, want 1", b.hostCount())
	}
	if z, n := b.RobustZ("old", "f", 1, 1); n != 0 || z != 0 {
		t.Errorf("pruned host still present: %v/%d", z, n)
	}
}

func TestMaxHosts_LRUEviction(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 10, MinSamples: 3, MaxHosts: 2})
	t0 := time.Now()
	b.Observe("a", "f", 1, t0)
	b.Observe("b", "f", 1, t0.Add(time.Minute))
	b.Observe("c", "f", 1, t0.Add(2*time.Minute)) // evicts "a" (oldest)
	if b.hostCount() != 2 {
		t.Fatalf("hostCount=%d, want 2 (cap)", b.hostCount())
	}
	if _, n := b.RobustZ("a", "f", 1, 1); n != 0 {
		t.Errorf("LRU host 'a' should have been evicted, n=%d", n)
	}
	if _, n := b.RobustZ("c", "f", 1, 1); n == 0 {
		t.Errorf("newest host 'c' should be present")
	}
}

func TestConfigDefaults(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{}) // all zero
	if b.cfg.Window != 60 || b.cfg.MinSamples != 8 {
		t.Errorf("defaults = win %d min %d, want 60/8", b.cfg.Window, b.cfg.MinSamples)
	}
	// MinSamples clamped to Window.
	b2 := newVhostBaseline(vhostBaselineConfig{Window: 5, MinSamples: 100})
	if b2.cfg.MinSamples != 5 {
		t.Errorf("MinSamples not clamped to Window: %d", b2.cfg.MinSamples)
	}
}

// -race smoke: concurrent Observe/RobustZ/Prune must not data-race.
func TestConcurrentAccess(t *testing.T) {
	b := newVhostBaseline(vhostBaselineConfig{Window: 32, MinSamples: 4})
	now := time.Now()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				b.Observe("h", "f", float64(i%7), now)
				_, _ = b.RobustZ("h", "f", float64(i), 1)
				if i%100 == 0 {
					b.Prune(now.Add(-time.Hour))
				}
			}
		}(g)
	}
	wg.Wait()
}
