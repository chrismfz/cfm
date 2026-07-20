package clam

import "testing"

// The breaker opens only after breakerFailThreshold *consecutive* failures,
// transitions are edge-triggered (one "down"/"recovered" per state change), and
// any success resets the streak.
func TestBreakerRecordTransitions(t *testing.T) {
	h := &scanHealth{}

	// Below threshold: no transition, breaker stays closed.
	for i := 0; i < breakerFailThreshold-1; i++ {
		if tr := h.record(false, "boom"); tr != "" {
			t.Fatalf("premature transition %q at failure %d", tr, i+1)
		}
		if h.isOpen() {
			t.Fatalf("breaker opened early after %d failures", i+1)
		}
	}
	// The threshold-th consecutive failure opens the breaker exactly once.
	if tr := h.record(false, "boom"); tr != "down" {
		t.Fatalf("threshold failure: transition = %q, want down", tr)
	}
	if !h.isOpen() {
		t.Fatal("breaker should be open at threshold")
	}
	// Further failures while open: no repeat "down".
	if tr := h.record(false, "boom"); tr != "" {
		t.Fatalf("repeat down transition %q while already open", tr)
	}
	// First success recovers exactly once.
	if tr := h.record(true, ""); tr != "recovered" {
		t.Fatalf("recovery: transition = %q, want recovered", tr)
	}
	if h.isOpen() {
		t.Fatal("breaker should be closed after recovery")
	}
	// Further successes: no repeat "recovered".
	if tr := h.record(true, ""); tr != "" {
		t.Fatalf("repeat recovered transition %q while already healthy", tr)
	}
}

// A success before the threshold resets the consecutive-failure streak, so the
// breaker does not open on transient, non-consecutive errors.
func TestBreakerResetsStreakOnSuccess(t *testing.T) {
	h := &scanHealth{}
	for i := 0; i < breakerFailThreshold-1; i++ {
		h.record(false, "x")
	}
	if tr := h.record(true, ""); tr != "" {
		t.Fatalf("unexpected transition %q on interleaved success", tr)
	}
	// Fresh run of failures one short of threshold — still closed because the
	// streak was reset.
	for i := 0; i < breakerFailThreshold-1; i++ {
		if tr := h.record(false, "x"); tr != "" {
			t.Fatalf("breaker opened too early after reset (failure %d): %q", i+1, tr)
		}
	}
	if h.isOpen() {
		t.Fatal("breaker must not open — the streak was reset by the interleaved success")
	}
}

// Health() reports a consistent snapshot of breaker state, queue geometry, and
// the lifetime counters.
func TestManagerHealthSnapshot(t *testing.T) {
	m := NewManager(Config{QueueSize: 8})
	m.health.scannedOK.Add(5)
	m.health.scanErrors.Add(2)
	m.health.skippedBreaker.Add(1)
	m.health.queueDrops.Add(3)
	for i := 0; i < breakerFailThreshold; i++ {
		m.health.record(false, "unreachable")
	}

	snap := m.Health()
	if !snap.BreakerOpen {
		t.Fatal("snapshot: BreakerOpen = false, want true")
	}
	if snap.DownSince.IsZero() {
		t.Fatal("snapshot: DownSince is zero while breaker open")
	}
	if snap.ScannedOK != 5 || snap.ScanErrors != 2 || snap.SkippedBreaker != 1 || snap.QueueDrops != 3 {
		t.Fatalf("snapshot counters wrong: %+v", snap)
	}
	if snap.QueueCap != 8 || snap.QueueLen != 0 {
		t.Fatalf("snapshot queue = %d/%d, want 0/8", snap.QueueLen, snap.QueueCap)
	}
}

// A full queue increments the drop counter (and Enqueue returns false) instead
// of blocking — the async scanner never back-pressures the request path.
func TestEnqueueDropCounter(t *testing.T) {
	m := NewManager(Config{QueueSize: 1})
	m.started = true // simulate running with no worker draining the channel

	if !m.Enqueue(Job{Path: "/tmp/a"}) {
		t.Fatal("first enqueue should succeed into an empty queue")
	}
	if m.Enqueue(Job{Path: "/tmp/b"}) {
		t.Fatal("second enqueue should drop (queue full)")
	}
	if got := m.Health().QueueDrops; got != 1 {
		t.Fatalf("QueueDrops = %d, want 1", got)
	}
}
