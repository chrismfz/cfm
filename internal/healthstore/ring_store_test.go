package healthstore

import (
	"testing"
	"time"
)

func sample(ts time.Time, marker string) Sample {
	return Sample{CollectedAt: ts, NodeID: "node-a", Hostname: marker}
}

func TestRingStoreAppendLatestAndCapacity(t *testing.T) {
	s := NewRingStore(3)
	base := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	s.Append("node-a", sample(base.Add(0*time.Minute), "a"))
	s.Append("node-a", sample(base.Add(1*time.Minute), "b"))
	s.Append("node-a", sample(base.Add(2*time.Minute), "c"))
	s.Append("node-a", sample(base.Add(3*time.Minute), "d"))

	got, ok := s.Latest("node-a")
	if !ok {
		t.Fatalf("latest missing")
	}
	if got.Hostname != "d" {
		t.Fatalf("latest=%q want d", got.Hostname)
	}

	rng := s.Range("node-a", time.Time{}, time.Time{})
	if len(rng) != 3 {
		t.Fatalf("range len=%d want 3", len(rng))
	}
	if rng[0].Hostname != "b" || rng[2].Hostname != "d" {
		t.Fatalf("unexpected order after overwrite: %#v", rng)
	}
}

func TestRingStoreRangeAndWindows(t *testing.T) {
	s := NewRingStore(10)
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	s.Append("node-a", sample(now.Add(-25*time.Hour), "old"))
	s.Append("node-a", sample(now.Add(-5*time.Hour), "mid"))
	s.Append("node-a", sample(now.Add(-30*time.Minute), "new"))

	last1 := s.Last1h("node-a", now)
	if len(last1) != 1 || last1[0].Hostname != "new" {
		t.Fatalf("last1h=%v", last1)
	}
	last6 := s.Last6h("node-a", now)
	if len(last6) != 2 {
		t.Fatalf("last6h len=%d want 2", len(last6))
	}
	last24 := s.Last24h("node-a", now)
	if len(last24) != 2 {
		t.Fatalf("last24h len=%d want 2", len(last24))
	}
}

func TestRingStoreMeta(t *testing.T) {
	s := NewRingStore(4)
	base := time.Date(2026, 4, 28, 9, 0, 0, 0, time.UTC)
	s.Append("node-a", sample(base, "a"))
	s.Append("node-a", sample(base.Add(10*time.Minute), "b"))

	m, ok := s.Meta("node-a")
	if !ok {
		t.Fatalf("meta missing")
	}
	if m.Count != 2 || m.Capacity != 4 || m.Appends != 2 {
		t.Fatalf("unexpected meta: %+v", m)
	}
	if !m.OldestAt.Equal(base) || !m.LatestAt.Equal(base.Add(10*time.Minute)) {
		t.Fatalf("unexpected bounds: %+v", m)
	}
}
