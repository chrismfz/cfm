package webdetector

import (
	"testing"
	"time"
)

func TestShadowMarks_MarkGetExpiry(t *testing.T) {
	m := newShadowMarks()
	base := time.Unix(1_700_000_000, 0)
	m.nowFn = func() time.Time { return base }

	m.mark("Example.COM", 7, time.Minute) // host is normalised (trim+lower)
	if got := m.get("example.com"); got != 7 {
		t.Fatalf("fresh mark: got %d, want 7", got)
	}
	// zero/negative count or ttl is a no-op.
	m.mark("z.com", 0, time.Minute)
	m.mark("z.com", 3, 0)
	if got := m.get("z.com"); got != 0 {
		t.Fatalf("no-op mark left %d, want 0", got)
	}
	// after expiry the count is gone.
	m.nowFn = func() time.Time { return base.Add(time.Minute + time.Second) }
	if got := m.get("example.com"); got != 0 {
		t.Fatalf("expired mark: got %d, want 0", got)
	}
}

func TestShadowMarks_ResetAndPruneOnWrite(t *testing.T) {
	m := newShadowMarks()
	base := time.Unix(1_700_000_000, 0)
	m.nowFn = func() time.Time { return base }
	m.mark("a.com", 2, time.Minute)
	m.mark("b.com", 4, time.Minute)

	// A later write prunes the now-expired entries.
	m.nowFn = func() time.Time { return base.Add(2 * time.Minute) }
	m.mark("c.com", 5, time.Minute)
	if n := len(m.hosts); n != 1 {
		t.Fatalf("prune-on-write left %d entries, want 1 (only c.com)", n)
	}
	if got := m.get("c.com"); got != 5 {
		t.Fatalf("c.com: got %d, want 5", got)
	}

	m.reset()
	if n := len(m.hosts); n != 0 {
		t.Fatalf("reset left %d entries", n)
	}
}

func TestShadowMarks_CapBounded(t *testing.T) {
	m := newShadowMarks()
	base := time.Unix(1_700_000_000, 0)
	m.nowFn = func() time.Time { return base }
	for i := 0; i < maxShadowMarks; i++ {
		m.mark("h"+ipKeyForTest(i), 1, time.Hour) // all unexpired
	}
	m.mark("overflow.com", 1, time.Hour) // must be rejected at cap
	if _, ok := m.hosts["overflow.com"]; ok {
		t.Fatal("mark past cap was admitted")
	}
	if n := len(m.hosts); n > maxShadowMarks {
		t.Fatalf("cache grew past cap: %d", n)
	}
}

// markBulk is the production path (emit → MarkAbuseShadowBulk): it prunes once,
// stamps all counts under one TTL, and honours the cap for new hosts.
func TestShadowMarks_MarkBulk(t *testing.T) {
	m := newShadowMarks()
	base := time.Unix(1_700_000_000, 0)
	m.nowFn = func() time.Time { return base }
	m.mark("stale.com", 9, time.Minute) // will be pruned by the later bulk

	m.nowFn = func() time.Time { return base.Add(2 * time.Minute) }
	m.markBulk(map[string]int{"A.com": 3, "b.com": 5, "skip.com": 0, "": 1}, time.Minute)

	if _, ok := m.hosts["stale.com"]; ok {
		t.Fatal("markBulk did not prune the expired entry")
	}
	if got := m.get("a.com"); got != 3 { // normalised key
		t.Fatalf("a.com: got %d, want 3", got)
	}
	if got := m.get("b.com"); got != 5 {
		t.Fatalf("b.com: got %d, want 5", got)
	}
	if _, ok := m.hosts["skip.com"]; ok {
		t.Fatal("count<=0 host should be skipped")
	}
	if n := len(m.hosts); n != 2 {
		t.Fatalf("store has %d entries, want 2", n)
	}
}

// The API decoration stamps the live count onto rows (global store path).
func TestDecorateShadow_StampsRows(t *testing.T) {
	ResetAbuseShadowMarks()
	defer ResetAbuseShadowMarks()
	MarkAbuseShadow("shop.example", 12, time.Minute)

	short := decorateShadowShort([]ShortRow{{Host: "shop.example"}, {Host: "quiet.example"}})
	if short[0].ShadowOutliers != 12 || short[1].ShadowOutliers != 0 {
		t.Fatalf("short decorate: got %d/%d, want 12/0", short[0].ShadowOutliers, short[1].ShadowOutliers)
	}
	susp := decorateShadowSuspicious([]SuspiciousRow{{Host: "shop.example"}})
	if susp[0].ShadowOutliers != 12 {
		t.Fatalf("suspicious decorate: got %d, want 12", susp[0].ShadowOutliers)
	}
}
