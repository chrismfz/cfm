package lvecpu

import (
	"errors"
	"testing"
	"time"

	"cfm/internal/lvestat"
)

func mkSnap(cpuByUID map[int64]int64) lvestat.Snapshot {
	s := lvestat.Snapshot{Version: 10}
	for uid, cpu := range cpuByUID {
		s.Entries = append(s.Entries, lvestat.LVE{Reseller: 0, UID: uid, CPUUsage: cpu, LimitCPU: 60000, NumCPU: 6})
	}
	return s
}

func TestCollector_NeedsTwoSamples(t *testing.T) {
	c := newCollector(time.Minute)
	seq := []lvestat.Snapshot{
		mkSnap(map[int64]int64{1004: 0}),
		mkSnap(map[int64]int64{1004: 6_000_000_000}), // +6e9 ns over 10s = 0.6 cores
	}
	now := time.Unix(1_000_000, 0)
	i := 0
	c.readFn = func() (lvestat.Snapshot, error) { s := seq[i]; return s, nil }
	c.nowFn = func() time.Time { return now }

	// First poll: only seeds prev, no rate yet.
	c.pollOnce()
	if _, _, ready := c.snapshot(); ready {
		t.Fatal("ready after one sample, want false")
	}

	// Second poll 10s later with a higher counter.
	i = 1
	now = now.Add(10 * time.Second)
	c.pollOnce()
	got, at, ready := c.snapshot()
	if !ready {
		t.Fatal("not ready after two samples")
	}
	if len(got) != 1 || got[0].UID != 1004 {
		t.Fatalf("samples = %+v, want one uid 1004", got)
	}
	if got[0].Cores < 0.5999 || got[0].Cores > 0.6001 {
		t.Errorf("cores = %v, want ~0.6", got[0].Cores)
	}
	if at != now {
		t.Errorf("sampled at = %v, want %v", at, now)
	}
}

func TestCollector_ReadErrorKeepsLastGood(t *testing.T) {
	c := newCollector(time.Minute)
	now := time.Unix(2_000_000, 0)
	c.nowFn = func() time.Time { return now }

	step := 0
	c.readFn = func() (lvestat.Snapshot, error) {
		switch step {
		case 0:
			return mkSnap(map[int64]int64{7: 0}), nil
		case 1:
			return mkSnap(map[int64]int64{7: 3_000_000_000}), nil // 0.3 cores over 10s
		default:
			return lvestat.Snapshot{}, errors.New("read failed")
		}
	}

	c.pollOnce() // seed
	step = 1
	now = now.Add(10 * time.Second)
	c.pollOnce() // computes 0.3 cores
	good, _, ready := c.snapshot()
	if !ready || len(good) != 1 {
		t.Fatalf("expected one ready sample, got ready=%v n=%d", ready, len(good))
	}
	cores := good[0].Cores

	// Now a failing read must NOT clobber the last good sample.
	step = 2
	now = now.Add(10 * time.Second)
	c.pollOnce()
	after, _, ready := c.snapshot()
	if !ready || len(after) != 1 || after[0].Cores != cores {
		t.Fatalf("read error changed the sample: before %v after %+v", cores, after)
	}
}

func TestCollector_SnapshotIsACopy(t *testing.T) {
	c := newCollector(time.Minute)
	now := time.Unix(3_000_000, 0)
	c.nowFn = func() time.Time { return now }
	vals := []int64{0, 9_000_000_000}
	k := 0
	c.readFn = func() (lvestat.Snapshot, error) { return mkSnap(map[int64]int64{5: vals[k]}), nil }
	c.pollOnce()
	k = 1
	now = now.Add(10 * time.Second)
	c.pollOnce()
	got, _, _ := c.snapshot()
	got[0].Cores = -123 // mutate the returned slice
	again, _, _ := c.snapshot()
	if again[0].Cores == -123 {
		t.Fatal("snapshot() returned a reference to internal state, want a copy")
	}
}

// On a non-CloudLinux host Enable is a no-op and the package stays inert.
func TestPackage_NoopWhenUnavailable(t *testing.T) {
	// CI has no /proc/lve/list, so Enable must not start anything.
	Enable()
	defer Shutdown()
	if Available() {
		t.Skip("host has /proc/lve/list; skipping the not-available assertion")
	}
	if _, _, ready := Latest(); ready {
		t.Fatal("Latest ready on a non-CloudLinux host")
	}
	Shutdown() // must be safe even though never started
}
