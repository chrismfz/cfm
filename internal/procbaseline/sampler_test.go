package procbaseline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cfm/internal/procstat"
)

func reliableHealth(total int, states map[string]int) procstat.HealthSummary {
	return procstat.HealthSummary{
		TotalProcesses: total,
		States:         states,
		Scan: procstat.ScanSummary{
			PIDsEnumerated: total,
			PIDsReadable:   total,
			PIDsSkipped:    0,
		},
	}
}

func TestSampleOnceRecordsReliableSnapshot(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Unix(1_700_100_000, 0).Truncate(time.Minute)
	c := NewCollector(st)
	c.health = func() (procstat.HealthSummary, map[string]int, error) {
		return reliableHealth(5, map[string]int{"S": 5}), map[string]int{
			"exim":    3,
			"php-fpm": 2,
		}, nil
	}

	recorded, reason, err := c.SampleOnce(t0)
	if err != nil || !recorded || reason != "" {
		t.Fatalf("SampleOnce = recorded=%v reason=%q err=%v", recorded, reason, err)
	}
	got, err := st.FamilySeries("exim", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Count != 3 || got[0].TotalProcesses != 5 {
		t.Fatalf("persisted exim series = %+v", got)
	}
}

func TestSampleOnceSkipsUnreliableSnapshotAsTelemetryGap(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Unix(1_700_110_000, 0).Truncate(time.Minute)
	c := NewCollector(st)
	c.health = func() (procstat.HealthSummary, map[string]int, error) {
		return procstat.HealthSummary{
			TotalProcesses: 7,
			States:         map[string]int{"S": 7},
			Scan: procstat.ScanSummary{
				PIDsEnumerated: 10,
				PIDsReadable:   7,
				PIDsSkipped:    3,
			},
		}, map[string]int{"exim": 7}, nil
	}

	recorded, reason, err := c.SampleOnce(t0)
	if err != nil || recorded {
		t.Fatalf("SampleOnce = recorded=%v reason=%q err=%v", recorded, reason, err)
	}
	if !strings.Contains(reason, "materially partial") {
		t.Fatalf("skip reason = %q, want materially partial", reason)
	}
	got, err := st.FamilySeries("exim", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unreliable sample became baseline data: %+v", got)
	}
}

func TestSampleOnceRecordsReliableSnapshotEvenWhenItHasFinding(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Unix(1_700_120_000, 0).Truncate(time.Minute)
	c := NewCollector(st)
	c.health = func() (procstat.HealthSummary, map[string]int, error) {
		h := reliableHealth(100, map[string]int{"S": 90, "D": 10})
		return h, map[string]int{"worker": 90, "blocked": 10}, nil
	}

	recorded, reason, err := c.SampleOnce(t0)
	if err != nil || !recorded || reason != "" {
		t.Fatalf("finding-bearing reliable sample was not recorded: recorded=%v reason=%q err=%v", recorded, reason, err)
	}
	got, err := st.FamilySeries("blocked", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Count != 10 {
		t.Fatalf("finding-bearing sample missing from history: %+v", got)
	}
}

func TestSampleOncePropagatesSourceAndStoreErrors(t *testing.T) {
	t.Run("source", func(t *testing.T) {
		st := openTestStore(t)
		c := NewCollector(st)
		want := errors.New("read failed")
		c.health = func() (procstat.HealthSummary, map[string]int, error) {
			return procstat.HealthSummary{}, nil, want
		}
		if recorded, reason, err := c.SampleOnce(time.Now()); recorded || reason != "" || !errors.Is(err, want) {
			t.Fatalf("SampleOnce = recorded=%v reason=%q err=%v", recorded, reason, err)
		}
	})

	t.Run("inconsistent family map", func(t *testing.T) {
		st := openTestStore(t)
		c := NewCollector(st)
		c.health = func() (procstat.HealthSummary, map[string]int, error) {
			return reliableHealth(5, map[string]int{"S": 5}), map[string]int{"exim": 4}, nil
		}
		if recorded, reason, err := c.SampleOnce(time.Now()); recorded || reason != "" || err == nil {
			t.Fatalf("SampleOnce = recorded=%v reason=%q err=%v, want store validation error", recorded, reason, err)
		}
	})
}

func TestCollectorRunSamplesImmediatelyAndStopsOnCancel(t *testing.T) {
	st := openTestStore(t)
	c := NewCollector(st)
	c.interval = time.Hour
	called := make(chan struct{}, 1)
	c.health = func() (procstat.HealthSummary, map[string]int, error) {
		select {
		case called <- struct{}{}:
		default:
		}
		return reliableHealth(1, map[string]int{"S": 1}), map[string]int{"worker": 1}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("collector did not sample immediately")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("collector did not stop after context cancellation")
	}
}
