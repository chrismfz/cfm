package procbaseline

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"cfm/internal/procstat"
)

func reliableLifecycleHealth() (procstat.HealthSummary, map[string]int, error) {
	return procstat.HealthSummary{
		TotalProcesses: 2,
		TotalThreads:   2,
		States:         map[string]int{"S": 2},
		UniqueFamilies: 1,
		Scan: procstat.ScanSummary{
			PIDsEnumerated: 2,
			PIDsReadable:   2,
			PIDsSkipped:    0,
		},
	}, map[string]int{"worker": 2}, nil
}

func TestLifecycleCloseStopsCollectorBeforeClosingStore(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "processbaseline.db"))
	if err != nil {
		t.Fatal(err)
	}

	collector := NewCollector(store)
	collector.interval = 5 * time.Millisecond
	var calls atomic.Int32
	collector.health = func() (procstat.HealthSummary, map[string]int, error) {
		calls.Add(1)
		return reliableLifecycleHealth()
	}

	lc := startLifecycle(context.Background(), store, collector)
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("collector did not take its immediate sample")
	}

	if err := lc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	afterClose := calls.Load()
	time.Sleep(20 * time.Millisecond)
	if got := calls.Load(); got != afterClose {
		t.Fatalf("collector continued after Close: calls %d -> %d", afterClose, got)
	}
	if err := lc.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if err := store.Record(time.Now(), Sample{TotalProcesses: 1, Families: map[string]int{"worker": 1}}); err == nil {
		t.Fatal("store remained writable after lifecycle Close")
	}
}

func TestStartRejectsNilParentContext(t *testing.T) {
	lc, err := Start(nil, filepath.Join(t.TempDir(), "processbaseline.db"))
	if err == nil {
		if lc != nil {
			_ = lc.Close()
		}
		t.Fatal("Start(nil, ...) unexpectedly succeeded")
	}
	if lc != nil {
		t.Fatalf("lifecycle = %#v, want nil on startup error", lc)
	}
}
