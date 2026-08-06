package procstat

import (
	"os"
	"runtime"
	"testing"
)

func TestTop_ReturnsSelfWithSaneFields(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procstat reads /proc; linux only")
	}

	// Burn a little CPU so this process is a plausible row and %cpu can be >0.
	go func() {
		deadline := 0
		for i := 0; i < 1<<28; i++ {
			deadline += i
		}
		_ = deadline
	}()

	procs, err := Top(200)
	if err != nil {
		t.Fatalf("Top: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("Top returned no processes")
	}

	self := os.Getpid()
	var mine *Process
	for i := range procs {
		p := procs[i]
		if p.PID <= 0 {
			t.Fatalf("non-positive pid: %+v", p)
		}
		if p.CPUPct < 0 || p.MemPct < 0 || p.RSSKB < 0 {
			t.Fatalf("negative metric: %+v", p)
		}
		if p.PID == self {
			mine = &procs[i]
		}
	}
	if mine == nil {
		t.Fatal("own pid not present in Top(200)")
	}
	if mine.Comm == "" {
		t.Errorf("own process has empty comm")
	}
	if mine.State == "" {
		t.Errorf("own process has empty state")
	}
	if mine.RSSKB <= 0 {
		t.Errorf("own process RSSKB = %d, want > 0", mine.RSSKB)
	}
}

func TestTop_ClampAndOrder(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procstat reads /proc; linux only")
	}
	procs, err := Top(3)
	if err != nil {
		t.Fatalf("Top: %v", err)
	}
	if len(procs) > 3 {
		t.Fatalf("Top(3) returned %d rows, want <= 3", len(procs))
	}
	// Sorted by CPU desc (RSS tiebreak) — verify non-increasing CPU.
	for i := 1; i < len(procs); i++ {
		if procs[i-1].CPUPct < procs[i].CPUPct {
			t.Fatalf("not sorted by cpu desc at %d: %v < %v", i, procs[i-1].CPUPct, procs[i].CPUPct)
		}
	}
}
