package procstat

import (
	"runtime"
	"testing"
)

func TestSummarizeHealthWithFamilyCountsKeepsFamiliesOutsideTopN(t *testing.T) {
	rows := []Process{
		{PID: 1, PPID: 0, Comm: "busy", State: "S", Threads: 1, RSSKB: 10},
		{PID: 2, PPID: 0, Comm: "busy", State: "S", Threads: 1, RSSKB: 10},
		{PID: 3, PPID: 0, Comm: "busy", State: "S", Threads: 1, RSSKB: 10},
		{PID: 4, PPID: 0, Comm: "small", State: "S", Threads: 1, RSSKB: 1},
		{PID: 5, PPID: 0, Comm: "tiny", State: "Z", Threads: 1, RSSKB: 0},
	}

	got, families := summarizeHealthWithFamilyCounts(rows, 1)
	if len(got.TopFamiliesByCount) != 1 || got.TopFamiliesByCount[0].Comm != "busy" {
		t.Fatalf("bounded ranking = %+v, want busy only", got.TopFamiliesByCount)
	}
	if len(families) != 3 || families["busy"] != 3 || families["small"] != 1 || families["tiny"] != 1 {
		t.Fatalf("full family counts = %#v, want busy=3 small=1 tiny=1", families)
	}
	total := 0
	for _, n := range families {
		total += n
	}
	if total != got.TotalProcesses {
		t.Fatalf("family total = %d, total_processes = %d", total, got.TotalProcesses)
	}
}

func TestHealthWithFamilyCountsLiveMatchesSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procstat reads /proc; linux only")
	}

	got, families, err := HealthWithFamilyCounts()
	if err != nil {
		t.Fatalf("HealthWithFamilyCounts: %v", err)
	}
	if len(families) != got.UniqueFamilies {
		t.Fatalf("family map len = %d, unique_families = %d", len(families), got.UniqueFamilies)
	}
	total := 0
	for comm, n := range families {
		if comm == "" || n <= 0 {
			t.Fatalf("invalid family count %q=%d", comm, n)
		}
		total += n
	}
	if total != got.TotalProcesses {
		t.Fatalf("family total = %d, total_processes = %d", total, got.TotalProcesses)
	}
}
