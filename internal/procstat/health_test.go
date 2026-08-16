package procstat

import (
	"os"
	"runtime"
	"testing"
)

func TestSummarizeHealth_AggregatesAndRanks(t *testing.T) {
	rows := []Process{
		{PID: 1, PPID: 0, Comm: "systemd", State: "S", Threads: 1, RSSKB: 100},
		{PID: 10, PPID: 1, Comm: "exim", State: "S", Threads: 1, RSSKB: 50},
		{PID: 11, PPID: 1, Comm: "exim", State: "D", Threads: 2, RSSKB: 70},
		{PID: 20, PPID: 1, Comm: "spamd", State: "S", Threads: 3, RSSKB: 200},
		{PID: 21, PPID: 20, Comm: "spamd child", State: "S", Threads: 1, RSSKB: 30},
		{PID: 22, PPID: 20, Comm: "spamd child", State: "Z", Threads: 1, RSSKB: 20},
	}

	got := summarizeHealth(rows, 20)
	if got.TotalProcesses != 6 {
		t.Fatalf("TotalProcesses = %d, want 6", got.TotalProcesses)
	}
	if got.TotalThreads != 9 {
		t.Fatalf("TotalThreads = %d, want 9", got.TotalThreads)
	}
	if got.UniqueFamilies != 4 {
		t.Fatalf("UniqueFamilies = %d, want 4", got.UniqueFamilies)
	}
	if got.States["S"] != 4 || got.States["D"] != 1 || got.States["Z"] != 1 {
		t.Fatalf("States = %#v, want S=4 D=1 Z=1", got.States)
	}

	if len(got.TopFamiliesByCount) != 4 {
		t.Fatalf("TopFamiliesByCount len = %d, want 4", len(got.TopFamiliesByCount))
	}
	if f := got.TopFamiliesByCount[0]; f.Comm != "exim" || f.Count != 2 || f.RSSKB != 120 || f.Threads != 3 {
		t.Fatalf("top family by count = %+v, want exim count=2 rss=120 threads=3", f)
	}
	if f := got.TopFamiliesByCount[1]; f.Comm != "spamd child" || f.Count != 2 || f.RSSKB != 50 || f.Threads != 2 {
		t.Fatalf("second family by count = %+v, want spamd child", f)
	}

	if len(got.TopFamiliesByRSS) != 4 {
		t.Fatalf("TopFamiliesByRSS len = %d, want 4", len(got.TopFamiliesByRSS))
	}
	if f := got.TopFamiliesByRSS[0]; f.Comm != "spamd" || f.RSSKB != 200 {
		t.Fatalf("top family by RSS = %+v, want spamd rss=200", f)
	}
	if f := got.TopFamiliesByRSS[1]; f.Comm != "exim" || f.RSSKB != 120 {
		t.Fatalf("second family by RSS = %+v, want exim rss=120", f)
	}

	if len(got.TopFanout) != 2 {
		t.Fatalf("TopFanout = %+v, want two parents with children", got.TopFanout)
	}
	if got.TopFanout[0].PID != 1 || got.TopFanout[0].Children != 3 {
		t.Fatalf("top fanout = %+v, want pid 1 with 3 direct children", got.TopFanout[0])
	}
	if got.TopFanout[1].PID != 20 || got.TopFanout[1].Children != 2 {
		t.Fatalf("second fanout = %+v, want pid 20 with 2 direct children", got.TopFanout[1])
	}
}

func TestSummarizeHealth_LimitsRankedListsAfterFullAggregation(t *testing.T) {
	rows := []Process{
		{PID: 1, PPID: 0, Comm: "parent", State: "S", Threads: 1, RSSKB: 1},
		{PID: 2, PPID: 1, Comm: "many", State: "S", Threads: 2, RSSKB: 10},
		{PID: 3, PPID: 1, Comm: "many", State: "S", Threads: 3, RSSKB: 20},
		{PID: 4, PPID: 2, Comm: "large", State: "S", Threads: 4, RSSKB: 1000},
	}

	got := summarizeHealth(rows, 1)
	if got.TotalProcesses != 4 || got.TotalThreads != 10 || got.UniqueFamilies != 3 {
		t.Fatalf("full aggregates were truncated: %+v", got)
	}
	if len(got.TopFamiliesByCount) != 1 || got.TopFamiliesByCount[0].Comm != "many" || got.TopFamiliesByCount[0].Count != 2 {
		t.Fatalf("TopFamiliesByCount = %+v, want only many/count=2", got.TopFamiliesByCount)
	}
	if len(got.TopFamiliesByRSS) != 1 || got.TopFamiliesByRSS[0].Comm != "large" || got.TopFamiliesByRSS[0].RSSKB != 1000 {
		t.Fatalf("TopFamiliesByRSS = %+v, want only large/rss=1000", got.TopFamiliesByRSS)
	}
	if len(got.TopFanout) != 1 || got.TopFanout[0].PID != 1 || got.TopFanout[0].Children != 2 {
		t.Fatalf("TopFanout = %+v, want pid 1 with 2 direct children", got.TopFanout)
	}
}

func TestReadHealthProcess_IsLightweight(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procstat reads /proc; linux only")
	}

	p, ok := readHealthProcess(os.Getpid())
	if !ok {
		t.Fatal("readHealthProcess(self) failed")
	}
	if p.PID != os.Getpid() || p.PPID != os.Getppid() {
		t.Fatalf("pid/ppid = %d/%d, want %d/%d", p.PID, p.PPID, os.Getpid(), os.Getppid())
	}
	if p.Comm == "" || p.State == "" || p.Threads <= 0 || p.RSSKB <= 0 {
		t.Fatalf("incomplete lightweight row: %+v", p)
	}
	if p.User != "" || p.CPUPct != 0 || p.MemPct != 0 || p.Argv != nil || p.Children != nil {
		t.Fatalf("health row unexpectedly did expensive/detail work: %+v", p)
	}
}

func TestHealth_LiveSnapshotIsBounded(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procstat reads /proc; linux only")
	}

	got, err := Health()
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if got.TotalProcesses <= 0 || got.TotalThreads <= 0 || got.UniqueFamilies <= 0 || len(got.States) == 0 {
		t.Fatalf("empty live health summary: %+v", got)
	}
	if len(got.TopFamiliesByCount) > healthTopN || len(got.TopFamiliesByRSS) > healthTopN || len(got.TopFanout) > healthTopN {
		t.Fatalf("health ranked lists exceeded cap %d: count=%d rss=%d fanout=%d",
			healthTopN, len(got.TopFamiliesByCount), len(got.TopFamiliesByRSS), len(got.TopFanout))
	}
}
