package procstat

import (
	"os"
	"runtime"
	"strings"
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
	if f := got.TopFamiliesByCount[0]; f.Comm != "exim" || f.Count != 2 || f.RSSKB != 120 || f.Threads != 3 || f.States["S"] != 1 || f.States["D"] != 1 {
		t.Fatalf("top family by count = %+v, want exim count=2 rss=120 threads=3 states=S1/D1", f)
	}
	if f := got.TopFamiliesByCount[1]; f.Comm != "spamd child" || f.Count != 2 || f.RSSKB != 50 || f.Threads != 2 || f.States["S"] != 1 || f.States["Z"] != 1 {
		t.Fatalf("second family by count = %+v, want spamd child states=S1/Z1", f)
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

	if d := got.TopFamiliesByState["D"]; len(d) != 1 || d[0].Comm != "exim" || d[0].Count != 1 {
		t.Fatalf("D-state families = %+v, want exim/count=1", d)
	}
	if z := got.TopFamiliesByState["Z"]; len(z) != 1 || z[0].Comm != "spamd child" || z[0].Count != 1 {
		t.Fatalf("Z-state families = %+v, want spamd child/count=1", z)
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
	if s := got.TopFamiliesByState["S"]; len(s) != 1 || s[0].Comm != "many" || s[0].Count != 2 {
		t.Fatalf("TopFamiliesByState[S] = %+v, want only many/count=2", s)
	}
	if len(got.TopFanout) != 1 || got.TopFanout[0].PID != 1 || got.TopFanout[0].Children != 2 {
		t.Fatalf("TopFanout = %+v, want pid 1 with 2 direct children", got.TopFanout)
	}
}

func TestSummarizeHealth_StateAttributionSurvivesGlobalTopN(t *testing.T) {
	rows := []Process{
		{PID: 1, PPID: 0, Comm: "busy", State: "S", Threads: 1, RSSKB: 100},
		{PID: 2, PPID: 0, Comm: "busy", State: "S", Threads: 1, RSSKB: 100},
		{PID: 3, PPID: 0, Comm: "busy", State: "S", Threads: 1, RSSKB: 100},
		{PID: 4, PPID: 0, Comm: "blocked", State: "D", Threads: 1, RSSKB: 1},
		{PID: 5, PPID: 0, Comm: "orphaned", State: "Z", Threads: 1, RSSKB: 0},
	}

	got := summarizeHealth(rows, 1)
	if len(got.TopFamiliesByCount) != 1 || got.TopFamiliesByCount[0].Comm != "busy" {
		t.Fatalf("TopFamiliesByCount = %+v, want busy only", got.TopFamiliesByCount)
	}
	if d := got.TopFamiliesByState["D"]; len(d) != 1 || d[0].Comm != "blocked" || d[0].Count != 1 {
		t.Fatalf("D-state attribution lost outside global top-N: %+v", d)
	}
	if z := got.TopFamiliesByState["Z"]; len(z) != 1 || z[0].Comm != "orphaned" || z[0].Count != 1 {
		t.Fatalf("Z-state attribution lost outside global top-N: %+v", z)
	}
}

func healthStatRaw(ppid, threads, rss string) []byte {
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[1] = ppid
	fields[17] = threads
	fields[21] = rss
	return []byte("123 (worker ) name) " + strings.Join(fields, " "))
}

func TestParseHealthStatRejectsMalformedNumericFields(t *testing.T) {
	p, ok := parseHealthStat(123, healthStatRaw("7", "3", "100"))
	if !ok {
		t.Fatal("valid stat row rejected")
	}
	if p.PID != 123 || p.PPID != 7 || p.Comm != "worker ) name" || p.State != "S" || p.Threads != 3 {
		t.Fatalf("parsed row = %+v", p)
	}
	if p.RSSKB != 100*(int64(os.Getpagesize())/1024) {
		t.Fatalf("rss_kb = %d, want %d pages converted to KB", p.RSSKB, 100)
	}

	for name, raw := range map[string][]byte{
		"ppid":    healthStatRaw("bad", "3", "100"),
		"threads": healthStatRaw("7", "bad", "100"),
		"rss":     healthStatRaw("7", "3", "bad"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := parseHealthStat(123, raw); ok {
				t.Fatal("malformed numeric field was accepted")
			}
		})
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
	if got.Scan.PIDsEnumerated <= 0 || got.Scan.PIDsReadable != got.TotalProcesses {
		t.Fatalf("inconsistent scan summary: scan=%+v total_processes=%d", got.Scan, got.TotalProcesses)
	}
	if got.Scan.PIDsSkipped != got.Scan.PIDsEnumerated-got.Scan.PIDsReadable || got.Scan.PIDsSkipped < 0 {
		t.Fatalf("invalid scan completeness accounting: %+v", got.Scan)
	}
	if len(got.TopFamiliesByCount) > healthTopN || len(got.TopFamiliesByRSS) > healthTopN || len(got.TopFanout) > healthTopN {
		t.Fatalf("health ranked lists exceeded cap %d: count=%d rss=%d fanout=%d",
			healthTopN, len(got.TopFamiliesByCount), len(got.TopFamiliesByRSS), len(got.TopFanout))
	}
	for state, ranked := range got.TopFamiliesByState {
		if state == "" || len(ranked) > healthTopN {
			t.Fatalf("invalid state ranking %q: %+v", state, ranked)
		}
		for _, f := range ranked {
			if f.Comm == "" || f.Count <= 0 {
				t.Fatalf("invalid state-family row for %q: %+v", state, f)
			}
		}
	}
	for _, families := range [][]FamilySummary{got.TopFamiliesByCount, got.TopFamiliesByRSS} {
		for _, f := range families {
			stateCount := 0
			for _, n := range f.States {
				stateCount += n
			}
			if stateCount != f.Count {
				t.Fatalf("family state total = %d, family count = %d: %+v", stateCount, f.Count, f)
			}
		}
	}
}
