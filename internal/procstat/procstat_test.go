package procstat

import (
	"os"
	"runtime"
	"strings"
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
	if mine.PPID != os.Getppid() {
		t.Errorf("own process PPID = %d, want %d", mine.PPID, os.Getppid())
	}
	if mine.Argv != nil || mine.Children != nil || mine.ArgvRedactions != 0 || mine.ArgvTruncated {
		t.Errorf("Top default unexpectedly returned detail fields: %+v", *mine)
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

func TestSelectProcesses_DefaultPreservesHistoricalRanking(t *testing.T) {
	in := []Process{
		{PID: 30, Comm: "rss", CPUPct: 1, RSSKB: 300},
		{PID: 20, Comm: "cpu", CPUPct: 50, RSSKB: 10},
		{PID: 10, Comm: "rss2", CPUPct: 1, RSSKB: 500},
	}
	got := selectProcesses(in, Options{Limit: 2})
	if len(got) != 2 || got[0].PID != 20 || got[1].PID != 10 {
		t.Fatalf("default ranking changed: got %+v", got)
	}
}

func TestSelectProcesses_FilterBeforeLimit(t *testing.T) {
	in := []Process{
		{PID: 1, Comm: "very-hot", CPUPct: 99, RSSKB: 9999},
		{PID: 2, Comm: "spamd-dormant", CPUPct: 0, RSSKB: 4},
		{PID: 3, Comm: "spamd child", CPUPct: 0, RSSKB: 3},
	}
	got := selectProcesses(in, Options{Limit: 1, Match: "SPAMD"})
	if len(got) != 1 || got[0].PID != 2 {
		t.Fatalf("match must be applied before global top limit: got %+v", got)
	}

	got = selectProcesses(in, Options{Limit: 1, PID: 3})
	if len(got) != 1 || got[0].PID != 3 {
		t.Fatalf("pid must be applied before global top limit: got %+v", got)
	}
}

func TestBuildChildIndex(t *testing.T) {
	idx := buildChildIndex([]Process{
		{PID: 10, PPID: 1},
		{PID: 12, PPID: 10},
		{PID: 11, PPID: 10},
		{PID: 13, PPID: 12},
	})
	if got := idx[10]; len(got) != 2 || got[0] != 11 || got[1] != 12 {
		t.Fatalf("children[10] = %v, want [11 12]", got)
	}
	if got := idx[12]; len(got) != 1 || got[0] != 13 {
		t.Fatalf("children[12] = %v, want [13]", got)
	}
}

func TestSanitizeArgvSecrets(t *testing.T) {
	args := []string{
		"mysql",
		"--password=one",
		"--token", "two",
		"-pthree",
		"DATABASE_URL=postgres://u:four@db/x",
		"https://user:five@example.com/path?api_key=six&ok=1",
		"Authorization: Bearer seven",
		"redis://:eight@cache/0",
		"--normal=value",
	}
	got, redactions, truncated := sanitizeArgv(args)
	if truncated {
		t.Fatal("unexpected truncation")
	}
	joined := strings.Join(got, " ")
	for _, secret := range []string{"one", "two", "three", "four", "five", "six", "seven", "eight"} {
		if strings.Contains(joined, secret) {
			t.Errorf("secret %q leaked in sanitized argv: %q", secret, joined)
		}
	}
	if redactions < 8 {
		t.Errorf("redactions = %d, want at least 8; argv=%q", redactions, joined)
	}
	if !strings.Contains(joined, "--normal=value") {
		t.Errorf("ordinary arg changed: %q", joined)
	}
}

func TestSanitizeArgvSeparatePasswordAndBounds(t *testing.T) {
	long := strings.Repeat("x", maxArgBytes+100)
	got, redactions, truncated := sanitizeArgv([]string{"tool", "--password", "secret", long})
	if redactions != 1 {
		t.Fatalf("redactions = %d, want 1", redactions)
	}
	if !truncated {
		t.Fatal("long argv element did not set truncated")
	}
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "secret") {
		t.Fatalf("separate password leaked: %q", joined)
	}
	if len(got[len(got)-1]) <= maxArgBytes {
		t.Fatalf("long arg was not marked with truncation suffix: len=%d", len(got[len(got)-1]))
	}
}

func TestSplitCmdline_TruncatedFinalArgFailsClosed(t *testing.T) {
	raw := []byte("tool\x00--normal=value\x00postgres://user:secret-without-at")
	got := splitCmdline(raw, true)
	if len(got) != 3 {
		t.Fatalf("splitCmdline = %#v, want 3 args", got)
	}
	if got[0] != "tool" || got[1] != "--normal=value" || got[2] != "[TRUNCATED]" {
		t.Fatalf("splitCmdline = %#v, want complete args + [TRUNCATED]", got)
	}
	if strings.Contains(strings.Join(got, " "), "secret") {
		t.Fatalf("partial final arg leaked: %#v", got)
	}
}

func TestSplitCmdline_CompleteFinalArgAtCapIsKept(t *testing.T) {
	raw := []byte("tool\x00--normal=value\x00")
	got := splitCmdline(raw, true)
	if len(got) != 2 || got[0] != "tool" || got[1] != "--normal=value" {
		t.Fatalf("splitCmdline = %#v, want complete args", got)
	}
}

func TestList_ExactPIDDetails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procstat reads /proc; linux only")
	}
	self := os.Getpid()
	got, err := List(Options{Limit: 1, PID: self, Details: true})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].PID != self {
		t.Fatalf("exact pid lookup = %+v, want pid %d", got, self)
	}
	if len(got[0].Argv) == 0 {
		t.Errorf("details lookup returned empty argv for live test process")
	}
}
