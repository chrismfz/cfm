package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSanitiseConfig_RedactsKnownSecretKeys(t *testing.T) {
	in := strings.Join([]string{
		"# this is a comment",
		"[section]",
		"plain_key = visible",
		"  bridge_token = abc123def456",
		`hmac_secret = "sup3rs3cr3t"`,
		"clamd_password = 'p@ss'",
		"api_key=longvalue1234",
		"private_key = -----BEGIN PRIVATE KEY-----",
		"some_token_path = /etc/cfm/token", // matches "token" → redact (defensive)
	}, "\n")

	out := sanitiseConfig(in + "\n")

	must := func(needle string) {
		t.Helper()
		if !strings.Contains(out, needle) {
			t.Errorf("expected output to contain %q\n--- got ---\n%s", needle, out)
		}
	}
	mustNot := func(needle string) {
		t.Helper()
		if strings.Contains(out, needle) {
			t.Errorf("output should NOT contain %q (leaked)\n--- got ---\n%s", needle, out)
		}
	}

	must("# this is a comment")
	must("[section]")
	must("plain_key = visible")
	must("<redacted len=12>")  // bridge_token = abc123def456 → len 12
	mustNot("abc123def456")
	mustNot("sup3rs3cr3t")
	mustNot("p@ss")
	mustNot("longvalue1234")
	mustNot("-----BEGIN PRIVATE KEY-----")
	mustNot("/etc/cfm/token")
}

func TestSanitiseConfig_Idempotent(t *testing.T) {
	in := "bridge_token = abc\n"
	once := sanitiseConfig(in)
	twice := sanitiseConfig(once)
	// Once redacted, the value is "<redacted len=N>" — applying the
	// sanitiser again must not change the line further.
	if once != twice {
		t.Fatalf("not idempotent:\nonce =%q\ntwice=%q", once, twice)
	}
}

func TestSummariseProcMaps_Categorises(t *testing.T) {
	// Each range is 0x100000 bytes = 1 MB so the per-category sums
	// are easy to verify (file-backed = 2 MB, the rest = 1 MB each
	// except shared = 2 MB across SYSV + memfd).
	maps := strings.Join([]string{
		"00400000-00500000 r-xp 00000000 fd:00 12345 /usr/bin/cfm",
		"00500000-00600000 rw-p 00000000 fd:00 12345 /usr/bin/cfm",
		"7f0000000000-7f0000100000 rw-p 00000000 00:00 0",            // anonymous (1 MB)
		"7f0000200000-7f0000300000 rw-p 00000000 00:00 0 [heap]",     // heap
		"7f0000400000-7f0000500000 rw-p 00000000 00:00 0 [stack]",    // stack
		"7f0000600000-7f0000700000 rw-s 00000000 00:0d 1 /SYSV0001",  // shared
		"7f0000800000-7f0000900000 rw-s 00000000 00:00 0 /memfd:foo", // shared
		"badline",
	}, "\n")
	s := summariseProcMaps(maps)
	if s.TotalMappings != 7 {
		t.Errorf("TotalMappings: got %d, want 7", s.TotalMappings)
	}
	const oneM = 0x100000
	if s.FileBackedBytes != 2*oneM {
		t.Errorf("FileBackedBytes: got %d, want %d", s.FileBackedBytes, 2*oneM)
	}
	if s.AnonymousBytes != oneM {
		t.Errorf("AnonymousBytes: got %d, want %d", s.AnonymousBytes, oneM)
	}
	if s.HeapBytes != oneM {
		t.Errorf("HeapBytes: got %d, want %d", s.HeapBytes, oneM)
	}
	if s.StackBytes != oneM {
		t.Errorf("StackBytes: got %d, want %d", s.StackBytes, oneM)
	}
	if s.SharedBytes != 2*oneM {
		t.Errorf("SharedBytes: got %d, want %d", s.SharedBytes, 2*oneM)
	}
}

func TestParsePProfTop_PicksUpToN(t *testing.T) {
	in := strings.Join([]string{
		"File: cfm",
		"Type: cpu",
		"Showing nodes accounting for 100ms, 100% of 100ms total",
		"      flat  flat%   sum%        cum   cum%",
		"      30ms 30.00% 30.00%       50ms 50.00%  cfm/internal/foo.Bar",
		"      20ms 20.00% 50.00%       30ms 30.00%  cfm/internal/baz.Qux",
		"      10ms 10.00% 60.00%       10ms 10.00%  cfm/internal/baz.Quux",
		"",
	}, "\n")
	rows := parsePProfTop(in, 2)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if !strings.Contains(rows[0].Function, "foo.Bar") {
		t.Errorf("rows[0].Function = %q", rows[0].Function)
	}
	if rows[0].FlatPct != 30.00 {
		t.Errorf("rows[0].FlatPct = %v, want 30.00", rows[0].FlatPct)
	}
	if rows[1].CumPct != 30.00 {
		t.Errorf("rows[1].CumPct = %v, want 30.00", rows[1].CumPct)
	}
}

func TestGoroutineCountFromDebug1(t *testing.T) {
	in := "goroutine profile: total 42\n\n1 @ 0xabc\n#\t0xdef\tfoo+0x1\n"
	if got := goroutineCountFromDebug1(in); got != 42 {
		t.Errorf("got %d, want 42", got)
	}
	if got := goroutineCountFromDebug1("nothing here"); got != 0 {
		t.Errorf("got %d, want 0 for missing total", got)
	}
}

func TestProcStatusFields_ExtractsKeyVitals(t *testing.T) {
	status := strings.Join([]string{
		"Name:\tcfm",
		"State:\tS (sleeping)",
		"Tgid:\t1234",
		"VmSize:\t   2 465 160 kB",
		"VmRSS:\t  111 044 kB",
		"VmHWM:\t  120 000 kB",
		"Threads:\t45",
		"voluntary_ctxt_switches:\t10",
	}, "\n")
	got := procStatusFields(status)
	for _, k := range []string{"Name", "State", "VmRSS", "VmSize", "VmHWM", "Threads"} {
		if got[k] == "" {
			t.Errorf("missing field %q", k)
		}
	}
	if got["Threads"] != "45" {
		t.Errorf("Threads = %q, want 45", got["Threads"])
	}
}

func TestBuildSummary_ContainsExpectedSections(t *testing.T) {
	in := summaryInput{
		BundlePath:       "/tmp/cfm-debug/test",
		StartedAt:        time.Date(2026, 5, 9, 16, 0, 0, 0, time.UTC),
		Duration:         60 * time.Second,
		DaemonPID:        1234,
		DaemonProcStatus: "Name:\tcfm\nVmRSS:\t100000 kB\nThreads:\t45\nVmSize:\t2000000 kB\n",
		DaemonCPUStart:   100,
		DaemonCPUEnd:     200,
		DaemonElapsedSec: 60,
		DaemonClkTck:     100,
		DaemonGoroutines: 88,
		DaemonPProfTop: []pprofTopLine{
			{FlatPct: 30.0, CumPct: 50.0, Function: "foo.Bar"},
		},
		WorkerSamples: []workerSample{
			{At: time.Date(2026, 5, 9, 16, 0, 0, 0, time.UTC), PID: 99, VmRSSKB: 100000, VmSizeKB: 5000000},
			{At: time.Date(2026, 5, 9, 16, 1, 0, 0, time.UTC), PID: 99, VmRSSKB: 110000, VmSizeKB: 5500000},
		},
		Manifest: map[string]string{
			"pprof-cpu.pb.gz":     "ok (1024 bytes)",
			"worker-mem-trace.txt": "ok (256 bytes)",
		},
	}
	out := buildSummary(in)
	for _, want := range []string{
		"cfm debug bundle",
		"bundle_path: /tmp/cfm-debug/test",
		"pid:         1234",
		"goroutines:  88",
		"foo.Bar",
		"Workers",
		"99",
		"Captured artifacts",
		"pprof-cpu.pb.gz",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// When the goroutine fetch failed (apiserver 401 / unreachable), the
// orchestrator records -1 to distinguish "fetch failed" from "the
// daemon happens to have zero goroutines" (which can't happen for a
// live Go runtime). The summary must render this as "unavailable" so
// the operator isn't misled.
func TestBuildSummary_GoroutinesUnavailableWhenFetchFailed(t *testing.T) {
	in := summaryInput{
		BundlePath:       "/tmp/cfm-debug/test",
		StartedAt:        time.Date(2026, 5, 9, 16, 0, 0, 0, time.UTC),
		Duration:         60 * time.Second,
		DaemonPID:        1234,
		DaemonProcStatus: "Name:\tcfm\nVmRSS:\t100 kB\n",
		DaemonGoroutines: -1, // sentinel: fetch failed
		Manifest:         map[string]string{},
	}
	out := buildSummary(in)
	if !strings.Contains(out, "goroutines:  unavailable") {
		t.Errorf("summary should render unavailable goroutine fetch as 'unavailable'\n--- got ---\n%s", out)
	}
	if strings.Contains(out, "goroutines:  0") {
		t.Errorf("summary must NOT render -1 sentinel as 'goroutines: 0'\n--- got ---\n%s", out)
	}
	if strings.Contains(out, "goroutines:  -1") {
		t.Errorf("summary must hide the -1 sentinel from the operator\n--- got ---\n%s", out)
	}
}

func TestBuildSummary_FlagsLeakers(t *testing.T) {
	// 100 MB → 200 MB across 1 minute = 100 MB/min; should trip the
	// ≥ 5 MB/min leaker threshold.
	in := summaryInput{
		WorkerSamples: []workerSample{
			{At: time.Date(2026, 5, 9, 16, 0, 0, 0, time.UTC), PID: 99, VmRSSKB: 100 * 1024},
			{At: time.Date(2026, 5, 9, 16, 1, 0, 0, time.UTC), PID: 99, VmRSSKB: 200 * 1024},
		},
	}
	out := buildSummary(in)
	if !strings.Contains(out, "growing ≥ 5 MB/min") {
		t.Errorf("expected leaker warning, got:\n%s", out)
	}
	if !strings.Contains(out, "pid=99") {
		t.Errorf("expected leaker pid=99 mention, got:\n%s", out)
	}
}

func TestTailFile_ReturnsLastNLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.txt")
	var b strings.Builder
	for i := 1; i <= 1000; i++ {
		b.WriteString("line ")
		b.WriteString(strings.Repeat("x", 5))
		b.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := tailFile(path, 10)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	got := strings.Count(string(out), "\n")
	if got != 10 {
		t.Errorf("expected 10 lines, got %d", got)
	}
}

func TestTailFile_ShorterFile_ReturnsAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.txt")
	if err := os.WriteFile(path, []byte("a\nb\nc\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := tailFile(path, 10)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	if string(out) != "a\nb\nc\n" {
		t.Errorf("got %q, want %q", string(out), "a\nb\nc\n")
	}
}

func TestParseDebugFlags_QuickShortcuts(t *testing.T) {
	opts, err := parseDebugFlags([]string{"--quick"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.duration != quickBundleDuration {
		t.Errorf("--quick duration: got %s, want %s", opts.duration, quickBundleDuration)
	}
	if !opts.skipLogs {
		t.Error("--quick should imply --no-logs")
	}
}

func TestParseDebugFlags_RejectsBadDuration(t *testing.T) {
	if _, err := parseDebugFlags([]string{"--duration", "20m"}); err == nil {
		t.Error("expected error for duration > 10m")
	}
	if _, err := parseDebugFlags([]string{"--duration", "0s"}); err == nil {
		t.Error("expected error for duration == 0")
	}
}

func TestPruneBundles_KeepsNewestN(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"20260101T000000Z",
		"20260102T000000Z",
		"20260103T000000Z",
		"20260104T000000Z",
		"some-unrelated-dir",
	} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
	pruneBundles(dir, 2)

	want := map[string]bool{
		"20260103T000000Z":   true,
		"20260104T000000Z":   true,
		"some-unrelated-dir": true, // non-conforming names left alone
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("expected %s to remain, but it was pruned", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("expected %s to be pruned, but it remained", k)
		}
	}
}
