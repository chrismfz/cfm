package mysqllog

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMyCnfPath(t *testing.T) {
	dir := t.TempDir()
	cnf := filepath.Join(dir, "my.cnf")
	os.WriteFile(cnf, []byte(`
[mysqld]
# a comment
log-error = /var/log/mysqld.log
slow_query_log = 1
slow_query_log_file = "/var/lib/mysql/host-slow.log"
`), 0o644)

	if got := parseMyCnfPath(cnf, "log_error"); got != "/var/log/mysqld.log" {
		t.Fatalf("log_error (dash spelling) = %q", got)
	}
	if got := parseMyCnfPath(cnf, "slow_query_log_file"); got != "/var/lib/mysql/host-slow.log" {
		t.Fatalf("slow_query_log_file (quoted) = %q", got)
	}
	if got := parseMyCnfPath(cnf, "nonexistent"); got != "" {
		t.Fatalf("missing key = %q, want empty", got)
	}
}

func TestNewestGlob(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a-slow.log")
	b := filepath.Join(dir, "b-slow.log")
	os.WriteFile(a, []byte("x"), 0o644)
	os.WriteFile(b, []byte("y"), 0o644)
	// make b newer than a
	os.Chtimes(a, time.Unix(1000, 0), time.Unix(1000, 0))
	os.Chtimes(b, time.Unix(2000, 0), time.Unix(2000, 0))

	if got := newestGlob(filepath.Join(dir, "*-slow.log")); got != b {
		t.Fatalf("newestGlob = %q, want %q", got, b)
	}
	if got := newestGlob(filepath.Join(dir, "none-*.log")); got != "" {
		t.Fatalf("no match = %q, want empty", got)
	}
}

func TestTail_ErrorLog_GrepAndCap(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "mysqld.log")
	var b strings.Builder
	for i := 0; i < 500; i++ {
		if i%5 == 0 {
			b.WriteString("2026-08-06 [ERROR] Deadlock found when trying to get lock\n")
		} else {
			b.WriteString("2026-08-06 [Note] some routine chatter\n")
		}
	}
	os.WriteFile(p, []byte(b.String()), 0o644)

	old := errorLogCommon
	errorLogCommon = append([]string{p}, old...)
	defer func() { errorLogCommon = old }()

	res, err := Tail(context.Background(), "error", 500, 10, "deadlock")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.LogFile != p {
		t.Fatalf("resolve failed: found=%v file=%q", res.Found, res.LogFile)
	}
	if res.Matched != 100 {
		t.Fatalf("matched = %d, want 100", res.Matched)
	}
	if len(res.Lines) != 10 || !res.Truncated {
		t.Fatalf("cap failed: lines=%d truncated=%v", len(res.Lines), res.Truncated)
	}
	for _, l := range res.Lines {
		if !strings.Contains(strings.ToLower(l), "deadlock") {
			t.Fatalf("grep leaked a non-matching line: %q", l)
		}
	}
}

func TestTail_SlowMissing_NotAnError(t *testing.T) {
	old := slowLogCommon
	slowLogCommon = []string{"/nonexistent/does-not-exist-slow.log"}
	defer func() { slowLogCommon = old }()

	res, err := Tail(context.Background(), "slow", 0, 0, "")
	if err != nil {
		t.Fatalf("missing slow log should not error, got %v", err)
	}
	if res.Found {
		t.Fatalf("found should be false for a missing slow log")
	}
}

func TestScanBoundedLines_OverlongLineNotFatal(t *testing.T) {
	// Reproduces the mysql_slow_queries 502: a line longer than the reader
	// buffer must be truncated + skipped, not abort the whole scan.
	huge := strings.Repeat("x", 300) // > tiny buffer below
	input := "short line 1\n" + huge + "\nshort line 2\n"
	r := bufio.NewReaderSize(strings.NewReader(input), 64) // force ErrBufferFull on `huge`

	var got []string
	if err := scanBoundedLines(r, func(s string) { got = append(got, s) }); err != nil {
		t.Fatalf("scanBoundedLines errored on long line: %v", err)
	}
	// 3 logical lines survive; the huge one is truncated to the buffer prefix.
	if len(got) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(got), got)
	}
	if got[0] != "short line 1" || got[2] != "short line 2" {
		t.Fatalf("surrounding lines corrupted: %q", got)
	}
	if len(got[1]) == 0 || len(got[1]) > 64 {
		t.Fatalf("huge line should be a non-empty bounded prefix, got %d bytes", len(got[1]))
	}
}

func TestScanBoundedLines_NoTrailingNewline(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("a\nb\nc"), 4096) // last line has no \n
	var got []string
	if err := scanBoundedLines(r, func(s string) { got = append(got, s) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "c" {
		t.Fatalf("want a,b,c; got %q", got)
	}
}

func TestTail_BadKind(t *testing.T) {
	if _, err := Tail(context.Background(), "bogus", 0, 0, ""); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}
