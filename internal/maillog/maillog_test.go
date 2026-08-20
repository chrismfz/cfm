package maillog

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTail_GrepAndCap(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "exim_mainlog")
	var b strings.Builder
	for i := 0; i < 500; i++ {
		if i%5 == 0 {
			b.WriteString("2026-08-07 12:00:00 1abc-x <= spammer@shop.gr A=dovecot_login:support@ordermusic.gr P=esmtpa\n")
		} else {
			b.WriteString("2026-08-07 12:00:00 1def-x => user@example.com R=dkim T=remote_smtp\n")
		}
	}
	os.WriteFile(p, []byte(b.String()), 0o644)

	// Inject the temp path as the sole exim candidate.
	old := candidates["exim"]
	candidates["exim"] = []string{p}
	defer func() { candidates["exim"] = old }()

	res, err := Tail(context.Background(), "exim", 500, 10, "dovecot_login")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.LogFile != p {
		t.Fatalf("resolve failed: found=%v file=%q", res.Found, res.LogFile)
	}
	if res.Scanned != 500 {
		t.Fatalf("scanned = %d, want 500", res.Scanned)
	}
	// 100 lines match the grep, but the limit caps returned to 10 and flags trunc.
	if res.Matched != 100 || len(res.Lines) != 10 || !res.Truncated {
		t.Fatalf("matched=%d returned=%d trunc=%v; want 100/10/true", res.Matched, len(res.Lines), res.Truncated)
	}
	for _, l := range res.Lines {
		if !strings.Contains(l, "dovecot_login") {
			t.Fatalf("grep leaked a non-matching line: %q", l)
		}
	}
}

func TestTail_UnknownWhich(t *testing.T) {
	if _, err := Tail(context.Background(), "sendmail", 0, 0, ""); err == nil {
		t.Fatal("expected error for unknown which")
	}
}

func TestTail_NotFoundIsNotError(t *testing.T) {
	// Point postfix at a nonexistent path → Found=false, no error.
	old := candidates["postfix"]
	candidates["postfix"] = []string{filepath.Join(t.TempDir(), "does-not-exist.log")}
	defer func() { candidates["postfix"] = old }()

	res, err := Tail(context.Background(), "postfix", 0, 0, "")
	if err != nil {
		t.Fatalf("missing log should not error: %v", err)
	}
	if res.Found || len(res.Lines) != 0 {
		t.Fatalf("expected Found=false empty result, got %+v", res)
	}
}

func TestScanTail_CountsWholeTail(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "exim_mainlog")
	var b strings.Builder
	for i := 0; i < 300; i++ {
		b.WriteString("2026-08-15 16:51:48 spam acl condition: error reading from spamd [127.0.0.1]:783\n")
	}
	os.WriteFile(p, []byte(b.String()), 0o644)

	old := candidates["exim"]
	candidates["exim"] = []string{p}
	defer func() { candidates["exim"] = old }()

	seen := 0
	logFile, scanned, err := ScanTail(context.Background(), "exim", 500, func(string) { seen++ })
	if err != nil {
		t.Fatalf("scan err: %v", err)
	}
	if logFile != p {
		t.Fatalf("logFile = %q, want %q", logFile, p)
	}
	// No result cap (unlike Tail): fn fires for every scanned line.
	if scanned != 300 || seen != 300 {
		t.Fatalf("scanned=%d seen=%d, want 300/300", scanned, seen)
	}
}

func TestScanTail_MissingIsNotError(t *testing.T) {
	old := candidates["exim"]
	candidates["exim"] = []string{filepath.Join(t.TempDir(), "does-not-exist")}
	defer func() { candidates["exim"] = old }()

	called := false
	logFile, scanned, err := ScanTail(context.Background(), "exim", 100, func(string) { called = true })
	if err != nil {
		t.Fatalf("missing log must not error: %v", err)
	}
	if logFile != "" || scanned != 0 || called {
		t.Fatalf("missing log: logFile=%q scanned=%d called=%v, want \"\"/0/false", logFile, scanned, called)
	}
}

func TestScanTail_UnknownWhich(t *testing.T) {
	if _, _, err := ScanTail(context.Background(), "sendmail", 0, func(string) {}); err == nil {
		t.Fatal("expected error for unknown which")
	}
}

// TestStreamTail_FailedTailSurfacesError pins the §6 fix: a non-zero `tail` exit
// (here, a file that vanished after the existence check) must surface as an error,
// NOT a clean empty read that a saturation-signal caller would misread as healthy.
func TestStreamTail_FailedTailSurfacesError(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	gone := filepath.Join(t.TempDir(), "vanished.log")
	err := streamTail(context.Background(), gone, 5, func(string) {})
	if err == nil {
		t.Fatal("failed tail must surface an error, not a clean empty read")
	}
	if !strings.Contains(err.Error(), "tail failed") {
		t.Fatalf("want a 'tail failed' error, got %v", err)
	}
}

func TestScanBoundedLines_TruncatesOverlongLine(t *testing.T) {
	// A line longer than the reader buffer must be emitted truncated (not fatal),
	// and the following normal line must still be read.
	small := 64
	long := strings.Repeat("A", small*3)
	input := long + "\nshort line\n"
	r := bufio.NewReaderSize(strings.NewReader(input), small)

	var got []string
	if err := scanBoundedLines(r, func(s string) { got = append(got, s) }); err != nil {
		t.Fatalf("scan err: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 lines (truncated long + short), got %d: %+v", len(got), got)
	}
	if len(got[0]) > small {
		t.Fatalf("over-long line not truncated to buffer: len=%d", len(got[0]))
	}
	if got[1] != "short line" {
		t.Fatalf("line after the monster line lost: %q", got[1])
	}
}
