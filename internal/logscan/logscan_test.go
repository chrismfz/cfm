package logscan

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeGz(t *testing.T, path, body string) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, buf.String())
}

func TestRotatedSiblings(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "cfm.abuse_shadow.log")
	writeFile(t, live, "live\n")
	s1 := live + ".1"
	writeFile(t, s1, "one\n")
	s2 := live + ".2.gz"
	writeGz(t, s2, "two\n")
	sDate := live + "-20260810.gz"
	writeGz(t, sDate, "date\n")
	// Must be EXCLUDED: the live file, an empty sibling, a directory, and an
	// unrelated file that doesn't share the base prefix.
	writeFile(t, live+".3", "") // empty → excluded
	if err := os.Mkdir(live+".d", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "unrelated.log"), "x\n")

	// mtimes so the order is deterministic: s1 newest, then s2, then sDate.
	now := time.Now()
	_ = os.Chtimes(s1, now.Add(-1*time.Hour), now.Add(-1*time.Hour))
	_ = os.Chtimes(s2, now.Add(-2*time.Hour), now.Add(-2*time.Hour))
	_ = os.Chtimes(sDate, now.Add(-3*time.Hour), now.Add(-3*time.Hour))

	got, total := RotatedSiblings(live, 10)
	if total != 3 {
		t.Errorf("total siblings = %d, want 3 (live/empty/dir/unrelated excluded)", total)
	}
	want := []string{s1, s2, sDate}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("siblings = %v, want newest-first %v", got, want)
	}

	// maxFiles caps the returned set but `total` still reports the true count, so a
	// caller can detect the cap hid some.
	capped, total2 := RotatedSiblings(live, 2)
	if total2 != 3 || len(capped) != 2 || capped[0] != s1 || capped[1] != s2 {
		t.Errorf("capped = %v (total %d), want [s1,s2] total 3", capped, total2)
	}

	// A directory with no siblings yields nothing (best-effort, not an error).
	if paths, tot := RotatedSiblings(filepath.Join(dir, "nope.log"), 10); len(paths) != 0 || tot != 0 {
		t.Errorf("no-sibling case = %v/%d, want empty/0", paths, tot)
	}
}

func TestScanWhole_PlainAndGz(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "a.log.1")
	writeFile(t, plain, "l1\nl2\nl3\n")
	gz := filepath.Join(dir, "a.log.2.gz")
	writeGz(t, gz, "g1\ng2\n")

	// Plain file: all lines fed, budget decremented per line.
	var got []string
	budget := 100
	if err := ScanWhole(context.Background(), plain, &budget, func(l string) bool { got = append(got, l); return true }); err != nil {
		t.Fatalf("plain scan err: %v", err)
	}
	if len(got) != 3 || got[0] != "l1" || got[2] != "l3" || budget != 97 {
		t.Errorf("plain: got %v budget %d, want 3 lines budget 97", got, budget)
	}

	// Gz file: streamed transparently.
	got = nil
	budget = 100
	if err := ScanWhole(context.Background(), gz, &budget, func(l string) bool { got = append(got, l); return true }); err != nil {
		t.Fatalf("gz scan err: %v", err)
	}
	if len(got) != 2 || got[0] != "g1" || got[1] != "g2" {
		t.Errorf("gz: got %v, want [g1 g2]", got)
	}

	// Budget exhaustion mid-file → ErrBudgetExceeded (a truncation signal, not a
	// clean EOF), and the file was cut short.
	got = nil
	budget = 2
	err := ScanWhole(context.Background(), plain, &budget, func(l string) bool { got = append(got, l); return true })
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("budget-exhausted err = %v, want ErrBudgetExceeded", err)
	}
	if len(got) != 2 {
		t.Errorf("budget=2 fed %d lines, want 2", len(got))
	}

	// fn returning false stops early with a nil error.
	got = nil
	budget = 100
	if err := ScanWhole(context.Background(), plain, &budget, func(l string) bool { got = append(got, l); return false }); err != nil {
		t.Errorf("early-stop err = %v, want nil", err)
	}
	if len(got) != 1 {
		t.Errorf("early stop fed %d lines, want 1", len(got))
	}

	// A missing file is an error the caller surfaces (never a silent empty).
	if err := ScanWhole(context.Background(), filepath.Join(dir, "gone.gz"), &budget, func(string) bool { return true }); err == nil {
		t.Error("missing file should error")
	}
}
