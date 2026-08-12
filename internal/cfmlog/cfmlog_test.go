package cfmlog

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailFile_UnknownKey(t *testing.T) {
	if _, err := TailFile(context.Background(), "bogus", 0, 0, ""); err == nil {
		t.Fatal("unknown key should error")
	}
}

func TestTailFile_MissingIsFoundFalse(t *testing.T) {
	// 'waf' has a single candidate that won't exist in the test env.
	res, err := TailFile(context.Background(), "waf", 0, 0, "")
	if err != nil {
		t.Fatalf("missing log must not error: %v", err)
	}
	if res.Found {
		t.Errorf("expected Found=false for absent log, got %+v", res)
	}
}

func TestTailFile_ReadsAndGreps(t *testing.T) {
	// Point the 'main' key's first candidate at a temp file by overriding the map.
	tmp := t.TempDir()
	logp := filepath.Join(tmp, "cfm.log")
	body := "alpha line one\nBRAVO error two\nalpha line three\n"
	if err := os.WriteFile(logp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	old := fileCandidates["main"]
	fileCandidates["main"] = []string{logp}
	t.Cleanup(func() { fileCandidates["main"] = old })

	// No grep: all three lines.
	res, err := TailFile(context.Background(), "main", 0, 0, "")
	if err != nil || !res.Found {
		t.Fatalf("read failed: err=%v found=%v", err, res.Found)
	}
	if res.Scanned != 3 || res.Matched != 3 || len(res.Lines) != 3 {
		t.Errorf("scanned/matched/lines = %d/%d/%d, want 3/3/3", res.Scanned, res.Matched, len(res.Lines))
	}

	// Case-insensitive grep 'error' → one line.
	res, _ = TailFile(context.Background(), "main", 0, 0, "ERROR")
	if res.Scanned != 3 || res.Matched != 1 || len(res.Lines) != 1 || !strings.Contains(res.Lines[0], "BRAVO") {
		t.Errorf("grep result wrong: %+v", res)
	}

	// limit caps returned lines + sets Truncated.
	res, _ = TailFile(context.Background(), "main", 0, 1, "alpha")
	if res.Matched != 2 || len(res.Lines) != 1 || !res.Truncated {
		t.Errorf("limit not honored: matched=%d lines=%d trunc=%v", res.Matched, len(res.Lines), res.Truncated)
	}

	// Full window (3 lines) is not saturated by default (lines=500).
	res, _ = TailFile(context.Background(), "main", 0, 0, "")
	if res.WindowFull {
		t.Errorf("3-line file should not report window_full at default window")
	}
	// A tiny window (lines=1) IS saturated → window_full true (older lines exist).
	res, _ = TailFile(context.Background(), "main", 1, 0, "")
	if res.Scanned != 1 || !res.WindowFull {
		t.Errorf("lines=1 should saturate window: scanned=%d window_full=%v", res.Scanned, res.WindowFull)
	}
}

func TestTailJournal_AllowlistAndNormalize(t *testing.T) {
	// Unknown unit → error.
	if _, err := TailJournal(context.Background(), "totally-not-allowed", 0, 0, ""); err == nil {
		t.Error("non-allowlisted unit should error")
	}
	// Empty unit → error.
	if _, err := TailJournal(context.Background(), "  ", 0, 0, ""); err == nil {
		t.Error("empty unit should error")
	}
	// Allow-listed with .service suffix + odd case normalizes and is accepted
	// (result may be Available=false if journalctl is absent in the test env —
	// that's the not-an-error path, which is what we assert).
	res, err := TailJournal(context.Background(), "CFM.service", 0, 0, "")
	if err != nil {
		t.Fatalf("allow-listed unit should not error: %v", err)
	}
	if res.Unit != "cfm" {
		t.Errorf("unit not normalized: got %q want cfm", res.Unit)
	}
	if !res.Available && res.Note == "" {
		t.Error("journalctl-absent path should carry a note")
	}
}

func TestScanBoundedLines_OverLongLineNotFatal(t *testing.T) {
	long := strings.Repeat("x", readerBufSize+500)
	input := "short1\n" + long + "\nshort2\n"
	r := bufio.NewReaderSize(strings.NewReader(input), readerBufSize)
	var got []string
	if err := scanBoundedLines(r, func(s string) { got = append(got, s) }); err != nil {
		t.Fatalf("scan err: %v", err)
	}
	// short1, the (truncated) long line prefix, short2 → 3 emissions; never panics.
	if len(got) != 3 || got[0] != "short1" || got[2] != "short2" {
		t.Errorf("unexpected lines: %d %+v", len(got), []string{got[0], got[len(got)-1]})
	}
}

func TestSources(t *testing.T) {
	fs := FileSources()
	if len(fs) == 0 || fs[0] > fs[len(fs)-1] {
		t.Errorf("FileSources should be sorted+nonempty: %v", fs)
	}
	ju := JournalUnits()
	if len(ju) == 0 {
		t.Error("JournalUnits empty")
	}
}
