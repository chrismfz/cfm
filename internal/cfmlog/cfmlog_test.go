package cfmlog

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTailFile_UnknownKey(t *testing.T) {
	if _, err := TailFile(context.Background(), "bogus", 0, 0, 0, ""); err == nil {
		t.Fatal("unknown key should error")
	}
}

func TestTailFile_MissingIsFoundFalse(t *testing.T) {
	// 'waf' has a single candidate that won't exist in the test env.
	res, err := TailFile(context.Background(), "waf", 0, 0, 0, "")
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
	res, err := TailFile(context.Background(), "main", 0, 0, 0, "")
	if err != nil || !res.Found {
		t.Fatalf("read failed: err=%v found=%v", err, res.Found)
	}
	if res.Scanned != 3 || res.Matched != 3 || len(res.Lines) != 3 {
		t.Errorf("scanned/matched/lines = %d/%d/%d, want 3/3/3", res.Scanned, res.Matched, len(res.Lines))
	}

	// Case-insensitive grep 'error' → one line.
	res, _ = TailFile(context.Background(), "main", 0, 0, 0, "ERROR")
	if res.Scanned != 3 || res.Matched != 1 || len(res.Lines) != 1 || !strings.Contains(res.Lines[0], "BRAVO") {
		t.Errorf("grep result wrong: %+v", res)
	}

	// limit caps returned lines + sets Truncated.
	res, _ = TailFile(context.Background(), "main", 0, 1, 0, "alpha")
	if res.Matched != 2 || len(res.Lines) != 1 || !res.Truncated {
		t.Errorf("limit not honored: matched=%d lines=%d trunc=%v", res.Matched, len(res.Lines), res.Truncated)
	}

	// Full window (3 lines) is not saturated by default (lines=500).
	res, _ = TailFile(context.Background(), "main", 0, 0, 0, "")
	if res.WindowFull {
		t.Errorf("3-line file should not report window_full at default window")
	}
	// A tiny window (lines=1) IS saturated → window_full true (older lines exist).
	res, _ = TailFile(context.Background(), "main", 1, 0, 0, "")
	if res.Scanned != 1 || !res.WindowFull {
		t.Errorf("lines=1 should saturate window: scanned=%d window_full=%v", res.Scanned, res.WindowFull)
	}
}

func TestTailFileReadsCanonicalAPILogSource(t *testing.T) {
	logp := filepath.Join(t.TempDir(), "cfm.api.log")
	if err := os.WriteFile(logp, []byte("event=auth_attempt result=success\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := fileCandidates["api"]
	fileCandidates["api"] = []string{logp}
	t.Cleanup(func() { fileCandidates["api"] = old })

	res, err := TailFile(context.Background(), "api", 10, 10, 0, "auth_attempt")
	if err != nil || !res.Found || res.Kind != "api" || len(res.Lines) != 1 {
		t.Fatalf("api log tail failed: result=%+v err=%v", res, err)
	}
}

func TestTailFile_RotatedReadsPlainAndGzSiblings(t *testing.T) {
	tmp := t.TempDir()
	live := filepath.Join(tmp, "cfm.abuse_shadow.log")
	// live (newest), .1 (plain, older), .2.gz (gzipped, oldest).
	mustWrite(t, live, "live MATCH a\nlive nope\n")
	rot1 := live + ".1"
	mustWrite(t, rot1, "rot1 MATCH b\n")
	rot2 := live + ".2.gz"
	mustWriteGz(t, rot2, "rot2 MATCH c\nrot2 nope\n")
	// mtime order so RotatedSiblings ranks .1 before .2.gz (newest first).
	now := time.Now()
	_ = os.Chtimes(rot1, now.Add(-1*time.Hour), now.Add(-1*time.Hour))
	_ = os.Chtimes(rot2, now.Add(-2*time.Hour), now.Add(-2*time.Hour))

	old := fileCandidates["abuse_shadow"]
	fileCandidates["abuse_shadow"] = []string{live}
	t.Cleanup(func() { fileCandidates["abuse_shadow"] = old })

	// rotated=0 → live only: one match, no files_scanned list.
	res, err := TailFile(context.Background(), "abuse_shadow", 0, 0, 0, "MATCH")
	if err != nil || res.Matched != 1 || len(res.FilesScanned) != 0 {
		t.Fatalf("live-only: matched=%d files=%v err=%v", res.Matched, res.FilesScanned, err)
	}

	// rotated=5 → live + both siblings: three matches, collected live-first then
	// newest-sibling-first, files_scanned = [live, .1, .2.gz].
	res, err = TailFile(context.Background(), "abuse_shadow", 0, 0, 5, "MATCH")
	if err != nil {
		t.Fatalf("rotated read err: %v", err)
	}
	if res.Matched != 3 || len(res.Lines) != 3 {
		t.Fatalf("rotated matched/lines = %d/%d, want 3/3 (%+v)", res.Matched, len(res.Lines), res.Lines)
	}
	if !strings.Contains(res.Lines[0], "live") || !strings.Contains(res.Lines[1], "rot1") || !strings.Contains(res.Lines[2], "rot2") {
		t.Errorf("order wrong (want live, rot1, rot2): %v", res.Lines)
	}
	if len(res.FilesScanned) != 3 || res.FilesScanned[0] != live || res.FilesScanned[1] != rot1 || res.FilesScanned[2] != rot2 {
		t.Errorf("files_scanned = %v, want [live, .1, .2.gz]", res.FilesScanned)
	}
	// Scanned counts lines across ALL files (2 live + 1 + 2 = 5).
	if res.Scanned != 5 {
		t.Errorf("scanned across files = %d, want 5", res.Scanned)
	}

	// A SATURATED live tail in rotated mode (lines=1 on a 2-line live file) must set
	// BOTH window_full and truncated: the un-scanned live line between the window and
	// .1 is a real coverage hole, not silently complete.
	res, err = TailFile(context.Background(), "abuse_shadow", 1, 0, 5, "MATCH")
	if err != nil {
		t.Fatalf("saturated-live rotated read err: %v", err)
	}
	if !res.WindowFull || !res.Truncated {
		t.Errorf("saturated live tail in rotated mode must set window_full AND truncated: window_full=%v truncated=%v", res.WindowFull, res.Truncated)
	}
}

// When the live window alone has more matches than `limit`, the NEWEST `limit` come
// back (not the oldest scanned) and the rotated siblings are skipped entirely — no
// point gunzipping strictly-older evidence that can't enter a newest-first view.
func TestTailFile_KeepsNewestMatchesAndSkipsRotatedWhenLiveFull(t *testing.T) {
	tmp := t.TempDir()
	live := filepath.Join(tmp, "cfm.abuse_shadow.log")
	mustWrite(t, live, "MATCH 1\nMATCH 2\nMATCH 3\nMATCH 4\n") // 4 matches, oldest→newest
	rot1 := live + ".1"
	mustWrite(t, rot1, "MATCH old\n")

	old := fileCandidates["abuse_shadow"]
	fileCandidates["abuse_shadow"] = []string{live}
	t.Cleanup(func() { fileCandidates["abuse_shadow"] = old })

	res, err := TailFile(context.Background(), "abuse_shadow", 0, 2, 5, "MATCH")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res.Lines) != 2 || !strings.Contains(res.Lines[0], "MATCH 3") || !strings.Contains(res.Lines[1], "MATCH 4") {
		t.Fatalf("want the newest 2 [MATCH 3, MATCH 4], got %v", res.Lines)
	}
	if !res.Truncated {
		t.Errorf("older live matches were dropped → Truncated must be set")
	}
	// Early stop: only the live file is scanned; the sibling is never opened.
	if len(res.FilesScanned) != 1 || res.FilesScanned[0] != live {
		t.Errorf("rotated must be skipped when the live block fills limit: files=%v", res.FilesScanned)
	}
	if res.Matched != 4 {
		t.Errorf("Matched counts every live match seen, got %d want 4", res.Matched)
	}
}

// When the live window has FEWER matches than `limit`, the remainder is filled from
// the rotated siblings (newest-first within each) — the historical reach `rotated`
// promises, which the old live-first-cap logic silently withheld on a busy log.
func TestTailFile_ReachesRotatedWhenLiveUnderLimit(t *testing.T) {
	tmp := t.TempDir()
	live := filepath.Join(tmp, "cfm.abuse_shadow.log")
	mustWrite(t, live, "MATCH live\nnope\n") // 1 match
	rot1 := live + ".1"
	mustWrite(t, rot1, "MATCH r1a\nMATCH r1b\n") // 2 matches, older; r1b is the newest
	now := time.Now()
	_ = os.Chtimes(rot1, now.Add(-time.Hour), now.Add(-time.Hour))

	old := fileCandidates["abuse_shadow"]
	fileCandidates["abuse_shadow"] = []string{live}
	t.Cleanup(func() { fileCandidates["abuse_shadow"] = old })

	// limit=2: 1 live match + the sibling's NEWEST 1 (r1b).
	res, err := TailFile(context.Background(), "abuse_shadow", 0, 2, 5, "MATCH")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res.Lines) != 2 || !strings.Contains(res.Lines[0], "MATCH live") || !strings.Contains(res.Lines[1], "MATCH r1b") {
		t.Fatalf("want [live, r1b (sibling's newest)], got %v", res.Lines)
	}
	if len(res.FilesScanned) != 2 || res.FilesScanned[1] != rot1 {
		t.Errorf("the sibling must be reached: files=%v", res.FilesScanned)
	}
	if !res.Truncated {
		t.Errorf("the sibling dropped an older match (r1a) → Truncated")
	}
	if res.Matched != 3 {
		t.Errorf("Matched across live+sibling = %d, want 3", res.Matched)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustWriteGz(t *testing.T, path, body string) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, buf.String())
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
