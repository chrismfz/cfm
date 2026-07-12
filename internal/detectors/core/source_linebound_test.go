package core

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A log line longer than the 256 KB reader buffer must be DROPPED (never
// accumulated — the pre-fix ReadString grew a []byte without bound), the
// surrounding lines must still tail (resync), and the resume offset must advance
// PAST the dropped line so a restart doesn't re-read it. Twin of the ingest
// socket fix (audit F26); before it, source.go's ErrBufferFull drain was dead
// code because ReadString never returns that error.
func TestFileTailer_DropsOversizedLineAndResyncs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")

	oversized := strings.Repeat("X", 300*1024) // > 256 KB buffer
	content := "normal1\n" + oversized + "\n" + "normal2\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ft := NewFileTailer(p)
	ft.StartAtEnd = false // replay from BOF
	ft.SetIdleStatInterval(0)
	if err := ft.Open(); err != nil {
		t.Fatal(err)
	}
	defer ft.Shutdown()

	ctx := context.Background()
	var got []string
	deadline := time.Now().Add(3 * time.Second)
	for len(got) < 2 && time.Now().Before(deadline) {
		line, err := ft.ReadNext(ctx)
		if err == io.EOF {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		if len(line) > 256*1024 {
			t.Fatalf("oversized line (%d bytes) was returned — not bounded/dropped", len(line))
		}
		if line == "" {
			continue // the dropped oversized line surfaces as an empty skip
		}
		got = append(got, line)
	}

	want := []string{"normal1", "normal2"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q, want %q (oversized line must be dropped, surrounding lines kept)", got, want)
	}

	// Resume correctness: the offset must have advanced past every byte,
	// including the dropped oversized line, so a restart skips it.
	off, inode, _ := ft.Position()
	if off != uint64(len(content)) {
		t.Fatalf("resume offset = %d, want %d (drain must advance the offset past the dropped line)",
			off, len(content))
	}

	// A fresh tailer resuming at that saved (inode, offset) must NOT re-read the
	// dropped line and must NOT skip a good line — it resumes exactly after
	// normal2. Append a line and confirm that's what comes next.
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("normal3\n"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()

	ft2 := NewFileTailer(p)
	ft2.SetIdleStatInterval(0)
	ft2.ApplyResume(inode, off)
	if err := ft2.Open(); err != nil {
		t.Fatal(err)
	}
	defer ft2.Shutdown()
	readLineEventually(t, ft2, "normal3")
}
