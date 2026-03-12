package core

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readLineEventually(t *testing.T, ft *FileTailer, want string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		line, err := ft.ReadNext(ctx)
		if err == nil {
			if line != want {
				t.Fatalf("unexpected line: got %q want %q", line, want)
			}
			return
		}
		if err != io.EOF {
			t.Fatalf("unexpected read error: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for line %q", want)
}

func TestFileTailerStartAtEndModes(t *testing.T) {
	t.Run("default starts at EOF", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "access.log")
		if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		ft := NewFileTailer(p)
		ft.SetIdleStatInterval(0)
		if err := ft.Open(); err != nil {
			t.Fatal(err)
		}
		defer ft.Shutdown()

		if _, err := ft.ReadNext(context.Background()); err != io.EOF {
			t.Fatalf("expected EOF on first read, got %v", err)
		}

		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("new\n"); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		_ = f.Close()

		readLineEventually(t, ft, "new")
	})

	t.Run("explicit false replays from BOF", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "access.log")
		if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		ft := NewFileTailer(p)
		ft.StartAtEnd = false
		ft.SetIdleStatInterval(0)
		if err := ft.Open(); err != nil {
			t.Fatal(err)
		}
		defer ft.Shutdown()

		readLineEventually(t, ft, "old")
	})
}

func TestFileTailerRotationTruncateAndDeleteStillRecover(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")
	if err := os.WriteFile(p, []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ft := NewFileTailer(p)
	ft.StartAtEnd = false
	ft.SetIdleStatInterval(0)
	if err := ft.Open(); err != nil {
		t.Fatal(err)
	}
	defer ft.Shutdown()

	readLineEventually(t, ft, "a")

	// truncation in-place (e.g. echo > file) should reopen at BOF.
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := ft.ReadNext(context.Background()); err != io.EOF {
		t.Fatalf("expected EOF during truncate recovery, got %v", err)
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("b\n"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	readLineEventually(t, ft, "b")

	// rename+create (rotation) should move to new inode and read from BOF
	rot := p + ".1"
	if err := os.Rename(p, rot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	readLineEventually(t, ft, "c")

	// remove and recreate should recover once path reappears
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("d\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	readLineEventually(t, ft, "d")
}
