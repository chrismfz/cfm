package safefs

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A spool or queued file swapped for a symlink or a FIFO in pending is not
// read through (a FIFO would block the scan worker or the bridge handler).
func TestOpenRegularRefusesSymlinksAndFIFOs(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "f")
	if err := os.WriteFile(reg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRegular(reg); err != nil {
		t.Fatalf("regular file: %v", err)
	} else {
		f.Close()
	}
	link := filepath.Join(dir, "l")
	if err := os.Symlink(reg, link); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenRegular(link); err == nil {
		f.Close()
		t.Error("followed a symlink")
	}
	fifo := filepath.Join(dir, "p")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := OpenRegular(fifo)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("accepted a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}

func TestCopyToNewMakesANewFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	p1, err := CopyToNew(src, dir, "upload_1_a*b_")
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := CopyToNew(src, dir, "upload_1_a*b_")
	if p1 == p2 || filepath.Dir(p1) != dir || !strings.HasPrefix(filepath.Base(p1), "upload_1_a_b_") {
		t.Fatalf("paths %q %q", p1, p2)
	}
	st, _ := os.Stat(p1)
	if b, _ := os.ReadFile(p1); string(b) != "payload" || st.Mode().Perm() != 0o600 {
		t.Fatalf("copy %q mode %o", b, st.Mode().Perm())
	}
	link := filepath.Join(dir, "l")
	_ = os.Symlink(src, link)
	if _, err := CopyToNew(link, dir, "x_"); err == nil {
		t.Error("copied from a symlinked source")
	}
}
