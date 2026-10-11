package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A data dir planted as a symlink (its parent is writable by the edge's user)
// is left alone: chmod 0770 / chown root:cfm by name went to its target.
func TestSecureDirRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "pending")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := secureDir(link, 0o770, os.Getgid()); err == nil {
		t.Error("secureDir followed a symlink without an error")
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o700 {
		t.Errorf("symlink target re-moded to %o", st.Mode().Perm())
	}
}

// testGID: a non-zero group to chown to when the test runs as root
// (root:<gid> needs root; gid 0 means "no chown"), 0 otherwise — the CI
// runner is not root.
func testGID() int {
	if os.Geteuid() == 0 {
		return 65534
	}
	return 0
}

func gidOf(t *testing.T, path string) int {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(st.Sys().(*syscall.Stat_t).Gid)
}

func TestSecureDirCreatesAndFixesTheMode(t *testing.T) {
	dir := t.TempDir()
	d := filepath.Join(dir, "a", "b")
	if err := secureDir(d, 0o770, testGID()); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(d); !st.IsDir() || st.Mode().Perm() != 0o770 {
		t.Fatalf("created %v %o", st.IsDir(), st.Mode().Perm())
	}
	if g := testGID(); g != 0 && gidOf(t, d) != g {
		t.Errorf("group %d, want %d", gidOf(t, d), g)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureDir(d, 0o770, 0); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(d); st.Mode().Perm() != 0o770 {
		t.Errorf("existing dir left at %o", st.Mode().Perm())
	}
}

// dump.json sits in the cfm-group writable sslcollector dir: a symlink or a
// FIFO planted there is left alone (and must not hang the start).
func TestChownRegularFileRefusesSymlinksAndFIFOs(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "shadow")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "dump.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := chownRegularFile(link, os.Getgid()); err == nil {
		t.Error("chownRegularFile followed a symlink without an error")
	}

	fifo := filepath.Join(dir, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- chownRegularFile(fifo, os.Getgid()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("chownRegularFile accepted a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("chownRegularFile hung on a FIFO")
	}

	if err := chownRegularFile(filepath.Join(dir, "missing.json"), os.Getgid()); err != nil {
		t.Errorf("missing file: %v", err)
	}
	// A hard link to another file (fs.protected_hardlinks off) is not ours.
	hl := filepath.Join(dir, "hard.json")
	if err := os.Link(victim, hl); err != nil {
		t.Fatal(err)
	}
	if err := chownRegularFile(hl, os.Getgid()); err == nil {
		t.Error("chownRegularFile accepted a hard link")
	}

	reg := filepath.Join(dir, "real.json")
	if err := os.WriteFile(reg, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if g := testGID(); g != 0 {
		if err := chownRegularFile(reg, g); err != nil || gidOf(t, reg) != g {
			t.Errorf("regular file: err=%v group %d, want %d", err, gidOf(t, reg), g)
		}
	}
}
