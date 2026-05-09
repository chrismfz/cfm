package kernsec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFile_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")

	if err := AtomicWriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello\n" {
		t.Errorf("got %q, want %q", got, "hello\n")
	}

	st, _ := os.Stat(path)
	if mode := st.Mode().Perm(); mode != 0o644 {
		t.Errorf("perm = %v, want 0644", mode)
	}

	// No tmp file should remain.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "out.conf" {
			t.Errorf("stray file in dir: %s", e.Name())
		}
	}
}

func TestAtomicWriteFile_OverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("got %q, want %q", got, "new")
	}
}

func TestAtomicWriteFile_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "nested", "out.conf")
	if err := AtomicWriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestBackupOnce_HappyPath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.conf")
	dst := filepath.Join(dir, "src.conf.bak")
	if err := os.WriteFile(src, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := BackupOnce(src, dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "original" {
		t.Errorf("backup = %q, want %q", got, "original")
	}
}

func TestBackupOnce_DoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.conf")
	dst := filepath.Join(dir, "src.conf.bak")
	if err := os.WriteFile(src, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("v1-original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := BackupOnce(src, dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "v1-original" {
		t.Errorf("backup overwritten: got %q, want %q", got, "v1-original")
	}
}

func TestBackupOnce_MissingSourceIsNoOp(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "missing")
	dst := filepath.Join(dir, "missing.bak")
	if err := BackupOnce(src, dst); err != nil {
		t.Fatalf("expected no error for missing src, got %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("dst should not exist when src is missing")
	}
}
