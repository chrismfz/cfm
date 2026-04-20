package authstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHardenSQLiteFiles(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "auth.db")
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	if err := HardenSQLiteFiles(db); err != nil {
		t.Fatalf("HardenSQLiteFiles: %v", err)
	}
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := st.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 600", p, got)
		}
	}
}

func TestHardenSQLiteFilesMissingOK(t *testing.T) {
	if err := HardenSQLiteFiles(filepath.Join(t.TempDir(), "missing.db")); err != nil {
		t.Fatalf("expected nil for missing files, got %v", err)
	}
}
