package sslcollector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// snapshotRoundTripTestHelpers exercise writeSnapshotAtomic +
// readSnapshotCounts without depending on the full Collector. The
// Collector-side WriteSnapshot is exercised in the daemon-level
// integration test below.

func TestWriteSnapshotAtomic_RoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.json")
	body := []byte(`{"version":"abc","exact":[{"x":1}],"wild":[]}`)

	if err := writeSnapshotAtomic(path, body); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o640 {
		t.Fatalf("mode = %o, want 640", got)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body mismatch: %s", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf(".tmp leaked: %v", err)
	}
}

func TestReadSnapshotCounts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.json")
	payload := map[string]any{
		"version": "v1",
		"exact":   []any{map[string]any{"host": "a"}, map[string]any{"host": "b"}},
		"wild":    []any{map[string]any{"suffix": "x"}},
	}
	b, _ := json.Marshal(payload)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ex, wi, ok := readSnapshotCounts(path)
	if !ok {
		t.Fatalf("expected ok")
	}
	if ex != 2 || wi != 1 {
		t.Fatalf("counts = (%d,%d), want (2,1)", ex, wi)
	}

	if _, _, ok := readSnapshotCounts(filepath.Join(dir, "missing.json")); ok {
		t.Fatalf("missing file should report ok=false")
	}
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("seed garbage: %v", err)
	}
	if _, _, ok := readSnapshotCounts(path); ok {
		t.Fatalf("garbage file should report ok=false")
	}
}
