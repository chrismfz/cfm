package detectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// countReads counts the layered reads the manager makes.
func countReads(t *testing.T) *int {
	t.Helper()
	n := new(int)
	orig := readLayered
	readLayered = func(base, dir string) (Sections, []byte, error) {
		*n++
		return orig(base, dir)
	}
	t.Cleanup(func() { readLayered = orig })
	return n
}

// A poll parses detectors.conf only when the base file or an overlay moved,
// or when the last read is older than reloadFullReadEvery.
func TestReadForReloadParsesOnlyOnAChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detectors.conf")
	if err := os.WriteFile(path, []byte("[global]\nA = 1\n\n[ssh]\nENABLED = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reads := countReads(t)
	m := &manager{}
	now := time.Now()
	read := func() Sections {
		t.Helper()
		s, err, fb := m.readForReload(path, now)
		if err != nil || fb {
			t.Fatalf("read: %v fallback=%v", err, fb)
		}
		return s
	}
	read()
	read()
	if *reads != 1 {
		t.Fatalf("an unchanged file: %d reads, want 1", *reads)
	}

	// An edit (a new size) is read at once.
	if err := os.WriteFile(path, []byte("[global]\nA = 22\n\n[ssh]\nENABLED = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s := read(); s.Global["A"] != "22" || *reads != 2 {
		t.Fatalf("after an edit: A=%q, %d reads; want 22, 2", s.Global["A"], *reads)
	}

	// A new overlay, with an old mtime (cp -p), is read at once.
	dd := filepath.Join(dir, "detectors.d")
	if err := os.Mkdir(dd, 0o700); err != nil {
		t.Fatal(err)
	}
	ov := filepath.Join(dd, "10-x.conf")
	if err := os.WriteFile(ov, []byte("[global]\nB = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(ov, old, old)
	if s := read(); s.Global["B"] != "3" || *reads != 3 {
		t.Fatalf("after a new overlay: B=%q, %d reads; want 3, 3", s.Global["B"], *reads)
	}

	// An edit the stamp cannot see (same size, mtime put back) is read once
	// the last read is reloadFullReadEvery old.
	st, _ := os.Stat(path)
	if err := os.WriteFile(path, []byte("[global]\nA = 99\n\n[ssh]\nENABLED = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(path, st.ModTime(), st.ModTime())
	if s := read(); s.Global["A"] != "22" || *reads != 3 {
		t.Fatalf("an invisible edit: A=%q, %d reads; want the cached 22, 3", s.Global["A"], *reads)
	}
	now = now.Add(reloadFullReadEvery)
	if s := read(); s.Global["A"] != "99" || *reads != 4 {
		t.Fatalf("after %s: A=%q, %d reads; want 99, 4", reloadFullReadEvery, s.Global["A"], *reads)
	}
}

// What the poll adds to its copy (the built-in sections) never reaches the
// cached read, and the copy keeps Global as ByName["global"].
func TestReadForReloadCopyIsTheCallers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detectors.conf")
	if err := os.WriteFile(path, []byte("[global]\nA = 1\n\n[ssh]\nENABLED = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	countReads(t)
	m := &manager{}
	now := time.Now()
	s1, _, _ := m.readForReload(path, now)
	s1.ByName["extra"] = KV{"X": "1"}
	s1.ByName["ssh"]["ENABLED"] = "0"
	s1.Global["A"] = "changed"
	s2, _, _ := m.readForReload(path, now)
	if _, ok := s2.ByName["extra"]; ok || s2.ByName["ssh"]["ENABLED"] != "1" || s2.Global["A"] != "1" {
		t.Fatalf("the cached read changed through a copy: %+v", s2.ByName)
	}
	s2.Global["Z"] = "z"
	if s2.ByName["global"]["Z"] != "z" {
		t.Fatal("the copy's Global is not its ByName[\"global\"]")
	}
}

// A failed read is never reused: the next poll reads again.
func TestReadForReloadDoesNotCacheAMissingFile(t *testing.T) {
	reads := countReads(t)
	m := &manager{running: true}
	path := filepath.Join(t.TempDir(), "detectors.conf")
	now := time.Now()
	m.readForReload(path, now)
	m.readForReload(path, now)
	if *reads != 2 {
		t.Fatalf("a missing file: %d reads, want 2", *reads)
	}
}
