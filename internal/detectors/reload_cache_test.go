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

// A poll parses detectors.conf only when the base file or an overlay moved.
func TestReadForReloadParsesOnlyOnAChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detectors.conf")
	if err := os.WriteFile(path, []byte("[global]\nA = 1\n\n[ssh]\nENABLED = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reads := countReads(t)
	m := &manager{}
	read := func() Sections {
		t.Helper()
		s, err, fb := m.readForReload(path)
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
	s1, _, _ := m.readForReload(path)
	s1.ByName["extra"] = KV{"X": "1"}
	s1.ByName["ssh"]["ENABLED"] = "0"
	s1.Global["A"] = "changed"
	s2, _, _ := m.readForReload(path)
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
	m.readForReload(path)
	m.readForReload(path)
	if *reads != 2 {
		t.Fatalf("a missing file: %d reads, want 2", *reads)
	}
}

// A file replaced with its mtime kept (rsync -a writes a temp file and
// renames it; cp -p keeps the source's mtime) is read again AND moves the
// reload signature: cfgSig's mtime alone missed it, and the detectors kept
// the old config.
func TestAnMtimeKeepingReplaceReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detectors.conf")
	if err := os.WriteFile(path, []byte("[global]\nA = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	m := &manager{}
	s1, _, _ := m.readForReload(path)
	sig1 := cfgSig(&s1, m.readCache.files)

	tmp := filepath.Join(dir, ".detectors.conf.tmp")
	if err := os.WriteFile(tmp, []byte("[global]\nA = 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(tmp, st.ModTime(), st.ModTime())
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	s2, _, _ := m.readForReload(path)
	if s2.Global["A"] != "2" {
		t.Fatalf("after the replace: A=%q, want 2 (the cached read was reused)", s2.Global["A"])
	}
	if s2.StampNS != s1.StampNS {
		t.Fatal("setup: the mtime moved")
	}
	if cfgSig(&s2, m.readCache.files) == sig1 {
		t.Fatal("the reload signature did not move: the detectors keep the old config")
	}
	// Unchanged files: the same signature, poll after poll.
	s3, _, _ := m.readForReload(path)
	if cfgSig(&s3, m.readCache.files) != cfgSig(&s2, m.readCache.files) {
		t.Fatal("the signature moved with nothing changed")
	}
}
