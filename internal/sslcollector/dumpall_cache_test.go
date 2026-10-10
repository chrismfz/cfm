package sslcollector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newSnapshotCollector seeds a Collector with one exact + one wild entry backed
// by real files, and points the snapshot at a temp path.
func newSnapshotCollector(t *testing.T) (*Collector, string) {
	t.Helper()
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	if err := os.WriteFile(certPath, []byte(strings.Repeat("CERT", 64)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("KEY", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	col := New(Config{CacheDir: tmp})
	col.exact = map[string]*Entry{"a.example.com": {Fingerprint: "fpA", CertPath: certPath, KeyPath: keyPath, NotAfter: time.Now().Add(24 * time.Hour)}}
	col.wildSuffix = map[string]*Entry{"example.com": {Fingerprint: "fpW", CertPath: certPath, KeyPath: keyPath, NotAfter: time.Now().Add(24 * time.Hour)}}
	orig := snapshotPathForTests
	snapshotPathForTests = filepath.Join(tmp, "dump.json")
	t.Cleanup(func() { snapshotPathForTests = orig })
	return col, snapshotPathForTests
}

// The header comes off the front of the file: counts written ahead of the
// entries are read without decoding them (a ~110 MB snapshot used to be fully
// unmarshalled on every write, for the regression guard's two numbers).
func TestReadSnapshotHeaderStopsBeforeTheEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.json")
	// Everything after "exact": is garbage: decoding it would fail.
	body := `{"version":"v9","generated_at":"2026-10-10T00:00:00Z","exact_n":2,"wild_n":1,"exact":[GARBAGE`
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	h, ok := readSnapshotHeader(path, true)
	if !ok || h.Version != "v9" || h.ExactN != 2 || h.WildN != 1 {
		t.Fatalf("header %+v ok=%v, want v9 2/1 from the front", h, ok)
	}
	if ex, wi, ok := readSnapshotCounts(path); !ok || ex != 2 || wi != 1 {
		t.Fatalf("readSnapshotCounts = %d,%d,%v", ex, wi, ok)
	}
}

// A Refresh that changes nothing (the hourly discovery tick, the stat tick
// and the watcher both firing for one change) does not rebuild and rewrite
// the snapshot: on earth that was ~110 MB and ~18 s each time.
func TestWriteSnapshotSkipsAnUnchangedVersion(t *testing.T) {
	col, path := newSnapshotCollector(t)
	col.WriteSnapshot()
	h, ok := readSnapshotHeader(path, true)
	if !ok || h.ExactN != 1 || h.WildN != 1 || h.Version != col.Stats().Version {
		t.Fatalf("first write: %+v ok=%v", h, ok)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	col.WriteSnapshot()
	if st, _ := os.Stat(path); !st.ModTime().Equal(old) {
		t.Errorf("unchanged version rewritten (mtime %v)", st.ModTime())
	}

	// A changed index is written.
	col.mu.Lock()
	col.exact["b.example.com"] = col.exact["a.example.com"]
	col.mu.Unlock()
	col.WriteSnapshot()
	if st, _ := os.Stat(path); st.ModTime().Equal(old) {
		t.Error("changed index not written")
	}
	if h, _ := readSnapshotHeader(path, true); h.ExactN != 2 {
		t.Errorf("rewritten snapshot exact_n=%d, want 2", h.ExactN)
	}
}

// A name moving to another, already known pair (betterEntry ranks by
// validity at scan time, so it happens as a cert expires with no pair
// changing) is a new version: the workers refetch and the snapshot is
// rewritten.
func TestVersionReflectsTheNameToPairMapping(t *testing.T) {
	col, _ := newSnapshotCollector(t)
	v1 := col.Stats().Version
	col.mu.Lock()
	a, w := col.exact["a.example.com"], col.wildSuffix["example.com"]
	col.exact["a.example.com"], col.wildSuffix["example.com"] = w, a
	col.mu.Unlock()
	if col.Stats().Version == v1 {
		t.Fatal("swapping which pair serves each name did not change the version")
	}
}

// /dumpall streams the snapshot file when it is the current version (no
// rebuild per worker), and builds the payload otherwise.
func TestDumpAllServesTheCurrentSnapshot(t *testing.T) {
	col, path := newSnapshotCollector(t)
	s := &sockServer{col: col, cfg: SockServerConfig{Token: strongToken}}
	get := func() string {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/dumpall", nil)
		req.Header.Set("X-SSLCollector-Token", strongToken)
		s.handleDumpAll(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		return rr.Body.String()
	}

	ver := col.Stats().Version
	marker := `{"version":"` + ver + `","exact_n":0,"wild_n":0,"exact":[],"wild":[],"marker":"from-file"}`
	if err := os.WriteFile(path, []byte(marker), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := get(); got != marker {
		t.Errorf("current snapshot not served as is:\n%s", got)
	}

	// An older snapshot (the regression guard kept it): built instead.
	if err := os.WriteFile(path, []byte(strings.Replace(marker, ver, "older", 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := get(); strings.Contains(got, "from-file") || !strings.Contains(got, `"a.example.com"`) {
		t.Errorf("stale snapshot served:\n%.200s", got)
	}
}
