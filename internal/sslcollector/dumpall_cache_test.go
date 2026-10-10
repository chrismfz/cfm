package sslcollector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	before, _ := os.ReadFile(path)
	old := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond) // generated_at would differ on a rebuild
	col.WriteSnapshot()
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Errorf("unchanged version rebuilt and rewritten")
	}
	// ...but re-stamped: the regression guard's staleness release reads the
	// mtime as "not confirmed current", and a quiet week must not release it.
	if st, _ := os.Stat(path); !st.ModTime().After(old.Add(time.Hour)) {
		t.Errorf("skipped write left the mtime at %v: the regression guard would release on a partial scan", st.ModTime())
	}

	old2 := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old2, old2); err != nil {
		t.Fatal(err)
	}
	// A changed index is written.
	col.mu.Lock()
	col.exact["b.example.com"] = col.exact["a.example.com"]
	col.mu.Unlock()
	col.WriteSnapshot()
	if st, _ := os.Stat(path); st.ModTime().Equal(old2) {
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
	marker := `{"version":"` + ver + `","exact_n":0,"wild_n":0,"complete":true,"exact":[],"wild":[],"marker":"from-file"}`
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

// A payload that lost an entry (its PEM could not be read: EIO, a key briefly
// missing) keeps the index's version, but is not complete: it is not served
// as current and not skipped as unchanged, so the next /dumpall and Refresh
// rebuild it (as every /dumpall did before) instead of serving the gap until
// some other cert changes.
func TestIncompleteSnapshotIsNeitherServedNorKept(t *testing.T) {
	col, path := newSnapshotCollector(t)
	// a.example.com gets its own key file (the wild entry keeps the shared one).
	key := col.exact["a.example.com"].KeyPath + ".a"
	if err := os.WriteFile(key, []byte("KEYA"), 0o600); err != nil {
		t.Fatal(err)
	}
	col.exact["a.example.com"] = &Entry{Fingerprint: "fpA2", CertPath: col.exact["a.example.com"].CertPath, KeyPath: key, NotAfter: time.Now().Add(24 * time.Hour)}
	if err := os.Rename(key, key+".gone"); err != nil {
		t.Fatal(err)
	}
	col.WriteSnapshot()
	h, ok := readSnapshotHeader(path, true)
	if !ok || h.Complete || h.ExactN != 0 {
		t.Fatalf("snapshot with an unreadable key: %+v ok=%v, want written but not complete", h, ok)
	}
	if f, _, ok := openCurrentSnapshot(col.Stats().Version); ok {
		f.Close()
		t.Error("incomplete snapshot served as current")
	}
	if err := os.Rename(key+".gone", key); err != nil {
		t.Fatal(err)
	}
	col.WriteSnapshot() // same version, but the file is not complete: rewritten
	if h, _ := readSnapshotHeader(path, true); !h.Complete || h.ExactN != 1 {
		t.Errorf("after the key came back: %+v, want a complete rewrite", h)
	}
}

// A Refresh swapping the index between the payload's version read and its
// copy of the maps labels the content with a version it does not have: such
// a payload is not complete, so the snapshot is not trusted at that label.
func TestPayloadRacingARefreshIsNotComplete(t *testing.T) {
	col, path := newSnapshotCollector(t)
	dumpAllAfterStatsHook = func() {
		col.mu.Lock()
		col.exact["late.example.com"] = col.exact["a.example.com"]
		col.mu.Unlock()
	}
	t.Cleanup(func() { dumpAllAfterStatsHook = nil })
	col.WriteSnapshot()
	h, ok := readSnapshotHeader(path, true)
	if !ok || h.Complete {
		t.Fatalf("payload built across an index swap: %+v ok=%v, want complete=false", h, ok)
	}
	dumpAllAfterStatsHook = nil
	col.WriteSnapshot() // same version now, but not complete: rewritten
	if h, _ := readSnapshotHeader(path, true); !h.Complete || h.ExactN != 2 || h.Version != col.Stats().Version {
		t.Errorf("rewrite after the race: %+v", h)
	}
}

// While the snapshot is not current (the window between a Refresh's swap and
// its WriteSnapshot, when every worker fetches), concurrent /dumpall calls
// share one build instead of rebuilding ~110 MB each at the same time.
func TestDumpAllFallbackBuildsOncePerVersion(t *testing.T) {
	col, path := newSnapshotCollector(t)
	_ = os.Remove(path) // no snapshot: every /dumpall falls back
	builds := 0
	dumpAllAfterStatsHook = func() { builds++ }
	t.Cleanup(func() { dumpAllAfterStatsHook = nil })
	s := &sockServer{col: col, cfg: SockServerConfig{Token: strongToken}}

	var wg sync.WaitGroup
	bodies := make([]string, 6)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/dumpall", nil)
			req.Header.Set("X-SSLCollector-Token", strongToken)
			s.handleDumpAll(rr, req)
			bodies[i] = rr.Body.String()
		}(i)
	}
	wg.Wait()
	if builds != 1 {
		t.Errorf("6 concurrent fallbacks made %d builds, want 1", builds)
	}
	for i, b := range bodies {
		if !strings.Contains(b, `"a.example.com"`) || b != bodies[0] {
			t.Errorf("worker %d got a different or empty payload", i)
		}
	}

	// A new version is built afresh.
	col.mu.Lock()
	col.exact["b.example.com"] = col.exact["a.example.com"]
	col.mu.Unlock()
	if b, _ := col.dumpAllFallback(); builds != 2 || !strings.Contains(string(b), `"b.example.com"`) {
		t.Errorf("new version: builds=%d", builds)
	}
}

// A fallback payload that lost an entry (a PEM read error) is served but not
// reused: the next request rebuilds instead of handing the gap to every
// worker until the next version change.
func TestDumpAllFallbackDoesNotReuseAnIncompletePayload(t *testing.T) {
	col, path := newSnapshotCollector(t)
	_ = os.Remove(path)
	key := col.exact["a.example.com"].KeyPath + ".a"
	if err := os.WriteFile(key, []byte("KEYA"), 0o600); err != nil {
		t.Fatal(err)
	}
	col.exact["a.example.com"] = &Entry{Fingerprint: "fpA2", CertPath: col.exact["a.example.com"].CertPath, KeyPath: key, NotAfter: time.Now().Add(24 * time.Hour)}
	if err := os.Rename(key, key+".gone"); err != nil {
		t.Fatal(err)
	}
	b1, _ := col.dumpAllFallback()
	if strings.Contains(string(b1), `"a.example.com"`) {
		t.Fatal("setup: the unreadable entry made it in")
	}
	if err := os.Rename(key+".gone", key); err != nil {
		t.Fatal(err)
	}
	if b2, _ := col.dumpAllFallback(); !strings.Contains(string(b2), `"a.example.com"`) {
		t.Error("incomplete fallback payload reused: the host stays missing for every worker")
	}
}
