package sslcollector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
// share one build (an unlinked temp file, reused for its version).
func TestDumpAllBuildsOncePerVersion(t *testing.T) {
	col, path := newSnapshotCollector(t)
	_ = os.Remove(path) // no snapshot
	var mu sync.Mutex
	builds := 0
	dumpAllAfterStatsHook = func() { mu.Lock(); builds++; mu.Unlock() }
	t.Cleanup(func() { dumpAllAfterStatsHook = nil })
	s := &sockServer{col: col, cfg: SockServerConfig{Token: strongToken}}

	var wg sync.WaitGroup
	bodies := make([]string, 6)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bodies[i] = dumpAllBody(t, s)
		}(i)
	}
	wg.Wait()
	if builds != 1 {
		t.Errorf("6 concurrent /dumpall made %d builds, want 1", builds)
	}
	for i, b := range bodies {
		if !strings.Contains(b, `"a.example.com"`) || b != bodies[0] {
			t.Errorf("worker %d got a different or empty payload", i)
		}
	}

	// A new version is built afresh (and becomes the snapshot).
	col.mu.Lock()
	col.exact["b.example.com"] = col.exact["a.example.com"]
	col.mu.Unlock()
	if b := dumpAllBody(t, s); builds != 2 || !strings.Contains(b, `"b.example.com"`) {
		t.Errorf("new version: builds=%d", builds)
	}
	// /dumpall never writes the snapshot: Refresh does.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("/dumpall wrote the snapshot: %v", err)
	}
}

func dumpAllBody(t *testing.T, s *sockServer) string {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dumpall", nil)
	req.Header.Set("X-SSLCollector-Token", strongToken)
	s.handleDumpAll(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/dumpall status %d", rr.Code)
	}
	return rr.Body.String()
}

// A payload that lost an entry (a PEM read error) is served (it is the best
// that version has), and the next /dumpall after the PEM is back rebuilds it
// instead of handing the gap to every worker until the next version change.
func TestDumpAllRebuildsAnIncompletePayload(t *testing.T) {
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
	s := &sockServer{col: col, cfg: SockServerConfig{Token: strongToken}}
	if b := dumpAllBody(t, s); strings.Contains(b, `"a.example.com"`) || !strings.Contains(b, `"example.com"`) {
		t.Fatalf("setup: unexpected payload %.200s", b)
	}
	if err := os.Rename(key+".gone", key); err != nil {
		t.Fatal(err)
	}
	if b := dumpAllBody(t, s); !strings.Contains(b, `"a.example.com"`) {
		t.Error("incomplete payload reused: the host stays missing for every worker")
	}
}

// When the regression guard keeps an older snapshot, /dumpall still serves
// the current index (built to a temp file), and the snapshot is left alone.
func TestDumpAllServesTheIndexWhenTheGuardKeepsTheSnapshot(t *testing.T) {
	col, path := newSnapshotCollector(t)
	big := `{"version":"older","exact_n":100,"wild_n":0,"complete":true,"exact":[],"wild":[]}`
	if err := os.WriteFile(path, []byte(big), 0o640); err != nil {
		t.Fatal(err)
	}
	s := &sockServer{col: col, cfg: SockServerConfig{Token: strongToken}}
	builds := 0
	dumpAllAfterStatsHook = func() { builds++ }
	t.Cleanup(func() { dumpAllAfterStatsHook = nil })
	b := dumpAllBody(t, s)
	h, ok := readSnapshotHeaderFrom(strings.NewReader(b), true)
	if !ok || h.Version != col.Stats().Version || h.ExactN != 1 || h.WildN != 1 || !h.Complete {
		t.Errorf("served %+v ok=%v, want the current index", h, ok)
	}
	// The workers' retries reuse it: not a rewrite of the snapshot (refused
	// by the guard) plus a build per request.
	for i := 0; i < 3; i++ {
		if dumpAllBody(t, s) != b {
			t.Errorf("retry %d served another payload", i)
		}
	}
	if builds != 1 {
		t.Errorf("4 /dumpall under the guard made %d builds, want 1", builds)
	}
	if got, _ := os.ReadFile(path); string(got) != big {
		t.Error("the guarded snapshot was overwritten")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".dumpall-*")); len(left) != 0 {
		t.Errorf("temp build left behind: %v", left)
	}
}

// bigCollector: 60 certs, 40 names each, ~8 KB of PEM per cert — a payload
// many times the size of its unique PEMs, as on a cPanel node.
func bigCollector(t *testing.T) (*Collector, string) {
	t.Helper()
	col, path := newSnapshotCollector(t)
	dir := filepath.Dir(path)
	col.exact = map[string]*Entry{}
	col.wildSuffix = map[string]*Entry{}
	pem := strings.Repeat("MIIFazCCBFOgAwIBAgISA0123456789abcdefghijklmnopqrstuvwxyz0123/+\n", 120)
	for i := 0; i < 60; i++ {
		cp := filepath.Join(dir, fmt.Sprintf("c%d.pem", i))
		kp := filepath.Join(dir, fmt.Sprintf("k%d.pem", i))
		if err := os.WriteFile(cp, []byte(pem), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(kp, []byte(pem[:1700]), 0o600); err != nil {
			t.Fatal(err)
		}
		e := &Entry{Fingerprint: fmt.Sprintf("fp%03d", i), CertPath: cp, KeyPath: kp, NotAfter: time.Now().Add(24 * time.Hour)}
		for j := 0; j < 40; j++ {
			col.exact[fmt.Sprintf("h%02d.d%03d.example", j, i)] = e
		}
		col.wildSuffix[fmt.Sprintf("d%03d.example", i)] = e
	}
	return col, path
}

func allocatedBy(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// The snapshot is written entry by entry: building it whole in memory (a map
// per entry, the JSON buffer, the encoder's copy) took about four times its
// size in heap — the daemon reached 1.2 GB on earth during an AutoSSL run.
func TestWriteSnapshotDoesNotHoldThePayloadInMemory(t *testing.T) {
	col, path := bigCollector(t)
	alloc := allocatedBy(col.WriteSnapshot)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if alloc > uint64(st.Size())/2 {
		t.Errorf("WriteSnapshot allocated %d KB for a %d KB snapshot, want under half of it", alloc>>10, st.Size()>>10)
	}
	var got struct {
		Exact []struct {
			Host    string `json:"host"`
			CertPEM string `json:"cert_pem"`
		} `json:"exact"`
		Wild []json.RawMessage `json:"wild"`
	}
	body, _ := os.ReadFile(path)
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if len(got.Exact) != 2400 || len(got.Wild) != 60 || got.Exact[0].Host != "h00.d000.example" || got.Exact[0].CertPEM == "" {
		t.Errorf("snapshot content: %d exact, %d wild, first %+v", len(got.Exact), len(got.Wild), got.Exact[0].Host)
	}
	if h, ok := readSnapshotHeader(path, false); !ok || !h.Complete || h.Version != col.Stats().Version {
		t.Errorf("header %+v ok=%v", h, ok)
	}
}

// /dumpall right after a version change (no current snapshot) does not
// build the payload in memory either: it builds it into a temp file.
func TestDumpAllAfterAVersionChangeDoesNotHoldThePayloadInMemory(t *testing.T) {
	col, path := bigCollector(t)
	col.WriteSnapshot()
	col.mu.Lock()
	col.exact["new.example"] = col.exact["h00.d000.example"]
	col.mu.Unlock()
	s := &sockServer{col: col, cfg: SockServerConfig{Token: strongToken}}
	var w discardWriter
	alloc := allocatedBy(func() {
		req := httptest.NewRequest(http.MethodGet, "/dumpall", nil)
		req.Header.Set("X-SSLCollector-Token", strongToken)
		s.handleDumpAll(&w, req)
	})
	if w.n < 1<<20 {
		t.Fatalf("served %d bytes", w.n)
	}
	if alloc > uint64(w.n)/2 {
		t.Errorf("/dumpall allocated %d KB for a %d KB payload, want under half of it", alloc>>10, w.n>>10)
	}
	_ = path
}

// No room for the temp build (a full /var): the payload is streamed to the
// worker as it is written, instead of a 500.
func TestDumpAllStreamsWhenNoTempFileCanBeMade(t *testing.T) {
	col, path := newSnapshotCollector(t)
	_ = os.Remove(path)
	orig := dumpAllTempDir
	dumpAllTempDir = func() string { return filepath.Join(path, "not-a-dir") }
	t.Cleanup(func() { dumpAllTempDir = orig })
	s := &sockServer{col: col, cfg: SockServerConfig{Token: strongToken}}
	var got struct {
		Version string            `json:"version"`
		Exact   []json.RawMessage `json:"exact"`
		Wild    []json.RawMessage `json:"wild"`
	}
	if err := json.Unmarshal([]byte(dumpAllBody(t, s)), &got); err != nil {
		t.Fatalf("streamed payload: %v", err)
	}
	if got.Version != col.Stats().Version || len(got.Exact) != 1 || len(got.Wild) != 1 {
		t.Errorf("streamed payload: %+v", got)
	}
}

// A shared build stays readable for whoever is reading it after it expires
// or is replaced, and is closed once the last reader is done.
func TestDumpAllBuildOutlivesItsReaders(t *testing.T) {
	col, path := newSnapshotCollector(t)
	_ = os.Remove(path)
	orig := dumpAllBuildTTL
	dumpAllBuildTTL = 300 * time.Millisecond
	t.Cleanup(func() { dumpAllBuildTTL = orig })
	b1, rel1, err := col.dumpAllBuilt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b2, rel2, _ := col.dumpAllBuilt(context.Background())
	if b2 != b1 {
		t.Fatal("not shared within the TTL")
	}
	rel2()
	time.Sleep(600 * time.Millisecond) // expired
	b3, rel3, _ := col.dumpAllBuilt(context.Background())
	if b3 == b1 {
		t.Fatal("reused past the TTL")
	}
	buf := make([]byte, 16)
	if _, err := b1.f.ReadAt(buf, 0); err != nil {
		t.Fatalf("expired build closed under its reader: %v", err)
	}
	rel1()
	rel1() // idempotent
	if _, err := b1.f.ReadAt(buf, 0); err == nil {
		t.Error("expired build left open after its last reader")
	}
	rel3()
	if _, err := b3.f.ReadAt(buf, 0); err != nil {
		t.Errorf("current build closed while still current: %v", err)
	}
}

type discardWriter struct {
	h http.Header
	n int64
}

func (d *discardWriter) Header() http.Header {
	if d.h == nil {
		d.h = http.Header{}
	}
	return d.h
}
func (d *discardWriter) Write(b []byte) (int, error) { d.n += int64(len(b)); return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}

// writeJSONString's output decodes to what encoding/json's would (invalid
// UTF-8 becomes U+FFFD in both), so the hand-written payload reads the same
// in the workers' cjson and in the Go readers.
func TestWriteJSONStringMatchesEncodingJSON(t *testing.T) {
	cases := []string{
		"", "plain", "-----BEGIN CERTIFICATE-----\nMIIF/+=\n-----END CERTIFICATE-----\n",
		`quote " backslash \ slash /`, "ctl \x00\x01\x1f\t\r\n\x7f", "ελληνικά é ü 漢字",
		"bad utf8 \xff\xfe end", "  ", "<script>&amp;</script>", "\\\"\\",
	}
	for _, in := range cases {
		var buf strings.Builder
		bw := bufio.NewWriter(&buf)
		writeJSONString(bw, in)
		if err := bw.Flush(); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
			t.Errorf("%q: invalid JSON %s: %v", in, buf.String(), err)
			continue
		}
		ref, _ := json.Marshal(in)
		var want string
		_ = json.Unmarshal(ref, &want)
		if got != want {
			t.Errorf("%q: decodes to %q, encoding/json's to %q", in, got, want)
		}
	}
}

// Every entry field round-trips, with the PEMs exactly as on disk.
func TestPayloadEntriesRoundTrip(t *testing.T) {
	col, path := newSnapshotCollector(t)
	col.WriteSnapshot()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version string              `json:"version"`
		ExactN  int                 `json:"exact_n"`
		WildN   int                 `json:"wild_n"`
		Exact   []map[string]string `json:"exact"`
		Wild    []map[string]string `json:"wild"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("payload: %v", err)
	}
	e := col.exact["a.example.com"]
	cert, _ := os.ReadFile(e.CertPath)
	key, _ := os.ReadFile(e.KeyPath)
	wantExact := map[string]string{"host": "a.example.com", "fingerprint": "fpA", "cert_pem": string(cert),
		"key_pem": string(key), "not_after": e.NotAfter.Format(time.RFC3339)}
	wantWild := map[string]string{"suffix": "example.com", "fingerprint": "fpW", "cert_pem": string(cert),
		"key_pem": string(key), "not_after": col.wildSuffix["example.com"].NotAfter.Format(time.RFC3339)}
	if got.Version != col.Stats().Version || got.ExactN != 1 || got.WildN != 1 || len(got.Exact) != 1 || len(got.Wild) != 1 {
		t.Fatalf("header/counts: %+v", got)
	}
	for k, v := range wantExact {
		if got.Exact[0][k] != v {
			t.Errorf("exact %s = %q, want %q", k, got.Exact[0][k], v)
		}
	}
	for k, v := range wantWild {
		if got.Wild[0][k] != v {
			t.Errorf("wild %s = %q, want %q", k, got.Wild[0][k], v)
		}
	}
	if len(got.Exact[0]) != len(wantExact) || len(got.Wild[0]) != len(wantWild) {
		t.Errorf("unexpected fields: %v / %v", got.Exact[0], got.Wild[0])
	}
}

// A caller that waited for the build lock serves the snapshot if it was
// written meanwhile, and a caller whose worker is gone builds nothing.
func TestDumpAllBuiltRechecksAfterWaiting(t *testing.T) {
	col, path := newSnapshotCollector(t)
	_ = os.Remove(path)
	builds := 0
	dumpAllAfterStatsHook = func() { builds++ }
	t.Cleanup(func() { dumpAllAfterStatsHook = nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := col.dumpAllBuilt(ctx); err == nil || builds != 0 {
		t.Errorf("cancelled caller: err=%v builds=%d", err, builds)
	}
	dumpAllAfterStatsHook = nil
	col.WriteSnapshot()
	builds = 0
	dumpAllAfterStatsHook = func() { builds++ }
	if _, _, err := col.dumpAllBuilt(context.Background()); !errors.Is(err, errSnapshotCurrent) || builds != 0 {
		t.Errorf("snapshot current: err=%v builds=%d", err, builds)
	}
}
