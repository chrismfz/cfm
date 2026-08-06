package enrich

import (
	"path/filepath"
	"testing"
	"time"
)

// resetSharedPTRForTest tears down any process-wide store a test enabled, so the
// global default (nil = in-memory only) is restored for other tests.
func resetSharedPTRForTest(t *testing.T) {
	t.Helper()
	sharedPTRMu.Lock()
	if sharedPTR != nil {
		sharedPTR.close()
		sharedPTR = nil
	}
	sharedPTRMu.Unlock()
}

func TestPTRStore_PersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ptr.db")

	s, err := openPTRStore(path, ptrCacheTTL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.upsert(ptrRow{ip: "8.8.8.8", ptr: "dns.google"}) // deterministic (sync) write
	if got, ok := s.get("8.8.8.8"); !ok || got != "dns.google" {
		t.Fatalf("get after upsert = %q,%v; want dns.google,true", got, ok)
	}
	s.close()

	// Reopen the same file — the row must still be there.
	s2, err := openPTRStore(path, ptrCacheTTL)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.close()
	if got, ok := s2.get("8.8.8.8"); !ok || got != "dns.google" {
		t.Fatalf("get after reopen = %q,%v; want dns.google,true (not persisted?)", got, ok)
	}
}

func TestPTRStore_TTLExpiry(t *testing.T) {
	s, err := openPTRStore(filepath.Join(t.TempDir(), "ptr.db"), 24*time.Hour)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.close()

	// Insert a row resolved 40 days ago — well past the 24h TTL used here.
	old := time.Now().Add(-40 * 24 * time.Hour).Unix()
	if _, err := s.db.Exec(`INSERT INTO ptr(ip, ptr, resolved_at) VALUES(?,?,?)`, "1.2.3.4", "stale.example", old); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got, ok := s.get("1.2.3.4"); ok {
		t.Fatalf("expected TTL-expired miss, got %q", got)
	}
}

func TestPTRStore_NegativeNotStored(t *testing.T) {
	s, err := openPTRStore(filepath.Join(t.TempDir(), "ptr.db"), ptrCacheTTL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.close()
	s.put("9.9.9.9", "") // empty PTR must be ignored
	s.put("", "x")       // empty IP must be ignored
	if _, ok := s.get("9.9.9.9"); ok {
		t.Fatalf("empty PTR should not be stored")
	}
}

func TestPTRStore_AsyncPut(t *testing.T) {
	s, err := openPTRStore(filepath.Join(t.TempDir(), "ptr.db"), ptrCacheTTL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.close()
	s.put("8.8.4.4", "dns.google")
	// The write is handled by the background writer; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := s.get("8.8.4.4"); ok && got == "dns.google" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("async put never became visible via get")
}

// TestLookupReadsSharedPTRStore proves the L2 path in Lookup: with the shared
// store seeded and the Enricher's L1 empty, Lookup returns the PTR from the
// persistent store WITHOUT a reverse-DNS query (the seeded value is not what
// real rDNS of 8.8.8.8 returns via this path — it comes straight from L2).
func TestLookupReadsSharedPTRStore(t *testing.T) {
	resetSharedPTRForTest(t) // start clean
	if err := EnablePersistentPTR(filepath.Join(t.TempDir(), "ptr.db")); err != nil {
		t.Fatalf("enable: %v", err)
	}
	t.Cleanup(func() { resetSharedPTRForTest(t) })

	sharedPTRStore().upsert(ptrRow{ip: "8.8.8.8", ptr: "shared.l2.example"})

	e, err := New(t.TempDir()) // fresh Enricher, empty L1, no mmdb
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()

	if got := e.Lookup("8.8.8.8").PTR; got != "shared.l2.example" {
		t.Fatalf("PTR = %q, want shared.l2.example served from the persistent L2", got)
	}
	// And L1 should now be warmed with the L2 value.
	if got, ok := e.ptrCache.Get("8.8.8.8"); !ok || got != "shared.l2.example" {
		t.Fatalf("L1 not warmed from L2: %q,%v", got, ok)
	}
}
