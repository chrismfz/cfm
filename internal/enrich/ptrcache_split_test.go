package enrich

import "testing"

// TestLookupUsesLongLivedPTRCache proves the PTR/geo split: a PTR already in the
// long-lived ptrCache is returned by Lookup WITHOUT a reverse-DNS query. The
// seeded value is one real rDNS would never return for 8.8.8.8 (dns.google), so
// getting it back proves the cache short-circuited the blocking resolve.
func TestLookupUsesLongLivedPTRCache(t *testing.T) {
	e, err := New(t.TempDir()) // no mmdb here: geo empty, PTR path still active
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()

	const ip = "8.8.8.8" // routable, so the PTR branch runs
	const seeded = "cached.example.test"
	e.ptrCache.Add(ip, seeded)

	if got := e.Lookup(ip).PTR; got != seeded {
		t.Fatalf("PTR = %q, want %q served from the long-lived ptrCache", got, seeded)
	}
}
