package enrich

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The generated databases must be real to the real reader: geoip2.Open maps
// them and decodes ASN/City exactly as it would GeoLite2.
func TestGeneratedMMDBIsReadByTheRealReader(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeMMDB(t, dir, "GeoLite2-ASN.mmdb", buildMMDB("GeoLite2-ASN", asnRecord(6799, "OTEnet S.A.")), now)
	writeMMDB(t, dir, "GeoLite2-City.mmdb", buildMMDB("GeoLite2-City", cityRecord("GR", "Greece", "Athens")), now)

	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	r := e.LookupGeoFast("94.68.42.127")
	if r.ASN != 6799 || r.ASNName != "OTEnet S.A." || r.CountryISO != "GR" || r.Country != "Greece" || r.City != "Athens" {
		t.Fatalf("real reader decoded %+v from the generated databases", r)
	}
}

// hotSwapFixture installs databases in dir and returns an Enricher on them
// plus a swap function that replaces both files the way geoipupdate does and
// forces the refresh (bypassing the 300s stat rate limit). Each swap flips the
// ASN between two values, so a reader can prove a swap actually happened.
func hotSwapFixture(t *testing.T) (*Enricher, func()) {
	t.Helper()
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	install := func(asn uint32, mt time.Time) {
		writeMMDB(t, dir, "GeoLite2-ASN.mmdb", buildMMDB("GeoLite2-ASN", asnRecord(asn, "Test AS")), mt)
		writeMMDB(t, dir, "GeoLite2-City.mmdb", buildMMDB("GeoLite2-City", cityRecord("GR", "Greece", "Athens")), mt)
	}
	install(6799, base)
	e, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	e.enablePTR = false // the full Lookup path must not touch the network
	n := 0
	swap := func() {
		n++
		asn := uint32(6799)
		if n%2 == 1 {
			asn = 3329
		}
		install(asn, base.Add(time.Duration(n)*time.Second))
		e.statChk.Store(0) // bypass the 300s stat rate limit
		e.refreshIfChanged()
	}
	return e, swap
}

// The weekly GeoLite2 update swaps the mmdb readers under live traffic. The
// old reader used to be closed (munmap'd) while a lookup that had already
// copied its pointer was still decoding from it: an unrecoverable SIGSEGV that
// took the daemon down — reproduced on the old code within ~2s by this test
// (`fatal error: fault` / `signal SIGSEGV`), and as a DATA RACE on
// maxminddb.Reader.Close under -race. The readers now hold mu.RLock for the
// whole read and a swapped-out reader is closed only once none can be reading
// it, so every lookup — on either path — sees a complete database: the old
// one or the new one, never a closed one (which read back as empty geo).
func TestHotSwapNeverReadsAClosedReader(t *testing.T) {
	e, swap := hotSwapFixture(t)
	defer e.Close()

	var stop atomic.Bool
	var seen sync.Map // ASN values observed by readers
	var bad atomic.Int64
	var wg sync.WaitGroup
	check := func(r Result) {
		if (r.ASN != 6799 && r.ASN != 3329) || r.CountryISO != "GR" {
			bad.Add(1)
			return
		}
		seen.Store(r.ASN, true)
	}
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				if g%2 == 0 {
					check(e.LookupGeoFast("94.68.42.127"))
				} else {
					// The full path, on a fresh address each time (16M per
					// goroutine before any repeats) so the cache never
					// answers for it; PTR is off, so no network.
					check(e.Lookup(fmt.Sprintf("%d.%d.%d.%d", 1+g, (i>>16)&255, (i>>8)&255, i&255)))
				}
			}
		}(g)
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	swaps := 0
	for ; time.Now().Before(deadline); swaps++ {
		swap()
	}
	stop.Store(true)
	wg.Wait()

	if n := bad.Load(); n > 0 {
		t.Fatalf("%d lookups read a closed or half-swapped database (empty/unknown geo) across %d swaps", n, swaps)
	}
	for _, asn := range []uint{6799, 3329} {
		if _, ok := seen.Load(asn); !ok {
			t.Fatalf("readers never saw ASN %d in %d swaps — the swaps did not happen under load, so this test checked nothing", asn, swaps)
		}
	}
}

// Close under live lookups must not fault either, and a lookup after Close
// sees no database (empty geo), not an unmapped one.
func TestCloseUnderLookupsIsSafe(t *testing.T) {
	e, _ := hotSwapFixture(t)
	var stop atomic.Bool
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_ = e.LookupGeoFast("94.68.42.127")
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	e.Close()
	time.Sleep(50 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	if r := e.LookupGeoFast("94.68.42.127"); r.ASN != 0 || r.CountryISO != "" {
		t.Fatalf("lookup after Close returned %+v, want empty geo", r)
	}
	if e.Enabled() {
		t.Fatal("Enabled() must be false once the databases are closed")
	}
}
