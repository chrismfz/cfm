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

// A GeoLite2 update swaps the mmdb readers under live traffic. The
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

// The refresh check is rate-limited lock-free (statChk). It must still run on
// the very first call ("never checked"), must NOT reopen within statEvery of
// the last check even when the files changed, and must pick the change up once
// the interval has passed.
func TestRefreshRateLimit(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	put := func(asn uint32, mt time.Time) {
		writeMMDB(t, dir, "GeoLite2-ASN.mmdb", buildMMDB("GeoLite2-ASN", asnRecord(asn, "Test AS")), mt)
	}
	put(6799, base)
	e, _ := New(dir)
	defer e.Close()
	asn := func() uint { return e.LookupGeoFast("94.68.42.127").ASN }

	put(3329, base.Add(time.Minute))
	e.refreshIfChanged() // first ever call: statChk is 0, so it checks
	if got := asn(); got != 3329 {
		t.Fatalf("the first refresh must run; ASN = %d, want 3329", got)
	}

	put(1241, base.Add(2*time.Minute))
	e.refreshIfChanged() // checked a moment ago: rate-limited
	if got := asn(); got != 3329 {
		t.Fatalf("a refresh within statEvery must not reopen; ASN = %d, want 3329", got)
	}

	// Pretend the last check was more than statEvery ago.
	e.statChk.Store(int64(time.Since(monoStart)) + 1 - int64(statEvery) - 1)
	e.refreshIfChanged()
	if got := asn(); got != 1241 {
		t.Fatalf("once statEvery has passed the change must be picked up; ASN = %d, want 1241", got)
	}
}

// Close is final: a refresh after it must not reopen the databases — a reader
// reopened then would never be closed, and Enabled/lookups would come back to
// life on a closed Enricher. (A refresh already past its stat when Close runs
// is covered by the same flag, checked again at the swap.)
func TestCloseIsFinal(t *testing.T) {
	e, swap := hotSwapFixture(t)
	e.Close()
	swap() // the files change and the rate limit is bypassed
	if e.Enabled() {
		t.Fatal("a refresh after Close reopened the databases")
	}
	if r := e.LookupGeoFast("94.68.42.127"); r.ASN != 0 || r.CountryISO != "" {
		t.Fatalf("lookup after Close read a database: %+v", r)
	}
}

// Fast-path lookups (LookupGeoFast, what challenge verify uses) while two
// goroutines take full-Lookup cache misses back to back — and every miss
// calls refreshIfChanged. Synthetic and miss-heavy, far above a production
// miss rate: it exaggerates any cost the miss path imposes on readers, which
// is the point. It caught a write lock taken on every miss just to test the
// refresh rate limit (see statChk) stalling readers. Self-contained on
// purpose (no hotSwapFixture), so the same file runs against older versions
// of enrich.go for an A/B.
func BenchmarkLookupGeoFastUnderMisses(b *testing.B) {
	dir := b.TempDir()
	mt := time.Now().Add(-time.Hour)
	writeMMDB(b, dir, "GeoLite2-ASN.mmdb", buildMMDB("GeoLite2-ASN", asnRecord(6799, "Test AS")), mt)
	writeMMDB(b, dir, "GeoLite2-City.mmdb", buildMMDB("GeoLite2-City", cityRecord("GR", "Greece", "Athens")), mt)
	e, err := New(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer e.Close()
	e.enablePTR = false // the miss path must not touch the network

	var stop atomic.Bool
	var wg sync.WaitGroup
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				_ = e.Lookup(fmt.Sprintf("%d.%d.%d.%d", 1+g, (i>>16)&255, (i>>8)&255, i&255))
			}
		}(g)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = e.LookupGeoFast("94.68.42.127")
		}
	})
	b.StopTimer()
	stop.Store(true)
	wg.Wait()
}

// HasASN / HasCountry track the databases actually loaded: nothing in an
// empty dir, each one once installed and picked up by the hot reload, and
// neither after Close.
func TestHasASNAndHasCountry(t *testing.T) {
	dir := t.TempDir()
	e, _ := New(dir)
	defer e.Close()
	if e.HasASN() || e.HasCountry() {
		t.Fatal("an empty dir must load no database")
	}

	writeMMDB(t, dir, "GeoLite2-ASN.mmdb", buildMMDB("GeoLite2-ASN", asnRecord(6799, "Test AS")), time.Now())
	e.statChk.Store(0) // bypass the 300s stat rate limit
	e.refreshIfChanged()
	if !e.HasASN() || e.HasCountry() {
		t.Fatalf("after installing only the ASN database: HasASN=%v HasCountry=%v", e.HasASN(), e.HasCountry())
	}

	writeMMDB(t, dir, "GeoLite2-City.mmdb", buildMMDB("GeoLite2-City", cityRecord("GR", "Greece", "Athens")), time.Now())
	e.statChk.Store(0)
	e.refreshIfChanged()
	if !e.HasASN() || !e.HasCountry() {
		t.Fatalf("after installing both: HasASN=%v HasCountry=%v", e.HasASN(), e.HasCountry())
	}

	e.Close()
	if e.HasASN() || e.HasCountry() {
		t.Fatal("Close must drop both")
	}
	var nilE *Enricher
	if nilE.HasASN() || nilE.HasCountry() {
		t.Fatal("a nil Enricher has no database")
	}
}
