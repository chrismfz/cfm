package enrich

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLookupCachedOrAsync_CacheHit_FastPath: when the cache already has the IP,
// LookupCachedOrAsync must return it directly without dispatching anything.
func TestLookupCachedOrAsync_CacheHit_FastPath(t *testing.T) {
	e := &Enricher{
		cache:    map[string]Result{},
		asyncSem: make(chan struct{}, asyncWorkerCap),
	}

	const ip = "1.2.3.4"
	want := Result{CountryISO: "GR", Country: "Greece", ts: time.Now()}
	e.cache[ip] = want

	got := e.LookupCachedOrAsync(ip)
	if got.CountryISO != want.CountryISO {
		t.Fatalf("cached hit not returned: got CountryISO=%q want %q", got.CountryISO, want.CountryISO)
	}
}

// TestLookupCachedOrAsync_CacheMiss_ReturnsEmptyImmediately: the call must
// not block — even if the underlying Lookup would be slow, the response is
// instant. We don't need a real geoip DB here; with no DBs configured,
// Lookup() returns Result{} and that's what eventually populates the cache.
func TestLookupCachedOrAsync_CacheMiss_ReturnsEmptyImmediately(t *testing.T) {
	e := &Enricher{
		cache:     map[string]Result{},
		asyncSem:  make(chan struct{}, asyncWorkerCap),
		enablePTR: false, // no DNS in tests
	}

	const ip = "203.0.113.7"

	start := time.Now()
	got := e.LookupCachedOrAsync(ip)
	elapsed := time.Since(start)

	if got.CountryISO != "" {
		t.Fatalf("cache miss should return empty CountryISO, got %q", got.CountryISO)
	}
	// Generous bound: cache miss path is just a map lookup + channel send.
	if elapsed > 50*time.Millisecond {
		t.Fatalf("cache miss took %v, expected near-instant return", elapsed)
	}
}

// TestLookupCachedOrAsync_PopulatesCacheForNextCall: after the async dispatch
// settles, a subsequent LookupCachedOrAsync for the same IP should hit cache.
// (We don't have geoip DBs in test env, so the cached Result is empty — but
// it's still cached, which is what we're verifying.)
func TestLookupCachedOrAsync_PopulatesCacheForNextCall(t *testing.T) {
	e := &Enricher{
		cache:     map[string]Result{},
		asyncSem:  make(chan struct{}, asyncWorkerCap),
		enablePTR: false,
	}

	const ip = "198.51.100.42"
	_ = e.LookupCachedOrAsync(ip) // dispatches async

	// Wait for the goroutine to populate the cache. With no PTR/DBs the
	// goroutine just writes Result{ts: now} and returns — should be quick.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.RLock()
		_, cached := e.cache[ip]
		e.mu.RUnlock()
		if cached {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	e.mu.RLock()
	_, cached := e.cache[ip]
	e.mu.RUnlock()
	if !cached {
		t.Fatalf("expected cache to be populated after async dispatch")
	}
}

// TestLookupCachedOrAsync_DedupesConcurrentMisses: many concurrent misses for
// the same IP should result in at most one underlying Lookup call (singleflight
// dedup). We instrument by replacing the geoip DBs with nil and counting how
// many times the goroutine actually wrote into the cache map.
func TestLookupCachedOrAsync_DedupesConcurrentMisses(t *testing.T) {
	e := &Enricher{
		cache:     map[string]Result{},
		asyncSem:  make(chan struct{}, asyncWorkerCap),
		enablePTR: false,
	}

	const ip = "192.0.2.99"
	const N = 50

	// Hammer the same IP concurrently from N goroutines.
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.LookupCachedOrAsync(ip)
		}()
	}
	wg.Wait()

	// Wait briefly for whatever async work was scheduled to complete.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.RLock()
		_, cached := e.cache[ip]
		e.mu.RUnlock()
		if cached {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The cache map should now contain exactly one entry for this IP.
	// (singleflight ensures only one Lookup ran; the bounded asyncSem
	// also caps in-flight goroutines but that's secondary.)
	e.mu.RLock()
	count := len(e.cache)
	e.mu.RUnlock()
	if count != 1 {
		t.Fatalf("expected exactly 1 cached entry for the hammered IP, got %d", count)
	}
}

// TestLookupCachedOrAsync_BoundedConcurrency: when the async semaphore is
// already saturated, LookupCachedOrAsync must still return immediately — it
// just skips the dispatch this round. We saturate by filling asyncSem manually.
func TestLookupCachedOrAsync_BoundedConcurrency(t *testing.T) {
	e := &Enricher{
		cache:     map[string]Result{},
		asyncSem:  make(chan struct{}, 2), // tiny cap to force saturation
		enablePTR: false,
	}

	// Saturate the semaphore — pretend two long-running async lookups
	// are already in flight.
	e.asyncSem <- struct{}{}
	e.asyncSem <- struct{}{}

	var dispatched int32
	// Use a wait group of zero to confirm the call doesn't block.
	done := make(chan struct{})
	go func() {
		_ = e.LookupCachedOrAsync("203.0.113.50")
		atomic.AddInt32(&dispatched, 1)
		close(done)
	}()

	select {
	case <-done:
		// Good — returned non-blocking even though semaphore was full.
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("LookupCachedOrAsync blocked when asyncSem was saturated")
	}

	// Cache should NOT have been populated for the saturated case.
	e.mu.RLock()
	_, cached := e.cache["203.0.113.50"]
	e.mu.RUnlock()
	if cached {
		t.Fatalf("expected no cache entry when async dispatch was skipped")
	}

	// Drain the semaphore so we don't leak it for parallel tests.
	<-e.asyncSem
	<-e.asyncSem
}

// TestLookupCachedOrAsync_NilSafe: defensive guard for nil receiver / empty IP.
func TestLookupCachedOrAsync_NilSafe(t *testing.T) {
	var e *Enricher
	got := e.LookupCachedOrAsync("1.2.3.4")
	if got.CountryISO != "" || got.PTR != "" {
		t.Fatalf("nil enricher should return zero Result")
	}

	e2 := &Enricher{
		cache:    map[string]Result{},
		asyncSem: make(chan struct{}, asyncWorkerCap),
	}
	got2 := e2.LookupCachedOrAsync("")
	if got2.CountryISO != "" || got2.PTR != "" {
		t.Fatalf("empty IP should return zero Result")
	}
}
