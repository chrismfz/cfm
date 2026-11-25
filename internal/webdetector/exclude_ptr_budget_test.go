package webdetector

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/enrich"
)

// fakeExcludeEnr: a cache, inline lookups that count, async lookups that
// only record the IP.
type fakeExcludeEnr struct {
	mu     sync.Mutex
	cache  map[string]enrich.Result
	ptrOf  map[string]string
	inline int
	async  []string
	ptrOn  bool
}

func (f *fakeExcludeEnr) LookupCached(ip string) (enrich.Result, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.cache[ip]
	return r, ok
}

func (f *fakeExcludeEnr) Lookup(ip string) enrich.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inline++
	r := enrich.Result{PTR: f.ptrOf[ip]}
	f.cache[ip] = r
	return r
}

func (f *fakeExcludeEnr) LookupCachedOrAsync(ip string) enrich.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.async = append(f.async, ip)
	return enrich.Result{}
}

func (f *fakeExcludeEnr) PTREnabled() bool { return f.ptrOn }

// warm plays the background lookups: their PTRs land in the cache.
func (f *fakeExcludeEnr) warm() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ip := range f.async {
		f.cache[ip] = enrich.Result{PTR: f.ptrOf[ip]}
	}
	f.async = nil
}

func withFakeExcludeEnr(t *testing.T, f *fakeExcludeEnr) {
	t.Helper()
	excludeEnricherForTest = f
	t.Cleanup(func() { excludeEnricherForTest = nil })
}

// ptrRule exempts *.crawler.example by PTR alone, like `ptr=*.ahrefs.com`.
func ptrRule(ip, host, ua, asn, ptr, rule string) (string, bool) {
	if strings.HasSuffix(ptr, ".crawler.example") {
		return "skip", true
	}
	return "", false
}

// A tick does at most excludePTRBudgetPerTick inline reverse lookups; the rest
// are held back (excluded this tick), looked up in the background, and judged
// from the cache next tick. A PTR-exempt crawler is never judged without its
// PTR, so it is never challenged on the way.
func TestIsExcluded_InlinePTRBudget(t *testing.T) {
	f := &fakeExcludeEnr{cache: map[string]enrich.Result{}, ptrOf: map[string]string{}, ptrOn: true}
	withFakeExcludeEnr(t, f)
	e := newTickTestEngine(t)
	e.SetChalExcludeFunc(ptrRule)
	crawler := "203.0.113.200"
	f.ptrOf[crawler] = "bot1.crawler.example"

	e.excludePTRBudget.Store(excludePTRBudgetPerTick)
	e.excludeDeferred.Store(0)
	held := 0
	for i := 0; i < 30; i++ {
		if e.isExcluded(fmt.Sprintf("198.51.100.%d", i+1), "shop.gr", "", "CHALLENGE_PATHS") {
			held++
		}
	}
	if !e.isExcluded(crawler, "shop.gr", "", "CHALLENGE_PATHS") {
		t.Fatal("the crawler, past the budget, was judged without its PTR")
	}
	if f.inline != excludePTRBudgetPerTick {
		t.Fatalf("inline lookups=%d, want the budget %d", f.inline, excludePTRBudgetPerTick)
	}
	if want := 30 - excludePTRBudgetPerTick; held != want || e.excludeDeferred.Load() != int64(want+1) {
		t.Fatalf("held=%d deferred=%d, want %d held and %d deferred", held, e.excludeDeferred.Load(), want, want+1)
	}

	// Next tick: the background lookups have landed; nothing inline, nothing
	// held, the farm IPs are judged (not excluded), the crawler exempted.
	f.warm()
	e.excludePTRBudget.Store(excludePTRBudgetPerTick)
	e.excludeDeferred.Store(0)
	before := f.inline
	for i := 0; i < 30; i++ {
		if e.isExcluded(fmt.Sprintf("198.51.100.%d", i+1), "shop.gr", "", "CHALLENGE_PATHS") {
			t.Fatalf("198.51.100.%d excluded from cache with no PTR", i+1)
		}
	}
	if !e.isExcluded(crawler, "shop.gr", "", "CHALLENGE_PATHS") {
		t.Fatal("the crawler was not exempted from its cached PTR")
	}
	if f.inline != before || e.excludeDeferred.Load() != 0 {
		t.Fatalf("second tick: inline=%d deferred=%d, want 0 and 0", f.inline-before, e.excludeDeferred.Load())
	}
}

// With the PTR switch off no PTR ever comes: nothing is held, nothing budgeted.
func TestIsExcluded_NoPTRSwitchJudgesNow(t *testing.T) {
	f := &fakeExcludeEnr{cache: map[string]enrich.Result{}, ptrOf: map[string]string{}, ptrOn: false}
	withFakeExcludeEnr(t, f)
	e := newTickTestEngine(t)
	e.SetChalExcludeFunc(ptrRule)
	e.excludePTRBudget.Store(0)
	if e.isExcluded("198.51.100.9", "shop.gr", "", "CHALLENGE_PATHS") {
		t.Fatal("held back with the PTR switch off")
	}
	if e.excludeDeferred.Load() != 0 {
		t.Fatal("deferred with the PTR switch off")
	}
}

// The tick resets the budget: emitIPChallenges, not a stale count, decides.
func TestEmitIPChallenges_ResetsPTRBudget(t *testing.T) {
	e := newTickTestEngine(t)
	e.excludePTRBudget.Store(-5)
	e.excludeDeferred.Store(7)
	e.emitIPChallenges(time.Now(), make(chan core.Alert, 16))
	if got := e.excludePTRBudget.Load(); got != excludePTRBudgetPerTick {
		t.Fatalf("budget after a quiet tick=%d, want %d", got, excludePTRBudgetPerTick)
	}
	if e.excludeDeferred.Load() != 0 {
		t.Fatal("deferred count not reset")
	}
}
