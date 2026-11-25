package enrich

import (
	"testing"
	"time"
)

// LookupCached never resolves: a miss reports false and caches nothing, a hit
// returns the cached record.
func TestLookupCached(t *testing.T) {
	e := newTestEnricher()
	if _, ok := e.LookupCached("198.51.100.7"); ok {
		t.Fatal("hit on an empty cache")
	}
	if _, ok := e.cache.Get("198.51.100.7"); ok {
		t.Fatal("a miss cached something")
	}
	e.cache.Add("198.51.100.7", Result{PTR: "host.example", ts: time.Now()})
	if r, ok := e.LookupCached("198.51.100.7"); !ok || r.PTR != "host.example" {
		t.Fatalf("hit: ok=%v ptr=%q", ok, r.PTR)
	}
	var nilE *Enricher
	if _, ok := nilE.LookupCached("198.51.100.7"); ok {
		t.Fatal("nil enricher hit")
	}
}
