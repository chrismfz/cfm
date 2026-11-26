package sslcollector

import (
	"fmt"
	"testing"
	"time"
)

func statsCollector(n int) *Collector {
	exact := make(map[string]*Entry, n)
	wild := make(map[string]*Entry, n/10)
	for i := 0; i < n; i++ {
		e := &Entry{Fingerprint: fmt.Sprintf("fp%05d", i), CertMTime: time.Unix(1_700_000_000, 0), Source: SrcCPanel}
		exact[fmt.Sprintf("h%05d.example", i)] = e
		if i%10 == 0 {
			wild[fmt.Sprintf("d%05d.example", i)] = e
		}
	}
	return &Collector{exact: exact, wildSuffix: wild, knownFiles: map[string]struct{}{}, certCache: map[string]cachedCert{}}
}

// The version is hashed once per pair of maps (a scan replaces them), not
// per /stats call, and moves when a scan brings a change.
func TestStatsReusesTheVersionUntilAScan(t *testing.T) {
	col := statsCollector(50)
	s1 := col.Stats()
	exact := col.statsCache.exact
	s2 := col.Stats()
	if s1.Version != s2.Version || !sameMap(col.statsCache.exact, exact) {
		t.Fatal("the same maps were hashed again")
	}
	s2.BySource[SrcCPanel] = -1 // the caller's copy
	if col.Stats().BySource[SrcCPanel] != 50 {
		t.Fatal("a caller's change reached the cached counts")
	}
	if s1.ExactHosts != 50 || s1.WildcardZones != 5 || s1.UniquePairs != 50 {
		t.Fatalf("counts: %+v", s1)
	}

	// A scan with the same content: new maps, the same version.
	next := statsCollector(50)
	col.mu.Lock()
	col.exact, col.wildSuffix = next.exact, next.wildSuffix
	col.mu.Unlock()
	if v := col.Stats().Version; v != s1.Version {
		t.Fatal("the same content hashed to another version")
	}
	// A scan with a renewal: another version.
	renewed := statsCollector(50)
	renewed.exact["h00007.example"] = &Entry{Fingerprint: "renewed", Source: SrcCPanel}
	col.mu.Lock()
	col.exact = renewed.exact
	col.mu.Unlock()
	if v := col.Stats().Version; v == s1.Version {
		t.Fatal("a renewal did not move the version")
	}
}

func BenchmarkStats5000(b *testing.B) {
	col := statsCollector(5000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = col.Stats()
	}
}
