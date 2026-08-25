package webdetector

import (
	"testing"
	"time"
)

// facetOutlier is the pure verdict: distinctURLs must clear the floor AND the
// distinct-URL/distinct-path ratio must clear the expansion floor.
func TestFacetOutlier_Verdict(t *testing.T) {
	c := facetShadowCfg{MinURLs: 300, MinExpansion: 20}

	cases := []struct {
		name  string
		urls  int
		paths int
		want  bool
	}{
		// The e-athlos shape: a huge distinct-URL fan-out on a couple of base paths.
		{"facet flood", 5000, 2, true},
		// A busy legit shop: distinct URLs track distinct paths (each product its
		// own path), so expansion stays low even at high absolute cardinality.
		{"busy shop", 5000, 4000, false},
		// Below the absolute floor: a small vhost with a high ratio is not enough.
		{"tiny high ratio", 100, 1, false},
		// Exactly at both floors is a hit (>=).
		{"at both floors", 300, 15, true},
		// Clears URLs but not expansion.
		{"low expansion", 400, 40, false},
		// Degenerate: zero paths never flags (guards a divide-by-zero).
		{"zero paths", 5000, 0, false},
	}
	for _, tc := range cases {
		if got := facetOutlier(tc.urls, tc.paths, c); got != tc.want {
			t.Errorf("%s: facetOutlier(%d,%d)=%v, want %v", tc.name, tc.urls, tc.paths, got, tc.want)
		}
	}
}

// facetShadowCfg() fills unset (zero) knobs with safe defaults.
func TestFacetShadowCfg_Defaults(t *testing.T) {
	e := &Engine{cfg: Config{}}
	c := e.facetShadowCfg()
	if c.MinURLs != 300 {
		t.Fatalf("MinURLs default: got %d, want 300", c.MinURLs)
	}
	if c.MinExpansion != 20 {
		t.Fatalf("MinExpansion default: got %v, want 20", c.MinExpansion)
	}

	e2 := &Engine{cfg: Config{AbuseShadowFacetMinURLs: 1000, AbuseShadowFacetMinExpansion: 50}}
	c2 := e2.facetShadowCfg()
	if c2.MinURLs != 1000 || c2.MinExpansion != 50 {
		t.Fatalf("explicit knobs not honoured: got %d/%v", c2.MinURLs, c2.MinExpansion)
	}
}

func TestFacetMarks_MarkBulkGetExpiry(t *testing.T) {
	m := newFacetMarks()
	base := time.Unix(1_700_000_000, 0)
	m.nowFn = func() time.Time { return base }

	m.markBulk(map[string]int{"Shop.EXAMPLE": 4200, "skip.com": 0, "": 1}, time.Minute)
	if got := m.get("shop.example"); got != 4200 { // normalised key
		t.Fatalf("fresh mark: got %d, want 4200", got)
	}
	if _, ok := m.hosts["skip.com"]; ok {
		t.Fatal("count<=0 host should be skipped")
	}

	// A later bulk prunes the now-expired entry and stamps the new one.
	m.nowFn = func() time.Time { return base.Add(2 * time.Minute) }
	m.markBulk(map[string]int{"fresh.com": 9}, time.Minute)
	if _, ok := m.hosts["shop.example"]; ok {
		t.Fatal("markBulk did not prune the expired entry")
	}
	if got := m.get("fresh.com"); got != 9 {
		t.Fatalf("fresh.com: got %d, want 9", got)
	}
	if n := len(m.hosts); n != 1 {
		t.Fatalf("store has %d entries, want 1", n)
	}
}

func TestFacetMarks_CapBounded(t *testing.T) {
	m := newFacetMarks()
	base := time.Unix(1_700_000_000, 0)
	m.nowFn = func() time.Time { return base }
	big := make(map[string]int, maxFacetMarks+1)
	for i := 0; i < maxFacetMarks; i++ {
		big["h"+ipKeyForTest(i)] = 1
	}
	m.markBulk(big, time.Hour)
	m.markBulk(map[string]int{"overflow.com": 1}, time.Hour) // must be rejected at cap
	if _, ok := m.hosts["overflow.com"]; ok {
		t.Fatal("mark past cap was admitted")
	}
	if n := len(m.hosts); n > maxFacetMarks {
		t.Fatalf("store grew past cap: %d", n)
	}
}

// The API decoration stamps the live cardinality onto rows (global store path).
func TestDecorateFacet_StampsRows(t *testing.T) {
	ResetFacetShadowMarks()
	defer ResetFacetShadowMarks()
	MarkFacetShadowBulk(map[string]int{"shop.example": 8100}, time.Minute)

	short := decorateFacetShort([]ShortRow{{Host: "shop.example"}, {Host: "quiet.example"}})
	if short[0].QueryCardinality != 8100 || short[1].QueryCardinality != 0 {
		t.Fatalf("short decorate: got %d/%d, want 8100/0", short[0].QueryCardinality, short[1].QueryCardinality)
	}
	susp := decorateFacetSuspicious([]SuspiciousRow{{Host: "shop.example"}})
	if susp[0].QueryCardinality != 8100 {
		t.Fatalf("suspicious decorate: got %d, want 8100", susp[0].QueryCardinality)
	}
}
