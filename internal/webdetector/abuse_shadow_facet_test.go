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

// End-to-end at the ingest+emit layer: a facet flood on ONE dynamic base path,
// mixed with a page's static-asset fan-out, must (a) count only the dynamic
// universe into fullURIs/facetPaths/facetTotal and (b) badge the vhost with the
// distinct-URL count. This locks in the "consistent dynamic universe" fix: the
// denominator must NOT come from b.paths (which also counts the static assets and
// would dilute the expansion ratio per-vhost).
func TestFacet_IngestEmit_DynamicUniverseAndBadge(t *testing.T) {
	ResetFacetShadowMarks()
	defer ResetFacetShadowMarks()
	e := NewEngine(Config{
		Every: 1 * time.Second, Window: 2 * time.Minute,
		AbuseShadow: true, AbuseShadowFacet: true,
		AbuseShadowFacetMinURLs: 10, AbuseShadowFacetMinExpansion: 5,
	})
	now := float64(time.Now().Unix())
	const host = "flood.example"

	// 50 distinct facet URLs on ONE base path /shop (the query is the whole fan-out).
	const nFacet = 50
	for i := 0; i < nFacet; i++ {
		e.ingest(LogRec{TS: now + float64(i)*0.001, IP: "9.9.9.9", Host: host,
			Method: "get", URI: "/shop?filter_category=" + ipKeyForTest(i), Status: 200}, "raw")
	}
	// One dynamic endpoint whose query ends in a static-looking tail — its stripped
	// path /api is NOT static, so it must count in the dynamic universe (this guards
	// the p-vs-rec.URI static check).
	e.ingest(LogRec{TS: now + 1, IP: "9.9.9.9", Host: host,
		Method: "get", URI: "/api?redirect=/trap.css", Status: 200}, "raw")

	// A large static-asset fan-out on MANY DISTINCT static base paths. These must be
	// excluded from every facet counter (numerator, denominator AND total). Crucially
	// there are enough of them that the OLD (buggy) denominator b.paths — which
	// counts static paths — would push the expansion ratio BELOW MinExpansion, while
	// the correct facetPaths denominator (2 dynamic paths) keeps it well above. That
	// is what makes the emit badge below actually depend on the dynamic-universe fix:
	// revert the emit denominator to b.paths and the vhost stops flagging (badge 0).
	const nStatic = 60
	for i := 0; i < nStatic; i++ {
		e.ingest(LogRec{TS: now + 1 + float64(i+1)*0.001, IP: "9.9.9.9", Host: host,
			Method: "get", URI: "/static/" + ipKeyForTest(i) + ".css", Status: 200}, "raw")
	}

	// Inspect the bucket accounting directly.
	e.mu.RLock()
	hs := e.hosts[host]
	if hs == nil {
		e.mu.RUnlock()
		t.Fatalf("host not recorded")
	}
	urls := map[uint64]struct{}{}
	fpaths := map[uint64]struct{}{}
	bpaths := map[string]struct{}{}
	facetTotal, bTotal := 0, 0
	for i := range hs.buckets {
		b := &hs.buckets[i]
		facetTotal += b.facetTotal
		bTotal += b.total
		for h := range b.fullURIs {
			urls[h] = struct{}{}
		}
		for h := range b.facetPaths {
			fpaths[h] = struct{}{}
		}
		for p := range b.paths {
			bpaths[p] = struct{}{}
		}
	}
	e.mu.RUnlock()

	// /api?redirect=/trap.css is dynamic (its stripped path /api is not static), so
	// the dynamic universe is the 50 facet hits + that one = 51.
	const nDyn = nFacet + 1
	if facetTotal != nDyn {
		t.Errorf("facetTotal = %d, want %d (static assets must be excluded)", facetTotal, nDyn)
	}
	if len(urls) != nDyn {
		t.Errorf("distinct fullURIs = %d, want %d", len(urls), nDyn)
	}
	// Dynamic base paths: /shop and /api = 2. The static paths must NOT appear here.
	if len(fpaths) != 2 {
		t.Errorf("distinct facetPaths = %d, want 2 (/shop + /api; static excluded)", len(fpaths))
	}
	// The discriminating property: with the CORRECT denominator the expansion clears
	// MinExpansion, but with the OLD (static-polluted) b.paths denominator it does
	// NOT — so the emit's flag decision depends on which denominator it uses. If this
	// invariant doesn't hold, the badge assertion below is not actually guarding the
	// fix (the exact bug this test exists to catch), so fail loudly here.
	const minExp = 5.0
	correctRatio := float64(nDyn) / float64(len(fpaths))
	dilutedRatio := float64(nDyn) / float64(len(bpaths))
	if !(correctRatio >= minExp && dilutedRatio < minExp) {
		t.Fatalf("test can't discriminate the fix: correct=%.2f (want ≥%.1f), diluted=%.2f (want <%.1f) — add more static paths",
			correctRatio, minExp, dilutedRatio, minExp)
	}
	if bTotal <= facetTotal {
		t.Errorf("b.total (%d) should exceed facetTotal (%d) by the static hits", bTotal, facetTotal)
	}

	// The emit badges the vhost with the distinct-URL count over the dynamic universe.
	// Because dilutedRatio < MinExpansion above, a badge of nDyn here can ONLY happen
	// with the correct facetPaths denominator — reverting the emit to b.paths would
	// stop the flag and this would read 0.
	e.emitAbuseShadowFacetOutliers(time.Now())
	if got := FacetShadowCardinality(host); got != nDyn {
		t.Errorf("badge cardinality = %d, want %d (0 would mean the emit used the static-polluted denominator)", got, nDyn)
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
