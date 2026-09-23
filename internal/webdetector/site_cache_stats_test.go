// internal/webdetector/site_cache_stats_test.go
package webdetector

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// ── store: upsert / copy semantics / bounds ──────────────────────────────────

func TestSiteCacheStatsStore_UpsertGet(t *testing.T) {
	s := newSiteCacheStatsStore()

	// Unknown host → nil.
	if got := s.Get("nope.com"); got != nil {
		t.Fatalf("unknown host should be nil, got %v", got)
	}

	in := map[string]int{"HIT": 8, "MISS": 2, "total": 10}
	s.Upsert("MySite.com", in) // host is lowercased/trimmed

	got := s.Get("mysite.com")
	if got == nil || got["HIT"] != 8 || got["MISS"] != 2 {
		t.Fatalf("Get after Upsert: %+v", got)
	}

	// Returned map is a COPY — mutating it must not touch the store.
	got["HIT"] = 999
	if again := s.Get("mysite.com"); again["HIT"] != 8 {
		t.Fatalf("Get returned an aliased map; store mutated to %d", again["HIT"])
	}

	// Mutating the INPUT map after Upsert must not touch the store either.
	in["HIT"] = 111
	if again := s.Get("mysite.com"); again["HIT"] != 8 {
		t.Fatalf("Upsert retained the caller's slice; store now %d", again["HIT"])
	}

	// Upsert REPLACES (absolute snapshot, not accumulate).
	s.Upsert("mysite.com", map[string]int{"HIT": 5})
	if again := s.Get("mysite.com"); again["HIT"] != 5 || again["MISS"] != 0 {
		t.Fatalf("Upsert should replace, got %+v", again)
	}

	// Empty host / empty counts are ignored.
	s.Upsert("", map[string]int{"HIT": 1})
	s.Upsert("x.com", nil)
	if len(s.Hosts()) != 1 {
		t.Fatalf("empty host/counts must not create entries: %+v", s.Hosts())
	}

	// Negative counts are clamped to 0 (defence against a buggy edge).
	s.Upsert("neg.com", map[string]int{"HIT": -4})
	if s.Get("neg.com")["HIT"] != 0 {
		t.Fatalf("negative count not clamped")
	}
}

// ── row derivation: hit ratio + total floor ──────────────────────────────────

func TestSiteCacheStatsRow(t *testing.T) {
	cases := []struct {
		name      string
		counts    map[string]int
		wantHit   int
		wantCache int
		wantRatio float64
		wantTotal int
	}{
		{"80pct", map[string]int{"HIT": 8, "MISS": 2, "total": 10}, 8, 10, 80.0, 10},
		{"half_no_total", map[string]int{"HIT": 1, "MISS": 1}, 1, 2, 50.0, 2},
		{"all_bypass", map[string]int{"BYPASS": 5}, 0, 0, 0.0, 5},
		{"expired_stale_count_cacheable", map[string]int{"HIT": 1, "EXPIRED": 1, "STALE": 2}, 1, 4, 25.0, 4},
		{"total_below_parts_is_floored", map[string]int{"HIT": 3, "MISS": 3, "total": 1}, 3, 6, 50.0, 6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := siteCacheStatsRow("h.com", c.counts)
			if r.Hit != c.wantHit || r.CacheableTotal != c.wantCache || r.HitRatioPct != c.wantRatio || r.Total != c.wantTotal {
				t.Fatalf("row=%+v want hit=%d cacheable=%d ratio=%.1f total=%d",
					r, c.wantHit, c.wantCache, c.wantRatio, c.wantTotal)
			}
		})
	}
}

// ── API handler: scope filtering (mirrors the other site-cache endpoints) ─────

func seedStats(e *Engine) {
	// Stats are shown only for CURRENTLY-armed vhosts, so arm them too.
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "mysite.com", Static: SiteCacheTier{Enabled: true, Recipe: "static_lean"}})
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "other.com", Static: SiteCacheTier{Enabled: true, Recipe: "static_lean"}})
	e.siteCacheStats.Upsert("mysite.com", map[string]int{"HIT": 9, "MISS": 1, "total": 10})
	e.siteCacheStats.Upsert("other.com", map[string]int{"HIT": 1, "MISS": 9, "total": 10})
}

func TestSiteCacheStatsAPI_ScopedListFiltered(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	seedStats(e)

	// Scoped token sees only its own vhost.
	rr := doRequest(mux, scopedCtx("mysite.com"), http.MethodGet, "/api/v1/site-cache/stats", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped stats: expected 200, got %d", rr.Code)
	}
	var out siteCacheStatsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Rows) != 1 || out.Rows[0].Host != "mysite.com" {
		t.Fatalf("scoped stats not filtered to own vhost: %+v", out.Rows)
	}
	if out.Rows[0].HitRatioPct != 90.0 {
		t.Fatalf("hit ratio wrong: %v", out.Rows[0].HitRatioPct)
	}

	// Admin sees both.
	rr = doRequest(mux, adminCtx(), http.MethodGet, "/api/v1/site-cache/stats", nil)
	var all siteCacheStatsResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &all)
	if len(all.Rows) != 2 {
		t.Fatalf("admin should see 2 rows, got %d", len(all.Rows))
	}
}

func TestSiteCacheStatsAPI_ScopedHostOutOfScope(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	seedStats(e)

	// A scoped caller asking for another tenant's host → 403 (fail closed).
	rr := doRequest(mux, scopedCtx("mysite.com"), http.MethodGet, "/api/v1/site-cache/stats?host=other.com", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope host: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Its own host is fine.
	rr = doRequest(mux, scopedCtx("mysite.com"), http.MethodGet, "/api/v1/site-cache/stats?host=mysite.com", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("own host: expected 200, got %d", rr.Code)
	}
	var out siteCacheStatsResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Rows) != 1 || out.Rows[0].Host != "mysite.com" {
		t.Fatalf("own-host stats wrong: %+v", out.Rows)
	}
}

func TestSiteCacheStatsAPI_NoScopeFailsClosed(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	seedStats(e)
	// A scoped token with NO vhosts (empty allowlist) must see nothing, never all.
	rr := doRequest(mux, scopedCtxNoVhosts(), http.MethodGet, "/api/v1/site-cache/stats", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out siteCacheStatsResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Rows) != 0 {
		t.Fatalf("empty-scope token must see 0 rows, got %d", len(out.Rows))
	}
}

// A vhost unarmed AFTER its counts were pushed must drop out of the view — the
// edge dict keeps stale counts until reload, so the armed policy set is truth.
func TestSiteCacheStats_UnarmedDropsOut(t *testing.T) {
	e, _ := newSiteCacheAPITestEngine(t)
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "gone.com", Static: SiteCacheTier{Enabled: true, Recipe: "static_lean"}})
	e.siteCacheStats.Upsert("gone.com", map[string]int{"HIT": 5, "MISS": 5, "total": 10})

	if rows := e.SiteCacheStatsAll(); len(rows) != 1 {
		t.Fatalf("armed vhost should appear, got %d rows", len(rows))
	}
	// Unarm it (turn caching off) — the store still holds the stale counts.
	e.SiteCacheRemove("gone.com")
	if rows := e.SiteCacheStatsAll(); len(rows) != 0 {
		t.Fatalf("unarmed vhost must not appear in stats, got %+v", rows)
	}
	if _, ok := e.SiteCacheStatsHost("gone.com", nil); ok {
		t.Fatalf("unarmed vhost must not resolve by host")
	}
}

// A concrete sub-host of a wildcard-armed vhost must resolve to the pattern row.
func TestSiteCacheStats_WildcardDrilldown(t *testing.T) {
	e, _ := newSiteCacheAPITestEngine(t)
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "*.cdn.example.com", Static: SiteCacheTier{Enabled: true, Recipe: "static_lean"}})
	// The edge keys stats under the pattern (policy_key_for folds sub-hosts).
	e.siteCacheStats.Upsert("*.cdn.example.com", map[string]int{"HIT": 3, "MISS": 1, "total": 4})

	// Drill down by a CONCRETE sub-host → resolves to the pattern row.
	row, ok := e.SiteCacheStatsHost("assets.cdn.example.com", nil)
	if !ok || row.Host != "*.cdn.example.com" || row.Hit != 3 {
		t.Fatalf("wildcard drill-down by sub-host failed: ok=%v row=%+v", ok, row)
	}
	// Querying the pattern itself also works.
	if _, ok := e.SiteCacheStatsHost("*.cdn.example.com", nil); !ok {
		t.Fatalf("pattern lookup should work")
	}
	// The bare suffix (not covered by *.cdn.example.com) does not resolve.
	if _, ok := e.SiteCacheStatsHost("cdn.example.com", nil); ok {
		t.Fatalf("bare suffix must not match the wildcard")
	}
}

// A scoped tenant drilling into its own sub-host of an admin's wildcard must NOT
// get the wildcard's counts: that row aggregates every sub-host under the
// pattern, other tenants' included.
func TestSiteCacheStatsAPI_ScopedDrilldownNeverResolvesForeignWildcard(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "*.example.com", Static: SiteCacheTier{Enabled: true, Recipe: "static_lean"}})
	e.siteCacheStats.Upsert("*.example.com", map[string]int{"HIT": 70, "MISS": 30, "total": 100})

	rr := doRequest(mux, scopedCtx("a.example.com"), http.MethodGet, "/api/v1/site-cache/stats?host=a.example.com", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("own host: expected 200, got %d", rr.Code)
	}
	var out siteCacheStatsResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Rows) != 0 {
		t.Fatalf("scoped drill-down resolved to the admin wildcard: %+v", out.Rows)
	}
	// An admin still drills down through the wildcard.
	rr = doRequest(mux, adminCtx(), http.MethodGet, "/api/v1/site-cache/stats?host=a.example.com", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Rows) != 1 || out.Rows[0].Host != "*.example.com" {
		t.Fatalf("admin drill-down: %+v", out.Rows)
	}
	// The 403 names why.
	rr = doRequest(mux, scopedCtx("a.example.com"), http.MethodGet, "/api/v1/site-cache/stats?host=b.example.com", nil)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "not in scope") {
		t.Fatalf("out-of-scope: %d %s", rr.Code, rr.Body.String())
	}
}

// The drill-down resolves to the key the edge counts under: an exact policy
// wins (armed → its own counts, never the wildcard's while it has none yet;
// all-off → nothing, it is an opt-out), else the most specific armed wildcard
// (never a broader one's counts).
func TestSiteCacheStats_DrilldownMirrorsEdgeKey(t *testing.T) {
	e, _ := newSiteCacheAPITestEngine(t)
	on := SiteCacheTier{Enabled: true, Recipe: "static_lean"}
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "*.example.com", Static: on})
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "*.shop.example.com", Static: on})
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "new.example.com", Static: on})
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "optout.example.com", Static: SiteCacheTier{Recipe: "static_lean"}})
	e.siteCacheStats.Upsert("*.example.com", map[string]int{"HIT": 1, "total": 1})
	e.siteCacheStats.Upsert("optout.example.com", map[string]int{"HIT": 5, "total": 5}) // stale, from when it was armed

	for _, h := range []string{"new.example.com", "optout.example.com", "x.shop.example.com"} {
		if row, ok := e.SiteCacheStatsHost(h, nil); ok {
			t.Errorf("%s resolved to %+v; want no row", h, row)
		}
	}
	if row, ok := e.SiteCacheStatsHost("a.example.com", nil); !ok || row.Host != "*.example.com" {
		t.Fatalf("plain sub-host: ok=%v row=%+v", ok, row)
	}
	// An all-off policy is not armed: its lingering counts stay out of the list.
	for _, r := range e.SiteCacheStatsAll() {
		if r.Host == "optout.example.com" {
			t.Fatalf("all-off vhost listed as live: %+v", r)
		}
	}
}
