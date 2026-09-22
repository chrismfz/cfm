// internal/webdetector/site_cache_stats_test.go
package webdetector

import (
	"encoding/json"
	"net/http"
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
