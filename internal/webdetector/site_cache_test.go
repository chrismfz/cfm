// internal/webdetector/site_cache_test.go
package webdetector

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// ── store round-trip ─────────────────────────────────────────────────────────

func newSiteCacheTestStore(t *testing.T) *siteCacheStore {
	t.Helper()
	return newSiteCacheStore(filepath.Join(t.TempDir(), "site_cache.json"))
}

func TestSiteCacheStore_SetGetListRemove(t *testing.T) {
	s := newSiteCacheTestStore(t)

	if s.HasAny() {
		t.Fatal("fresh store must have no enabled entries")
	}

	got, err := s.Set(SiteCacheEntry{
		Host:   "MyIP.gr.",
		Static: SiteCacheTier{Enabled: true, Recipe: "static_aggressive", TTL: "7d"},
		Micro:  SiteCacheTier{Enabled: true, Recipe: "micro_safe", TTL: "1s"},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got.Host != "myip.gr" {
		t.Fatalf("host not normalized: %q", got.Host)
	}
	if got.Generation != 0 {
		t.Fatalf("fresh generation should be 0, got %d", got.Generation)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatal("timestamps not stamped")
	}
	if !s.HasAny() {
		t.Fatal("HasAny should be true after enabling a tier")
	}

	e, ok := s.Get("myip.gr")
	if !ok || e.Static.Recipe != "static_aggressive" || e.Micro.TTL != "1s" {
		t.Fatalf("Get mismatch: ok=%v e=%+v", ok, e)
	}

	if got := s.List(); len(got) != 1 {
		t.Fatalf("List len=%d", len(got))
	}

	if !s.Remove("myip.gr") {
		t.Fatal("Remove should succeed")
	}
	if _, ok := s.Get("myip.gr"); ok {
		t.Fatal("entry should be gone after Remove")
	}
	if s.Remove("myip.gr") {
		t.Fatal("second Remove should fail")
	}
}

func TestSiteCacheStore_PersistAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "site_cache.json")
	s := newSiteCacheStore(path)
	if _, err := s.Set(SiteCacheEntry{
		Host:  "example.com",
		Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"},
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// Fresh store from the same file must see the entry.
	s2 := newSiteCacheStore(path)
	e, ok := s2.Get("example.com")
	if !ok || !e.Micro.Enabled || e.Micro.Recipe != "micro_safe" {
		t.Fatalf("reload mismatch: ok=%v e=%+v", ok, e)
	}
}

func TestSiteCacheStore_SetPreservesGenerationAndCreatedAt(t *testing.T) {
	s := newSiteCacheTestStore(t)
	first, _ := s.Set(SiteCacheEntry{Host: "a.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})

	// Purge bumps generation…
	purged, ok := s.Purge("a.com")
	if !ok || purged.Generation != 1 {
		t.Fatalf("purge: ok=%v gen=%d", ok, purged.Generation)
	}
	// …and a later config change must NOT reset it.
	upd, err := s.Set(SiteCacheEntry{Host: "a.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_aggressive"}})
	if err != nil {
		t.Fatalf("Set update: %v", err)
	}
	if upd.Generation != 1 {
		t.Fatalf("config change reset generation to %d (want 1)", upd.Generation)
	}
	if !upd.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("config change changed CreatedAt")
	}
}

func TestSiteCacheStore_GenerationAndCreatedAtNotClientSettable(t *testing.T) {
	s := newSiteCacheTestStore(t)
	backdated := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now().UTC().Add(-time.Second)
	got, err := s.Set(SiteCacheEntry{
		Host:       "a.com",
		Generation: 2_000_000_000, // a caller must not be able to seed the cache-key generation
		CreatedAt:  backdated,      // …nor forge the audit creation time
		Micro:      SiteCacheTier{Enabled: true, Recipe: "micro_safe"},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got.Generation != 0 {
		t.Fatalf("client-seeded generation honored: got %d, want 0", got.Generation)
	}
	if got.CreatedAt.Before(before) {
		t.Fatalf("client-backdated CreatedAt honored: got %v", got.CreatedAt)
	}
}

func TestSiteCacheStore_ScopeHostsPreservedAcrossEdits(t *testing.T) {
	s := newSiteCacheTestStore(t)
	// A scoped tenant first enables caching (the API layer stamps scope_hosts).
	if _, err := s.Set(SiteCacheEntry{
		Host:       "alice.com",
		ScopeHosts: []string{"alice.com"},
		Micro:      SiteCacheTier{Enabled: true, Recipe: "micro_safe"},
	}); err != nil {
		t.Fatalf("Set create: %v", err)
	}
	// An admin later edits it (nil scope → empty scope_hosts). The original
	// opt-in attribution must survive.
	got, err := s.Set(SiteCacheEntry{
		Host:  "alice.com",
		Micro: SiteCacheTier{Enabled: true, Recipe: "micro_aggressive"},
	})
	if err != nil {
		t.Fatalf("Set update: %v", err)
	}
	if len(got.ScopeHosts) != 1 || got.ScopeHosts[0] != "alice.com" {
		t.Fatalf("scope_hosts attribution lost on admin edit: %+v", got.ScopeHosts)
	}
}

func TestSiteCacheStore_PurgeAll(t *testing.T) {
	s := newSiteCacheTestStore(t)
	_, _ = s.Set(SiteCacheEntry{Host: "a.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})
	_, _ = s.Set(SiteCacheEntry{Host: "b.com", Static: SiteCacheTier{Enabled: true, Recipe: "static_lean"}})

	if n := s.PurgeAll(); n != 2 {
		t.Fatalf("PurgeAll returned %d, want 2", n)
	}
	for _, h := range []string{"a.com", "b.com"} {
		e, _ := s.Get(h)
		if e.Generation != 1 {
			t.Fatalf("%s generation=%d, want 1", h, e.Generation)
		}
	}
	// PurgeAll on an empty store is a no-op (0), never an error.
	empty := newSiteCacheTestStore(t)
	if n := empty.PurgeAll(); n != 0 {
		t.Fatalf("PurgeAll on empty returned %d", n)
	}
}

func TestSiteCacheStore_Validation(t *testing.T) {
	s := newSiteCacheTestStore(t)
	cases := []struct {
		name string
		in   SiteCacheEntry
	}{
		{"bad host wildcard mid", SiteCacheEntry{Host: "cdn.*.example.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}}},
		{"empty host", SiteCacheEntry{Host: "   ", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}}},
		{"unknown static recipe", SiteCacheEntry{Host: "a.com", Static: SiteCacheTier{Enabled: true, Recipe: "nope"}}},
		{"micro recipe in static tier", SiteCacheEntry{Host: "a.com", Static: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}}},
		{"enabled tier without recipe", SiteCacheEntry{Host: "a.com", Micro: SiteCacheTier{Enabled: true}}},
		{"bad ttl", SiteCacheEntry{Host: "a.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe", TTL: "5x"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Set(tc.in); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
	// A "*.suffix" wildcard IS allowed.
	if _, err := s.Set(SiteCacheEntry{Host: "*.cdn.example.com", Static: SiteCacheTier{Enabled: true, Recipe: "static_lean"}}); err != nil {
		t.Fatalf("wildcard host should be allowed: %v", err)
	}
}

func TestSiteCacheStore_PolicyFeed(t *testing.T) {
	s := newSiteCacheTestStore(t)
	// Enabled static tier → appears in the feed.
	if _, err := s.Set(SiteCacheEntry{
		Host:   "on.com",
		Static: SiteCacheTier{Enabled: true, Recipe: "static_lean", TTL: "1h"},
	}); err != nil {
		t.Fatalf("Set on.com: %v", err)
	}
	// Configured but both tiers disabled (staged) → must NOT appear in the feed.
	if _, err := s.Set(SiteCacheEntry{
		Host:   "off.com",
		Static: SiteCacheTier{Enabled: false, Recipe: "static_lean"},
	}); err != nil {
		t.Fatalf("Set off.com: %v", err)
	}

	feed := s.PolicyFeed()
	if len(feed) != 1 {
		t.Fatalf("feed should contain only vhosts with an enabled tier, got %d: %+v", len(feed), feed)
	}
	row := feed[0]
	if row.Host != "on.com" {
		t.Fatalf("wrong host in feed: %q", row.Host)
	}
	if row.Static == nil || !row.Static.On || row.Static.TTL != "1h" || row.Static.Recipe != "static_lean" {
		t.Fatalf("static tier not carried: %+v", row.Static)
	}
	if row.Micro != nil {
		t.Fatalf("disabled micro tier must be absent (nil), got: %+v", row.Micro)
	}
}

func TestParseCacheTTL(t *testing.T) {
	ok := []string{"1s", "30s", "5m", "1h", "7d", "30d"}
	for _, v := range ok {
		if _, err := parseCacheTTL(v); err != nil {
			t.Errorf("parseCacheTTL(%q) unexpected error: %v", v, err)
		}
	}
	bad := []string{"", "s", "0s", "-1s", "5x", "abc", "10"}
	for _, v := range bad {
		if _, err := parseCacheTTL(v); err == nil {
			t.Errorf("parseCacheTTL(%q) expected error", v)
		}
	}
}

// ── API scope enforcement ────────────────────────────────────────────────────

func newSiteCacheAPITestEngine(t *testing.T) (*Engine, *http.ServeMux) {
	t.Helper()
	e := NewEngine(Config{SiteCacheStorePath: filepath.Join(t.TempDir(), "site_cache.json")})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)
	return e, mux
}

func siteCacheSetBody(t *testing.T, host string) []byte {
	t.Helper()
	b, err := json.Marshal(SiteCacheEntry{
		Host:  host,
		Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe", TTL: "1s"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestSiteCacheAPI_ScopedCanMutateOwnHost(t *testing.T) {
	_, mux := newSiteCacheAPITestEngine(t)

	// Scoped token for mysite.com may set its own host.
	rr := doRequest(mux, scopedCtx("mysite.com"), http.MethodPost, "/api/v1/site-cache/set", siteCacheSetBody(t, "mysite.com"))
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped set own host: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	// The audit scope_hosts must be stamped from the token, not the client body.
	var res siteCacheResultResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res.Entry.ScopeHosts) != 1 || res.Entry.ScopeHosts[0] != "mysite.com" {
		t.Fatalf("scope_hosts not stamped from token: %+v", res.Entry.ScopeHosts)
	}

	// …but NOT another tenant's host.
	rr = doRequest(mux, scopedCtx("mysite.com"), http.MethodPost, "/api/v1/site-cache/set", siteCacheSetBody(t, "other.com"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped set other host: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSiteCacheAPI_ScopedListFiltered(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	// Seed two tenants directly through the engine (admin path).
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "mysite.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "other.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})

	rr := doRequest(mux, scopedCtx("mysite.com"), http.MethodGet, "/api/v1/site-cache/list", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped list: expected 200, got %d", rr.Code)
	}
	var out siteCacheListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Rows) != 1 || out.Rows[0].Host != "mysite.com" {
		t.Fatalf("scoped list not filtered to own vhost: %+v", out.Rows)
	}

	// Admin sees both.
	rr = doRequest(mux, adminCtx(), http.MethodGet, "/api/v1/site-cache/list", nil)
	var all siteCacheListResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &all)
	if len(all.Rows) != 2 {
		t.Fatalf("admin list should see 2, got %d", len(all.Rows))
	}
}

func TestSiteCacheAPI_ScopedGetRemovePurgeOutOfScope(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "other.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})

	for _, tc := range []struct {
		name, method, path string
	}{
		{"get", http.MethodGet, "/api/v1/site-cache/get?host=other.com"},
		{"remove", http.MethodPost, "/api/v1/site-cache/remove?host=other.com"},
		{"purge", http.MethodPost, "/api/v1/site-cache/purge?host=other.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := doRequest(mux, scopedCtx("mysite.com"), tc.method, tc.path, nil)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("scoped %s out-of-scope: expected 403, got %d body=%s", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestSiteCacheAPI_PurgeAllAdminOnly(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	_, _ = e.SiteCacheSet(SiteCacheEntry{Host: "mysite.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})

	// Scoped may NOT purge-all, even with a vhost in scope.
	rr := doRequest(mux, scopedCtx("mysite.com"), http.MethodPost, "/api/v1/site-cache/purge?all=1", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped purge-all: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	// Admin may.
	rr = doRequest(mux, adminCtx(), http.MethodPost, "/api/v1/site-cache/purge?all=1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin purge-all: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSiteCacheAPI_NoScopeFailsClosed(t *testing.T) {
	_, mux := newSiteCacheAPITestEngine(t)
	// A scoped token with a NIL vhost map must not be mistaken for admin.
	rr := doRequest(mux, scopedCtxNoVhosts(), http.MethodPost, "/api/v1/site-cache/set", siteCacheSetBody(t, "mysite.com"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-scope set: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}
