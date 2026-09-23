// internal/webdetector/site_cache_test.go
package webdetector

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	if got.Generation <= 0 {
		t.Fatalf("a new policy must get a (wall-clock) generation, got %d", got.Generation)
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

	// Purge replaces the generation with a new, larger one…
	purged, ok := s.Purge("a.com")
	if !ok || purged.Generation <= first.Generation {
		t.Fatalf("purge: ok=%v gen=%d (was %d)", ok, purged.Generation, first.Generation)
	}
	// …and a later config change must NOT touch it.
	upd, err := s.Set(SiteCacheEntry{Host: "a.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_aggressive"}})
	if err != nil {
		t.Fatalf("Set update: %v", err)
	}
	if upd.Generation != purged.Generation {
		t.Fatalf("config change changed generation to %d (want %d)", upd.Generation, purged.Generation)
	}
	if !upd.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("config change changed CreatedAt")
	}
}

func TestSiteCacheStore_GenerationAndCreatedAtNotClientSettable(t *testing.T) {
	s := newSiteCacheTestStore(t)
	backdated := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now().UTC().Add(-time.Second)
	const seeded = 9_000_000_000_000 // far past the wall clock in ms
	got, err := s.Set(SiteCacheEntry{
		Host:       "a.com",
		Generation: seeded,    // a caller must not be able to seed the cache-key generation
		CreatedAt:  backdated, // …nor forge the audit creation time
		Micro:      SiteCacheTier{Enabled: true, Recipe: "micro_safe"},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got.Generation == seeded || got.Generation < before.UnixMilli() || got.Generation > time.Now().UnixMilli() {
		t.Fatalf("generation %d is not the server's wall clock (client seeded %d)", got.Generation, seeded)
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

	before := map[string]int64{}
	for _, h := range []string{"a.com", "b.com"} {
		e, _ := s.Get(h)
		before[h] = e.Generation
	}
	if n := s.PurgeAll(); n != 2 {
		t.Fatalf("PurgeAll returned %d, want 2", n)
	}
	for _, h := range []string{"a.com", "b.com"} {
		e, _ := s.Get(h)
		if e.Generation <= before[h] {
			t.Fatalf("%s generation=%d, want > %d", h, e.Generation, before[h])
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

// A generation must never repeat for a host: a remove + re-add (or a purge)
// that reused an old value would turn that value's still-on-disk objects back
// into HITs, undoing the purge. Exercised inside one millisecond on purpose.
func TestSiteCacheStore_GenerationNeverReused(t *testing.T) {
	s := newSiteCacheTestStore(t)
	seen := map[int64]bool{}
	note := func(g int64, what string) {
		t.Helper()
		if seen[g] {
			t.Fatalf("%s reused generation %d", what, g)
		}
		seen[g] = true
	}
	micro := SiteCacheTier{Enabled: true, Recipe: "micro_safe"}
	for i := 0; i < 50; i++ {
		e, err := s.Set(SiteCacheEntry{Host: "a.com", Micro: micro})
		if err != nil {
			t.Fatalf("Set: %v", err)
		}
		note(e.Generation, "re-add")
		p, ok := s.Purge("a.com")
		if !ok {
			t.Fatal("Purge failed")
		}
		note(p.Generation, "purge")
		if !s.Remove("a.com") {
			t.Fatal("Remove failed")
		}
	}
}

// Across a restart the in-memory high-water mark is rebuilt from disk, and a
// stored generation AHEAD of the clock (a skewed clock, or a store written by a
// host whose clock ran fast) is still never re-issued.
func TestSiteCacheStore_GenerationPastStoredValueAfterReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "site_cache.json")
	future := time.Now().Add(24 * time.Hour).UnixMilli()
	raw := `[{"host":"a.com","generation":` + strconv.FormatInt(future, 10) + `,"static":{"enabled":true,"recipe":"static_lean"},"micro":{"enabled":false}}]`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newSiteCacheStore(path)
	p, ok := s.Purge("a.com")
	if !ok || p.Generation <= future {
		t.Fatalf("purge after reload: ok=%v gen=%d, want > %d", ok, p.Generation, future)
	}
	if !s.Remove("a.com") {
		t.Fatal("Remove failed")
	}
	e, err := s.Set(SiteCacheEntry{Host: "a.com", Static: SiteCacheTier{Enabled: true, Recipe: "static_lean"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.Generation <= p.Generation {
		t.Fatalf("re-add after remove got gen %d, want > %d", e.Generation, p.Generation)
	}
}

// scope_hosts is exactly [Host] for a scoped creator — never the creating
// token's whole allowlist (which leaked a tenant's domain list) — including a
// legacy entry loaded from disk.
func TestSiteCacheStore_ScopeHostsTrimmedToHost(t *testing.T) {
	s := newSiteCacheTestStore(t)
	got, err := s.Set(SiteCacheEntry{
		Host:       "alice.com",
		ScopeHosts: []string{"bob.com", "alice.com", "carol.com"},
		Micro:      SiteCacheTier{Enabled: true, Recipe: "micro_safe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ScopeHosts) != 1 || got.ScopeHosts[0] != "alice.com" {
		t.Fatalf("scope_hosts = %v, want [alice.com]", got.ScopeHosts)
	}

	path := filepath.Join(t.TempDir(), "site_cache.json")
	raw := `[{"host":"alice.com","scope_hosts":["alice.com","bob.com","carol.com"],"generation":7,"static":{"enabled":false},"micro":{"enabled":true,"recipe":"micro_safe"}}]`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	e, ok := newSiteCacheStore(path).Get("alice.com")
	if !ok || len(e.ScopeHosts) != 1 || e.ScopeHosts[0] != "alice.com" {
		t.Fatalf("legacy scope_hosts not trimmed on load: ok=%v %v", ok, e.ScopeHosts)
	}
	if e.Generation != 7 {
		t.Fatalf("load changed the stored generation: %d", e.Generation)
	}
}

func strPtr(v string) *string { return &v }
func boolPtr(v bool) *bool    { return &v }

// set is a MERGE: a field the patch does not carry keeps its stored value, so
// retuning one knob cannot reset the cookie safety settings or the other tier.
func TestSiteCacheStore_ApplyMerges(t *testing.T) {
	s := newSiteCacheTestStore(t)
	cookies := []string{"my_session"}
	created, err := s.Apply(SiteCachePatch{
		Host:          "a.com",
		Static:        &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("static_lean"), TTL: strPtr("7d")},
		Micro:         &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("micro_safe"), TTL: strPtr("1s")},
		StrictCookies: boolPtr(true),
		AuthCookies:   &cookies,
	}, false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Retune only the micro TTL.
	got, err := s.Apply(SiteCachePatch{Host: "a.com", Micro: &SiteCacheTierPatch{TTL: strPtr("30s")}}, false)
	if err != nil {
		t.Fatalf("retune: %v", err)
	}
	if got.Micro != (SiteCacheTier{Enabled: true, Recipe: "micro_safe", TTL: "30s"}) {
		t.Fatalf("micro tier = %+v, want micro_safe/30s still enabled", got.Micro)
	}
	if got.Static != (SiteCacheTier{Enabled: true, Recipe: "static_lean", TTL: "7d"}) {
		t.Fatalf("static tier was reset by a micro retune: %+v", got.Static)
	}
	if !got.StrictCookies || len(got.AuthCookies) != 1 || got.AuthCookies[0] != "my_session" {
		t.Fatalf("cookie settings were reset by a TTL retune: strict=%v auth=%v", got.StrictCookies, got.AuthCookies)
	}
	if got.Generation != created.Generation || !got.CreatedAt.Equal(created.CreatedAt) {
		t.Fatal("a merge changed the generation or CreatedAt")
	}

	// Explicit values ARE applied: disable a tier (recipe kept), strict off,
	// an empty auth-cookie list clears it.
	empty := []string{}
	got, err = s.Apply(SiteCachePatch{
		Host:          "a.com",
		Static:        &SiteCacheTierPatch{Enabled: boolPtr(false)},
		StrictCookies: boolPtr(false),
		AuthCookies:   &empty,
	}, false)
	if err != nil {
		t.Fatalf("explicit values: %v", err)
	}
	if got.Static.Enabled || got.Static.Recipe != "static_lean" || !got.Micro.Enabled {
		t.Fatalf("tier toggle: static=%+v micro=%+v", got.Static, got.Micro)
	}
	if got.StrictCookies || got.AuthCookies != nil {
		t.Fatalf("explicit false / empty list not applied: strict=%v auth=%v", got.StrictCookies, got.AuthCookies)
	}

	// An invalid patch is rejected whole: nothing stored changes.
	if _, err := s.Apply(SiteCachePatch{Host: "a.com", Micro: &SiteCacheTierPatch{Recipe: strPtr("nope")}}, false); err == nil {
		t.Fatal("unknown recipe accepted")
	}
	if e, _ := s.Get("a.com"); e.Micro.Recipe != "micro_safe" || e.Micro.TTL != "30s" {
		t.Fatalf("a rejected patch changed the stored policy: %+v", e.Micro)
	}
	// A new host enabled without a recipe is rejected and NOT created.
	if _, err := s.Apply(SiteCachePatch{Host: "b.com", Micro: &SiteCacheTierPatch{Enabled: boolPtr(true)}}, false); err == nil {
		t.Fatal("enabled tier without a recipe accepted")
	}
	if _, ok := s.Get("b.com"); ok {
		t.Fatal("a rejected patch created an entry")
	}
}

func TestSiteCacheStore_ApplyScopeAttribution(t *testing.T) {
	s := newSiteCacheTestStore(t)
	on := &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("micro_safe")}
	got, err := s.Apply(SiteCachePatch{Host: "Alice.com", Micro: on}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ScopeHosts) != 1 || got.ScopeHosts[0] != "alice.com" {
		t.Fatalf("scoped create: scope_hosts=%v, want [alice.com]", got.ScopeHosts)
	}
	// An admin edit keeps the tenant attribution…
	got, _ = s.Apply(SiteCachePatch{Host: "alice.com", Micro: &SiteCacheTierPatch{TTL: strPtr("5s")}}, false)
	if len(got.ScopeHosts) != 1 {
		t.Fatalf("admin edit erased the attribution: %v", got.ScopeHosts)
	}
	// …and an admin create records none.
	got, _ = s.Apply(SiteCachePatch{Host: "admin.com", Micro: on}, false)
	if got.ScopeHosts != nil {
		t.Fatalf("admin create: scope_hosts=%v, want none", got.ScopeHosts)
	}
}

// The feed: armed vhosts, plus an opt-out row (no tier) for an all-off EXACT
// host that an armed wildcard covers — the edge's exact match wins, so a tenant
// can opt its vhost out of an admin wildcard. Order: exact hosts, then
// wildcards most specific first (the edge takes the first matching wildcard).
func TestSiteCacheStore_PolicyFeedOptOutAndOrder(t *testing.T) {
	s := newSiteCacheTestStore(t)
	on := SiteCacheTier{Enabled: true, Recipe: "static_lean"}
	off := SiteCacheTier{Enabled: false, Recipe: "static_lean"}
	for _, e := range []SiteCacheEntry{
		{Host: "b.com", Static: on},
		{Host: "*.example.com", Static: on},
		{Host: "a.com", Static: on},
		{Host: "*.shop.example.com", Static: on},
		{Host: "tenant.example.com", Static: off}, // covered → opt-out row
		{Host: "example.com", Static: off},        // bare suffix, NOT covered → absent
		{Host: "off.com", Static: off},            // not covered → absent
		{Host: "*.staged.com", Static: off},       // all-off wildcard → absent
		{Host: "x.staged.com", Static: off},       // under an UNARMED wildcard → absent
	} {
		if _, err := s.Set(e); err != nil {
			t.Fatalf("Set %s: %v", e.Host, err)
		}
	}
	feed := s.PolicyFeed()
	var hosts []string
	for _, r := range feed {
		hosts = append(hosts, r.Host)
	}
	want := []string{"a.com", "b.com", "tenant.example.com", "*.shop.example.com", "*.example.com"}
	if strings.Join(hosts, " ") != strings.Join(want, " ") {
		t.Fatalf("feed order = %v, want %v", hosts, want)
	}
	opt := feed[2]
	if opt.Static != nil || opt.Micro != nil || opt.Generation <= 0 {
		t.Fatalf("opt-out row must carry no tier (and its generation): %+v", opt)
	}
	b, _ := json.Marshal(opt)
	if strings.Contains(string(b), `"static"`) || strings.Contains(string(b), `"micro"`) {
		t.Fatalf("opt-out row leaks a tier on the wire: %s", b)
	}
}

// StatsKeyFor must pick the key the edge counts under (policy_key_for).
func TestSiteCacheStore_StatsKeyFor(t *testing.T) {
	s := newSiteCacheTestStore(t)
	on := SiteCacheTier{Enabled: true, Recipe: "static_lean"}
	off := SiteCacheTier{Enabled: false, Recipe: "static_lean"}
	for _, e := range []SiteCacheEntry{
		{Host: "*.example.com", Static: on},
		{Host: "*.shop.example.com", Static: on},
		{Host: "*.staged.example.com", Static: off},
		{Host: "armed.example.com", Static: on},
		{Host: "tenant.example.com", Static: off},
	} {
		if _, err := s.Set(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		host, key string
		ok        bool
	}{
		{"x.shop.example.com", "*.shop.example.com", true}, // most specific wins
		{"a.example.com", "*.example.com", true},
		{"y.staged.example.com", "*.example.com", true},  // an unarmed wildcard is skipped
		{"armed.example.com", "armed.example.com", true}, // exact wins, never its wildcard
		{"tenant.example.com", "", false},                // opt-out: counted nowhere
		{"example.com", "", false},                       // bare suffix
		{"*.shop.example.com", "*.shop.example.com", true},
		{"other.com", "", false},
	} {
		key, ok := s.StatsKeyFor(tc.host)
		if key != tc.key || ok != tc.ok {
			t.Errorf("StatsKeyFor(%q) = %q,%v; want %q,%v", tc.host, key, ok, tc.key, tc.ok)
		}
	}
}

// A NEW entry that ends up all-off is an opt-out (it stops a covering armed
// wildcard from caching the host), so it is created only when the patch turns
// BOTH tiers off explicitly — never as a side effect of staging a TTL.
func TestSiteCacheStore_ApplyNewAllOffOnlyWhenExplicit(t *testing.T) {
	s := newSiteCacheTestStore(t)
	for _, tc := range []struct {
		name string
		p    SiteCachePatch
	}{
		{"ttl only", SiteCachePatch{Host: "a.com", Micro: &SiteCacheTierPatch{TTL: strPtr("30s")}}},
		{"cookie only", SiteCachePatch{Host: "a.com", StrictCookies: boolPtr(true)}},
		{"host only", SiteCachePatch{Host: "a.com"}},
		{"one tier off", SiteCachePatch{Host: "a.com", Static: &SiteCacheTierPatch{Enabled: boolPtr(false)}}},
	} {
		if _, err := s.Apply(tc.p, false); err == nil {
			t.Errorf("%s: a new all-off entry was created implicitly", tc.name)
		}
	}
	if _, ok := s.Get("a.com"); ok {
		t.Fatal("a rejected patch created an entry")
	}
	off := &SiteCacheTierPatch{Enabled: boolPtr(false)}
	e, err := s.Apply(SiteCachePatch{Host: "a.com", Static: off, Micro: off}, true)
	if err != nil {
		t.Fatalf("explicit opt-out rejected: %v", err)
	}
	if e.Static.Enabled || e.Micro.Enabled || e.Generation <= 0 {
		t.Fatalf("opt-out entry = %+v", e)
	}
	// An EXISTING armed entry may be turned all-off by any patch.
	on := &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("static_lean")}
	if _, err := s.Apply(SiteCachePatch{Host: "b.com", Static: on}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(SiteCachePatch{Host: "b.com", Static: off}, false); err != nil {
		t.Fatalf("turning an existing tier off: %v", err)
	}
}

// The edge strips a :port from both the request Host and the feed's hosts, so
// the store keys on the bare host too; a NEW policy with a port is rejected.
func TestSiteCacheStore_PortHandling(t *testing.T) {
	s := newSiteCacheTestStore(t)
	on := &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("static_lean")}
	if _, err := s.Apply(SiteCachePatch{Host: "a.com:443", Static: on}, false); err == nil {
		t.Fatal("a host with a port was accepted")
	}
	if _, err := s.Apply(SiteCachePatch{Host: "*.example.com:8080", Static: on}, false); err == nil {
		t.Fatal("a wildcard with a port was accepted")
	}

	// Loading: a stored port is stripped (it always acted as the bare host at
	// the edge), a duplicate keeps the higher generation, and the file is
	// rewritten normalized.
	path := filepath.Join(t.TempDir(), "site_cache.json")
	raw := `[
	 {"host":"a.com:443","generation":9000,"static":{"enabled":true,"recipe":"static_lean"},"micro":{"enabled":false}},
	 {"host":"A.com","generation":5,"static":{"enabled":false},"micro":{"enabled":true,"recipe":"micro_safe"}},
	 {"host":"b.com","generation":7,"scope_hosts":["b.com","secret.com"],"static":{"enabled":true,"recipe":"static_lean"},"micro":{"enabled":false}}
	]`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := newSiteCacheStore(path)
	e, ok := s2.Get("a.com")
	if !ok || e.Generation != 9000 || !e.Static.Enabled {
		t.Fatalf("duplicate resolution: ok=%v %+v (want the gen-9000 row)", ok, e)
	}
	if len(s2.List()) != 2 {
		t.Fatalf("want 2 entries, got %d", len(s2.List()))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, leftover := range []string{"secret.com", "a.com:443", `"A.com"`} {
		if strings.Contains(string(b), leftover) {
			t.Fatalf("store not rewritten normalized on load; still holds %s:\n%s", leftover, b)
		}
	}
	if p, ok := s2.Purge("a.com"); !ok || p.Generation <= 9000 {
		t.Fatalf("purge after load: %+v", p)
	}
}

// Generations are unique across the WHOLE store, so an exact host's fresh
// policy never shares a value — and so a key space — with its covering
// wildcard, even when both are created within one millisecond.
func TestSiteCacheStore_GenerationsUniqueStoreWide(t *testing.T) {
	s := newSiteCacheTestStore(t)
	seen := map[int64]string{}
	on := SiteCacheTier{Enabled: true, Recipe: "static_lean"}
	for i := 0; i < 200; i++ {
		h := "h" + strconv.Itoa(i) + ".example.com"
		if i == 0 {
			h = "*.example.com"
		}
		e, err := s.Set(SiteCacheEntry{Host: h, Static: on})
		if err != nil {
			t.Fatal(err)
		}
		if other, dup := seen[e.Generation]; dup {
			t.Fatalf("%s and %s share generation %d", h, other, e.Generation)
		}
		seen[e.Generation] = h
	}
	if n := s.PurgeAll(); n != 200 {
		t.Fatalf("purge-all: %d", n)
	}
	for _, e := range s.List() {
		if other, dup := seen[e.Generation]; dup {
			t.Fatalf("purge-all reissued %d (%s) for %s", e.Generation, other, e.Host)
		}
		seen[e.Generation] = e.Host
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

// Through the API: a patch body changes only what it carries, a scoped
// creator is recorded as exactly the host (not its token's whole allowlist),
// and an error response carries no entry.
func TestSiteCacheAPI_SetMergesAndStampsHostOnly(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	ctx := scopedCtx("mysite.com", "tenant-other.com", "tenant-third.com")
	full := []byte(`{"host":"mysite.com","static":{"enabled":true,"recipe":"static_lean","ttl":"7d"},"micro":{"enabled":true,"recipe":"micro_safe","ttl":"1s"},"strict_cookies":true,"auth_cookies":["sess"]}`)
	if rr := doRequest(mux, ctx, http.MethodPost, "/api/v1/site-cache/set", full); rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	rr := doRequest(mux, ctx, http.MethodPost, "/api/v1/site-cache/set", []byte(`{"host":"mysite.com","micro":{"ttl":"30s"}}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("retune: %d %s", rr.Code, rr.Body.String())
	}
	got, _ := e.SiteCacheGet("mysite.com")
	if !got.Static.Enabled || got.Static.TTL != "7d" || got.Micro.TTL != "30s" || !got.StrictCookies || len(got.AuthCookies) != 1 {
		t.Fatalf("a TTL-only set reset other fields: %+v", got)
	}
	if len(got.ScopeHosts) != 1 || got.ScopeHosts[0] != "mysite.com" {
		t.Fatalf("scope_hosts = %v, want exactly [mysite.com] (never the token's allowlist)", got.ScopeHosts)
	}

	rr = doRequest(mux, ctx, http.MethodPost, "/api/v1/site-cache/set", []byte(`{"host":"mysite.com","micro":{"recipe":"nope"}}`))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad recipe: %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), `"entry"`) {
		t.Fatalf("error response carries an entry: %s", rr.Body.String())
	}
}

func TestSiteCacheAPI_ScopedListFiltered(t *testing.T) {
	e, mux := newSiteCacheAPITestEngine(t)
	// Seed two tenants directly through the engine (admin path).
	_, _ = e.siteCache.Set(SiteCacheEntry{Host: "mysite.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})
	_, _ = e.siteCache.Set(SiteCacheEntry{Host: "other.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})

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
	_, _ = e.siteCache.Set(SiteCacheEntry{Host: "other.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})

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
	_, _ = e.siteCache.Set(SiteCacheEntry{Host: "mysite.com", Micro: SiteCacheTier{Enabled: true, Recipe: "micro_safe"}})

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
