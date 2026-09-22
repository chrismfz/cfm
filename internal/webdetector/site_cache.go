// internal/webdetector/site_cache.go
//
// Site Cache — per-vhost edge caching policy store.
// Design / plan of record: docs/site-cache-design.md.
//
// PHASE 1 (this file): the daemon-side store ONLY. Nothing here makes
// OpenResty/Angie cache anything — there is no edge bridge or Lua yet. This
// persists an operator's per-vhost cache INTENT so the later phases (the
// /nginx/cache/config edge-pull + cfm_cache.lua) have a source of truth to
// serve.
//
// Semantics (opt-in, like http3OverrideStore — NOT like the exclude stores):
//   - The global default for every vhost is "NO caching".
//   - A host appears here only when an operator (or a scoped cPanel user, for
//     their own domain) turned caching on.
//   - Two INDEPENDENT tiers per host — a static-asset cache and a micro-cache
//     of HTML — each with its own recipe + TTL, so a vhost can run one or both.
//   - Exact host by default (e.g. "myip.gr" and "www.myip.gr" are two entries);
//     a "*.suffix" wildcard is the only pattern class allowed, mirroring
//     http3OverrideStore, so a scoped user manages exact hosts and the Lua data
//     path (later phase) can always match what is stored.
//
// SAFETY: enabling a tier here records INTENT only. The absolute never-cache
// rails (auth cookies, Set-Cookie responses, redirects, panel/webmail hosts,
// /.well-known, …) live at the EDGE (docs/site-cache-design.md §4) and are
// neither expressible nor disableable here. This store can only ever say
// "vhost X opted into tier Y with recipe R / ttl T".
//
// Storage: JSON array of SiteCacheEntry on disk at
// /var/lib/cfm/webdetector_site_cache.json (SITE_CACHE_STORE_PATH), atomic
// write, root:cfm-safe 0600. Same store mechanics as http3_overrides_store.go.

package webdetector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// maxSiteCacheEntries caps the store so a runaway API caller cannot grow the
// on-disk file without bound. One entry per vhost, so this is generous.
const maxSiteCacheEntries = 5000

// maxSiteCacheAuthCookies caps the per-vhost extra auth-cookie-name list.
const maxSiteCacheAuthCookies = 32

// cacheTierKind selects which recipe vocabulary a tier validates against.
type cacheTierKind int

const (
	cacheTierStatic cacheTierKind = iota
	cacheTierMicro
)

// Recipe vocabularies (docs §8). Kept intentionally small in Phase 1; the edge
// (Lua) will enforce Lua↔Go parity on these names in a later phase, so treat
// this list as the source of truth when that lands.
var staticCacheRecipes = map[string]struct{}{
	"static_lean":       {},
	"static_aggressive": {},
}

var microCacheRecipes = map[string]struct{}{
	"micro_safe":        {},
	"micro_aggressive":  {},
	"micro_custom":      {},
	"fullpage_advanced": {},
}

func cacheRecipeAllowed(recipe string, kind cacheTierKind) bool {
	switch kind {
	case cacheTierStatic:
		_, ok := staticCacheRecipes[recipe]
		return ok
	case cacheTierMicro:
		_, ok := microCacheRecipes[recipe]
		return ok
	}
	return false
}

// SiteCacheTier is one caching tier's per-vhost policy. A disabled tier with no
// recipe/ttl is a valid "off" state (staging a config before arming it).
type SiteCacheTier struct {
	Enabled bool   `json:"enabled"`
	Recipe  string `json:"recipe,omitempty"` // one of the tier's recipe vocabulary
	TTL     string `json:"ttl,omitempty"`    // e.g. "1s", "30s", "1h", "7d" (a bucket; the edge snaps)
}

// SiteCacheEntry is one vhost's cache policy: independent static + micro tiers,
// a purge generation, and the cookie-handling advanced knobs (docs §4.1, §6).
type SiteCacheEntry struct {
	Host string `json:"host"`
	// ScopeHosts records who FIRST enabled caching for this vhost (audit trail),
	// stamped from the token scope at creation and PRESERVED across later edits
	// (an admin tweak does not erase the tenant that opted in). It does not gate
	// access — that is the live token scope at the API layer.
	ScopeHosts []string `json:"scope_hosts,omitempty"`
	// Generation is folded into the edge cache key (later phase). A Purge bumps
	// it so old keys become unreachable and age out — a config change never
	// touches it.
	Generation int           `json:"generation"`
	Static     SiteCacheTier `json:"static"`
	Micro      SiteCacheTier `json:"micro"`
	// StrictCookies inverts the cookie-bypass logic to "bypass on ANY cookie not
	// on the ignore-list" (docs §4.1) — max safety, less cache. Default false
	// (the named-auth-cookie allowlist).
	StrictCookies bool `json:"strict_cookies,omitempty"`
	// AuthCookies are extra app-session cookie NAMES (beyond the built-in
	// allowlist) that force a bypass for this vhost (docs §4.1).
	AuthCookies []string  `json:"auth_cookies,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type siteCacheStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]SiteCacheEntry // key = normalized host
}

func newSiteCacheStore(path string) *siteCacheStore {
	s := &siteCacheStore{
		path:    strings.TrimSpace(path),
		entries: make(map[string]SiteCacheEntry),
	}
	s.load()
	return s
}

// normalize lowercases the host, strips a trailing dot, and accepts only exact
// hosts and "*.suffix" wildcards — same rule class as http3OverrideStore so the
// later Lua data path can always match what is stored.
func (s *siteCacheStore) normalize(host string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", false
	}
	if strings.ContainsAny(h, "?[") {
		return "", false
	}
	if strings.Contains(h, "*") {
		if !strings.HasPrefix(h, "*.") || strings.Contains(h[2:], "*") {
			return "", false
		}
	}
	return h, true
}

// parseCacheTTL accepts "<n><unit>" with unit s/m/h/d (time.ParseDuration does
// not understand "d", which the static tier uses). Returns a positive duration.
func parseCacheTTL(v string) (time.Duration, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) < 2 {
		return 0, errors.New("too short")
	}
	unit := v[len(v)-1]
	n, err := strconv.Atoi(v[:len(v)-1])
	if err != nil || n <= 0 {
		return 0, errors.New("bad quantity")
	}
	switch unit {
	case 's':
		return time.Duration(n) * time.Second, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("bad unit %q", string(unit))
	}
}

func normalizeCacheTier(t SiteCacheTier, kind cacheTierKind) (SiteCacheTier, error) {
	out := SiteCacheTier{Enabled: t.Enabled}
	if r := strings.ToLower(strings.TrimSpace(t.Recipe)); r != "" {
		if !cacheRecipeAllowed(r, kind) {
			return SiteCacheTier{}, fmt.Errorf("unknown recipe %q", t.Recipe)
		}
		out.Recipe = r
	}
	if ttl := strings.ToLower(strings.TrimSpace(t.TTL)); ttl != "" {
		if _, err := parseCacheTTL(ttl); err != nil {
			return SiteCacheTier{}, fmt.Errorf("invalid ttl %q: %w", t.TTL, err)
		}
		out.TTL = ttl
	}
	// An enabled tier must say what to cache with: require a recipe.
	if out.Enabled && out.Recipe == "" {
		return SiteCacheTier{}, errors.New("enabled tier needs a recipe")
	}
	return out, nil
}

// normalizeCookieNames trims, de-duplicates (case-insensitively) and caps the
// list. Cookie names keep their original case (some apps are case-sensitive);
// dedup is case-insensitive to avoid near-duplicates.
func normalizeCookieNames(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		key := strings.ToLower(c)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
		if len(out) >= maxSiteCacheAuthCookies {
			break
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *siteCacheStore) normalizeEntry(in SiteCacheEntry) (SiteCacheEntry, error) {
	h, ok := s.normalize(in.Host)
	if !ok {
		return SiteCacheEntry{}, errors.New("invalid or unsupported host (exact host or *.suffix only)")
	}
	r := in
	r.Host = h
	r.ScopeHosts = normalizeScopeHosts(r.ScopeHosts)

	st, err := normalizeCacheTier(r.Static, cacheTierStatic)
	if err != nil {
		return SiteCacheEntry{}, fmt.Errorf("static: %w", err)
	}
	r.Static = st

	mi, err := normalizeCacheTier(r.Micro, cacheTierMicro)
	if err != nil {
		return SiteCacheEntry{}, fmt.Errorf("micro: %w", err)
	}
	r.Micro = mi

	r.AuthCookies = normalizeCookieNames(r.AuthCookies)
	if r.Generation < 0 {
		r.Generation = 0
	}
	return r, nil
}

// Set upserts a vhost's cache policy. Generation and CreatedAt are preserved on
// an existing host (a config change never bumps the purge generation — only
// Purge does). Returns the stored entry.
//
// On save failure the in-memory map is rolled back so the daemon's view matches
// disk (a restart must not silently gain or lose a policy).
func (s *siteCacheStore) Set(in SiteCacheEntry) (SiteCacheEntry, error) {
	norm, err := s.normalizeEntry(in)
	if err != nil {
		return SiteCacheEntry{}, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, existed := s.entries[norm.Host]
	if existed {
		norm.CreatedAt = prev.CreatedAt
		norm.Generation = prev.Generation
		// Preserve the original opt-in attribution: an admin edit (nil scope →
		// empty ScopeHosts) must not erase which tenant first enabled caching.
		norm.ScopeHosts = prev.ScopeHosts
	} else {
		if len(s.entries) >= maxSiteCacheEntries {
			return SiteCacheEntry{}, fmt.Errorf("too many site-cache entries (max %d)", maxSiteCacheEntries)
		}
		// Generation is purge-managed ONLY: a fresh policy always starts at 0 and
		// CreatedAt is stamped server-side. Neither is client-settable — a caller
		// cannot seed a generation (which is folded into the edge cache key) or
		// forge the audit creation time.
		norm.CreatedAt = now
		norm.Generation = 0
	}
	norm.UpdatedAt = now
	s.entries[norm.Host] = norm
	if err := s.saveLocked(); err != nil {
		if existed {
			s.entries[norm.Host] = prev
		} else {
			delete(s.entries, norm.Host)
		}
		logging.Logf("[webdetector][site-cache] failed to persist policy for %q (rollback): %v (path=%s)", norm.Host, err, s.path)
		return SiteCacheEntry{}, err
	}
	return norm, nil
}

// Remove turns caching OFF for a vhost (deletes its policy). Returns true if a
// row was removed.
func (s *siteCacheStore) Remove(host string) bool {
	h, ok := s.normalize(host)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, existed := s.entries[h]
	if !existed {
		return false
	}
	delete(s.entries, h)
	if err := s.saveLocked(); err != nil {
		s.entries[h] = prev
		logging.Logf("[webdetector][site-cache] failed to persist removal of %q (rollback): %v (path=%s)", h, err, s.path)
		return false
	}
	return true
}

// Purge bumps a vhost's generation (invalidating its cached entries at the edge
// in a later phase). Returns the updated entry.
func (s *siteCacheStore) Purge(host string) (SiteCacheEntry, bool) {
	h, ok := s.normalize(host)
	if !ok {
		return SiteCacheEntry{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, existed := s.entries[h]
	if !existed {
		return SiteCacheEntry{}, false
	}
	prev := e
	e.Generation++
	e.UpdatedAt = time.Now().UTC()
	s.entries[h] = e
	if err := s.saveLocked(); err != nil {
		s.entries[h] = prev
		logging.Logf("[webdetector][site-cache] failed to persist purge of %q (rollback): %v (path=%s)", h, err, s.path)
		return SiteCacheEntry{}, false
	}
	return e, true
}

// PurgeAll bumps every vhost's generation. Returns the number of vhosts purged.
func (s *siteCacheStore) PurgeAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) == 0 {
		return 0
	}
	prev := make(map[string]SiteCacheEntry, len(s.entries))
	now := time.Now().UTC()
	for h, e := range s.entries {
		prev[h] = e
		e.Generation++
		e.UpdatedAt = now
		s.entries[h] = e
	}
	if err := s.saveLocked(); err != nil {
		for h, e := range prev {
			s.entries[h] = e
		}
		logging.Logf("[webdetector][site-cache] failed to persist purge-all (rollback): %v (path=%s)", err, s.path)
		return 0
	}
	return len(prev)
}

func (s *siteCacheStore) Get(host string) (SiteCacheEntry, bool) {
	h, ok := s.normalize(host)
	if !ok {
		return SiteCacheEntry{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[h]
	return e, ok
}

// List returns all policies sorted by host. Caller MUST treat the slice as
// read-only.
func (s *siteCacheStore) List() []SiteCacheEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SiteCacheEntry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// HasAny reports whether any vhost has at least one ENABLED tier — the cheap
// gate the edge (later phase) uses to skip its lookup entirely.
func (s *siteCacheStore) HasAny() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.Static.Enabled || e.Micro.Enabled {
			return true
		}
	}
	return false
}

func (s *siteCacheStore) load() {
	if s == nil || s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var arr []SiteCacheEntry
	if err := json.Unmarshal(b, &arr); err != nil {
		// Loud, not silent: a corrupt/truncated store must not vanish quietly
		// (the next write would overwrite it, making the loss permanent). We
		// still start empty — there is nothing safe to recover — but the
		// operator sees why in the log.
		logging.Logf("[webdetector][site-cache] store %s is not valid JSON (%v); starting with no policies — the next write will overwrite it", s.path, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range arr {
		norm, err := s.normalizeEntry(e)
		if err != nil {
			// Loud, not silent: a hand-edit typo or a recipe this build no longer
			// knows would otherwise drop a policy with no trace.
			logging.Logf("[webdetector][site-cache] dropping stored policy for %q on load: %v (path=%s)", e.Host, err, s.path)
			continue
		}
		if norm.CreatedAt.IsZero() {
			norm.CreatedAt = time.Now().UTC()
		}
		if norm.UpdatedAt.IsZero() {
			norm.UpdatedAt = norm.CreatedAt
		}
		s.entries[norm.Host] = norm
	}
}

func (s *siteCacheStore) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	arr := make([]SiteCacheEntry, 0, len(s.entries))
	for _, e := range s.entries {
		arr = append(arr, e)
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].Host < arr[j].Host })
	b, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}
