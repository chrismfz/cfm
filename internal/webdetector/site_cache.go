// internal/webdetector/site_cache.go
//
// Site Cache — per-vhost edge caching policy store.
// Design / plan of record: docs/site-cache-design.md.
//
// The daemon-side store: an operator's per-vhost cache INTENT, served to the
// edge on /nginx/cache/config (PolicyFeed) where cfm_cache.lua turns it into
// the per-request cache gates.
//
// Semantics (opt-in, like http3OverrideStore — NOT like the exclude stores):
//   - The global default for every vhost is "NO caching".
//   - A host appears here when an operator (or a scoped cPanel user, for their
//     own domain) configured it: with at least one tier on, or with both tiers
//     off — an explicit opt-out, which matters when a broader armed "*.suffix"
//     wildcard covers the entry (the more specific entry wins at the edge, so
//     everything it matches caches nothing). A host with NO entry follows the
//     most specific covering armed wildcard, if any.
//   - Two INDEPENDENT tiers per host — a static-asset cache and a micro-cache
//     of HTML — each with its own recipe + TTL, so a vhost can run one or both.
//   - Exact host by default (e.g. "myip.gr" and "www.myip.gr" are two entries);
//     a "*.suffix" wildcard is the only pattern class allowed, mirroring
//     http3OverrideStore, so the edge matcher (cfm_hostmatch.lua) can always
//     match what is stored.
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
	"bytes"
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
	"unicode"

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

// Recipe vocabularies (docs §8). This list is the source of truth for the
// recipe names; the edge reads only the TTL (it does not interpret the recipe
// name yet).
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

// SiteCacheTier is one caching tier's per-vhost policy. A disabled tier keeps
// its recipe/ttl, so it can be re-armed as it was. An entry with BOTH tiers
// off is an explicit opt-out (see the file header), so a new entry may be
// created all-off only on purpose (Apply). As on SiteCacheEntry, a NEW field
// must be `omitempty` with its zero value meaning the old behaviour (an
// unknown nested field freezes the whole row on an older build).
type SiteCacheTier struct {
	Enabled bool   `json:"enabled"`
	Recipe  string `json:"recipe,omitempty"` // one of the tier's recipe vocabulary
	TTL     string `json:"ttl,omitempty"`    // e.g. "1s", "30s", "1h", "7d" (a bucket; the edge snaps)
}

// siteCacheArmed reports whether an entry has at least one tier on.
func siteCacheArmed(e SiteCacheEntry) bool { return e.Static.Enabled || e.Micro.Enabled }

// siteCacheMinGeneration / siteCacheMaxGeneration bound a generation. Below
// the floor (1e12 ms = 2001-09-09) is a LEGACY value: stores written before
// generations were wall-clock ms counted every policy from 0, so an exact host
// and its covering wildcard could share one (the same key space for that
// host), and a retired value could come back. At or past the ceiling the edge
// cannot render it exactly (Lua tostring is %.14g) — only a hand edit gets
// there. Load reissues both.
const (
	siteCacheMinGeneration = int64(1e12)
	siteCacheMaxGeneration = int64(1e14)
)

// SiteCacheEntry is one vhost's cache policy: independent static + micro tiers,
// a purge generation, and the cookie-handling advanced knobs (docs §4.1, §6).
type SiteCacheEntry struct {
	Host string `json:"host"`
	// ScopeHosts records that a scoped (tenant) token FIRST enabled caching for
	// this vhost (audit trail): exactly [Host] when a scoped token created it,
	// empty when an admin did. It is PRESERVED across later edits (an admin
	// tweak does not erase the tenant that opted in). It used to hold the
	// creating token's WHOLE vhost allowlist, which leaked a tenant's full
	// domain list to any other tenant whose scope overlapped this host (and
	// grew the store quadratically); legacy entries are trimmed to [Host] on
	// load. It does not gate access — that is the live token scope at the API.
	ScopeHosts []string `json:"scope_hosts,omitempty"`
	// Generation is folded into the edge cache key; a Purge replaces it so old
	// keys become unreachable and age out. A config change keeps it, EXCEPT
	// re-arming — the static tier going from off to on, or the micro tier
	// going from off to on with the recipe it kept while off — which also
	// issues a new one: a tier is often turned off BECAUSE something wrong got
	// cached (a per-user asset or page, design §14), and its zone may still
	// hold — and, through use_stale, serve — those objects, so turning it back
	// on must not reach them. (Both tiers share the generation, so re-arming
	// one also starts the other from an empty cache — a refill, never a wrong
	// answer. A FIRST micro enable, with no stored recipe, has no old micro
	// objects to hide, so it keeps the static cache.)
	// A value must NEVER be issued twice: a remove + re-add that reused an old
	// value (it used to restart at 0) made that value's still-on-disk objects
	// (static entries live 7 days, and may carry a year of origin max-age) HITs
	// again, undoing an earlier purge. So a new or purged generation is the
	// wall clock in MILLISECONDS, bumped past every generation the store has
	// issued or loaded (nextGenerationLocked) — unique across the whole store,
	// so an exact host's fresh policy never lands on its covering wildcard's
	// key space either. Milliseconds, not nanoseconds: the edge renders it with
	// Lua tostring (%.14g), exact only below 1e14 — ms stays there until the
	// year 5138; ns would render as "1.7e+18" and collide.
	//
	// A purge covers ONE policy key. The edge keys a request on the generation
	// of the policy that MATCHED it, so a host that moves back under a covering
	// "*.suffix" wildcard (its exact policy removed, a narrower wildcard
	// removed) finds that wildcard's own cached objects for it again — served
	// within the wildcard's TTL, like any object of that policy, and cleared
	// only by purging the wildcard. A purge of the host's former exact policy
	// never reached them.
	Generation int64         `json:"generation"`
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
	// A NEW field must be `omitempty`, with its zero value meaning the old
	// behaviour: load freezes any row with a field it does not know (see
	// siteCacheStore.frozen), so a field an older build would see on every
	// row makes a downgrade fail EVERY vhost closed (uncached).
}

type siteCacheStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]SiteCacheEntry // key = normalized host
	// genHWM is the highest generation this store issued or loaded, for ANY
	// host (nextGenerationLocked issues past it). It survives a Remove, so a
	// host removed and re-added within one millisecond still gets a new value.
	// In memory only: after a restart it is rebuilt from the stored entries,
	// so a REMOVED host's last value is forgotten. That can repeat only if the
	// clock stepped back (a VM restore, a boot before NTP sync) past a value
	// issued before the restart AND a new generation then lands on exactly
	// that millisecond.
	genHWM int64
	// frozen holds the stored rows this build could not load — a recipe or a
	// field from a newer build (a downgrade), a malformed hand edit — as
	// stored. saveLocked writes them back (re-indented), so neither a
	// normalizing rewrite at load nor a later change deletes another build's
	// policy. This build does not serve them: a frozen row whose host it can
	// read FAILS CLOSED — the feed treats that host as an opt-out, never as
	// "no entry", which would let a covering wildcard cache it. Remove deletes
	// the frozen rows of its host; purges do not reach them.
	frozen []siteCacheFrozenRow
}

// siteCacheFrozenRow is one stored row this build could not load; host is its
// normalized host, "" when that is unreadable too.
type siteCacheFrozenRow struct {
	host string
	raw  json.RawMessage
}

// SiteCacheTierPatch and SiteCachePatch are the MERGE form of a set request
// (POST /api/v1/site-cache/set): a nil field keeps what is stored, so a client
// that changes one knob — a TTL — cannot silently reset the others (the cookie
// safety settings, the other tier). The set used to REPLACE the whole policy
// with what the request carried, and the CLI built that from the flags given,
// so `set X --micro micro_safe --micro-ttl 30s` disabled the static tier and
// dropped strict_cookies / auth_cookies. An explicit value is applied:
// enabled=false, strict_cookies=false, ttl="", and an EMPTY auth_cookies list
// (which clears it; JSON null keeps it). A recipe cannot be cleared (see
// Apply).
type SiteCacheTierPatch struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Recipe  *string `json:"recipe,omitempty"`
	TTL     *string `json:"ttl,omitempty"`
}

type SiteCachePatch struct {
	Host          string              `json:"host"`
	Static        *SiteCacheTierPatch `json:"static,omitempty"`
	Micro         *SiteCacheTierPatch `json:"micro,omitempty"`
	StrictCookies *bool               `json:"strict_cookies,omitempty"`
	AuthCookies   *[]string           `json:"auth_cookies,omitempty"`
}

func applySiteCacheTierPatch(t *SiteCacheTier, p *SiteCacheTierPatch) {
	if p == nil {
		return
	}
	if p.Enabled != nil {
		t.Enabled = *p.Enabled
	}
	if p.Recipe != nil {
		t.Recipe = *p.Recipe
	}
	if p.TTL != nil {
		t.TTL = *p.TTL
	}
}

func newSiteCacheStore(path string) *siteCacheStore {
	s := &siteCacheStore{
		path:    strings.TrimSpace(path),
		entries: make(map[string]SiteCacheEntry),
	}
	s.load()
	return s
}

// normalize lowercases the host, strips a ":port" and trailing dots, and
// accepts only exact hosts and "*.suffix" wildcards — the same key and rule
// class as the edge (cfm_hostmatch.lua normalize_host / is_supported_pattern),
// which strips the port too: a stored "a.com:443" always acted as "a.com"
// there, so keeping the port here made the opt-out rows and StatsKeyFor
// disagree with the edge. (A NEW policy with a port is rejected in Apply; this
// strip keeps loading, and every lookup, edge-faithful.) An IPv6 literal is
// rejected ("[").
func (s *siteCacheStore) normalize(host string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	// No whitespace or control character inside a host: it is never valid
	// there, and trimming it would make normalize non-idempotent ("a.com ."
	// → "a.com " → "a.com"), so an Apply lookup would miss the stored entry
	// and replace it instead of merging.
	if strings.IndexFunc(h, func(r rune) bool { return r <= ' ' || r == 0x7f || unicode.IsSpace(r) }) >= 0 {
		return "", false
	}
	// Port first, then every trailing dot, so the result is a fixed point:
	// "a.com.:443" and "a.com.." both become "a.com" (normalizing the result
	// again changes nothing, which the Apply lookup and the setLocked store
	// rely on to hit the same key).
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimRight(h, ".")
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
	// A scoped creator is recorded as exactly [Host] (never the token's whole
	// allowlist — see SiteCacheEntry.ScopeHosts); an admin creator as nothing.
	if len(normalizeScopeHosts(r.ScopeHosts)) > 0 {
		r.ScopeHosts = []string{h}
	} else {
		r.ScopeHosts = nil
	}

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

// Set upserts a vhost's WHOLE cache policy (a full replace of the tiers and
// cookie settings). TESTS ONLY: the API uses the merging Apply, and Set skips
// Apply's input rules (no :port, no implicit all-off new entry). CreatedAt is
// preserved on an existing host, and so is Generation, except that re-arming a
// tier issues a new one (see SiteCacheEntry.Generation). Returns the stored
// entry.
//
// On save failure the in-memory map is rolled back so the daemon's view matches
// disk (a restart must not silently gain or lose a policy).
func (s *siteCacheStore) Set(in SiteCacheEntry) (SiteCacheEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setLocked(in)
}

// Apply merges a patch onto the stored policy for p.Host (a new host starts
// from an empty, all-off policy) and stores the result, all under one lock so
// two concurrent edits cannot lose each other. scoped marks a scoped (tenant)
// caller: on a NEW entry it records the opt-in attribution (ScopeHosts =
// [Host]); an existing entry keeps its original attribution either way.
//
// A NEW entry that would end up all-off is created only when the patch turns
// BOTH tiers off explicitly: it is an opt-out, which silently stops a covering
// armed wildcard from caching the host, so it must never be a side effect of
// staging a TTL or a cookie setting for a host not configured yet.
func (s *siteCacheStore) Apply(p SiteCachePatch, scoped bool) (SiteCacheEntry, error) {
	if strings.Contains(p.Host, ":") {
		return SiteCacheEntry{}, errors.New("host must not include a port (the edge keys policies on the bare host)")
	}
	h, ok := s.normalize(p.Host)
	if !ok {
		return SiteCacheEntry{}, errors.New("invalid or unsupported host (exact host or *.suffix only)")
	}
	for _, tp := range []*SiteCacheTierPatch{p.Static, p.Micro} {
		if tp != nil && tp.Recipe != nil && strings.TrimSpace(*tp.Recipe) == "" {
			// A disabled tier keeps its recipe on purpose: it is how a later
			// re-enable knows the tier may have cached something (and must
			// start from a fresh generation — see SiteCacheEntry.Generation).
			return SiteCacheEntry{}, errors.New("a tier's recipe cannot be empty (to turn a tier off, set enabled=false; its recipe is kept)")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	merged, existed := s.entries[h]
	if !existed {
		merged = SiteCacheEntry{Host: h}
		if s.hasFrozenLocked(h) && ((p.Static != nil && p.Static.Enabled != nil && *p.Static.Enabled) ||
			(p.Micro != nil && p.Micro.Enabled != nil && *p.Micro.Enabled)) {
			// The host has a stored policy this build cannot load: merging onto
			// an empty one would silently drop that policy's settings (its
			// cookie rails first). Only an explicit off is allowed — it
			// replaces that policy (setLocked), which the caller asked for.
			return SiteCacheEntry{}, errors.New(siteCacheUnloadableMsg + "; turning caching on for it is refused — remove it first (or turn it off, which replaces it), or upgrade")
		}
	}
	applySiteCacheTierPatch(&merged.Static, p.Static)
	applySiteCacheTierPatch(&merged.Micro, p.Micro)
	if p.StrictCookies != nil {
		merged.StrictCookies = *p.StrictCookies
	}
	if p.AuthCookies != nil {
		merged.AuthCookies = append([]string(nil), (*p.AuthCookies)...)
	}
	if !existed && !merged.Static.Enabled && !merged.Micro.Enabled &&
		!(siteCacheTierPatchOff(p.Static) && siteCacheTierPatchOff(p.Micro)) {
		return SiteCacheEntry{}, errors.New("new policy enables no tier: enable static and/or micro with a recipe, or set BOTH tiers off explicitly for an opt-out")
	}
	if !existed && scoped {
		merged.ScopeHosts = []string{h}
	}
	return s.setLocked(merged)
}

// siteCacheTierPatchOff reports whether a tier patch explicitly turns the tier
// off.
func siteCacheTierPatchOff(t *SiteCacheTierPatch) bool {
	return t != nil && t.Enabled != nil && !*t.Enabled
}

func (s *siteCacheStore) setLocked(in SiteCacheEntry) (SiteCacheEntry, error) {
	norm, err := s.normalizeEntry(in)
	if err != nil {
		return SiteCacheEntry{}, err
	}
	now := time.Now().UTC()
	prev, existed := s.entries[norm.Host]
	if existed {
		norm.CreatedAt = prev.CreatedAt
		norm.Generation = prev.Generation
		if (!prev.Static.Enabled && norm.Static.Enabled) ||
			(!prev.Micro.Enabled && norm.Micro.Enabled && prev.Micro.Recipe != "") {
			// A tier re-armed: start from a fresh key space (see Generation).
			norm.Generation = s.nextGenerationLocked()
		}
		// Preserve the original opt-in attribution: an admin edit (nil scope →
		// empty ScopeHosts) must not erase which tenant first enabled caching.
		norm.ScopeHosts = prev.ScopeHosts
	} else {
		if len(s.entries) >= maxSiteCacheEntries {
			return SiteCacheEntry{}, fmt.Errorf("too many site-cache entries (max %d)", maxSiteCacheEntries)
		}
		// Generation is purge-managed ONLY and CreatedAt is stamped server-side.
		// Neither is client-settable — a caller cannot seed a generation (which is
		// folded into the edge cache key) or forge the audit creation time. A new
		// policy gets a generation this host has never used (a remove + re-add
		// must not bring the old one's cached objects back).
		norm.CreatedAt = now
		norm.Generation = s.nextGenerationLocked()
	}
	norm.UpdatedAt = now
	s.entries[norm.Host] = norm
	// A write REPLACES any stored row of this host this build could not load
	// (see frozen): a host never has both, so what the feed serves, what list
	// shows and what the next build loads always agree. (Apply lets only an
	// explicit off reach here for such a host.)
	prevFrozen := s.frozen
	s.frozen = s.frozenWithoutLocked(norm.Host)
	if err := s.saveLocked(); err != nil {
		if existed {
			s.entries[norm.Host] = prev
		} else {
			delete(s.entries, norm.Host)
		}
		s.frozen = prevFrozen
		logging.Logf("[webdetector][site-cache] failed to persist policy for %q (rollback): %v (path=%s)", norm.Host, err, s.path)
		return SiteCacheEntry{}, err
	}
	if len(s.frozen) != len(prevFrozen) {
		logging.Logf("[webdetector][site-cache] the new policy for %q replaced a stored policy this build could not load (path=%s)", norm.Host, s.path)
	}
	return norm, nil
}

// frozenWithoutLocked returns s.frozen minus the rows of host h (a new slice
// when any is dropped, so a caller can roll back to the old one). Caller holds
// s.mu.
func (s *siteCacheStore) frozenWithoutLocked(h string) []siteCacheFrozenRow {
	if !s.hasFrozenLocked(h) {
		return s.frozen
	}
	kept := make([]siteCacheFrozenRow, 0, len(s.frozen))
	for _, f := range s.frozen {
		if f.host != h {
			kept = append(kept, f)
		}
	}
	return kept
}

// Remove deletes a vhost's policy — and any stored row for that host this
// build could not load (see frozen). Returns true if a row was removed. The
// host is then uncached unless an armed "*.suffix" wildcard covers it — use an
// all-off entry (an opt-out, what the CLI's `off` sets) to keep it uncached
// there too.
func (s *siteCacheStore) Remove(host string) bool {
	h, ok := s.normalize(host)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, existed := s.entries[h]
	prevFrozen := s.frozen
	kept := s.frozenWithoutLocked(h)
	if !existed && len(kept) == len(s.frozen) {
		return false
	}
	delete(s.entries, h)
	s.frozen = kept
	if err := s.saveLocked(); err != nil {
		if existed {
			s.entries[h] = prev
		}
		s.frozen = prevFrozen
		logging.Logf("[webdetector][site-cache] failed to persist removal of %q (rollback): %v (path=%s)", h, err, s.path)
		return false
	}
	return true
}

// Purge gives a vhost a new generation, so every object cached under the old
// one becomes unreachable at the edge (and ages out). Returns the updated entry.
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
	e.Generation = s.nextGenerationLocked()
	e.UpdatedAt = time.Now().UTC()
	s.entries[h] = e
	if err := s.saveLocked(); err != nil {
		s.entries[h] = prev
		logging.Logf("[webdetector][site-cache] failed to persist purge of %q (rollback): %v (path=%s)", h, err, s.path)
		return SiteCacheEntry{}, false
	}
	return e, true
}

// PurgeAll gives every vhost a new generation. Returns the number purged.
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
		e.Generation = s.nextGenerationLocked()
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

// nextGenerationLocked returns a generation the store has never issued or
// loaded: the wall clock in milliseconds, bumped past genHWM (so values are
// unique store-wide and strictly increasing; a purge-all of N hosts within one
// millisecond runs up to N ms ahead of the clock, which is harmless). Caller
// holds s.mu.
func (s *siteCacheStore) nextGenerationLocked() int64 {
	g := time.Now().UnixMilli()
	if g <= s.genHWM {
		g = s.genHWM + 1
	}
	s.genHWM = g
	return g
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

// HasAny reports whether any vhost has at least one ENABLED tier. (The edge
// computes its own has_any from the feed; this is kept for tests.)
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

// CacheTierRow is one tier in the compact edge feed. Referenced by pointer in
// CachePolicyRow so a disabled tier is OMITTED from the wire (a value-typed
// field would always marshal, `omitempty` being a no-op on structs).
type CacheTierRow struct {
	On     bool   `json:"on"`
	Recipe string `json:"recipe,omitempty"`
	TTL    string `json:"ttl,omitempty"`
}

// CachePolicyRow is one vhost's policy as served to the edge on
// /nginx/cache/config. A disabled tier is a nil pointer (absent from the
// JSON), so the edge sees only what is armed. A row with NO tier is an opt-out:
// an all-off entry (exact host or narrower wildcard), emitted only when a
// broader armed wildcard covers it (see PolicyFeed). Deliberately omits created_at/updated_at/
// scope_hosts — the edge does not need them.
type CachePolicyRow struct {
	Host          string        `json:"host"`
	Generation    int64         `json:"gen"`
	Static        *CacheTierRow `json:"static,omitempty"`
	Micro         *CacheTierRow `json:"micro,omitempty"`
	StrictCookies bool          `json:"strict_cookies,omitempty"`
	AuthCookies   []string      `json:"auth_cookies,omitempty"`
}

// PolicyFeed returns the compact per-vhost feed for the edge: every vhost with
// at least one ENABLED tier, plus an opt-out row (no tier) for each all-off
// entry that a broader armed "*.suffix" wildcard covers — an exact host, or a
// narrower wildcard. The edge takes the exact match, else the most specific
// wildcard, so everything the opt-out matches caches nothing (a tenant can opt
// its own vhost out of an admin wildcard). An all-off entry nothing armed
// covers is left out: it changes nothing. Order: exact hosts, then wildcards
// MOST SPECIFIC (longest) first, so an edge that takes the first matching
// wildcard applies *.shop.example.com, not *.example.com, to x.shop.example.com
// (the edge sorts too; this keeps the wire deterministic). Read-only snapshot
// (the returned AuthCookies slices alias stored slices, which the store never
// mutates in place — it replaces entries wholesale).
func (s *siteCacheStore) PolicyFeed() []CachePolicyRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := s.feedEntriesLocked()
	var armedWild []string
	for _, e := range entries {
		if strings.HasPrefix(e.Host, "*.") && (e.Static.Enabled || e.Micro.Enabled) {
			armedWild = append(armedWild, e.Host)
		}
	}
	out := make([]CachePolicyRow, 0, len(entries))
	for _, e := range entries {
		if !siteCacheArmed(e) && !siteCacheWildcardCovers(armedWild, e.Host) {
			continue
		}
		row := CachePolicyRow{
			Host:          e.Host,
			Generation:    e.Generation,
			StrictCookies: e.StrictCookies,
			AuthCookies:   e.AuthCookies,
		}
		if e.Static.Enabled {
			row.Static = &CacheTierRow{On: true, Recipe: e.Static.Recipe, TTL: e.Static.TTL}
		}
		if e.Micro.Enabled {
			row.Micro = &CacheTierRow{On: true, Recipe: e.Micro.Recipe, TTL: e.Micro.TTL}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return siteCacheFeedLess(out[i].Host, out[j].Host) })
	return out
}

// hasFrozenLocked reports whether a frozen row has host h. Caller holds s.mu.
func (s *siteCacheStore) hasFrozenLocked(h string) bool {
	for _, f := range s.frozen {
		if f.host == h {
			return true
		}
	}
	return false
}

// FrozenHosts returns the sorted, de-duplicated hosts of the stored rows this
// build cannot load (see frozen) and that have no loaded entry — each treated
// as an opt-out at the edge. (A host with both exists only after a hand edit,
// until its next write; its loaded entry is what the edge uses.)
func (s *siteCacheStore) FrozenHosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]struct{}{}
	var out []string
	for _, f := range s.frozen {
		_, live := s.entries[f.host] // a loaded row of the host wins (feedEntriesLocked)
		if _, dup := seen[f.host]; f.host != "" && !dup && !live {
			seen[f.host] = struct{}{}
			out = append(out, f.host)
		}
	}
	sort.Strings(out)
	return out
}

// siteCacheUnloadableMsg is the API's explanation for a host whose stored
// policy this build cannot load.
const siteCacheUnloadableMsg = "this host has a stored policy this build cannot load (e.g. from a newer version; the node's daemon log has the details): it is treated as opted out, never cached"

// feedEntriesLocked is what the feed (and StatsKeyFor) is computed over: the
// loaded entries, plus an all-off stand-in for the host of each frozen row
// that has no loaded entry — a row this build cannot read fails closed, as an
// opt-out, instead of vanishing and leaving the host to a covering wildcard.
// A loaded entry of the same host wins. Caller holds s.mu; the result is
// READ-ONLY (with nothing frozen it is s.entries itself).
func (s *siteCacheStore) feedEntriesLocked() map[string]SiteCacheEntry {
	if len(s.frozen) == 0 {
		return s.entries
	}
	out := make(map[string]SiteCacheEntry, len(s.entries)+len(s.frozen))
	for h, e := range s.entries {
		out[h] = e
	}
	for _, f := range s.frozen {
		if _, live := out[f.host]; f.host != "" && !live {
			out[f.host] = SiteCacheEntry{Host: f.host}
		}
	}
	return out
}

// siteCacheWildcardCovers reports whether any "*.suffix" pattern matches host
// (a proper sub-host: *.example.com covers a.example.com, not example.com —
// the same rule as the edge glob and StatsKeyFor). host may itself be a
// narrower pattern: *.example.com covers *.shop.example.com.
func siteCacheWildcardCovers(wilds []string, host string) bool {
	for _, w := range wilds {
		if strings.HasSuffix(host, w[1:]) {
			return true
		}
	}
	return false
}

// siteCacheFeedLess orders the edge feed: exact hosts first (alphabetical),
// then wildcards most specific (longest) first, alphabetical on a tie.
func siteCacheFeedLess(a, b string) bool {
	aw, bw := strings.HasPrefix(a, "*."), strings.HasPrefix(b, "*.")
	if aw != bw {
		return !aw
	}
	if aw && len(a) != len(b) {
		return len(a) > len(b)
	}
	return a < b
}

// StatsKeyFor mirrors the edge's policy_key_for (cfm_cache.lua) over the
// PolicyFeed rows: the policy key the edge counts host's cache statuses under,
// or ok=false when it counts nothing for host. An exact entry wins even when
// it is all-off (an opt-out, or one nothing armed covers): the edge never
// counts that host under a wildcard. Otherwise the most specific (longest)
// wildcard IN THE FEED that covers host — an armed one (its key), or an
// all-off one a broader armed wildcard covers (an opt-out: nothing).
func (s *siteCacheStore) StatsKeyFor(host string) (string, bool) {
	h, ok := s.normalize(host)
	if !ok {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := s.feedEntriesLocked()
	if e, exact := entries[h]; exact {
		if siteCacheArmed(e) {
			return h, true
		}
		return "", false
	}
	var armedWild []string
	for k, e := range entries {
		if strings.HasPrefix(k, "*.") && siteCacheArmed(e) {
			armedWild = append(armedWild, k)
		}
	}
	best, bestArmed := "", false
	for k, e := range entries {
		if !strings.HasPrefix(k, "*.") || !strings.HasSuffix(h, k[1:]) {
			continue
		}
		armed := siteCacheArmed(e)
		if !armed && !siteCacheWildcardCovers(armedWild, k) {
			continue // not in the feed
		}
		if best == "" || siteCacheFeedLess(k, best) {
			best, bestArmed = k, armed
		}
	}
	if !bestArmed {
		return "", false
	}
	return best, true
}

func (s *siteCacheStore) load() {
	if s == nil || s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		// Loud, not silent: a corrupt/truncated store must not vanish quietly
		// (the next write would overwrite it, making the loss permanent). We
		// still start empty — there is nothing safe to recover — but the
		// operator sees why in the log.
		logging.Logf("[webdetector][site-cache] store %s is not valid JSON (%v); starting with no policies — the next write will overwrite it", s.path, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// rewrite: the file holds something the store now normalizes away — a
	// legacy scope_hosts allowlist (trimmed to [host]; rewritten at once so
	// the other tenants' domains do not linger on disk until an unrelated
	// write), a non-normalized host (a :port, a trailing dot, upper case), a
	// duplicate host, or a generation reissued below. Rows this build cannot
	// load are kept as stored (s.frozen), so the rewrite never loses one.
	rewrite := false
	for _, raw := range raws {
		var e SiteCacheEntry
		err := json.Unmarshal(raw, &e)
		if err == nil {
			// A field this build does not know (a newer build's, e.g. a safety
			// setting) freezes the row: loading it without the field would
			// serve a policy that build never meant, and the next save would
			// drop the field.
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			var strict SiteCacheEntry
			err = dec.Decode(&strict)
		}
		var norm SiteCacheEntry
		if err == nil {
			norm, err = s.normalizeEntry(e)
		}
		if err != nil {
			// Loud, not silent — and kept (as stored, re-indented by the next
			// save): a newer build's policy (a downgrade) or a hand-edit typo
			// must not be deleted by this build.
			fh, _ := s.normalize(e.Host)
			logging.Logf("[webdetector][site-cache] cannot load stored policy for %q: %v — kept in the file, not served (the host is treated as opted out) (path=%s)", e.Host, err, s.path)
			s.frozen = append(s.frozen, siteCacheFrozenRow{host: fh, raw: append(json.RawMessage(nil), raw...)})
			if e.Generation > s.genHWM && e.Generation < siteCacheMaxGeneration {
				s.genHWM = e.Generation
			}
			continue
		}
		if norm.Host != e.Host || !sameStrings(norm.ScopeHosts, e.ScopeHosts) {
			rewrite = true
		}
		if norm.CreatedAt.IsZero() {
			norm.CreatedAt = time.Now().UTC()
		}
		if norm.UpdatedAt.IsZero() {
			norm.UpdatedAt = norm.CreatedAt
		}
		if norm.Generation > s.genHWM && norm.Generation < siteCacheMaxGeneration {
			s.genHWM = norm.Generation
		}
		if prev, dup := s.entries[norm.Host]; dup {
			// Two stored rows for one host (a hand edit, "A.com" + "a.com", or
			// a host with and without a port). Keep the one with the higher
			// generation: serving the lower one would bring back objects a
			// purge had retired.
			rewrite = true
			logging.Logf("[webdetector][site-cache] duplicate stored policy for %q on load; keeping the one with the higher generation (path=%s)", norm.Host, s.path)
			if prev.Generation >= norm.Generation {
				continue
			}
		}
		s.entries[norm.Host] = norm
	}

	// Reissue every generation outside [siteCacheMinGeneration,
	// siteCacheMaxGeneration): a legacy per-policy counter (an exact host and
	// its wildcard may both sit at 0 — one key space for that host — and an
	// earlier value may be one a purge retired), or one the edge cannot render
	// exactly. All of them, not one side of a collision: the objects under
	// such a key can belong to either policy. It costs each such policy one
	// cache refill, once (the file is rewritten).
	for h, e := range s.entries {
		if e.Generation >= siteCacheMinGeneration && e.Generation < siteCacheMaxGeneration {
			continue
		}
		old := e.Generation
		e.Generation = s.nextGenerationLocked()
		s.entries[h] = e
		rewrite = true
		logging.Logf("[webdetector][site-cache] reissued generation %d for %q on load (a legacy or out-of-range value) (path=%s)", old, h, s.path)
	}
	if rewrite {
		if err := s.saveLocked(); err != nil {
			logging.Logf("[webdetector][site-cache] failed to rewrite the normalized store on load: %v (path=%s)", err, s.path)
		}
	}
}

// sameStrings reports whether two string lists are equal (nil and empty are).
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
	rows := make([]any, 0, len(arr)+len(s.frozen))
	for _, e := range arr {
		rows = append(rows, e)
	}
	for _, f := range s.frozen {
		rows = append(rows, f.raw) // rows this build cannot load, as stored (see frozen)
	}
	b, err := json.MarshalIndent(rows, "", "  ")
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
