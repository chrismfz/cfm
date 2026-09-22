// internal/webdetector/site_cache_stats.go
//
// Site Cache — Tier A per-vhost stats aggregate (design §11.2). The edge counts
// cache verdicts (HIT/MISS/BYPASS/…) per armed vhost in a lua_shared_dict and
// pushes an absolute snapshot to /nginx/cache/stats every ~60s
// (configs/lua/cfm_cache.lua schedule_stats_flush_if_needed). This store holds the latest
// snapshot per vhost; the /api/v1/site-cache/stats endpoint + the MCP
// site_cache_stats tool read it.
//
// v1 scope: a LIVE totals view (absolute counts since the edge last reloaded,
// node-local, not persisted across daemon restarts). Hour-bucketed history —
// the shape the WAF-stats pipeline uses — is a documented follow-up; a first
// cut needs only "is this armed vhost actually getting HITs?".

package webdetector

import (
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// siteCacheStatsStore maps host -> cache status -> absolute count. Each push
// REPLACES a host's counts (UPSERT), matching the edge's absolute snapshot.
type siteCacheStatsStore struct {
	mu    sync.RWMutex
	hosts map[string]map[string]int
}

func newSiteCacheStatsStore() *siteCacheStatsStore {
	return &siteCacheStatsStore{hosts: make(map[string]map[string]int)}
}

// Bounds against a buggy/compromised edge. The edge only keys armed vhosts
// (few) with a fixed status set, so these sit far above any real push.
const (
	maxSiteCacheStatsHosts = 4096
	maxSiteCacheStatsKeys  = 16
)

// Upsert replaces one host's counts. Wired as the bridge SetCacheStatsHook;
// called async, once per pushed row. The incoming map aliases request-scoped
// memory, so it is copied (and bounded) before being retained.
func (s *siteCacheStatsStore) Upsert(host string, counts map[string]int) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(counts) == 0 {
		return
	}
	cp := make(map[string]int, len(counts))
	for k, v := range counts {
		if len(cp) >= maxSiteCacheStatsKeys {
			break
		}
		if v < 0 {
			v = 0
		}
		cp[k] = v
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[host]; !ok && len(s.hosts) >= maxSiteCacheStatsHosts {
		return // at capacity; drop an unknown host rather than grow unbounded
	}
	s.hosts[host] = cp
}

// Get returns a copy of one host's counts (nil if never seen).
func (s *siteCacheStatsStore) Get(host string) map[string]int {
	host = strings.ToLower(strings.TrimSpace(host))
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.hosts[host]
	if c == nil {
		return nil
	}
	cp := make(map[string]int, len(c))
	for k, v := range c {
		cp[k] = v
	}
	return cp
}

// Hosts returns a copy of every host's counts.
func (s *siteCacheStatsStore) Hosts() map[string]map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]map[string]int, len(s.hosts))
	for h, c := range s.hosts {
		cp := make(map[string]int, len(c))
		for k, v := range c {
			cp[k] = v
		}
		out[h] = cp
	}
	return out
}

// SiteCacheStatsRow is one vhost's cache effectiveness (absolute counts since
// the edge last reloaded). hit_ratio_pct is a STRICT hit ratio —
// hit / cacheable_total, cacheable_total = hit+miss+expired+stale+updating+
// revalidated (BYPASS excluded: a bypassed request never had a chance to hit) —
// the same split cfm_stats.lua's cache_zone_stats uses. Note STALE / UPDATING /
// REVALIDATED are ALSO served from cache but sit in the denominator only, so on
// a vhost that leans on stale-while-revalidate the strict ratio understates the
// real cache benefit; read the full HIT/MISS/EXPIRED/STALE/UPDATING breakdown,
// not just the one number.
type SiteCacheStatsRow struct {
	Host           string  `json:"host"`
	Total          int     `json:"total"`
	Hit            int     `json:"hit"`
	Miss           int     `json:"miss"`
	Bypass         int     `json:"bypass"`
	Expired        int     `json:"expired"`
	Stale          int     `json:"stale"`
	Updating       int     `json:"updating"`
	Revalidated    int     `json:"revalidated"`
	CacheableTotal int     `json:"cacheable_total"`
	HitRatioPct    float64 `json:"hit_ratio_pct"`
}

func siteCacheStatsRow(host string, c map[string]int) SiteCacheStatsRow {
	g := func(k string) int {
		if v, ok := c[k]; ok && v > 0 {
			return v
		}
		return 0
	}
	hit, miss, bypass := g("HIT"), g("MISS"), g("BYPASS")
	expired, stale, updating, reval := g("EXPIRED"), g("STALE"), g("UPDATING"), g("REVALIDATED")
	cacheable := hit + miss + expired + stale + updating + reval
	ratio := 0.0
	if cacheable > 0 {
		ratio = math.Round(float64(hit)/float64(cacheable)*1000) / 10
	}
	total := g("total")
	if total < cacheable+bypass {
		// The edge sends its own "total", but never trust it below the parts.
		total = cacheable + bypass
	}
	return SiteCacheStatsRow{
		Host: host, Total: total, Hit: hit, Miss: miss, Bypass: bypass,
		Expired: expired, Stale: stale, Updating: updating, Revalidated: reval,
		CacheableTotal: cacheable, HitRatioPct: ratio,
	}
}

// armedCacheKeys is the set of currently-armed policy keys (exact hosts +
// "*.suffix" patterns) — the same keys the edge stats are keyed under. The
// stats read paths filter on it because the edge dict retains a vhost's counts
// after it is unarmed (no TTL until an edge reload), so the armed policy store
// is the source of truth for what is still live.
func (e *Engine) armedCacheKeys() map[string]struct{} {
	if e == nil || e.siteCache == nil {
		return nil
	}
	list := e.siteCache.List()
	out := make(map[string]struct{}, len(list))
	for _, ent := range list {
		out[strings.ToLower(ent.Host)] = struct{}{}
	}
	return out
}

// candidateArmedCacheKeys returns the armed policy keys covering host, in a
// DETERMINISTIC precedence: the exact host first, then matching "*.suffix"
// patterns most-specific (longest) first. Overlapping wildcards (e.g.
// *.example.com and *.cdn.example.com) are rare, but the edge keys stats under
// exactly one of them — iterating a Go map at random could resolve a drill-down
// to a different, empty pattern between requests, so the order is fixed and the
// caller walks it until it finds the pattern that actually holds counts.
func candidateArmedCacheKeys(host string, armed map[string]struct{}) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	out := make([]string, 0, 4)
	if _, ok := armed[host]; ok {
		out = append(out, host)
	}
	wilds := make([]string, 0, 4)
	for k := range armed {
		if strings.HasPrefix(k, "*.") && strings.HasSuffix(host, k[1:]) {
			wilds = append(wilds, k)
		}
	}
	sort.Slice(wilds, func(i, j int) bool {
		if len(wilds[i]) != len(wilds[j]) {
			return len(wilds[i]) > len(wilds[j]) // most specific (longest) first
		}
		return wilds[i] < wilds[j] // stable tiebreak
	})
	return append(out, wilds...)
}

// SiteCacheStatsHost returns one vhost's cache stats row. `host` may be a
// concrete sub-host of a wildcard-armed vhost — it resolves to the armed policy
// key the edge keyed stats under. ok=false if nothing armed covers it, or it is
// armed but the edge has not reported counts yet.
func (e *Engine) SiteCacheStatsHost(host string) (SiteCacheStatsRow, bool) {
	if e == nil || e.siteCacheStats == nil {
		return SiteCacheStatsRow{}, false
	}
	for _, key := range candidateArmedCacheKeys(host, e.armedCacheKeys()) {
		if c := e.siteCacheStats.Get(key); c != nil {
			return siteCacheStatsRow(key, c), true
		}
	}
	return SiteCacheStatsRow{}, false
}

// SiteCacheStatsAll returns the stats row for every CURRENTLY-ARMED vhost the
// edge has reported, sorted by host. Rows for vhosts unarmed since their last
// push are dropped (see armedCacheKeys) so the view never shows a stale vhost
// as still cached.
func (e *Engine) SiteCacheStatsAll() []SiteCacheStatsRow {
	if e == nil || e.siteCacheStats == nil {
		return nil
	}
	armed := e.armedCacheKeys()
	hosts := e.siteCacheStats.Hosts()
	out := make([]SiteCacheStatsRow, 0, len(hosts))
	for h, c := range hosts {
		if _, ok := armed[h]; !ok {
			continue // unarmed → the edge's lingering counts are stale; hide it
		}
		out = append(out, siteCacheStatsRow(h, c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

type siteCacheStatsResponse struct {
	Rows []SiteCacheStatsRow `json:"rows"`
}

// GET /api/v1/site-cache/stats[?host=<host>]
//
// Scope model identical to the other site-cache handlers: admin/loopback sees
// all; a scoped (cPanel) token sees only its own vhosts (a ?host= outside the
// allowlist is 403, and the unfiltered list is filtered to the caller's hosts).
func (e *Engine) handleSiteCacheStats(w http.ResponseWriter, r *http.Request) {
	if e == nil {
		writeJSON(w, http.StatusOK, siteCacheStatsResponse{Rows: nil})
		return
	}
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if host := strings.TrimSpace(r.URL.Query().Get("host")); host != "" {
		if !scopeAllowsVhosts(r, []string{host}) {
			writeJSON(w, http.StatusForbidden, siteCacheStatsResponse{})
			return
		}
		row, ok := e.SiteCacheStatsHost(host)
		if !ok {
			writeJSON(w, http.StatusOK, siteCacheStatsResponse{Rows: nil})
			return
		}
		writeJSON(w, http.StatusOK, siteCacheStatsResponse{Rows: []SiteCacheStatsRow{row}})
		return
	}
	rows := e.SiteCacheStatsAll()
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		filtered := make([]SiteCacheStatsRow, 0, len(rows))
		for _, row := range rows {
			if vhostAllowed(strings.ToLower(row.Host), scope) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	writeJSON(w, http.StatusOK, siteCacheStatsResponse{Rows: rows})
}
