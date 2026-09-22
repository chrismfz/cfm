// internal/webdetector/site_cache_stats.go
//
// Site Cache — Tier A per-vhost stats aggregate (design §11.2). The edge counts
// cache verdicts (HIT/MISS/BYPASS/…) per armed vhost in a lua_shared_dict and
// pushes an absolute snapshot to /nginx/cache/stats every ~60s
// (configs/lua/cfm_cache.lua maybe_flush_stats). This store holds the latest
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
// the edge last reloaded). hit_ratio_pct is hit / cacheable_total, where
// cacheable_total excludes BYPASS (a bypassed request never had a chance to
// hit) — the same split cfm_stats.lua's cache_zone_stats uses.
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

// SiteCacheStatsHost returns one vhost's cache stats row (ok=false if the edge
// has not reported it — e.g. unarmed, or armed but no traffic yet).
func (e *Engine) SiteCacheStatsHost(host string) (SiteCacheStatsRow, bool) {
	if e == nil || e.siteCacheStats == nil {
		return SiteCacheStatsRow{}, false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	c := e.siteCacheStats.Get(host)
	if c == nil {
		return SiteCacheStatsRow{}, false
	}
	return siteCacheStatsRow(host, c), true
}

// SiteCacheStatsAll returns every reported vhost's stats row, sorted by host.
func (e *Engine) SiteCacheStatsAll() []SiteCacheStatsRow {
	if e == nil || e.siteCacheStats == nil {
		return nil
	}
	hosts := e.siteCacheStats.Hosts()
	out := make([]SiteCacheStatsRow, 0, len(hosts))
	for h, c := range hosts {
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
