// internal/webdetector/site_cache_stats.go
//
// Site Cache — Tier A per-vhost stats aggregate (design §11.2). The edge counts
// cache verdicts (HIT/MISS/BYPASS/…) per armed vhost in a lua_shared_dict and
// pushes an absolute snapshot to /nginx/cache/stats every ~60s
// (configs/lua/cfm_cache.lua schedule_stats_flush_if_needed). This store holds the latest
// snapshot per vhost; the /api/v1/site-cache/stats endpoint + the MCP
// site_cache_stats tool read it.
//
// v1 scope: a LIVE totals view (absolute counts since the edge last restarted —
// a reload keeps the lua_shared_dict —
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
	"time"
)

// siteCacheStatsStore maps host -> cache status -> absolute count. Each push
// REPLACES a host's counts (UPSERT), matching the edge's absolute snapshot.
type siteCacheStatsStore struct {
	mu        sync.RWMutex
	hosts     map[string]map[string]int
	lastPrune time.Time
}

func newSiteCacheStatsStore() *siteCacheStatsStore {
	return &siteCacheStatsStore{hosts: make(map[string]map[string]int)}
}

// Bounds against a buggy/compromised edge. The edge keys only ARMED policies,
// of which the policy store holds at most maxSiteCacheEntries (the cap used to
// be 4096, so past that some armed vhosts never got a row), and counts only
// the fixed set of cache statuses (cfm_cache_log.lua VALID) — any other key is
// dropped, not stored; a key longer than maxSiteCacheHostLen too.
const (
	maxSiteCacheStatsHosts = maxSiteCacheEntries
	siteCacheStatsPruneGap = 5 * time.Minute
)

var siteCacheStatsKeys = map[string]struct{}{
	"HIT": {}, "MISS": {}, "BYPASS": {}, "EXPIRED": {}, "STALE": {},
	"UPDATING": {}, "REVALIDATED": {},
	"total": {}, // an edge-supplied total (floored at the parts; see siteCacheStatsRow)
}

// Upsert replaces one host's counts. Fed from the bridge SetCacheStatsHook
// through Engine.ingestSiteCacheStats (armed keys only); called async, once
// per pushed row. The incoming map aliases request-scoped memory, so it is
// copied (and bounded) before being retained.
func (s *siteCacheStatsStore) Upsert(host string, counts map[string]int) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(host) > maxSiteCacheHostLen || len(counts) == 0 {
		return
	}
	cp := make(map[string]int, len(siteCacheStatsKeys))
	for k, v := range counts {
		if _, known := siteCacheStatsKeys[k]; !known {
			continue
		}
		if v < 0 {
			v = 0
		}
		cp[k] = v
	}
	if len(cp) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[host]; !ok && len(s.hosts) >= maxSiteCacheStatsHosts {
		return // at capacity; drop an unknown host rather than grow unbounded
	}
	s.hosts[host] = cp
}

// maybePrune drops, at most once per siteCacheStatsPruneGap, the rows of keys
// armed() no longer holds. The edge dict keeps a vhost's counts until an edge
// reload, and the read paths already hide unarmed rows, but without this the
// rows of every policy ever armed stayed in memory until a daemon restart. It
// runs on every pushed row and on the list read (so also once the edge stops
// pushing); armed is called only when a prune is due.
func (s *siteCacheStatsStore) maybePrune(now time.Time, armed func() map[string]struct{}) int {
	s.mu.Lock()
	if now.Sub(s.lastPrune) < siteCacheStatsPruneGap {
		s.mu.Unlock()
		return 0
	}
	s.lastPrune = now
	s.mu.Unlock()
	keep := armed() // outside s.mu: it takes the policy store's lock
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for h := range s.hosts {
		if _, ok := keep[h]; !ok {
			delete(s.hosts, h)
			n++
		}
	}
	return n
}

// ingestSiteCacheStats is the bridge's cache-stats hook: a row is kept only
// for a policy key that is ARMED now (the edge can lag a disarm by a feed
// poll, and a buggy or compromised edge can send anything), then unarmed rows
// are pruned periodically.
func (e *Engine) ingestSiteCacheStats(host string, counts map[string]int) {
	if e == nil || e.siteCacheStats == nil || e.siteCache == nil {
		return
	}
	// Prune first: once the last policy is disarmed every pushed row is
	// rejected below, and the stale rows must still go.
	e.siteCacheStats.maybePrune(time.Now(), e.armedCacheKeys)
	if !e.siteCache.ArmedKey(host) {
		return
	}
	e.siteCacheStats.Upsert(host, counts)
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
// the edge last restarted; a reload keeps them). hit_ratio_pct is a STRICT hit ratio —
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
// "*.suffix" patterns with at least one ENABLED tier) — the same keys the edge
// stats are keyed under. The stats read paths filter on it because the edge
// dict retains a vhost's counts after it is unarmed (no TTL until an edge
// reload), so the policy store is the source of truth for what is still live.
// A stored but all-off policy (an opt-out) is NOT armed: it used to count, so
// a vhost turned off kept showing its old counts as live.
func (e *Engine) armedCacheKeys() map[string]struct{} {
	if e == nil || e.siteCache == nil {
		return nil
	}
	list := e.siteCache.List()
	out := make(map[string]struct{}, len(list))
	for _, ent := range list {
		if !ent.Static.Enabled && !ent.Micro.Enabled {
			continue
		}
		out[strings.ToLower(ent.Host)] = struct{}{}
	}
	return out
}

// SiteCacheStatsHost returns one vhost's cache stats row. `host` may be a
// concrete sub-host of a wildcard-armed vhost — it resolves to the policy key
// the edge counts it under (siteCacheStore.StatsKeyFor, the Go mirror of
// policy_key_for: its exact policy, else the most specific wildcard in the
// feed — nothing when that one, or the exact policy, is an opt-out).
// ok=false if the edge counts nothing for it (unarmed, an opt-out, out of the
// caller's scope) or has not reported counts yet. It used to walk every
// covering key until one held counts, which could hand back a broader
// wildcard's — or, for an exact host with no counts yet, its wildcard's —
// numbers as this host's.
//
// scope is the caller's vhost allowlist (nil = admin/loopback): a scoped
// caller resolves only to a policy key inside it. A "*.suffix" key aggregates
// EVERY sub-host under the pattern — other tenants' vhosts included — so a
// tenant asking about its own a.example.com must not be handed the counts of
// an admin's *.example.com (it used to be). The scope match is literal, as on
// every site-cache endpoint: a token whose scope holds "*.example.com" itself
// (a cPanel wildcard subdomain the account owns) does see that key.
func (e *Engine) SiteCacheStatsHost(host string, scope map[string]struct{}) (SiteCacheStatsRow, bool) {
	if e == nil || e.siteCacheStats == nil || e.siteCache == nil {
		return SiteCacheStatsRow{}, false
	}
	key, ok := e.siteCache.StatsKeyFor(host)
	if !ok || !vhostAllowed(key, scope) {
		return SiteCacheStatsRow{}, false
	}
	c := e.siteCacheStats.Get(key)
	if c == nil {
		return SiteCacheStatsRow{}, false
	}
	return siteCacheStatsRow(key, c), true
}

// SiteCacheStatsAll returns the stats row for every CURRENTLY-ARMED vhost the
// edge has reported, sorted by host. Rows for vhosts unarmed since their last
// push are dropped (see armedCacheKeys) so the view never shows a stale vhost
// as still cached.
func (e *Engine) SiteCacheStatsAll() []SiteCacheStatsRow {
	if e == nil || e.siteCacheStats == nil {
		return nil
	}
	e.siteCacheStats.maybePrune(time.Now(), e.armedCacheKeys) // also when the edge stopped pushing (SITE_CACHE=0)
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
	Rows  []SiteCacheStatsRow `json:"rows"`
	Error string              `json:"error,omitempty"`
}

// GET /api/v1/site-cache/stats[?host=<host>]
//
// Scope model identical to the other site-cache handlers: admin/loopback sees
// all; a scoped (cPanel) token sees only its own vhosts (a ?host= outside the
// allowlist is 403, a ?host= drill-down resolves only to policy keys in the
// token's scope — so not to a wildcard the scope does not literally hold — and
// the unfiltered list is filtered to the caller's hosts).
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
			writeJSON(w, http.StatusForbidden, siteCacheStatsResponse{Error: "host not in scope"})
			return
		}
		row, ok := e.SiteCacheStatsHost(host, vhostScopeFromContext(r.Context()))
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
