package webdetector

import (
	"strings"
	"sync"
	"time"
)

// Facet-shadow marks: the distinct-full-URL count (query cardinality) that
// Signal F currently sees on each flagged vhost, for a UI badge / API field.
//
// Same design as the abuse-shadow rate-outlier mark (abuse_shadow_marks.go) and
// the solver-farm mark: NOT the log line — Signal F writes a structured line per
// flagged vhost per throttle window to cfm.abuse_shadow.log (the place to tune
// thresholds). The per-tick emit stamps a per-vhost COUNT here with a short TTL,
// so the badge means exactly "N distinct facet URLs on this vhost right now",
// clearing on its own within one TTL once the flood stops. There is deliberately
// no un-mark path; expiry is the only way a mark goes away, so a missed refresh
// cannot pin a stale badge. It is a shadow/visibility number, never an
// enforcement input.
//
// Package-level (not an Engine field) for the same reason the other mark stores
// are: the API handlers decorate rows without threading a pointer, and there is
// one challenge subsystem per process.

type facetMark struct {
	count int // distinct full URLs (query cardinality)
	exp   time.Time
}

type facetMarks struct {
	mu    sync.RWMutex
	hosts map[string]facetMark
	nowFn func() time.Time
}

func newFacetMarks() *facetMarks {
	return &facetMarks{hosts: make(map[string]facetMark), nowFn: time.Now}
}

var abuseFacetMarks = newFacetMarks()

// maxFacetMarks bounds the store. The key is the Host header (client-influenced),
// so a flood of junk vhost names must not grow it without limit; reaching it
// needs that many DISTINCT vhosts carrying facet floods within one TTL.
const maxFacetMarks = 10000

func (m *facetMarks) get(host string) int {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return 0
	}
	m.mu.RLock()
	mk, ok := m.hosts[host]
	m.mu.RUnlock()
	if !ok || !mk.exp.After(m.nowFn()) {
		return 0
	}
	return mk.count
}

func (m *facetMarks) reset() {
	m.mu.Lock()
	m.hosts = make(map[string]facetMark)
	m.mu.Unlock()
}

// markBulk stamps many host→count marks under a SINGLE prune pass — the per-tick
// emit calls this once with all flagged vhosts, so a broad multi-vhost flood does
// not re-scan the store per host.
func (m *facetMarks) markBulk(counts map[string]int, ttl time.Duration) {
	if len(counts) == 0 || ttl <= 0 {
		return
	}
	now := m.nowFn()
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, mk := range m.hosts { // one prune for the whole batch
		if !mk.exp.After(now) {
			delete(m.hosts, h)
		}
	}
	exp := now.Add(ttl)
	for host, count := range counts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || count <= 0 {
			continue
		}
		if _, known := m.hosts[host]; !known && len(m.hosts) >= maxFacetMarks {
			continue
		}
		m.hosts[host] = facetMark{count: count, exp: exp}
	}
}

// FacetShadowCardinality returns host's current live distinct-URL count (0 if
// none or expired).
func FacetShadowCardinality(host string) int { return abuseFacetMarks.get(host) }

// MarkFacetShadowBulk stamps a whole tick's worth of vhost cardinalities at once
// (one prune pass).
func MarkFacetShadowBulk(counts map[string]int, ttl time.Duration) {
	abuseFacetMarks.markBulk(counts, ttl)
}

// ResetFacetShadowMarks drops every mark. The detectors manager calls it on
// teardown so a reload that disables/retunes the facet signal leaves no stale
// badge.
func ResetFacetShadowMarks() { abuseFacetMarks.reset() }

// decorateFacetShort stamps the query cardinality onto short-window rows.
func decorateFacetShort(rows []ShortRow) []ShortRow {
	for i := range rows {
		rows[i].QueryCardinality = FacetShadowCardinality(rows[i].Host)
	}
	return rows
}

// decorateFacetSuspicious stamps the query cardinality onto long-window rows.
// Applied in the API handlers (not the scorer) — like the other shadow marks it
// is an external verdict, not an input to the score.
func decorateFacetSuspicious(rows []SuspiciousRow) []SuspiciousRow {
	for i := range rows {
		rows[i].QueryCardinality = FacetShadowCardinality(rows[i].Host)
	}
	return rows
}
