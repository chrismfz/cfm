package webdetector

import (
	"strings"
	"sync"
	"time"
)

// Abuse-shadow marks: how many rate-outlier IPs the abuse_shadow signal
// currently sees on each vhost, for a UI badge / API field.
//
// Like the solver-farm mark (solverfarm_marks.go), this is NOT the log line:
// abuse_shadow writes one structured line per (vhost,IP) outlier per throttle
// window to cfm.abuse_shadow.log — the right place to tune thresholds, the wrong
// place to drive a badge from. So the per-tick emit stamps a per-vhost COUNT of
// live outliers here with a short TTL, and the badge means exactly "N shadow
// rate-outliers right now", clearing on its own within one TTL once the burst
// stops. There is deliberately no un-mark path to get wrong; expiry is the only
// way a mark goes away, so a missed refresh cannot pin a stale badge.
//
// The count is the cheap concentration signal (rate outliers vs the vhost
// median), computed without DNS, so it is complete even when the log/enrich
// budget throttles the detailed lines. It is a shadow/visibility number, never
// an enforcement input.
//
// Package-level (not an Engine field) for the same reason the solver-farm store
// is: the API handlers decorate rows without threading a pointer, and there is
// one challenge subsystem per process.

type shadowMark struct {
	count int
	exp   time.Time
}

type shadowMarks struct {
	mu    sync.RWMutex
	hosts map[string]shadowMark
	nowFn func() time.Time
}

func newShadowMarks() *shadowMarks {
	return &shadowMarks{hosts: make(map[string]shadowMark), nowFn: time.Now}
}

var abuseShadowMarks = newShadowMarks()

// maxShadowMarks bounds the store. The key is the Host header (client-influenced),
// so a flood of junk vhost names must not grow it without limit; reaching it
// needs that many DISTINCT vhosts carrying outliers within one TTL.
const maxShadowMarks = 10000

func (m *shadowMarks) mark(host string, count int, ttl time.Duration) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || count <= 0 || ttl <= 0 {
		return
	}
	now := m.nowFn()
	m.mu.Lock()
	defer m.mu.Unlock()
	// Prune on write (rare — once per flagged vhost per eval), keeping the read
	// path mutation-free.
	for h, mk := range m.hosts {
		if !mk.exp.After(now) {
			delete(m.hosts, h)
		}
	}
	if _, known := m.hosts[host]; !known && len(m.hosts) >= maxShadowMarks {
		return
	}
	m.hosts[host] = shadowMark{count: count, exp: now.Add(ttl)}
}

func (m *shadowMarks) get(host string) int {
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

func (m *shadowMarks) reset() {
	m.mu.Lock()
	m.hosts = make(map[string]shadowMark)
	m.mu.Unlock()
}

// MarkAbuseShadow records that host currently has `count` rate-outlier IPs. Call
// it on every emit pass (not only when a line is logged) so the badge tracks the
// live count; ttl should be a small multiple of the eval interval so the mark
// survives jitter and clears promptly once the burst stops.
func MarkAbuseShadow(host string, count int, ttl time.Duration) {
	abuseShadowMarks.mark(host, count, ttl)
}

// markBulk stamps many host→count marks under a SINGLE prune pass — the per-tick
// emit calls this once with all flagged vhosts, so a broad multi-vhost burst
// does not re-scan the store per host. TTL/cap semantics match mark().
func (m *shadowMarks) markBulk(counts map[string]int, ttl time.Duration) {
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
		if _, known := m.hosts[host]; !known && len(m.hosts) >= maxShadowMarks {
			continue
		}
		m.hosts[host] = shadowMark{count: count, exp: exp}
	}
}

// AbuseShadowOutliers returns host's current live rate-outlier count (0 if none
// or expired).
func AbuseShadowOutliers(host string) int { return abuseShadowMarks.get(host) }

// MarkAbuseShadowBulk stamps a whole tick's worth of vhost outlier counts at once
// (one prune pass). Preferred over a per-host MarkAbuseShadow loop in the emit.
func MarkAbuseShadowBulk(counts map[string]int, ttl time.Duration) {
	abuseShadowMarks.markBulk(counts, ttl)
}

// ResetAbuseShadowMarks drops every mark. The detectors manager calls it on
// teardown so a reload that disables/retunes abuse_shadow leaves no stale badge.
func ResetAbuseShadowMarks() { abuseShadowMarks.reset() }

// decorateShadowShort stamps the outlier count onto short-window rows.
func decorateShadowShort(rows []ShortRow) []ShortRow {
	for i := range rows {
		rows[i].ShadowOutliers = AbuseShadowOutliers(rows[i].Host)
	}
	return rows
}

// decorateShadowSuspicious stamps the outlier count onto long-window rows. Applied
// in the API handlers (not the scorer) — like the solver-farm mark, it is an
// external verdict, not an input to the score.
func decorateShadowSuspicious(rows []SuspiciousRow) []SuspiciousRow {
	for i := range rows {
		rows[i].ShadowOutliers = AbuseShadowOutliers(rows[i].Host)
	}
	return rows
}
