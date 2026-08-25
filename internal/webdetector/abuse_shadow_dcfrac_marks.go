package webdetector

import (
	"strings"
	"sync"
	"time"
)

// Datacenter-fraction marks: the unverified-datacenter percent that Signal H
// currently sees on each flagged vhost, for a UI badge / API field. Same design as
// the other shadow mark stores (abuse_shadow_cost_marks.go): NOT the log line — the
// per-tick emit stamps a per-vhost value here with a short TTL, so the badge means
// exactly "N% of this vhost's traffic is unverified datacenter right now", clearing
// on its own within one TTL. No un-mark path; expiry is the only way a mark goes
// away. Shadow/visibility only, NEVER an enforcement input (origin is never
// innocence — datacenter-ASN alone does not drive any decision). Package-level for
// the same reason the other stores are.

type dcFracMark struct {
	pct int // unverified-datacenter percent (1–100)
	exp time.Time
}

type dcFracMarks struct {
	mu    sync.RWMutex
	hosts map[string]dcFracMark
	nowFn func() time.Time
}

func newDCFracMarks() *dcFracMarks {
	return &dcFracMarks{hosts: make(map[string]dcFracMark), nowFn: time.Now}
}

var abuseDCFracMarks = newDCFracMarks()

// maxDCFracMarks bounds the store (client-influenced Host key); reaching it needs
// that many DISTINCT vhosts carrying a datacenter-heavy mix within one TTL.
const maxDCFracMarks = 10000

func (m *dcFracMarks) get(host string) int {
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
	return mk.pct
}

func (m *dcFracMarks) reset() {
	m.mu.Lock()
	m.hosts = make(map[string]dcFracMark)
	m.mu.Unlock()
}

// markBulk stamps many host→pct marks under a SINGLE prune pass.
func (m *dcFracMarks) markBulk(counts map[string]int, ttl time.Duration) {
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
	for host, pct := range counts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" || pct <= 0 {
			continue
		}
		if _, known := m.hosts[host]; !known && len(m.hosts) >= maxDCFracMarks {
			continue
		}
		m.hosts[host] = dcFracMark{pct: pct, exp: exp}
	}
}

// DCFracShadowPercent returns host's current live unverified-datacenter percent
// (0 if none or expired).
func DCFracShadowPercent(host string) int { return abuseDCFracMarks.get(host) }

// MarkDCFracShadowBulk stamps a whole tick's worth of vhost percents at once.
func MarkDCFracShadowBulk(counts map[string]int, ttl time.Duration) {
	abuseDCFracMarks.markBulk(counts, ttl)
}

// ResetDCFracShadowMarks drops every mark (detectors manager teardown).
func ResetDCFracShadowMarks() { abuseDCFracMarks.reset() }

// decorateDCFracShort stamps the datacenter percent onto short-window rows.
func decorateDCFracShort(rows []ShortRow) []ShortRow {
	for i := range rows {
		rows[i].DCFraction = DCFracShadowPercent(rows[i].Host)
	}
	return rows
}

// decorateDCFracSuspicious stamps the datacenter percent onto long-window rows.
func decorateDCFracSuspicious(rows []SuspiciousRow) []SuspiciousRow {
	for i := range rows {
		rows[i].DCFraction = DCFracShadowPercent(rows[i].Host)
	}
	return rows
}
