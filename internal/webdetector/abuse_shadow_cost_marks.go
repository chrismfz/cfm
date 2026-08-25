package webdetector

import (
	"strings"
	"sync"
	"time"
)

// Cost-pressure marks: the 5xx percent that Signal G currently sees on each
// flagged vhost, for a UI badge / API field. Same design as the other shadow
// mark stores (abuse_shadow_facet_marks.go): NOT the log line — the per-tick emit
// stamps a per-vhost value here with a short TTL, so the badge means exactly "N%
// 5xx on this vhost right now", clearing on its own within one TTL once the origin
// recovers. No un-mark path; expiry is the only way a mark goes away. Shadow /
// visibility only, never an enforcement input. Package-level for the same reason
// the other stores are.

type costMark struct {
	pct int // 5xx percent (1–100)
	exp time.Time
}

type costMarks struct {
	mu    sync.RWMutex
	hosts map[string]costMark
	nowFn func() time.Time
}

func newCostMarks() *costMarks {
	return &costMarks{hosts: make(map[string]costMark), nowFn: time.Now}
}

var abuseCostMarks = newCostMarks()

// maxCostMarks bounds the store (client-influenced Host key); reaching it needs
// that many DISTINCT vhosts under 5xx pressure within one TTL.
const maxCostMarks = 10000

func (m *costMarks) get(host string) int {
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

func (m *costMarks) reset() {
	m.mu.Lock()
	m.hosts = make(map[string]costMark)
	m.mu.Unlock()
}

// markBulk stamps many host→pct marks under a SINGLE prune pass.
func (m *costMarks) markBulk(counts map[string]int, ttl time.Duration) {
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
		if _, known := m.hosts[host]; !known && len(m.hosts) >= maxCostMarks {
			continue
		}
		m.hosts[host] = costMark{pct: pct, exp: exp}
	}
}

// CostShadowPressure returns host's current live 5xx-pressure percent (0 if none
// or expired).
func CostShadowPressure(host string) int { return abuseCostMarks.get(host) }

// MarkCostShadowBulk stamps a whole tick's worth of vhost 5xx percents at once.
func MarkCostShadowBulk(counts map[string]int, ttl time.Duration) {
	abuseCostMarks.markBulk(counts, ttl)
}

// ResetCostShadowMarks drops every mark (detectors manager teardown).
func ResetCostShadowMarks() { abuseCostMarks.reset() }

// decorateCostShort stamps the 5xx percent onto short-window rows.
func decorateCostShort(rows []ShortRow) []ShortRow {
	for i := range rows {
		rows[i].CostPressure = CostShadowPressure(rows[i].Host)
	}
	return rows
}

// decorateCostSuspicious stamps the 5xx percent onto long-window rows.
func decorateCostSuspicious(rows []SuspiciousRow) []SuspiciousRow {
	for i := range rows {
		rows[i].CostPressure = CostShadowPressure(rows[i].Host)
	}
	return rows
}
