package webdetector

import (
	"strings"
	"sync"
	"time"
)

// Solver-farm marks: which vhosts the challenge_solver_farm detector currently
// sees a distributed solver farm on.
//
// WHY THIS IS NOT JUST THE ALERT
//
// The alert is deliberately rate-limited: COOLDOWN defaults to 30m, because a
// farm runs for hours and one mail per 30s evaluation would be unusable. That
// makes it the wrong thing to drive a UI badge from — a vhost farmed
// continuously for six hours produces twelve alerts, so a badge fed by alerts
// would blink on and off while the farm never stopped.
//
// So the detector marks a vhost on EVERY over-threshold evaluation, before the
// cooldown is consulted, and the mark carries a short TTL. The badge then means
// exactly "farmed right now" and clears on its own within one TTL of the farm
// stopping, with no un-mark path to get wrong.
//
// The store is package-level rather than a field on Engine for the same reason
// SubscribeChallengeSolveEvents is: the detector is constructed by the detectors
// registry, which has no engine handle, and there is one challenge subsystem per
// process. Keeping it here means the API handlers can decorate rows without any
// pointer plumbing through the registry.

type farmMarks struct {
	mu    sync.RWMutex
	hosts map[string]time.Time // host -> when the mark expires
	nowFn func() time.Time
}

func newFarmMarks() *farmMarks {
	return &farmMarks{hosts: make(map[string]time.Time), nowFn: time.Now}
}

var solverFarmMarks = newFarmMarks()

// maxFarmMarks bounds the store. The key comes from the Host header, so it is
// client-influenced: a flood of junk vhost names must not grow this without
// limit. Reaching it needs that many DISTINCT vhosts to cross the farm
// threshold within one TTL, which no real deployment does.
const maxFarmMarks = 10000

func (m *farmMarks) mark(host string, ttl time.Duration) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || ttl <= 0 {
		return
	}
	now := m.nowFn()
	m.mu.Lock()
	defer m.mu.Unlock()
	// Prune on write: this runs once per flagged vhost per evaluation, so it is
	// rare enough to scan and it keeps the read path free of mutation.
	for h, exp := range m.hosts {
		if !exp.After(now) {
			delete(m.hosts, h)
		}
	}
	if _, known := m.hosts[host]; !known && len(m.hosts) >= maxFarmMarks {
		return
	}
	m.hosts[host] = now.Add(ttl)
}

func (m *farmMarks) active(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	m.mu.RLock()
	exp, ok := m.hosts[host]
	m.mu.RUnlock()
	return ok && exp.After(m.nowFn())
}

func (m *farmMarks) reset() {
	m.mu.Lock()
	m.hosts = make(map[string]time.Time)
	m.mu.Unlock()
}

// solverFarmFPMarks is the FINGERPRINT-level twin of solverFarmMarks: which
// client fingerprints (the X-CFM-TLS id) the detector currently convicts as
// farming, keyed by fingerprint instead of vhost. Same TTL-mark store type (one
// type, two instances — no second copy to drift, CLAUDE.md §5); a fingerprint is
// the group-by key the cross-host and per-host-concentration tracks convict on.
//
// Why a fingerprint mark, not just the vhost one: the vhost mark answers "is a
// farm active on this site", but the strongest per-client guilt is "is THIS
// solve's fingerprint one the detector convicted" — a signal that travels with
// the client across vhosts and IPs. The per-IP challenge score reads it as the
// fingerprint-anchored SPINE (docs/traffic-classifier.md § "Third grain").
var solverFarmFPMarks = newFarmMarks()

// MarkSolverFarm records that host is currently being solved by a distributed
// farm. Call it on every over-threshold evaluation, not only when an alert
// fires — see the package comment above for why.
//
// ttl should be a small multiple of the detector's evaluation interval so the
// mark survives normal jitter between passes and clears promptly once the farm
// stops. There is deliberately no unmark: expiry is the only way a mark goes
// away, so a missed callback cannot leave a vhost badged forever.
func MarkSolverFarm(host string, ttl time.Duration) { solverFarmMarks.mark(host, ttl) }

// IsSolverFarm reports whether host currently carries a live solver-farm mark.
func IsSolverFarm(host string) bool { return solverFarmMarks.active(host) }

// MarkSolverFarmFingerprint records that a client fingerprint is currently
// convicted as farming. Call it wherever the vhost is marked, passing the
// finding's RESOLVED fingerprint (cross-host preferred over per-host). Same
// cadence / TTL / no-unmark contract as MarkSolverFarm; an empty fingerprint is
// a no-op (older edge, plain-HTTP, or legacy DNAT — no X-CFM-TLS stamp).
func MarkSolverFarmFingerprint(fp string, ttl time.Duration) { solverFarmFPMarks.mark(fp, ttl) }

// IsSolverFarmFingerprint reports whether fp currently carries a live conviction.
func IsSolverFarmFingerprint(fp string) bool { return solverFarmFPMarks.active(fp) }

// ResetSolverFarmMarks drops every mark (vhost AND fingerprint). The detectors
// manager calls it when it tears detectors down, so a config reload that
// disables or retunes challenge_solver_farm cannot leave stale badges/convictions
// behind with nothing left running to expire or refresh them.
func ResetSolverFarmMarks() {
	solverFarmMarks.reset()
	solverFarmFPMarks.reset()
}

// decorateSolverFarmShort stamps the mark onto short-window rows.
func decorateSolverFarmShort(rows []ShortRow) []ShortRow {
	for i := range rows {
		rows[i].SolverFarm = IsSolverFarm(rows[i].Host)
	}
	return rows
}

// decorateSolverFarmSuspicious stamps the mark onto long-window rows.
//
// It is applied in the API handlers rather than inside SuspiciousTop because
// the long-window scorer is a pure function of traffic counters; the farm mark
// is an external verdict, and mixing it into the scorer would make it look like
// an input to the score, which it is not.
func decorateSolverFarmSuspicious(rows []SuspiciousRow) []SuspiciousRow {
	for i := range rows {
		rows[i].SolverFarm = IsSolverFarm(rows[i].Host)
	}
	return rows
}
