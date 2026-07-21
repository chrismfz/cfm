package clam

import (
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/notify"
)

// Resilience for the async upload scanner. clamd can be down (not installed,
// stopped, socket gone) or hung. Without a guard each worker blocks up to
// Config.Timeout on every SCAN dial, so a handful of workers stall for
// seconds/job while the bounded queue silently drops the rest — and nothing
// tells the operator. This adds:
//
//   - a circuit breaker: after breakerFailThreshold consecutive failures the
//     workers stop dialing clamd per-job and fast-skip (cheap cleanup) until it
//     recovers, so a dead clamd can't starve the workers or fill the queue;
//   - a background prober: pings clamd on a fixed cadence so "down" is detected
//     (and "recovered" cleared) even with no upload traffic;
//   - an edge-triggered alert on the down→up / up→down transitions, via the
//     same notify section ("clam") the upload/infected events use.
const (
	breakerFailThreshold = 3                // consecutive failures (scan or probe) that open the breaker
	breakerProbeInterval = 10 * time.Second // how often the prober pings clamd
	breakerProbeTimeout  = 3 * time.Second  // bounded dial+read for a probe (never the full Config.Timeout)
)

// scanHealth is the breaker state plus lifetime counters. The time/flag fields
// are mutex-guarded (read together for a consistent snapshot); the counters are
// independent atomics on the hot path.
type scanHealth struct {
	mu          sync.Mutex
	breakerOpen bool
	consecFails int
	lastOK      time.Time
	lastFail    time.Time
	downSince   time.Time // zero while healthy
	lastErr     string

	scannedOK      atomic.Uint64
	scanErrors     atomic.Uint64
	skippedBreaker atomic.Uint64
	queueDrops     atomic.Uint64
}

// record folds one outcome (scan result or probe) into the breaker state and
// returns the transition it caused: "down", "recovered", or "" for none. The
// caller emits an alert only on a non-empty transition, so alerts are
// edge-triggered (one per state change, not one per failing job).
func (h *scanHealth) record(ok bool, errStr string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if ok {
		h.lastOK = now
		h.consecFails = 0
		if h.breakerOpen {
			h.breakerOpen = false
			h.downSince = time.Time{}
			h.lastErr = ""
			return "recovered"
		}
		return ""
	}
	h.lastFail = now
	h.lastErr = errStr
	h.consecFails++
	if !h.breakerOpen && h.consecFails >= breakerFailThreshold {
		h.breakerOpen = true
		h.downSince = now
		return "down"
	}
	return ""
}

func (h *scanHealth) isOpen() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.breakerOpen
}

// HealthSnapshot is a consistent read of the scanner's clamd-reachability state
// and lifetime counters — for `cfm clam status` and the admin/insights API.
type HealthSnapshot struct {
	Enabled        bool
	BreakerOpen    bool
	DownSince      time.Time
	ConsecFails    int
	LastOK         time.Time
	LastFail       time.Time
	LastErr        string
	QueueLen       int
	QueueCap       int
	ScannedOK      uint64
	ScanErrors     uint64
	SkippedBreaker uint64
	QueueDrops     uint64
}

// Health returns a snapshot of scanner reachability + counters. Cheap and
// non-blocking (no dial): reads cached breaker state, never probes clamd.
func (m *Manager) Health() HealthSnapshot {
	if m == nil || m.health == nil {
		return HealthSnapshot{}
	}
	h := m.health
	ql, qc := m.QueueDepth()
	h.mu.Lock()
	snap := HealthSnapshot{
		Enabled:     m.Enabled(),
		BreakerOpen: h.breakerOpen,
		DownSince:   h.downSince,
		ConsecFails: h.consecFails,
		LastOK:      h.lastOK,
		LastFail:    h.lastFail,
		LastErr:     h.lastErr,
	}
	h.mu.Unlock()
	snap.QueueLen, snap.QueueCap = ql, qc
	snap.ScannedOK = h.scannedOK.Load()
	snap.ScanErrors = h.scanErrors.Load()
	snap.SkippedBreaker = h.skippedBreaker.Load()
	snap.QueueDrops = h.queueDrops.Load()
	return snap
}

// recordScan folds a scan outcome into the breaker (ok == clamd reachable) and
// bumps the lifetime counter. A clean OR infected result is a success — only a
// transport error (dial/timeout/read) counts as a failure.
func (m *Manager) recordScan(ok bool, errStr string) {
	if ok {
		m.health.scannedOK.Add(1)
	} else {
		m.health.scanErrors.Add(1)
	}
	if trans := m.health.record(ok, errStr); trans != "" {
		m.alertClamState(trans, errStr)
	}
}

// healthLoop pings clamd on a fixed cadence so down/recovery is observed even
// with no upload traffic. Started by Start(); stops with the manager.
func (m *Manager) healthLoop() {
	t := time.NewTicker(breakerProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-t.C:
			errStr := ""
			if err := m.client.PingWithTimeout(breakerProbeTimeout); err != nil {
				errStr = err.Error()
			}
			if trans := m.health.record(errStr == "", errStr); trans != "" {
				m.alertClamState(trans, errStr)
			}
			// While degraded, heartbeat the snapshot so the outage (and its
			// cost — skipped scans, dropped uploads) stays visible in the log,
			// not just at the one-shot down alert.
			if s := m.Health(); s.BreakerOpen {
				logf("[clam_health] breaker=open down_since=%s consec_fails=%d skipped=%d queue_drops=%d last_err=%q",
					s.DownSince.UTC().Format(time.RFC3339), s.ConsecFails,
					s.SkippedBreaker, s.QueueDrops, s.LastErr)
			}
		}
	}
}

// alertClamState emits the edge-triggered clamd down/recovery notification.
func (m *Manager) alertClamState(state, errStr string) {
	kind, sev, reason, msg := "CLAM/DOWN", "critical",
		"clamd unreachable",
		"ClamAV daemon unreachable — upload scanning paused (circuit breaker open)"
	if state == "recovered" {
		kind, sev, reason, msg = "CLAM/UP", "info",
			"clamd recovered",
			"ClamAV daemon reachable again — upload scanning resumed"
	}
	logf("[clam_health] state=%s address=%s err=%q", state, m.cfg.Address, errStr)
	notify.Enqueue(notify.Event{
		Kind:     kind,
		Section:  "clam",
		Severity: sev,
		Reason:   reason,
		When:     time.Now(),
		Samples:  []string{msg, "address=" + m.cfg.Address, "err=" + errStr},
		Extra: map[string]string{
			"state":   state,
			"address": m.cfg.Address,
			"err":     errStr,
		},
	})
}
