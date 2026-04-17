package webdetector

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/logging"
)

type excludeMetric struct {
	calls   atomic.Uint64
	totalNs atomic.Uint64
	maxNs   atomic.Uint64
}

type excludeProfiler struct {
	enabled bool
	window  time.Duration
	lastLog atomic.Int64
	flushMu sync.Mutex

	matchChallenge excludeMetric
	matchWAF       excludeMetric
	hostInScope    excludeMetric
}

var globalExcludeProfiler = newExcludeProfiler()

func newExcludeProfiler() *excludeProfiler {
	p := &excludeProfiler{window: time.Second}
	if v := os.Getenv("CFM_EXCLUDE_PROFILING_WINDOW_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			p.window = time.Duration(ms) * time.Millisecond
		}
	}
	enabled := os.Getenv("CFM_EXCLUDE_PROFILING")
	p.enabled = enabled == "1" || enabled == "true" || enabled == "TRUE"
	if p.enabled {
		p.lastLog.Store(time.Now().UnixNano())
	}
	return p
}

func (p *excludeProfiler) start() (time.Time, bool) {
	if p == nil || !p.enabled {
		return time.Time{}, false
	}
	return time.Now(), true
}

func (p *excludeProfiler) end(name string, start time.Time, enabled bool) {
	if !enabled {
		return
	}
	elapsed := uint64(time.Since(start).Nanoseconds())
	var m *excludeMetric
	switch name {
	case "match_challenge":
		m = &p.matchChallenge
	case "match_waf":
		m = &p.matchWAF
	case "host_in_scope":
		m = &p.hostInScope
	default:
		return
	}
	m.calls.Add(1)
	m.totalNs.Add(elapsed)
	for {
		curr := m.maxNs.Load()
		if elapsed <= curr {
			break
		}
		if m.maxNs.CompareAndSwap(curr, elapsed) {
			break
		}
	}
	p.maybeFlush()
}

func (p *excludeProfiler) maybeFlush() {
	now := time.Now()
	last := time.Unix(0, p.lastLog.Load())
	if now.Sub(last) < p.window {
		return
	}
	p.flushMu.Lock()
	defer p.flushMu.Unlock()
	last = time.Unix(0, p.lastLog.Load())
	if now.Sub(last) < p.window {
		return
	}
	windowSec := now.Sub(last).Seconds()
	if windowSec <= 0 {
		windowSec = p.window.Seconds()
	}
	p.logMetric("MatchChallenge", &p.matchChallenge, windowSec)
	p.logMetric("MatchWAF", &p.matchWAF, windowSec)
	p.logMetric("hostInScope", &p.hostInScope, windowSec)
	p.lastLog.Store(now.UnixNano())
}

func (p *excludeProfiler) logMetric(name string, m *excludeMetric, windowSec float64) {
	calls := m.calls.Swap(0)
	totalNs := m.totalNs.Swap(0)
	maxNs := m.maxNs.Swap(0)
	if calls == 0 {
		return
	}
	avgUs := float64(totalNs) / float64(calls) / 1000.0
	maxUs := float64(maxNs) / 1000.0
	cps := float64(calls) / windowSec
	logging.Logf("[exclude-prof] %s cps=%.2f avg_us=%.2f max_us=%.2f calls=%d window_sec=%.2f", name, cps, avgUs, maxUs, calls, windowSec)
}
