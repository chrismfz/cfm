package clam

import (
	"sync"
	"time"
)

// Scan-event fan-out. The scanner (internal/clam) is a leaf package that
// internal/webdetector imports, so webdetector can't be referenced from here to
// persist scan results — but it CAN register a sink. This is the inverse of the
// WAF-hit pub/sub (which lives in webdetector because webdetector publishes it):
// here clam publishes and webdetector's HistoryStore subscribes, so the fan-out
// lives in clam.
//
// A single settable sink (not an append-only subscriber list) is deliberate:
// there is exactly one consumer (the history store), and the engine is rebuilt
// on config reload — replacing the sink keeps it pointed at the current engine
// with no duplicate-subscriber accumulation.

// ScanEvent is a normalized per-scan result for persistence/insights. v1 only
// publishes infections (clean uploads are high-volume and would prune the rare,
// valuable infected rows out of the bounded history store; scan *volume* is
// covered by the HealthSnapshot counters instead).
type ScanEvent struct {
	EventType  string // "clam_infected"
	Host       string
	IP         string
	URI        string
	FileName   string
	Signature  string
	Evidence   string // empty for a sig-ignored hit (nothing is quarantined)
	SigIgnored bool   // verdict downgraded to log-only by the signature-trust layer
	IgnoredBy  string // which config pattern / store entry downgraded it
	When       time.Time
}

var (
	scanSinkMu sync.RWMutex
	scanSink   func(ScanEvent)
)

// SetScanEventSink registers (replacing any prior) the consumer of scan events.
// Pass nil to detach. Safe for concurrent use.
func SetScanEventSink(fn func(ScanEvent)) {
	scanSinkMu.Lock()
	scanSink = fn
	scanSinkMu.Unlock()
}

// publishScanEvent delivers ev to the sink if one is set. A misbehaving sink
// must never take down a scanner worker, so panics are contained.
func publishScanEvent(ev ScanEvent) {
	scanSinkMu.RLock()
	fn := scanSink
	scanSinkMu.RUnlock()
	if fn == nil {
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			logf("[clam] scan-event sink panic kind=%s host=%s err=%v", ev.EventType, ev.Host, rec)
		}
	}()
	fn(ev)
}
