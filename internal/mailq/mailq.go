// Package mailq holds the latest MTA queue measurement.
//
// The exim_queues / postfix_queues detectors publish here after each
// successful count, and the health snapshot (→ `cfm health`, dashboard
// Node health card) reads it. A tiny shared store — same pattern as
// healthstore — so the queue is counted ONCE, by the detector with its
// operator-configurable TOTAL_CMD/LIST_CMD, instead of every consumer
// shelling out its own mailq probe.
//
// If neither queue detector is enabled, Latest reports nothing and the
// health surfaces simply omit the mail-queue line/tile.
package mailq

import (
	"sync"
	"time"
)

// Measurement is one published queue reading.
type Measurement struct {
	MTA        string    // "exim" | "postfix"
	Total      int       // messages in queue
	Frozen     int       // exim frozen / postfix deferred (0 when unknown)
	MeasuredAt time.Time
}

var (
	mu     sync.RWMutex
	latest = map[string]Measurement{}
)

// Publish records the latest measurement for m.MTA (no-op on empty MTA).
func Publish(m Measurement) {
	if m.MTA == "" {
		return
	}
	if m.MeasuredAt.IsZero() {
		m.MeasuredAt = time.Now()
	}
	mu.Lock()
	latest[m.MTA] = m
	mu.Unlock()
}

// Latest returns the most recent measurement across MTAs (dual-MTA boxes:
// freshest wins), or ok=false when nothing has been published yet.
func Latest() (Measurement, bool) {
	mu.RLock()
	defer mu.RUnlock()
	var best Measurement
	var ok bool
	for _, m := range latest {
		if !ok || m.MeasuredAt.After(best.MeasuredAt) {
			best, ok = m, true
		}
	}
	return best, ok
}

// TestOnlyReset clears the store (tests share the package-global state).
func TestOnlyReset() {
	mu.Lock()
	latest = map[string]Measurement{}
	mu.Unlock()
}
