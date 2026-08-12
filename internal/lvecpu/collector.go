// Package lvecpu is the in-memory collector for the CloudLinux per-tenant CPU
// signal (#30). It samples /proc/lve/list on a ticker and keeps the latest
// per-tenant CPU delta (cores + %-of-limit, computed by lvestat.Diff) in memory
// — no persistence, only the current rate matters. A read endpoint / MCP tool
// serves the latest hottest-first sample. On a non-CloudLinux host (no
// /proc/lve/list) the collector never starts and Available() stays false.
package lvecpu

import (
	"sync"
	"time"

	"cfm/internal/lvestat"
)

// defaultInterval is the sample cadence. Each sample is one cheap /proc read;
// the reported rate is the CPU delta over the last interval.
const defaultInterval = 15 * time.Second

// Collector samples /proc/lve/list and folds each consecutive pair into
// per-tenant CPU deltas. readFn/nowFn are seams for tests.
type Collector struct {
	mu      sync.RWMutex
	latest  []lvestat.CPUSample
	sampled time.Time
	prev    lvestat.Snapshot
	prevAt  time.Time
	hasPrev bool

	interval time.Duration
	readFn   func() (lvestat.Snapshot, error)
	nowFn    func() time.Time
	stop     chan struct{}
	done     chan struct{}
}

func newCollector(interval time.Duration) *Collector {
	if interval <= 0 {
		interval = defaultInterval
	}
	return &Collector{
		interval: interval,
		readFn:   lvestat.Read,
		nowFn:    time.Now,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (c *Collector) run() {
	defer close(c.done)
	c.pollOnce()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.pollOnce()
		}
	}
}

// pollOnce reads /proc/lve/list and, once it has a previous sample, folds the
// two into per-tenant CPU deltas. The first successful read only seeds prev (no
// rate yet). A read error leaves the last good sample untouched.
func (c *Collector) pollOnce() {
	cur, err := c.readFn()
	if err != nil {
		return
	}
	now := c.nowFn()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hasPrev {
		if d := lvestat.Diff(c.prev, cur, now.Sub(c.prevAt)); d != nil {
			c.latest = d
			c.sampled = now
		}
	}
	c.prev = cur
	c.prevAt = now
	c.hasPrev = true
}

// snapshot returns a copy of the latest per-tenant samples (hottest-first) and
// when they were computed. ready=false until two samples have been taken.
func (c *Collector) snapshot() (samples []lvestat.CPUSample, at time.Time, ready bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.latest == nil {
		return nil, time.Time{}, false
	}
	out := make([]lvestat.CPUSample, len(c.latest))
	copy(out, c.latest)
	return out, c.sampled, true
}

var (
	sharedMu sync.Mutex
	shared   *Collector
)

// Enable starts the background collector iff this host exposes /proc/lve/list
// (CloudLinux + LVE module). On any other host it is a no-op and Available()
// stays false. Idempotent — a second call while running does nothing.
func Enable() {
	if !lvestat.Available() {
		return
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if shared != nil {
		return
	}
	shared = newCollector(defaultInterval)
	go shared.run()
}

// Shutdown stops the collector and waits for its goroutine to exit. Safe to call
// when never enabled.
func Shutdown() {
	sharedMu.Lock()
	c := shared
	shared = nil
	sharedMu.Unlock()
	if c != nil {
		close(c.stop)
		<-c.done
	}
}

// Available reports whether the collector is running (i.e. a CloudLinux host).
func Available() bool {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	return shared != nil
}

// Latest returns the newest per-tenant CPU samples (hottest-first), the time
// they were computed, and ready=false when the host isn't CloudLinux or the
// first delta isn't available yet (needs two samples).
func Latest() (samples []lvestat.CPUSample, at time.Time, ready bool) {
	sharedMu.Lock()
	c := shared
	sharedMu.Unlock()
	if c == nil {
		return nil, time.Time{}, false
	}
	return c.snapshot()
}

// IntervalSeconds is the sample cadence in seconds, for reporting in responses.
func IntervalSeconds() int { return int(defaultInterval / time.Second) }
