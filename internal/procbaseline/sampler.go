package procbaseline

import (
	"context"
	"errors"
	"time"

	"cfm/internal/logging"
	"cfm/internal/procstat"
)

const defaultSampleInterval = time.Minute

type healthSource func() (procstat.HealthSummary, map[string]int, error)

// Collector samples the cheap procstat health path and persists only snapshots
// that the existing process-health evaluator considers reliable. It does not
// apply any baseline policy itself; it only builds trustworthy history.
type Collector struct {
	store    *Store
	interval time.Duration
	health   healthSource
}

// NewCollector builds a one-minute process baseline collector over store.
func NewCollector(store *Store) *Collector {
	return &Collector{
		store:    store,
		interval: defaultSampleInterval,
		health:   procstat.HealthWithFamilyCounts,
	}
}

// SampleOnce takes one lightweight /proc snapshot and records it only when the
// current process-health reliability checks pass. A snapshot may still contain
// D/Z findings and be recorded: anomaly presence is data, while Reliable=false
// means the scan itself is unsafe to learn from.
//
// recorded=false with a non-empty skipReason is a deliberate telemetry gap, not
// an error and not a zero-valued sample. Store/write failures are returned as
// errors so a daemon lifecycle can surface them operationally.
func (c *Collector) SampleOnce(now time.Time) (recorded bool, skipReason string, err error) {
	if c == nil || c.store == nil {
		return false, "", errors.New("procbaseline: collector store is unavailable")
	}
	if c.health == nil {
		return false, "", errors.New("procbaseline: collector health source is unavailable")
	}

	h, families, err := c.health()
	if err != nil {
		return false, "", err
	}
	eval := procstat.EvaluateHealth(h)
	if !eval.Reliable {
		reason := eval.Reason
		if reason == "" {
			reason = "process snapshot is unreliable"
		}
		return false, reason, nil
	}

	if err := c.store.Record(now, Sample{
		TotalProcesses: h.TotalProcesses,
		Families:       families,
	}); err != nil {
		return false, "", err
	}
	return true, "", nil
}

// Run samples immediately and then once per interval until ctx is canceled.
// Sampling failures do not terminate the collector: a failed/unreliable minute
// remains a telemetry gap and the next minute is tried normally.
func (c *Collector) Run(ctx context.Context) {
	if c == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
	}

	c.poll(time.Now())
	interval := c.interval
	if interval <= 0 {
		interval = defaultSampleInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.poll(now)
		}
	}
}

func (c *Collector) poll(now time.Time) {
	recorded, reason, err := c.SampleOnce(now)
	switch {
	case err != nil:
		logging.Logf("[procbaseline] sample failed: %v", err)
	case !recorded && reason != "":
		logging.Logf("[procbaseline] sample skipped: %s", reason)
	}
}
