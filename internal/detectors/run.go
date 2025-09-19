package detectors

import (
	"context"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
)

type LoggerSink struct{}

func (LoggerSink) Publish(a core.Alert) {
	lim := ""
	if a.Extra != nil {
		lim = a.Extra["limit"]
	}
	if lim != "" {
		logging.LogfDETECTOR(
			"\nTime:  %s\nType:  %s, %s\nCount: %d (limit: %s)\nBlocked: No\n\nSample of the first %d lines:\n\n%s\n",
			a.When.Format("Mon Jan 2 15:04:05 2006 -0700"),
			a.Kind, a.Key, a.Count, lim,
			len(a.Samples),
			joinLines(a.Samples),
		)
	} else {
		logging.LogfDETECTOR(
			"\nTime:  %s\nType:  %s, %s\nCount: %d\nBlocked: No\n\nSample of the first %d lines:\n\n%s\n",
			a.When.Format("Mon Jan 2 15:04:05 2006 -0700"),
			a.Kind, a.Key, a.Count,
			len(a.Samples),
			joinLines(a.Samples),
		)
	}
}

func joinLines(ss []string) string {
	out := ""
	for _, s := range ss {
		out += s + "\n"
	}
	return out
}

// runOnceSafe wraps a detector RunOnce with panic recovery so one bad detector
// cannot crash the daemon.
func runOnceSafe(ctx context.Context, d core.PeriodicDetector, out chan<- core.Alert) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logging.Logf("[detectors] %s panic: %v", d.Name(), r)
			// keep the loop alive; convert panic into an error-ish signal
			err = context.Canceled
		}
	}()
	return d.RunOnce(ctx, out)
}

// Fixed-delay loop: waits `every` after each successful (or failed) run.
// This avoids bursts if RunOnce is slower than the period.
func periodicLoop(ctx context.Context, every time.Duration, fn func() error) error {
	if every <= 0 {
		every = 60 * time.Second
	}
	timer := time.NewTimer(0) // fire immediately for first run
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			_ = fn()
			// schedule next iteration relative to *now*
			timer.Reset(every)
		}
	}
}

func RunPeriodic(ctx context.Context, d core.PeriodicDetector, sink core.Sink) error {
	out := make(chan core.Alert, 8)

	// publisher
	pubDone := make(chan struct{})
	go func() {
		defer close(pubDone)
		for {
			select {
			case a, ok := <-out:
				if !ok {
					return
				}
				sink.Publish(a)
			case <-ctx.Done():
				return
			}
		}
	}()

	every := d.Every()
	if every <= 0 {
		every = 60 * time.Second
	}
	logging.Logf("[detectors] %s started (every=%s)", d.Name(), every)

	// fixed-delay schedule with panic-safe RunOnce
	err := periodicLoop(ctx, every, func() error {
		if err := runOnceSafe(ctx, d, out); err != nil && err != context.Canceled {
			logging.Logf("[detectors] %s run error: %v", d.Name(), err)
		}
		return nil
	})

	// shutdown
	close(out)
	<-pubDone
	return err
}

func RunPeriodicWithState(ctx context.Context, d core.PeriodicDetector, sink core.Sink, state *core.State) error {
	out := make(chan core.Alert, 8)

	// publisher
	pubDone := make(chan struct{})
	go func() {
		defer close(pubDone)
		for {
			select {
			case a, ok := <-out:
				if !ok {
					return
				}
				sink.Publish(a)
			case <-ctx.Done():
				return
			}
		}
	}()

	every := d.Every()
	if every <= 0 {
		every = 60 * time.Second
	}
	logging.Logf("[detectors] %s started (every=%s)", d.Name(), every)

	// fixed-delay schedule with position save on successful runs
	err := periodicLoop(ctx, every, func() error {
		if err := runOnceSafe(ctx, d, out); err != nil && err != context.Canceled {
			logging.Logf("[detectors] %s run error: %v", d.Name(), err)
			return nil
		}
		if pa, ok := d.(core.PositionAware); ok && state != nil {
			state.Put(pa.Name(), pa.Position())
			_ = state.Save() // no-op in dir-mode; safe to keep
		}
		return nil
	})

	// shutdown
	close(out)
	<-pubDone
	return err
}
