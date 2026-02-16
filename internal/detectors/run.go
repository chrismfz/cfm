package detectors

import (
	"context"
	"time"
	"fmt"
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

// runOnceSafeTimed wraps a detector RunOnce with:
//  - panic recovery (so one bad detector cannot crash the daemon)
//  - a per-run watchdog timeout (so a stuck tailer / infinite loop can't freeze the scheduler)
//
// NOTE: The detector must respect ctx; otherwise a truly stuck goroutine can't be force-killed.
func runOnceSafeTimed(ctx context.Context, d core.PeriodicDetector, out chan<- core.Alert, timeout time.Duration) (err error) {
	defer func() {
		if r := recover(); r != nil {
	            logging.Logf("[detectors] %s PANIC: %v", d.Name(), r)
	            err = fmt.Errorf("%s panic: %v", d.Name(), r)
		}
	}()
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctxRun, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		// RunOnce may block; isolate it so the watchdog can trigger.
		done <- d.RunOnce(ctxRun, out)
	}()

	select {
	case e := <-done:
		return e
	case <-ctxRun.Done():
		// distinguish "caller canceled" vs "watchdog timeout"
		if ctx.Err() != nil {
			return ctx.Err()
		}
		logging.Logf("[detectors] %s run timeout after %s", d.Name(), timeout)
		return ctxRun.Err()
	}

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
	// webdetector can burst; keep this large to avoid backpressure deadlocks.
	out := make(chan core.Alert, 1024)

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
	logging.Logf("[detectors][%s] started (every=%s)", d.Name(), every)

	// Per-run watchdog: >=30s, <=5m, scaled by schedule.
	runTimeout := 2 * every
	if runTimeout < 30*time.Second {
		runTimeout = 30 * time.Second
	}
	if runTimeout > 5*time.Minute {
		runTimeout = 5 * time.Minute
	}


	// fixed-delay schedule with panic-safe RunOnce
	err := periodicLoop(ctx, every, func() error {
		if err := runOnceSafeTimed(ctx, d, out, runTimeout); err != nil && err != context.Canceled {
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
	// webdetector can burst; keep this large to avoid backpressure deadlocks.
	out := make(chan core.Alert, 1024)

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
	logging.Logf("[detectors][%s] started (every=%s)", d.Name(), every)

	// Per-run watchdog: >=30s, <=5m, scaled by schedule.
	runTimeout := 2 * every
	if runTimeout < 30*time.Second {
		runTimeout = 30 * time.Second
	}
	if runTimeout > 5*time.Minute {
		runTimeout = 5 * time.Minute
	}


	// fixed-delay schedule with position save on successful runs
	err := periodicLoop(ctx, every, func() error {
		if err := runOnceSafeTimed(ctx, d, out, runTimeout); err != nil && err != context.Canceled {
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
