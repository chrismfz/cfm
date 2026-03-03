package detectors

import (
	"context"
	"fmt"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
)

// ctxParentKey stashes the long-lived manager ctx inside the per-run ctx that
// may have a watchdog timeout.  Some detectors (webdetector) need a ctx that
// outlives a single RunOnce tick for background listeners.
type ctxParentKey struct{}

// parentCtxFrom returns the long-lived manager ctx if embedded by runOnceSafeTimed.
func parentCtxFrom(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	if v := ctx.Value(ctxParentKey{}); v != nil {
		if p, ok := v.(context.Context); ok {
			return p
		}
	}
	return nil
}

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
//   - panic recovery (so one bad detector cannot crash the daemon)
//   - a per-run watchdog timeout (so a stuck tailer / infinite loop can't
//     freeze the scheduler)
//
// NOTE: the detector must respect ctx cancellation; a truly stuck goroutine
// that ignores ctx cannot be force-killed here.
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

	// Embed long-lived ctx so detectors can opt into it.
	ctxRun = context.WithValue(ctxRun, ctxParentKey{}, ctx)

	done := make(chan error, 1)
	go func() {
		done <- d.RunOnce(ctxRun, out)
	}()

	select {
	case e := <-done:
		return e
	case <-ctxRun.Done():
		if ctx.Err() != nil {
			return ctx.Err()
		}
		logging.Logf("[detectors] %s run timeout after %s", d.Name(), timeout)
		return ctxRun.Err()
	}
}

// periodicLoop runs fn on a fixed-delay schedule (waits `every` after each
// run, whether it succeeded or failed).  This avoids bursts when RunOnce is
// slower than the period.
func periodicLoop(ctx context.Context, every time.Duration, fn func() error) error {
	if every <= 0 {
		every = 60 * time.Second
	}
	timer := time.NewTimer(0) // fire immediately on first tick
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			_ = fn()
			timer.Reset(every)
		}
	}
}

// shutdown calls d.Shutdown() if the detector implements core.Shutdowner,
// then logs the result.  Called once after the periodic loop exits.
func shutdown(d core.PeriodicDetector) {
	if s, ok := d.(core.Shutdowner); ok {
		if err := s.Shutdown(); err != nil {
			logging.Logf("[detectors][%s] shutdown error: %v", d.Name(), err)
		}
	}
}

func RunPeriodic(ctx context.Context, d core.PeriodicDetector, sink core.Sink) error {
	out := make(chan core.Alert, 1024)

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

	runTimeout := 2 * every
	if runTimeout < 30*time.Second {
		runTimeout = 30 * time.Second
	}
	if runTimeout > 5*time.Minute {
		runTimeout = 5 * time.Minute
	}

	err := periodicLoop(ctx, every, func() error {
		if err := runOnceSafeTimed(ctx, d, out, runTimeout); err != nil && err != context.Canceled {
			logging.Logf("[detectors] %s run error: %v", d.Name(), err)
		}
		return nil
	})

	// Drain and close the alert channel before shutting down the source,
	// so the publisher goroutine has a clean exit.
	close(out)
	<-pubDone

	// Close file handles / child processes now that the loop is done.
	shutdown(d)
	return err
}

func RunPeriodicWithState(ctx context.Context, d core.PeriodicDetector, sink core.Sink, state *core.State) error {
	out := make(chan core.Alert, 1024)

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

	runTimeout := 2 * every
	if runTimeout < 30*time.Second {
		runTimeout = 30 * time.Second
	}
	if runTimeout > 5*time.Minute {
		runTimeout = 5 * time.Minute
	}

	err := periodicLoop(ctx, every, func() error {
		if err := runOnceSafeTimed(ctx, d, out, runTimeout); err != nil && err != context.Canceled {
			logging.Logf("[detectors] %s run error: %v", d.Name(), err)
			return nil
		}
		if pa, ok := d.(core.PositionAware); ok && state != nil {
			state.Put(pa.Name(), pa.Position())
			_ = state.Save()
		}
		return nil
	})

	// Drain and close the alert channel before shutting down the source.
	close(out)
	<-pubDone

	// Close file handles / child processes now that the loop is done.
	shutdown(d)
	return err
}
