package detectors

import (
	"context"
	"fmt"
	"sync"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
	"cfm/internal/telemetry"
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

type runOnceTask struct {
	done     chan error
	cancel   context.CancelFunc
	deadline time.Time
	timeout  time.Duration
	timedOut bool
}

type RunHooks struct {
	OnRunStart    func(name string)
	OnRunComplete func(name string, runErr error)
	OnRunTimeout  func(name string)
}

// runOnceSafeTimed starts a detector RunOnce in its own goroutine and returns
// a handle that can be polled without allowing overlapping runs.
//
// The goroutine has its own panic recovery so panics are converted to errors
// and reported via task.done instead of crashing the process.
func runOnceSafeTimed(ctx context.Context, d core.PeriodicDetector, out chan<- core.Alert, timeout time.Duration, active *sync.WaitGroup) *runOnceTask {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctxRun, cancel := context.WithTimeout(ctx, timeout)

	// Embed long-lived ctx so detectors can opt into it.
	ctxRun = context.WithValue(ctxRun, ctxParentKey{}, ctx)

	done := make(chan error, 1)
	active.Add(1)
	go func() {
		defer active.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.Logf("[detectors] %s PANIC: %v", d.Name(), r)
				done <- fmt.Errorf("%s panic: %v", d.Name(), r)
			}
		}()
		start := time.Now()
		err := d.RunOnce(ctxRun, out)
		telemetry.RecordDetectorRun(d.Name(), time.Since(start), err != nil && err != context.Canceled)
		done <- err
	}()

	return &runOnceTask{
		done:     done,
		cancel:   cancel,
		deadline: time.Now().Add(timeout),
		timeout:  timeout,
	}
}

// pollRunOnce checks whether a run has finished. If it exceeded its watchdog
// timeout, we cancel its context once and keep waiting for the goroutine to
// actually exit before allowing another run.
func pollRunOnce(now time.Time, d core.PeriodicDetector, task *runOnceTask, hooks *RunHooks) (bool, error) {
	select {
	case err := <-task.done:
		task.cancel()
		return true, err
	default:
	}

	if !task.timedOut && !now.Before(task.deadline) {
		task.timedOut = true
		task.cancel()
		logging.Logf("[detectors] %s run timeout after %s", d.Name(), task.timeout)
		telemetry.RecordDetectorTimeout(d.Name())
		if hooks != nil && hooks.OnRunTimeout != nil {
			hooks.OnRunTimeout(d.Name())
		}
	}
	return false, nil
}

func waitGroupTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
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
	return runPeriodicInternal(ctx, d, sink, nil, nil)
}

func RunPeriodicWithState(ctx context.Context, d core.PeriodicDetector, sink core.Sink, state *core.State) error {
	return runPeriodicInternal(ctx, d, sink, state, nil)
}

func RunPeriodicWithStateAndHooks(ctx context.Context, d core.PeriodicDetector, sink core.Sink, state *core.State, hooks *RunHooks) error {
	return runPeriodicInternal(ctx, d, sink, state, hooks)
}

func runPeriodicInternal(ctx context.Context, d core.PeriodicDetector, sink core.Sink, state *core.State, hooks *RunHooks) error {
	// Ownership rule: producers own writes to out; therefore out must only be
	// closed after all RunOnce producer goroutines have exited.
	out := make(chan core.Alert, 1024)

	pubStop := make(chan struct{})
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
			case <-pubStop:
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

	var active sync.WaitGroup
	var current *runOnceTask

	err := periodicLoop(ctx, every, func() error {
		if current != nil {
			done, runErr := pollRunOnce(time.Now(), d, current, hooks)
			if !done {
				return nil
			}
			current = nil
			if runErr != nil && runErr != context.Canceled {
				logging.Logf("[detectors] %s run error: %v", d.Name(), runErr)
				if hooks != nil && hooks.OnRunComplete != nil {
					hooks.OnRunComplete(d.Name(), runErr)
				}
				return nil
			}
			if hooks != nil && hooks.OnRunComplete != nil {
				hooks.OnRunComplete(d.Name(), nil)
			}
			if pa, ok := d.(core.PositionAware); ok && state != nil {
				state.Put(pa.Name(), pa.Position())
				_ = state.Save()
			}
			return nil
		}

		if hooks != nil && hooks.OnRunStart != nil {
			hooks.OnRunStart(d.Name())
		}
		current = runOnceSafeTimed(ctx, d, out, runTimeout, &active)
		return nil
	})

	if current != nil {
		current.cancel()
	}

	// Close file handles / child processes now that the loop is done.
	shutdown(d)

	shutdownWait := runTimeout
	if shutdownWait < 5*time.Second {
		shutdownWait = 5 * time.Second
	}
	if shutdownWait > 30*time.Second {
		shutdownWait = 30 * time.Second
	}
	if waitGroupTimeout(&active, shutdownWait) {
		close(out)
		<-pubDone
	} else {
		logging.Logf("[detectors][%s] shutdown wait exceeded %s; leaving out open to avoid send-on-closed panic", d.Name(), shutdownWait)
		close(pubStop)
		<-pubDone
	}

	return err
}
