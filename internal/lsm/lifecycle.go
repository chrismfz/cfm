//go:build linux

package lsm

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"cfm/internal/logging"
	"cfm/internal/notify"
)

// Lifecycle owns the daemon-side adoption of cfm-lsm. Mirrors the
// shape of internal/outbound's Lifecycle: created once in
// cmd/cfm/main.go, ApplyConfig is called on every config-reload tick,
// and the first call where conditions are met spawns the adopt
// goroutine. Subsequent calls are no-ops.
//
// Conditions for activation:
//
//   - /etc/cfm/lsm.conf has enabled=true.
//   - At least one policy in lsm.conf is mode=monitor or mode=enforce.
//   - InspectPinned(DefaultPinDir) reports Exists=true (the operator
//     has already run `cfm lsm enable`).
//
// When any of those is false the lifecycle stays dormant. The
// daemon's start path does NOT auto-pin — that is an explicit
// operator action so cfm-lsm protection is never silently activated
// without consent. (If the operator wants auto-attach on daemon start
// they can run `cfm lsm enable` once; subsequent daemon restarts
// adopt the existing pinned state.)
type Lifecycle struct {
	mu      sync.Mutex
	started bool

	// loader is the live AdoptPinned result. Held so Stop can close
	// it cleanly. Nil before ApplyConfig has activated.
	loader *Loader

	// drainCancel cancels the ringbuf drain goroutine on Stop.
	drainCancel context.CancelFunc
	drainDone   chan struct{}
}

// NewLifecycle returns a fresh lifecycle. Safe to call before any
// config has loaded.
func NewLifecycle() *Lifecycle { return &Lifecycle{} }

// ApplyConfig checks whether cfm-lsm should be active and, if so,
// adopts the operator's pre-pinned BPF state.
//
// Called on every daemon config-reload tick. The activation is
// start-once — if cfm-lsm was already adopted in this daemon
// process, this is a no-op even if lsm.conf changed. Stop the
// daemon and run `cfm lsm disable` / `cfm lsm enable` to apply a
// fresh policy set.
func (l *Lifecycle) ApplyConfig(ctx context.Context) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		return
	}

	conf, err := LoadConf(false)
	if err != nil {
		// Absent or unreadable config — nothing to adopt. Quiet: the
		// `cfm lsm status` command surfaces the underlying error.
		l.mu.Unlock()
		return
	}
	if !conf.Enabled {
		l.mu.Unlock()
		return
	}
	// At least one policy must be enabled in conf, otherwise there
	// is nothing meaningful to drain even if pinned state exists.
	if !anyEnabled(conf) {
		l.mu.Unlock()
		return
	}

	pinned := InspectPinned(DefaultPinDir)
	if !pinned.Exists || len(pinned.Links) == 0 {
		// Operator has set enabled=true in lsm.conf but has not run
		// `cfm lsm enable` yet. Log once and stay dormant — the
		// next reload tick will pick up the change.
		logging.Logf("[lsm] config enabled but no pinned BPF state at %s; run `cfm lsm enable`", DefaultPinDir)
		l.mu.Unlock()
		return
	}

	loader, err := AdoptPinned(DefaultPinDir, LoaderOptions{EventBufferSize: 1024})
	if err != nil {
		logging.Logf("[lsm] adopt pinned state at %s failed: %v", DefaultPinDir, err)
		l.mu.Unlock()
		return
	}

	drainCtx, drainCancel := context.WithCancel(ctx)
	l.loader = loader
	l.drainCancel = drainCancel
	l.drainDone = make(chan struct{})
	l.started = true
	l.mu.Unlock()

	loader.Start(drainCtx)
	go l.run(loader)

	attach := loader.Attach()
	logging.Logf("[lsm] adopted pinned state at %s (policies: %v)", DefaultPinDir, attach.Attached)
}

// Stop tears down the adoption goroutine and releases the userspace
// fds. It does NOT unpin — the pinned BPF programs remain attached
// at the kernel level past daemon shutdown. `cfm lsm disable` is the
// only path that actually detaches.
func (l *Lifecycle) Stop() {
	if l == nil {
		return
	}
	l.mu.Lock()
	cancel := l.drainCancel
	done := l.drainDone
	loader := l.loader
	l.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			logging.Logf("[lsm] drain goroutine did not exit within 2s; continuing shutdown")
		}
	}
	if loader != nil {
		if err := loader.Close(); err != nil {
			logging.Logf("[lsm] loader close: %v", err)
		}
	}
}

// run is the drain goroutine: pulls events from the loader and
// forwards them into the CFM notify pipeline. Exits when the
// context is cancelled or the events channel closes.
func (l *Lifecycle) run(loader *Loader) {
	defer close(l.drainDone)
	for {
		select {
		case ev, ok := <-loader.Events():
			if !ok {
				return
			}
			emitNotify(ev)
		case err, ok := <-loader.Errors():
			if !ok {
				return
			}
			logging.Logf("[lsm] drain error: %v", err)
			// Errors() has capacity 1; the loader's drain has
			// already exited. Wait for the events channel to close
			// rather than spinning on the same error.
		}
	}
}

// anyEnabled reports whether any policy in conf has a non-disabled
// mode. If every policy is disabled there is no reason to adopt
// the pinned state — even if it exists.
func anyEnabled(c *Conf) bool {
	if c == nil {
		return false
	}
	for _, p := range AllPolicies() {
		if c.ModeFor(p.ID) != ModeDisabled {
			return true
		}
	}
	return false
}

// emitNotify converts an Event into a notify.Event and dispatches
// via the existing CFM notify pipeline. Shape mirrors
// internal/outbound's emission so downstream subscribers can treat
// outbound and lsm events symmetrically.
func emitNotify(ev Event) {
	p, _ := PolicyByID(ev.PolicyID)
	title := string(ev.PolicyID)
	if p.Title != "" {
		title = p.Title
	}

	reason := fmt.Sprintf("%s: pid=%d (%s) policy=%s",
		title, ev.PID, ev.Comm, ev.PolicyID)
	if ev.Filename != "" {
		reason += " path=" + ev.Filename
	}

	extra := map[string]string{
		"policy_id": string(ev.PolicyID),
		"pid":       strconv.FormatUint(uint64(ev.PID), 10),
		"tgid":      strconv.FormatUint(uint64(ev.TGID), 10),
		"uid":       strconv.FormatUint(uint64(ev.UID), 10),
		"gid":       strconv.FormatUint(uint64(ev.GID), 10),
		"comm":      ev.Comm,
		"hook":      p.Hook,
	}
	if ev.Filename != "" {
		extra["path"] = ev.Filename
	}

	_ = notify.Emit(notify.Event{
		Kind:     "lsm_detect",
		Section:  "lsm",
		When:     time.Now(),
		Reason:   reason,
		Severity: "warning",
		Extra:    extra,
	})
	logging.Logf("[lsm] %s", reason)
}
