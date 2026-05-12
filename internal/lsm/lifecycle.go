//go:build linux

package lsm

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"cfm/internal/logging"
	"cfm/internal/notify"
)

// Lifecycle owns the daemon-side activation of cfm-lsm. Mirrors the
// shape of internal/outbound's Lifecycle: created once in
// cmd/cfm/main.go, ApplyConfig is called on every config-reload tick,
// and the first call where conditions are met activates the BPF
// programs and starts the drain goroutine. Subsequent calls are
// no-ops.
//
// Activation flow when /etc/cfm/lsm.conf has enabled=true and at
// least one policy is non-disabled:
//
//  1. InspectPinned(DefaultPinDir) — does bpffs already have our pins?
//  2. If YES (a previous daemon already enabled, or the operator ran
//     `cfm lsm enable` directly): AdoptPinned and start draining.
//  3. If NO (fresh boot — bpffs is RAM-only, so reboots wipe pins):
//     run preflight, then NewLoader{PinDir=…} to load + attach + pin
//     in one shot, then start draining from that loader.
//
// This makes "enabled = true" in lsm.conf a self-healing state:
// after reboot, the first daemon start re-pins and resumes
// protection. Operators can still use `cfm lsm enable` for ad-hoc
// or interactive activation, but the daemon does not depend on it.
type Lifecycle struct {
	mu      sync.Mutex
	started bool

	// loader is the live AdoptPinned-or-NewLoader result. Held so
	// Stop can close it cleanly. Nil before ApplyConfig has activated.
	loader *Loader

	// drainCancel cancels the ringbuf drain goroutine on Stop.
	drainCancel context.CancelFunc
	drainDone   chan struct{}
}

// NewLifecycle returns a fresh lifecycle. Safe to call before any
// config has loaded.
func NewLifecycle() *Lifecycle { return &Lifecycle{} }

// ApplyConfig checks whether cfm-lsm should be active and, if so,
// either adopts the existing pinned state or creates fresh pins
// (the auto-enable path used after reboot, when bpffs is empty).
//
// Called on every daemon config-reload tick. The activation is
// start-once — if cfm-lsm was already started in this daemon
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
		// Absent or unreadable config — nothing to activate. Quiet:
		// the `cfm lsm status` command surfaces the underlying error.
		l.mu.Unlock()
		return
	}
	// Apply kmsg config early so subsequent emissions honour the
	// operator's state_transitions / detect_events toggles.
	ConfigureKmsg(conf.Kmsg)
	if !conf.Enabled {
		l.mu.Unlock()
		return
	}
	// At least one policy must be enabled in conf, otherwise there
	// is nothing meaningful to activate.
	if !anyEnabled(conf) {
		l.mu.Unlock()
		return
	}

	loader, fresh, err := openOrCreateLoader(conf)
	if err != nil {
		l.mu.Unlock()
		return // openOrCreateLoader already logged + emitted to kmsg
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
	summary := policyModeSummary(conf, attach.Attached)
	if fresh {
		logging.Logf("[lsm] auto-enabled at %s (policies: %v)", DefaultPinDir, attach.Attached)
		KmsgStatef("ALIVE", "daemon auto-enabled %s pinned=%s", summary, DefaultPinDir)
	} else {
		logging.Logf("[lsm] adopted pinned state at %s (policies: %v)", DefaultPinDir, attach.Attached)
		KmsgStatef("ADOPT", "daemon attached to pinned state at %s, draining ringbuf (policies: %s)",
			DefaultPinDir, summary)
	}

	// Always refresh the FS-005 + CRED-002 maps from the live host.
	// On the fresh path this is part of activation; on the adopt
	// path the pinned maps survived in bpffs but their contents may
	// be stale (new cPanel/DA accounts, newly-installed setuid
	// binaries) so refreshing on every daemon start is cheap and
	// keeps the detector accurate.
	uids, inodes, setuid, perr := PopulateMaps(loader)
	if perr != nil {
		logging.Logf("[lsm] partial map population: %v (uids=%d inodes=%d setuid=%d)",
			perr, uids, inodes, setuid)
		KmsgStatef("ISSUE", "partial map population: %v", perr)
	} else {
		logging.Logf("[lsm] maps populated: watched_uids=%d watched_inodes=%d setuid_inodes=%d",
			uids, inodes, setuid)
	}
}

// openOrCreateLoader is the activation core: either adopt existing
// pinned state, or run preflight + NewLoader to create fresh pins.
// Returns the loader, a `fresh` boolean indicating which path was
// taken, and any error. On error the caller stays dormant — every
// failure path here also logs and emits to kmsg so the operator
// sees what happened.
//
// The fresh path is what makes "enabled = true" survive a reboot:
// bpffs is RAM-only, so on every boot the daemon comes up to find
// no pins, runs the same load+attach+pin work `cfm lsm enable` would
// have done, and resumes protection without operator intervention.
func openOrCreateLoader(conf *Conf) (loader *Loader, fresh bool, err error) {
	pinned := InspectPinned(DefaultPinDir)
	if pinned.Exists && len(pinned.Links) > 0 {
		l, err := AdoptPinned(DefaultPinDir, LoaderOptions{EventBufferSize: 1024})
		if err != nil {
			logging.Logf("[lsm] adopt pinned state at %s failed: %v", DefaultPinDir, err)
			KmsgStatef("ISSUE", "adopt pinned state at %s failed: %v", DefaultPinDir, err)
			return nil, false, err
		}
		return l, false, nil
	}

	// No pinned state — auto-enable. Run preflight first; if it
	// fails (kernel too old, CONFIG_BPF_LSM not set, `bpf` not in
	// /sys/kernel/security/lsm, BTF missing, caps missing, bpffs
	// not mounted) we stay dormant and the daemon continues
	// normally. `cfm lsm status` will report the failing checks.
	pf := RunPreflight()
	if !pf.OK {
		logging.Logf("[lsm] auto-enable skipped: kernel preflight FAIL (run `cfm lsm status` for details)")
		return nil, false, errors.New("preflight failed")
	}

	// Build the same policies + modes map that `cfm lsm enable`
	// would have built. Apply the CRED-002 enforce-downgrade so an
	// operator who set mode=enforce on CRED-002 in lsm.conf still
	// gets safe monitor-mode behaviour from the daemon-driven path.
	availability := map[PolicyID]PolicyAvailability{}
	for _, pa := range pf.PolicyAvailability {
		availability[pa.PolicyID] = pa
	}

	var policies []PolicyID
	modes := map[PolicyID]Mode{}
	for _, p := range AllPolicies() {
		m := conf.ModeFor(p.ID)
		if m == ModeDisabled {
			continue
		}
		if pa, ok := availability[p.ID]; ok && !pa.Available {
			logging.Logf("[lsm] auto-enable: %s unavailable on this kernel; skipping policy: %s", p.ID, pa.Reason)
			continue
		}
		if (p.ID == PolicyCredEscal || p.ID == PolicyDirectCredInstall) && m == ModeEnforce {
			logging.Logf("[lsm] auto-enable: %s enforce downgraded to monitor (cred-install telemetry is monitor-only; see docs/cfm-lsm.md)", p.ID)
			m = ModeMonitor
		}
		policies = append(policies, p.ID)
		modes[p.ID] = m
	}

	if len(policies) == 0 {
		logging.Logf("[lsm] auto-enable skipped: no configured policies are available on this kernel")
		return nil, false, errors.New("no configured policies available")
	}

	l, lerr := NewLoader(LoaderOptions{
		EventBufferSize:       1024,
		Policies:              policies,
		Modes:                 modes,
		FS005WebOriginMonitor: conf.FS005WebOriginMonitor,
		PinDir:                DefaultPinDir,
	})
	if lerr != nil {
		logging.Logf("[lsm] auto-enable failed: %v", lerr)
		KmsgStatef("ISSUE", "auto-enable failed: %v", lerr)
		// Try to clean up any partial pin state so the next reload
		// tick starts from scratch rather than half-pinned.
		_ = UnpinAll(DefaultPinDir)
		return nil, false, lerr
	}
	return l, true, nil
}

// Stop tears down the activation goroutine and releases the userspace
// fds. It does NOT unpin — the pinned BPF programs remain attached
// at the kernel level past daemon shutdown. `cfm lsm disable` is the
// only path that actually detaches at the kernel level.
//
// (Note: bpffs is RAM-only, so a reboot DOES detach everything. That
// is fine — the next daemon start re-runs ApplyConfig and the
// auto-enable path re-pins from scratch.)
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
		KmsgStatef("STATE", "daemon stopping; pinned BPF state remains attached")
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
			KmsgStatef("ISSUE", "drain error: %v", err)
			// Errors() has capacity 1; the loader's drain has
			// already exited. Wait for the events channel to close
			// rather than spinning on the same error.
		}
	}
}

// anyEnabled reports whether any policy in conf has a non-disabled
// mode. If every policy is disabled there is no reason to activate
// even if pinned state exists.
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
	if ev.PolicyID == PolicySensitiveWrite && ev.Flags&EventFlagWebOrigin != 0 {
		reason += " origin=web"
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
	if ev.PolicyID == PolicySensitiveWrite && ev.Flags&EventFlagWebOrigin != 0 {
		extra["origin"] = "web"
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
	// Emit a DETECT line to dmesg / /var/log/messages too. Rate-
	// limited per-policy by KmsgDetect so a burst cannot flood the
	// kernel log. The notify pipeline + cfm.log always get the
	// full stream regardless.
	KmsgDetect(ev)
}
