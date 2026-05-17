//go:build linux

package lsm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"cfm/internal/logging"
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

	// deprecationWarnings fires the one-time configuration-deprecation
	// log lines (watched_uid_fallback_min = -1 today, more in future).
	// ApplyConfig runs every cfm.conf reload tick AND on every drift-
	// adopt cycle, so a plain "log if -1" check would re-emit at the
	// reload cadence on disabled hosts; a single Once per Lifecycle
	// instance suppresses the flood while still surfacing the warning
	// the first time the operator's conf is parsed.
	deprecationWarnings sync.Once

	// pinnedRingbufIno is the bpffs inode of the pinned ringbuf at
	// activation time. Re-checked on every ApplyConfig tick: a missing
	// pin (ENOENT) or a changed inode means the kernel state was torn
	// down (`cfm lsm disable`) or rebuilt (`cfm lsm enable` / `restart`)
	// under the running daemon — the loader's fd points at the orphan,
	// no new events flow, so we tear down and re-adopt.
	//
	// Zero when no activation has occurred yet, or when the underlying
	// stat could not produce a meaningful inode (legacy bpffs without
	// stat support, platform anomalies). In that case drift detection
	// is a no-op and the start-once invariant holds.
	pinnedRingbufIno uint64
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
		// Drift check: if the pinned ringbuf inode has changed (CLI
		// disable+enable rebuilt the pin) or the pin is gone (CLI
		// disable left it absent), our loader is reading from an
		// orphaned ringbuf. Tear the stale drain down here so the
		// rest of this function falls through to the normal adopt /
		// auto-enable path. This is what makes `cfm lsm restart`
		// (CLI-only) actually take effect on the daemon without
		// requiring a `systemctl restart cfm`.
		curIno, statErr := pinnedRingbufIno()
		if statErr == nil && curIno != 0 && curIno == l.pinnedRingbufIno {
			l.mu.Unlock()
			return
		}
		// Capture for teardown and clear in-flight state under lock,
		// then release the mutex — Close() / drain shutdown can block
		// up to 2s and must not hold up other ApplyConfig callers.
		oldIno := l.pinnedRingbufIno
		cancel := l.drainCancel
		done := l.drainDone
		loader := l.loader
		l.started = false
		l.loader = nil
		l.drainCancel = nil
		l.drainDone = nil
		l.pinnedRingbufIno = 0
		l.mu.Unlock()

		if statErr != nil {
			logging.LogfLSM("[lsm] pinned ringbuf gone under daemon (%v); tearing down stale drain", statErr)
			KmsgStatef("STATE", "pinned ringbuf gone; tearing down stale drain")
		} else {
			logging.LogfLSM("[lsm] pinned ringbuf rebuilt under daemon (was_ino=%d now_ino=%d); re-adopting", oldIno, curIno)
			KmsgStatef("ADOPT", "pinned ringbuf rebuilt under daemon; re-adopting")
		}

		if cancel != nil {
			cancel()
		}
		if done != nil {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				logging.LogfLSM("[lsm] drain goroutine did not exit within 2s during re-adopt; continuing")
			}
		}
		if loader != nil {
			if err := loader.Close(); err != nil {
				logging.LogfLSM("[lsm] stale loader close: %v", err)
			}
		}

		// Re-acquire and fall through to normal activation. A racing
		// Stop() between unlock and re-lock would have left started
		// false (we just zeroed it), so the standard checks below
		// handle the case where conf.Enabled has since flipped.
		l.mu.Lock()
	}

	conf, err := LoadConf(false)
	if err != nil {
		// Absent or unreadable config — nothing to activate. Quiet:
		// the `cfm lsm status` command surfaces the underlying error.
		l.mu.Unlock()
		return
	}
	// One-time deprecation warning for the legacy -1 "auto" sentinel.
	// Gated by sync.Once because ApplyConfig fires on every cfm.conf
	// reload tick AND on every drift-adopt cycle; without the gate,
	// a host with `enabled = false` would log this on every tick. The
	// one-time semantics intentionally span Stop→re-Start cycles
	// within the same process (the Once lives on the Lifecycle, which
	// is created once in main.go and held for the daemon's lifetime).
	// See resolveWatchedUidFallback godoc for why auto-detect was
	// removed.
	if conf.WatchedUidFallbackMin < 0 {
		l.deprecationWarnings.Do(func() {
			logging.LogfLSM("[lsm] watched_uid_fallback_min=-1 (auto) is deprecated; treating as 1000.\n" +
				"[lsm]   This is a BEHAVIOUR CHANGE on panel hosts: under -1 with cPanel/DirectAdmin\n" +
				"[lsm]   present, the uid-range fallback used to be SKIPPED. After this change it\n" +
				"[lsm]   applies at 1000, so admin / sysadmin accounts at uid >= 1000 are now in\n" +
				"[lsm]   cfm_watched_uids. To preserve the old behaviour exactly, set:\n" +
				"[lsm]     watched_uid_fallback_min = 0      # panel-manifest-only (matches old -1 on panel hosts)\n" +
				"[lsm]   To adopt the new coverage (recommended; closes the admin-account gap) plus\n" +
				"[lsm]   opt out specific admin accounts, set:\n" +
				"[lsm]     watched_uid_fallback_min = 1000\n" +
				"[lsm]     exclude_user = <your-admin-username>\n" +
				"[lsm]     exclude_uid  = <numeric-uid>\n" +
				"[lsm]     exclude_gid  = <primary-gid>")
		})
	}
	// Apply kmsg config early so subsequent emissions honour the
	// operator's state_transitions / detect_events toggles.
	ConfigureKmsg(conf.Kmsg)
	ConfigureEventSink(conf.EventSink)
	// Install the userspace allowlist before the drain goroutine
	// starts so the first event already goes through the filter.
	SetEventFilter(BuildEventFilter(conf))
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
	// Snapshot the pinned ringbuf inode under lock — future ticks
	// compare against this to spot a CLI rebuild (different inode) or
	// a CLI disable (ENOENT) and trigger the re-adopt branch above. A
	// stat failure here leaves the field at zero, which the drift
	// check treats as "no record, no drift" — equivalent to the old
	// pure start-once behaviour on legacy bpffs.
	if ino, err := pinnedRingbufIno(); err == nil {
		l.pinnedRingbufIno = ino
	}
	l.mu.Unlock()

	loader.Start(drainCtx)
	go l.run(loader)

	attach := loader.Attach()
	summary := policyModeSummary(conf, attach.Attached)
	if fresh {
		logging.LogfLSM("[lsm] auto-enabled at %s (policies: %v)", DefaultPinDir, attach.Attached)
		KmsgStatef("ALIVE", "daemon auto-enabled %s pinned=%s", summary, DefaultPinDir)
	} else {
		logging.LogfLSM("[lsm] adopted pinned state at %s (policies: %v)", DefaultPinDir, attach.Attached)
		KmsgStatef("ADOPT", "daemon attached to pinned state at %s, draining ringbuf (policies: %s)",
			DefaultPinDir, summary)
	}

	// Always refresh the FS-005 + CRED-002 maps from the live host.
	// On the fresh path this is part of activation; on the adopt
	// path the pinned maps survived in bpffs but their contents may
	// be stale (new cPanel/DA accounts, newly-installed setuid
	// binaries) so refreshing on every daemon start is cheap and
	// keeps the detector accurate.
	uids, inodes, setuid, knobs, perr := PopulateMaps(loader, conf)
	if perr != nil {
		logging.LogfLSM("[lsm] partial map population: %v (uids=%d inodes=%d setuid=%d knobs=%d)",
			perr, uids, inodes, setuid, knobs)
		KmsgStatef("ISSUE", "partial map population: %v", perr)
	} else {
		logging.LogfLSM("[lsm] maps populated: watched_uids=%d watched_inodes=%d setuid_inodes=%d kernel_knob_inodes=%d",
			uids, inodes, setuid, knobs)
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
			logging.LogfLSM("[lsm] adopt pinned state at %s failed: %v", DefaultPinDir, err)
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
		logging.LogfLSM("[lsm] auto-enable skipped: kernel preflight FAIL (run `cfm lsm status` for details)")
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
			logging.LogfLSM("[lsm] auto-enable: %s unavailable on this kernel; skipping policy: %s", p.ID, pa.Reason)
			continue
		}
		if !isEnforceCapable(p.ID) && m == ModeEnforce {
			logging.LogfLSM("[lsm] auto-enable: %s enforce downgraded to monitor (policy is monitor-only; see docs/cfm-lsm.md)", p.ID)
			m = ModeMonitor
		}
		policies = append(policies, p.ID)
		modes[p.ID] = m
	}

	if len(policies) == 0 {
		logging.LogfLSM("[lsm] auto-enable skipped: no configured policies are available on this kernel")
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
		logging.LogfLSM("[lsm] auto-enable failed: %v", lerr)
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
			logging.LogfLSM("[lsm] drain goroutine did not exit within 2s; continuing shutdown")
		}
	}
	if loader != nil {
		if err := loader.Close(); err != nil {
			logging.LogfLSM("[lsm] loader close: %v", err)
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
			if shouldSuppressEvent(ev) {
				continue
			}
			emitNotify(ev)
		case err, ok := <-loader.Errors():
			if !ok {
				return
			}
			logging.LogfLSM("[lsm] drain error: %v", err)
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
	if ev.Op != FSOpNone {
		reason += " op=" + ev.Op.String()
	}
	if (ev.PolicyID == PolicySensitiveWrite || ev.PolicyID == PolicyUnexpectedBPF || ev.PolicyID == PolicyKernelModuleLoad || ev.PolicyID == PolicyKexecLoad) && ev.Flags&EventFlagWebOrigin != 0 {
		reason += " origin=web"
	}
	if signal := ev.ExecStdioSignal(); signal != "" {
		reason += " stdio=" + signal
	}
	if prim := ev.PrivInstallPrimitive(); prim != "" {
		reason += " primitive=" + prim
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
	if ev.Op != FSOpNone {
		extra["op"] = ev.Op.String()
	}
	if (ev.PolicyID == PolicySensitiveWrite || ev.PolicyID == PolicyUnexpectedBPF || ev.PolicyID == PolicyKernelModuleLoad || ev.PolicyID == PolicyKexecLoad) && ev.Flags&EventFlagWebOrigin != 0 {
		extra["origin"] = "web"
	}
	if signal := ev.ExecStdioSignal(); signal != "" {
		extra["stdio_signal"] = signal
	}
	if prim := ev.PrivInstallPrimitive(); prim != "" {
		extra["primitive"] = prim
	}

	// Userspace sinks (cfm.log + notify) and the kmsg sink have
	// independent per-policy rate caps so a chatty trigger cannot
	// flood any one of them. See eventsink.go and kmsg.go.
	emitDetectEvent(ev, reason, extra)
	KmsgDetect(ev)
}

// pinnedRingbufIno returns the bpffs inode of the pinned ringbuf
// map at /sys/fs/bpf/cfm/maps/cfm_events. Used by the drift check in
// ApplyConfig: the CLI's disable+enable sequence (`cfm lsm restart`)
// unlinks and recreates the pin, which the kernel allocates a fresh
// inode for. Comparing inodes across ticks is the cheapest signal
// that the daemon's loader fd has been orphaned by the rebuild.
//
// Returns 0 with an error when the pin is absent (typical "operator
// ran `cfm lsm disable`" case — ENOENT here is informational, not a
// failure) or the platform doesn't surface inode info via stat. The
// caller treats both as "drift": tear down the stale drain and let
// the normal adopt / auto-enable path re-run.
func pinnedRingbufIno() (uint64, error) {
	path := filepath.Join(DefaultPinDir, pinSubdirMaps, pinFileMap)
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: sys is %T, want *syscall.Stat_t", path, fi.Sys())
	}
	return sys.Ino, nil
}
