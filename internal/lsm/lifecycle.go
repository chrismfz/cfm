//go:build linux

package lsm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"cfm/internal/logging"
)

// lsmActivationClock returns the current time for activation-backoff
// bookkeeping. A package var so tests can drive backoff transitions
// deterministically without sleeping.
var lsmActivationClock = time.Now

// errActivationBackoff is returned by openOrCreateLoader when the fresh
// auto-enable path is deferred by backoff. ApplyConfig treats it like
// any other activation error (stay dormant) but it is deliberately
// unlogged — the failure that armed the backoff already logged once.
var errActivationBackoff = errors.New("fresh activation deferred by backoff")

const (
	// activationBackoffInitial is the wait after the first failed fresh
	// auto-enable attempt; it doubles on each subsequent failure.
	activationBackoffInitial = 1 * time.Minute
	// activationBackoffMax caps the fresh-path retry interval so a
	// permanently-incompatible kernel logs at most this often.
	activationBackoffMax = 30 * time.Minute
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

	// build identifies the cfm binary that owns this Lifecycle. Stamped
	// into DefaultBuildVersionMarker at every successful enable (fresh
	// or CLI-driven) and compared against the marker at every adopt-
	// path entry — when they differ (package upgrade since the pins
	// were created), the adopt path tears the old pins down and the
	// fresh path re-pins with this binary's BPF. Empty BuildMarker is
	// allowed; the adopt path then treats every existing pin as stale
	// (one-time refresh on first upgrade to a marker-aware build).
	build BuildMarker

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

	// activationBackoff / nextActivationAttempt implement exponential
	// backoff for the FRESH auto-enable path (preflight + NewLoader).
	// A permanently-incompatible kernel — e.g. CloudLinux 8 lve, which
	// passes bpf-lsm-program-type but lacks task-local storage maps, so
	// the shared BPF object never loads — would otherwise re-run
	// preflight and log a FAIL on every reload tick. On each fresh-path
	// failure the wait doubles from activationBackoffInitial up to
	// activationBackoffMax; any successful activation (fresh or adopt)
	// resets it. The adopt path is never gated, so an operator's
	// `cfm lsm enable` (which creates pins the daemon then adopts) is
	// still picked up on the very next tick regardless of backoff state.
	activationBackoff     time.Duration
	nextActivationAttempt time.Time
}

// NewLifecycle returns a fresh lifecycle. Safe to call before any
// config has loaded. build identifies the cfm binary so the adopt
// path can detect stale pins from a prior build (package-upgrade
// case). The zero BuildMarker is accepted — older callers that
// haven't been updated still work; the adopt path then treats every
// existing pin as stale (one-time refresh per startup).
func NewLifecycle(build BuildMarker) *Lifecycle {
	return &Lifecycle{build: build}
}

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

	loader, fresh, err := l.openOrCreateLoader(conf)
	if err != nil {
		l.mu.Unlock()
		// openOrCreateLoader already surfaced the reason (log, and kmsg
		// for load/attach failures); a backoff-deferred attempt returns
		// errActivationBackoff silently by design. Either way we stay
		// dormant this tick.
		return
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
// taken, and any error. On error the caller stays dormant. Every
// failure path here logs (and, for load/attach failures, emits to
// kmsg) so the operator sees what happened — with one deliberate
// exception: a fresh attempt deferred by activation backoff returns
// errActivationBackoff silently, because the failure that armed the
// backoff already logged once.
//
// The fresh path is what makes "enabled = true" survive a reboot:
// bpffs is RAM-only, so on every boot the daemon comes up to find
// no pins, runs the same load+attach+pin work `cfm lsm enable` would
// have done, and resumes protection without operator intervention.
func (l *Lifecycle) openOrCreateLoader(conf *Conf) (loader *Loader, fresh bool, err error) {
	pinned := InspectPinned(DefaultPinDir)
	if pinned.Exists && len(pinned.Links) > 0 {
		// Version-marker gate: compare the build that stamped the pins
		// against this binary. Mismatch (or absent marker on a host
		// that pinned with an older marker-unaware build) → tear down
		// and fall through to the fresh path so the new BPF gets
		// loaded. Preflight inside the fresh path is the safety net:
		// if it FAILs (kernel mismatch, missing BTF), the fresh path
		// returns an error and the host is left without LSM coverage
		// — that's the documented trade-off and matches what the
		// operator would see if they ran `cfm lsm restart` by hand.
		pinnedBuild, present, rerr := ReadBuildMarker(DefaultBuildVersionMarker)
		if rerr != nil {
			logging.LogfLSM("[lsm] startup version check: marker at %s unreadable (%v); treating as stale and refreshing",
				DefaultBuildVersionMarker, rerr)
		}
		switch {
		case !present:
			logging.LogfLSM("[lsm] startup version check: no marker at %s — pinned BPF was loaded by a pre-marker build; refreshing to running=%q",
				DefaultBuildVersionMarker, l.build.String())
		case !pinnedBuild.Equal(l.build):
			logging.LogfLSM("[lsm] startup version check: pinned=%q running=%q — build changed since pins were created; refreshing",
				pinnedBuild.String(), l.build.String())
		default:
			logging.LogfLSM("[lsm] startup version check: pinned=%q matches running build; adopting existing pins",
				pinnedBuild.String())
			lr, err := AdoptPinned(DefaultPinDir, LoaderOptions{EventBufferSize: 1024})
			if err != nil {
				logging.LogfLSM("[lsm] adopt pinned state at %s failed: %v", DefaultPinDir, err)
				KmsgStatef("ISSUE", "adopt pinned state at %s failed: %v", DefaultPinDir, err)
				return nil, false, err
			}
			// Healthy adopt clears any fresh-path backoff so a later
			// pin loss re-enters the fresh path without an inherited wait.
			l.resetActivationBackoff()
			return lr, false, nil
		}
		// Stale pin → unpin so the fresh path below has a clean slate.
		// UnpinAll is best-effort; if it leaves residue the fresh path
		// will likely fail to attach (EBUSY on link create) and log a
		// loud error rather than silently load nothing.
		if uerr := UnpinAll(DefaultPinDir); uerr != nil {
			logging.LogfLSM("[lsm] refresh: failed to remove stale pins at %s: %v (continuing — fresh attach may fail)",
				DefaultPinDir, uerr)
			KmsgStatef("ISSUE", "refresh: stale pin removal failed: %v", uerr)
		} else {
			logging.LogfLSM("[lsm] refresh: stale pins removed at %s; entering fresh-enable path", DefaultPinDir)
		}
	}

	// Fresh auto-enable path. Gate repeated attempts behind exponential
	// backoff: a kernel that will never load our BPF (e.g. CloudLinux 8
	// lve, which passes bpf-lsm-program-type but lacks task-local
	// storage maps) would otherwise re-run preflight + NewLoader and log
	// on every reload tick. The adopt branch above is deliberately
	// outside this gate, so a CLI `cfm lsm enable` is still adopted next
	// tick. Deferred attempts return errActivationBackoff, which
	// ApplyConfig handles like any dormant outcome — silently.
	now := lsmActivationClock()
	if !l.freshActivationDue(now) {
		return nil, false, errActivationBackoff
	}

	// No pinned state — auto-enable. Run preflight first; if it
	// fails (kernel too old, CONFIG_BPF_LSM not set, `bpf` not in
	// /sys/kernel/security/lsm, BTF missing, task-local storage maps
	// unsupported, caps missing, bpffs not mounted) we stay dormant and
	// the daemon continues normally. `cfm lsm status` reports the
	// failing checks.
	pf := RunPreflight()
	if !pf.OK {
		// Escalate the backoff only on a PERMANENT FAIL (a kernel/config
		// problem that won't clear without a reboot — e.g. task-storage
		// unsupported). A recoverable FAIL (bpffs mounting late at boot)
		// or an inconclusive UNKNOWN (a briefly-unreadable /proc file)
		// may heal on its own, so retry it on a short fixed interval
		// rather than marching a genuinely-supported host toward the
		// 30-minute cap. HasPermanentFail encodes that distinction.
		if pf.HasPermanentFail() {
			l.noteFreshActivationFailure(now)
		} else {
			l.armTransientRetry(now)
		}
		logging.LogfLSM("[lsm] auto-enable skipped: kernel preflight not satisfied (run `cfm lsm status` for details); next retry in %s", l.activationBackoff)
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
		l.noteFreshActivationFailure(now)
		logging.LogfLSM("[lsm] auto-enable skipped: no configured policies are available on this kernel; next retry in %s", l.activationBackoff)
		return nil, false, errors.New("no configured policies available")
	}

	lr, lerr := NewLoader(LoaderOptions{
		EventBufferSize:       1024,
		Policies:              policies,
		Modes:                 modes,
		FS005WebOriginMonitor: conf.FS005WebOriginMonitor,
		PinDir:                DefaultPinDir,
	})
	if lerr != nil {
		l.noteFreshActivationFailure(now)
		logging.LogfLSM("[lsm] auto-enable failed: %v (next retry in %s)", lerr, l.activationBackoff)
		KmsgStatef("ISSUE", "auto-enable failed: %v", lerr)
		// Try to clean up any partial pin state so the next reload
		// tick starts from scratch rather than half-pinned.
		_ = UnpinAll(DefaultPinDir)
		return nil, false, lerr
	}
	// Stamp the marker so the NEXT daemon start can detect a stale
	// pin after a package upgrade. Best-effort — a write failure here
	// just means the next start treats the pin as marker-absent and
	// refreshes once (harmless, idempotent).
	if werr := WriteBuildMarker(DefaultBuildVersionMarker, l.build); werr != nil {
		logging.LogfLSM("[lsm] version marker write failed at %s: %v (continuing — next start will refresh once)",
			DefaultBuildVersionMarker, werr)
	} else {
		logging.LogfLSM("[lsm] version marker stamped: %q at %s",
			l.build.String(), DefaultBuildVersionMarker)
	}
	l.resetActivationBackoff()
	return lr, true, nil
}

// freshActivationDue reports whether the fresh auto-enable path may run
// at time now. Called with l.mu held.
func (l *Lifecycle) freshActivationDue(now time.Time) bool {
	return !now.Before(l.nextActivationAttempt)
}

// noteFreshActivationFailure grows the fresh-path backoff after a failed
// auto-enable attempt and arms the next-attempt gate. The first failure
// waits activationBackoffInitial; each subsequent failure doubles the
// wait up to activationBackoffMax. Called with l.mu held.
func (l *Lifecycle) noteFreshActivationFailure(now time.Time) {
	switch {
	case l.activationBackoff <= 0:
		l.activationBackoff = activationBackoffInitial
	default:
		l.activationBackoff *= 2
		if l.activationBackoff > activationBackoffMax {
			l.activationBackoff = activationBackoffMax
		}
	}
	l.nextActivationAttempt = now.Add(l.activationBackoff)
}

// armTransientRetry arms a short retry after a recoverable-FAIL or
// inconclusive-UNKNOWN preflight result. It neither escalates the
// backoff (a transient condition should heal soon, not push a
// genuinely-supported host toward activationBackoffMax) nor SHORTENS an
// escalation already accumulated from prior permanent-fail / load
// failures (a transient blip mid-escalation must not reset spam
// suppression and let doomed attempts resume at the 1-minute floor).
// It therefore arms the next attempt at the larger of the fixed floor
// and the current backoff. Called with l.mu held.
func (l *Lifecycle) armTransientRetry(now time.Time) {
	wait := activationBackoffInitial
	if l.activationBackoff > wait {
		wait = l.activationBackoff
	}
	l.activationBackoff = wait
	l.nextActivationAttempt = now.Add(wait)
}

// resetActivationBackoff clears the fresh-path backoff after a
// successful activation. Called with l.mu held.
func (l *Lifecycle) resetActivationBackoff() {
	l.activationBackoff = 0
	l.nextActivationAttempt = time.Time{}
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

// webOriginPolicy reports whether a policy stamps the web-origin flag
// (bit 0) with "this task started under, or is running as, a watched
// web/panel uid" semantics — i.e. whether an `origin=web` tag is
// meaningful for it. Single source of truth consulted by emitNotify and
// KmsgDetect (kmsg.go); keeping it here avoids the divergent inline OR
// lists that previously had to be edited in lockstep across sinks.
func webOriginPolicy(id PolicyID) bool {
	switch id {
	case PolicySensitiveWrite, PolicyUnexpectedBPF, PolicyKernelModuleLoad,
		PolicyKernelKnobWrite, PolicyKexecLoad, PolicyPtraceAccess,
		PolicyRawSocket, PolicyCapRaise:
		return true
	}
	return false
}

// originTag returns " origin=web" for a web-origin-flagged event on a
// web-origin policy, else "". Single origin-check consulted by both the
// per-event and the caller-stable reason builders.
func originTag(ev Event) string {
	if webOriginPolicy(ev.PolicyID) && ev.Flags&EventFlagWebOrigin != 0 {
		return " origin=web"
	}
	return ""
}

// eventCallerTags renders the per-event behaviour tags (origin / stdio /
// primitive / ptrace mode+sameuid / cap-raise). Some of these vary per
// target within one caller's burst — ptrace mode and sameuid especially
// (a sweep touches same-uid AND cross-uid targets) — so this belongs in
// the per-event log line and samples, NOT in the collapsed notify reason.
func eventCallerTags(ev Event) string {
	var b strings.Builder
	b.WriteString(originTag(ev))
	if signal := ev.ExecStdioSignal(); signal != "" {
		b.WriteString(" stdio=" + signal)
	}
	if prim := ev.PrivInstallPrimitive(); prim != "" {
		b.WriteString(" primitive=" + prim)
	}
	if mode := ev.PtraceMode(); mode != "" {
		b.WriteString(" ptrace=" + mode)
		if ev.PtraceSameUid() {
			b.WriteString(" sameuid=1")
		}
	}
	if sets := ev.CapRaiseSets(); sets != "" {
		b.WriteString(" cap_raise=" + sets)
	}
	return b.String()
}

// eventDetailTail is the full per-event tail (target path/op plus the
// caller tags) shared by the cfm.log line and the notify sample line.
func eventDetailTail(ev Event) string {
	var b strings.Builder
	if ev.Filename != "" {
		b.WriteString(" path=" + ev.Filename)
	}
	// OBS-004 ptrace target identity (per-target — kept out of the
	// collapsed dedup key, which uses eventCallerTags).
	if tpid, tuid, ok := ev.PtraceTarget(); ok {
		fmt.Fprintf(&b, " target_pid=%d target_uid=%d", tpid, tuid)
	}
	if ev.Op != FSOpNone {
		b.WriteString(" op=" + ev.Op.String())
	}
	b.WriteString(eventCallerTags(ev))
	return b.String()
}

// collapsesToCallerIdentity reports whether a policy's events should use
// a caller-identity-stable notify reason so one caller's /proc sweep
// becomes a SINGLE email (the notify deduper keys on Reason) instead of
// one per target. Only the introspection-sweep policy needs this today:
// CFML-OBS-004 fires once per (caller,target) pair as pgrep-style tools
// walk /proc, dozens of events per second from one caller. Discrete-
// action policies (FS-005 write, CRED-002 escalation, EXEC-*) keep the
// full per-event reason so distinct targets remain distinct emails and
// the notify JSONL audit keeps the target/pid. Add a policy here only
// after confirming its events are genuinely a per-caller sweep.
func collapsesToCallerIdentity(id PolicyID) bool {
	return id == PolicyPtraceAccess
}

// stripCtl replaces control characters (newlines, CR, etc.) with '?' so
// an attacker-chosen exe path / cwd / comm — all of which may legally
// contain any byte but NUL and '/' — cannot forge a cfm.log line or
// break the email body. cmdline is already strconv.Quote'd upstream; this
// is the belt-and-braces pass over the fully composed line.
func stripCtl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// composeReasons builds the three strings emitNotify hands to the sink:
//
//   - logReason: full per-event forensic line for cfm.log (caller + this
//     specific target + enrichment: snapshot, swarm summary, captured
//     paths).
//   - notifyReason: the notify (email) dedup key. For a sweep-class policy
//     it is caller-identity-stable (title + uid + comm + identity, no pid
//     and no per-target/relationship tags) so the whole burst collapses to
//     one email; uid is always present so distinct accounts stay distinct
//     even with enrichment off. For discrete-action policies it keeps the
//     full per-event reason (distinct targets → distinct emails, JSONL
//     keeps the target).
//   - samples: per-event target detail + the multi-line swarm roster +
//     captured-binary references, for the email body.
//
// All three are stripCtl'd because they embed attacker-controlled fields.
func composeReasons(ev Event, enr eventEnrichment) (logReason, notifyReason string, samples []string) {
	p, _ := PolicyByID(ev.PolicyID)
	title := string(ev.PolicyID)
	if p.Title != "" {
		title = p.Title
	}
	detail := eventDetailTail(ev)

	base := fmt.Sprintf("%s: pid=%d (%s) policy=%s%s", title, ev.PID, ev.Comm, ev.PolicyID, detail)
	logReason = stripCtl(base + enr.logSuffix())

	if collapsesToCallerIdentity(ev.PolicyID) {
		// Caller-identity-stable: exclude pid and the per-target
		// relationship tags (ptrace mode / sameuid) that vary across a
		// sweep. uid keeps distinct accounts distinct even when
		// enrichment (and thus identitySuffix) is off.
		notifyReason = stripCtl(fmt.Sprintf("%s: uid=%d comm=%s policy=%s%s%s",
			title, ev.UID, ev.Comm, ev.PolicyID, originTag(ev), enr.identitySuffix()))
	} else {
		notifyReason = stripCtl(base + enr.identitySuffix())
	}

	samples = []string{stripCtl(fmt.Sprintf("pid=%d comm=%s%s", ev.PID, ev.Comm, detail))}
	for _, s := range enr.samples() {
		samples = append(samples, stripCtl(s))
	}
	return
}

// buildExtra assembles the structured Extra map (notify JSONL audit +
// downstream consumers) for an event.
func buildExtra(ev Event, enr eventEnrichment) map[string]string {
	p, _ := PolicyByID(ev.PolicyID)
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
	if originTag(ev) != "" {
		extra["origin"] = "web"
	}
	if signal := ev.ExecStdioSignal(); signal != "" {
		extra["stdio_signal"] = signal
	}
	if prim := ev.PrivInstallPrimitive(); prim != "" {
		extra["primitive"] = prim
	}
	if mode := ev.PtraceMode(); mode != "" {
		extra["ptrace_mode"] = mode
		if ev.PtraceSameUid() {
			extra["ptrace_sameuid"] = "1"
		}
	}
	if tpid, tuid, ok := ev.PtraceTarget(); ok {
		extra["target_pid"] = strconv.FormatUint(uint64(tpid), 10)
		extra["target_uid"] = strconv.FormatUint(uint64(tuid), 10)
	}
	if sets := ev.CapRaiseSets(); sets != "" {
		extra["cap_raise_sets"] = sets
	}
	enr.addExtra(extra)
	return extra
}

// emitNotify converts an Event into a notify.Event and dispatches via the
// existing CFM notify pipeline. The rate decision is made FIRST so a
// rate-dropped event skips the expensive /proc enrichment entirely (the
// cap bounds a flood's work, not just its output). kmsg has its own
// independent cap.
func emitNotify(ev Event) {
	KmsgDetect(ev)

	allow, summary := admitDetect(ev.PolicyID)
	if summary != "" {
		emitDetectSummary(summary)
	}
	if !allow {
		return
	}

	// Gather the caller's /proc context — the caller may be short-lived
	// (an OBS-004 sweep's pgrep, an EXEC-006 dropper) and racing its own
	// exit, so this snapshots identity, the uid swarm roster, and
	// preserves any suspicious binary before it can be unlinked. Cached so
	// a burst does the work once; a no-op when enrichment is disabled.
	enr := gatherEnrichment(ev.PID, ev.UID, ev.PPid, eventSinkEnrichCfg(), time.Now())
	logReason, notifyReason, samples := composeReasons(ev, enr)
	emitDetect(logReason, notifyReason, buildExtra(ev, enr), samples)
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
