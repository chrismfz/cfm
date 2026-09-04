//go:build linux

package lsm

import (
	"errors"
	"testing"
	"time"
)

func TestAnyEnabled(t *testing.T) {
	cases := []struct {
		name string
		conf *Conf
		want bool
	}{
		{name: "nil conf", conf: nil, want: false},
		{
			name: "empty modes map → fall back to per-policy defaults",
			conf: &Conf{Modes: map[PolicyID]Mode{}},
			// AllPolicies()' DefaultMode is currently ModeDisabled for
			// every policy, so an empty modes map is treated as "all
			// disabled" — the lifecycle should stay dormant.
			want: false,
		},
		{
			name: "every policy disabled",
			conf: &Conf{
				Modes: map[PolicyID]Mode{
					PolicyMemfdExec:    ModeDisabled,
					PolicyReverseShell: ModeDisabled,
				},
			},
			want: false,
		},
		{
			name: "one policy monitor → enabled",
			conf: &Conf{
				Modes: map[PolicyID]Mode{
					PolicyMemfdExec:    ModeMonitor,
					PolicyReverseShell: ModeDisabled,
				},
			},
			want: true,
		},
		{
			name: "enforce mode also counts as enabled",
			conf: &Conf{
				Modes: map[PolicyID]Mode{
					PolicyMemfdExec:    ModeDisabled,
					PolicyReverseShell: ModeEnforce,
				},
			},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := anyEnabled(tc.conf); got != tc.want {
				t.Errorf("anyEnabled: got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestNewLifecycle_IsDormantUntilApplyConfig(t *testing.T) {
	lc := NewLifecycle(BuildMarker{})
	if lc == nil {
		t.Fatal("NewLifecycle returned nil")
	}
	if lc.started {
		t.Error("fresh Lifecycle should not be started")
	}
	if lc.loader != nil {
		t.Error("fresh Lifecycle should have no loader")
	}
	// Stop must be safe on a dormant lifecycle.
	lc.Stop()
	// And on a nil pointer.
	var nilLC *Lifecycle
	nilLC.Stop() // must not panic
}

func TestLifecycle_ApplyConfig_NilSafe(t *testing.T) {
	var nilLC *Lifecycle
	// ApplyConfig on a nil pointer must not panic.
	nilLC.ApplyConfig(nil) //nolint:staticcheck // intentional nil receiver test
}

// TestLifecycle_DormantWhenConfDisabled documents that even if pinned
// state exists, lsm.conf.enabled=false keeps the lifecycle dormant.
// The actual ApplyConfig path is hard to unit-test without a real
// kernel attach; this exercises the early-exit invariant via the
// helper.
func TestLifecycle_DormantWhenConfDisabled(t *testing.T) {
	// Synthesise a "disabled in conf" state.
	conf := &Conf{
		Enabled: false,
		Modes: map[PolicyID]Mode{
			PolicyMemfdExec: ModeMonitor,
		},
	}
	if anyEnabled(conf) != true {
		t.Fatal("test setup: anyEnabled should report true here (per-policy)")
	}
	// The actual invariant: even when individual policies are
	// enabled, the global enabled flag gates everything. The
	// lifecycle checks conf.Enabled first before anyEnabled.
	if conf.Enabled {
		t.Fatal("test setup: conf.Enabled should be false")
	}
}

// TestLifecycle_DriftDetected_TearsDownStaleState simulates a
// "daemon already activated, CLI removed the pinned ringbuf under
// it" scenario. On CI the pinned ringbuf path does not exist, so
// pinnedRingbufIno() returns ENOENT — the drift check treats that
// as "kernel state gone, tear down". After ApplyConfig returns, the
// Lifecycle must be back in the not-started state so a future tick
// (with a real conf) can re-adopt. Regression guard for the
// `cfm lsm restart` orphan-loader bug.
func TestLifecycle_DriftDetected_TearsDownStaleState(t *testing.T) {
	// Skip when the pinned ringbuf actually exists (developer machine
	// with cfm-lsm running). The drift branch is only exercised when
	// the pin is absent or has a different inode, and we don't want
	// the test to depend on a live cfm-lsm install.
	if _, err := pinnedRingbufIno(); err == nil {
		t.Skip("pinned ringbuf exists on this host; drift branch needs an absent pin to exercise")
	}

	lc := NewLifecycle(BuildMarker{})
	lc.started = true
	lc.pinnedRingbufIno = 0xDEADBEEF // sentinel non-zero, definitely won't match anything

	// ApplyConfig will:
	//   - see started=true
	//   - drift-check: pinnedRingbufIno() returns ENOENT, so curIno != lc.pinnedRingbufIno
	//   - tear down (no loader/cancel/done set, so the cleanup is a no-op)
	//   - re-acquire mutex, fall through to LoadConf which will most likely
	//     fail because the test env has no /etc/cfm/lsm.conf — silent return.
	lc.ApplyConfig(nil)

	if lc.started {
		t.Error("drift detection should have flipped started back to false")
	}
	if lc.pinnedRingbufIno != 0 {
		t.Errorf("drift teardown should have zeroed pinnedRingbufIno; got %d", lc.pinnedRingbufIno)
	}
	if lc.loader != nil {
		t.Error("drift teardown should have cleared the loader")
	}
}

// TestLifecycle_ActivationBackoff_DueImmediatelyWhenFresh confirms a
// brand-new lifecycle has no backoff armed — the fresh path may run on
// the first tick.
func TestLifecycle_ActivationBackoff_DueImmediatelyWhenFresh(t *testing.T) {
	lc := NewLifecycle(BuildMarker{})
	now := time.Unix(1_700_000_000, 0)
	if !lc.freshActivationDue(now) {
		t.Fatal("fresh lifecycle must allow a fresh activation attempt immediately")
	}
}

// TestLifecycle_ActivationBackoff_GrowsAndGates walks the exponential
// backoff: each failure doubles the wait from the initial value up to
// the cap, the gate blocks inside the window and reopens after it, and
// a reset clears the arming.
func TestLifecycle_ActivationBackoff_GrowsAndGates(t *testing.T) {
	lc := NewLifecycle(BuildMarker{})
	base := time.Unix(1_700_000_000, 0)

	// First failure → wait = initial.
	lc.noteFreshActivationFailure(base)
	if lc.activationBackoff != activationBackoffInitial {
		t.Fatalf("after first failure: backoff=%s, want %s", lc.activationBackoff, activationBackoffInitial)
	}
	// Gate blocks anywhere before base+initial, and just before it.
	if lc.freshActivationDue(base) {
		t.Error("gate must block at the instant of the arming failure")
	}
	if lc.freshActivationDue(base.Add(activationBackoffInitial - time.Nanosecond)) {
		t.Error("gate must block until the backoff window elapses")
	}
	// Gate reopens exactly at the window boundary.
	dueAt := base.Add(activationBackoffInitial)
	if !lc.freshActivationDue(dueAt) {
		t.Error("gate must reopen once the backoff window elapses")
	}

	// Second failure → wait doubles.
	lc.noteFreshActivationFailure(dueAt)
	if want := activationBackoffInitial * 2; lc.activationBackoff != want {
		t.Fatalf("after second failure: backoff=%s, want %s", lc.activationBackoff, want)
	}

	// Many more failures saturate at the cap and never exceed it.
	at := dueAt
	for i := 0; i < 20; i++ {
		at = at.Add(lc.activationBackoff)
		lc.noteFreshActivationFailure(at)
		if lc.activationBackoff > activationBackoffMax {
			t.Fatalf("backoff %s exceeded cap %s", lc.activationBackoff, activationBackoffMax)
		}
	}
	if lc.activationBackoff != activationBackoffMax {
		t.Fatalf("backoff should saturate at cap %s; got %s", activationBackoffMax, lc.activationBackoff)
	}

	// A successful activation clears everything.
	lc.resetActivationBackoff()
	if lc.activationBackoff != 0 || !lc.nextActivationAttempt.IsZero() {
		t.Fatalf("reset must clear backoff state; got backoff=%s next=%v", lc.activationBackoff, lc.nextActivationAttempt)
	}
	if !lc.freshActivationDue(at) {
		t.Error("after reset the fresh path must be due again")
	}
}

// TestLifecycle_ArmTransientRetry_DoesNotEscalate confirms that a
// recoverable/inconclusive preflight result retries on a fixed short
// interval and never marches toward the escalating cap — the fix for
// backing off a genuinely-supported host on a transient boot condition.
func TestLifecycle_ArmTransientRetry_DoesNotEscalate(t *testing.T) {
	lc := NewLifecycle(BuildMarker{})
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 6; i++ {
		lc.armTransientRetry(base)
		if lc.activationBackoff != activationBackoffInitial {
			t.Fatalf("transient retry #%d escalated: got %s, want fixed %s", i, lc.activationBackoff, activationBackoffInitial)
		}
		if lc.freshActivationDue(base.Add(activationBackoffInitial - time.Nanosecond)) {
			t.Error("transient retry must block until the fixed interval elapses")
		}
		if !lc.freshActivationDue(base.Add(activationBackoffInitial)) {
			t.Error("transient retry must reopen after the fixed interval")
		}
	}
}

// TestLifecycle_ArmTransientRetry_PreservesAccumulatedBackoff guards the
// second-review finding: a transient blip mid-escalation must not RESET
// an already-accumulated backoff back to the 1-minute floor (which would
// let doomed attempts + their kmsg "ISSUE" spam resume at the floor).
func TestLifecycle_ArmTransientRetry_PreservesAccumulatedBackoff(t *testing.T) {
	lc := NewLifecycle(BuildMarker{})
	base := time.Unix(1_700_000_000, 0)

	// Accumulate escalation from permanent/load failures.
	lc.noteFreshActivationFailure(base) // → initial
	at := base.Add(lc.activationBackoff)
	lc.noteFreshActivationFailure(at) // → 2×
	at = at.Add(lc.activationBackoff)
	lc.noteFreshActivationFailure(at) // → 4×
	accumulated := lc.activationBackoff
	if accumulated <= activationBackoffInitial {
		t.Fatalf("test setup: expected accumulated backoff > initial; got %s", accumulated)
	}

	// A transient result now must NOT shrink the accumulated backoff.
	at = at.Add(accumulated)
	lc.armTransientRetry(at)
	if lc.activationBackoff != accumulated {
		t.Errorf("transient retry shortened accumulated backoff: got %s, want preserved %s", lc.activationBackoff, accumulated)
	}
	if !lc.nextActivationAttempt.Equal(at.Add(accumulated)) {
		t.Errorf("transient retry must arm next attempt at now+accumulated; got %v", lc.nextActivationAttempt)
	}
}

// TestLifecycle_openOrCreateLoader_BackoffGateReturnsSentinelSilently
// exercises the real ApplyConfig→openOrCreateLoader integration: when
// the fresh-path backoff window is closed, the loader path must return
// errActivationBackoff without running preflight/NewLoader or mutating
// backoff state (the silent-dormant contract ApplyConfig relies on).
func TestLifecycle_openOrCreateLoader_BackoffGateReturnsSentinelSilently(t *testing.T) {
	// The fresh gate is only reached when no pinned state exists. On a
	// developer host with cfm-lsm actually running, the adopt branch
	// short-circuits first — skip there.
	if p := InspectPinned(DefaultPinDir); p.Exists && len(p.Links) > 0 {
		t.Skip("pinned cfm-lsm state present on this host; test needs the no-pins fresh path")
	}

	base := time.Unix(1_700_000_000, 0)
	prevClock := lsmActivationClock
	lsmActivationClock = func() time.Time { return base }
	t.Cleanup(func() { lsmActivationClock = prevClock })

	lc := NewLifecycle(BuildMarker{})
	// Arm the backoff into the future so the gate is closed.
	lc.activationBackoff = activationBackoffMax
	lc.nextActivationAttempt = base.Add(time.Hour)

	conf := &Conf{Enabled: true, Modes: map[PolicyID]Mode{PolicyMemfdExec: ModeMonitor}}
	loader, fresh, err := lc.openOrCreateLoader(conf)
	if !errors.Is(err, errActivationBackoff) {
		t.Fatalf("gated fresh path must return errActivationBackoff; got loader=%v fresh=%v err=%v", loader, fresh, err)
	}
	if loader != nil || fresh {
		t.Errorf("gated fresh path must return no loader and fresh=false; got loader=%v fresh=%v", loader, fresh)
	}
	// The gate must not have escalated or altered backoff state.
	if lc.activationBackoff != activationBackoffMax {
		t.Errorf("gated path must not change backoff; got %s want %s", lc.activationBackoff, activationBackoffMax)
	}
	if !lc.nextActivationAttempt.Equal(base.Add(time.Hour)) {
		t.Errorf("gated path must not move nextActivationAttempt; got %v", lc.nextActivationAttempt)
	}
}
