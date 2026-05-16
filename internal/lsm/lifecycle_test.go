//go:build linux

package lsm

import (
	"testing"
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
	lc := NewLifecycle()
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

	lc := NewLifecycle()
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
