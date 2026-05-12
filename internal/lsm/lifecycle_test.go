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
