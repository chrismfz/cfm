package dnat

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPanelFailSafeOnHealthyNoAction(t *testing.T) {
	origStatus, origProbe, origDisable := panelStatusFn, panelProbeFn, panelDisableTableFn
	defer func() { panelStatusFn, panelProbeFn, panelDisableTableFn = origStatus, origProbe, origDisable }()
	panelStatusFn = func() (bool, string, error) { return true, "", nil }
	panelProbeFn = func(time.Duration) error { return nil }
	disabled := 0
	panelDisableTableFn = func() error { disabled++; return nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv("CFM_PANEL_FAILSAFE_INTERVAL_MS", "10")
	t.Setenv("CFM_PANEL_FAILSAFE_CONSECUTIVE_FAILS", "2")
	StartPanelFailSafe(ctx, nil)
	time.Sleep(60 * time.Millisecond)
	if disabled != 0 { t.Fatalf("unexpected disable action") }
}

func TestPanelFailSafeOnDownThresholdAutoOff(t *testing.T) {
	origStatus, origProbe, origDisable := panelStatusFn, panelProbeFn, panelDisableTableFn
	defer func() { panelStatusFn, panelProbeFn, panelDisableTableFn = origStatus, origProbe, origDisable }()
	panelStatusFn = func() (bool, string, error) { return true, "", nil }
	panelProbeFn = func(time.Duration) error { return errors.New("down") }
	disabled := 0
	panelDisableTableFn = func() error { disabled++; return nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv("CFM_PANEL_FAILSAFE_INTERVAL_MS", "10")
	t.Setenv("CFM_PANEL_FAILSAFE_CONSECUTIVE_FAILS", "2")
	StartPanelFailSafe(ctx, nil)
	time.Sleep(60 * time.Millisecond)
	if disabled == 0 { t.Fatalf("expected disable action") }
}

func TestPanelFailSafeOffNoAction(t *testing.T) {
	origStatus, origProbe, origDisable := panelStatusFn, panelProbeFn, panelDisableTableFn
	defer func() { panelStatusFn, panelProbeFn, panelDisableTableFn = origStatus, origProbe, origDisable }()
	panelStatusFn = func() (bool, string, error) { return false, "", nil }
	probes := 0
	panelProbeFn = func(time.Duration) error { probes++; return errors.New("down") }
	disabled := 0
	panelDisableTableFn = func() error { disabled++; return nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv("CFM_PANEL_FAILSAFE_INTERVAL_MS", "10")
	t.Setenv("CFM_PANEL_FAILSAFE_CONSECUTIVE_FAILS", "2")
	StartPanelFailSafe(ctx, nil)
	time.Sleep(60 * time.Millisecond)
	if disabled != 0 { t.Fatalf("unexpected disable action") }
	if probes != 0 { t.Fatalf("probe should not run when table is off") }
}
