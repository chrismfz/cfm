package dnat

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPanelFailSafeOnHealthyNoAction(t *testing.T) {
	origStatus, origProbe, origOff := panelStatusFn, panelProbeFn, panelOffFn
	defer func() { panelStatusFn, panelProbeFn, panelOffFn = origStatus, origProbe, origOff }()
	panelStatusFn = func() (bool, string, error) { return true, "", nil }
	panelProbeFn = func(time.Duration) error { return nil }
	disabled := 0
	panelOffFn = func() (panelOffResult, error) { disabled++; return panelOffResult{}, nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv("CFM_PANEL_FAILSAFE_INTERVAL_MS", "10")
	t.Setenv("CFM_PANEL_FAILSAFE_CONSECUTIVE_FAILS", "2")
	StartPanelFailSafe(ctx, nil)
	time.Sleep(60 * time.Millisecond)
	if disabled != 0 {
		t.Fatalf("unexpected disable action")
	}
}

func TestPanelFailSafeOnDownThresholdAutoOff(t *testing.T) {
	origStatus, origProbe, origOff := panelStatusFn, panelProbeFn, panelOffFn
	defer func() { panelStatusFn, panelProbeFn, panelOffFn = origStatus, origProbe, origOff }()
	panelStatusFn = func() (bool, string, error) { return true, "", nil }
	panelProbeFn = func(time.Duration) error { return errors.New("down") }
	disabled := 0
	panelOffFn = func() (panelOffResult, error) {
		disabled++
		return panelOffResult{FirewallChanges: []string{"tcp/2083 removed"}}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv("CFM_PANEL_FAILSAFE_INTERVAL_MS", "10")
	t.Setenv("CFM_PANEL_FAILSAFE_CONSECUTIVE_FAILS", "2")
	StartPanelFailSafe(ctx, nil)
	time.Sleep(60 * time.Millisecond)
	if disabled == 0 {
		t.Fatalf("expected disable action")
	}
	health := getPanelFirewallHealth()
	if health.State != "AUTO_FAILSAFE" || !strings.Contains(health.LastReason, "allowlist removed: tcp/2083 removed") {
		t.Fatalf("expected failsafe health reason to include shared cleanup details, got %+v", health)
	}
}

func TestPanelFailSafeOffNoAction(t *testing.T) {
	origStatus, origProbe, origOff := panelStatusFn, panelProbeFn, panelOffFn
	defer func() { panelStatusFn, panelProbeFn, panelOffFn = origStatus, origProbe, origOff }()
	panelStatusFn = func() (bool, string, error) { return false, "", nil }
	probes := 0
	panelProbeFn = func(time.Duration) error { probes++; return errors.New("down") }
	disabled := 0
	panelOffFn = func() (panelOffResult, error) { disabled++; return panelOffResult{}, nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv("CFM_PANEL_FAILSAFE_INTERVAL_MS", "10")
	t.Setenv("CFM_PANEL_FAILSAFE_CONSECUTIVE_FAILS", "2")
	StartPanelFailSafe(ctx, nil)
	time.Sleep(60 * time.Millisecond)
	if disabled != 0 {
		t.Fatalf("unexpected disable action")
	}
	if probes != 0 {
		t.Fatalf("probe should not run when table is off")
	}
}

func TestProbePanelTargetsBoundedDurationWithMixedSpeeds(t *testing.T) {
	origPorts, origDial := panelProbePorts, panelProbeDialContextFn
	defer func() { panelProbePorts, panelProbeDialContextFn = origPorts, origDial }()

	panelProbePorts = []int{1, 2, 3}
	panelProbeDialContextFn = func(ctx context.Context, _, address string) (net.Conn, error) {
		switch {
		case strings.HasSuffix(address, ":1"):
			time.Sleep(10 * time.Millisecond)
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		case strings.HasSuffix(address, ":2"):
			<-ctx.Done()
			return nil, ctx.Err()
		default:
			time.Sleep(5 * time.Millisecond)
			return nil, errors.New("connection refused")
		}
	}

	timeout := 40 * time.Millisecond
	start := time.Now()
	err := probePanelTargets(timeout)
	dur := time.Since(start)

	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), ":2") || !strings.Contains(err.Error(), ":3") {
		t.Fatalf("expected summarized failure to include failed ports, got: %v", err)
	}
	if dur > timeout+30*time.Millisecond {
		t.Fatalf("expected bounded runtime <= %v (+slack), got %v", timeout, dur)
	}
}

func TestProbePanelTargetsAllSuccess(t *testing.T) {
	origPorts, origDial := panelProbePorts, panelProbeDialContextFn
	defer func() { panelProbePorts, panelProbeDialContextFn = origPorts, origDial }()

	panelProbePorts = []int{1, 2}
	panelProbeDialContextFn = func(context.Context, string, string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}

	if err := probePanelTargets(20 * time.Millisecond); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
