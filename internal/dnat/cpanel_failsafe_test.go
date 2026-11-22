package dnat

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPanelDNATFailSafeTargetCleanupWiring(t *testing.T) {
	origOff := panelOffFn
	defer func() { panelOffFn = origOff }()

	setPanelFirewallHealth("OK", "", false)
	panelFailSafeMu.Lock()
	panelFailSafe = panelFailSafeState{}
	panelFailSafeMu.Unlock()

	called := 0
	var gotAutoRemove bool
	panelOffFn = func(autoRemoveAllowlist bool) (panelOffResult, error) {
		called++
		gotAutoRemove = autoRemoveAllowlist
		return panelOffResult{}, nil
	}
	t.Setenv("CFM_PANEL_FAILSAFE_AUTO_REMOVE_ALLOWLIST", "false")

	target := newPanelDNATFailSafeTarget(nil)
	target.Cleanup(4, errors.New("panel down"))

	if called != 1 {
		t.Fatalf("expected shared panel off action once, got %d", called)
	}
	if gotAutoRemove {
		t.Fatalf("expected auto-remove allowlist=false")
	}
	health := getPanelFirewallHealth()
	if health.State != "AUTO_FAILSAFE" || !health.Attempted || !strings.Contains(health.LastReason, "auto-disabled after 4 consecutive probe failures: panel down") || !strings.Contains(health.LastReason, "allowlist removal skipped") {
		t.Fatalf("unexpected health update: %+v", health)
	}
	state := getPanelFailSafeState()
	if state.LastActionAt.IsZero() || !strings.Contains(state.LastActionReason, "panel down") {
		t.Fatalf("expected panel failsafe action state to be updated, got %+v", state)
	}
}

func TestPanelDNATFailSafeTargetReportsAllowlistRemoval(t *testing.T) {
	origOff := panelOffFn
	defer func() { panelOffFn = origOff }()

	panelFailSafeMu.Lock()
	panelFailSafe = panelFailSafeState{}
	panelFailSafeMu.Unlock()

	panelOffFn = func(autoRemoveAllowlist bool) (panelOffResult, error) {
		if !autoRemoveAllowlist {
			t.Fatalf("expected auto-remove allowlist=true")
		}
		return panelOffResult{FirewallChanges: []string{"tcp/12083 removed", "tcp/12087 removed"}}, nil
	}
	t.Setenv("CFM_PANEL_FAILSAFE_AUTO_REMOVE_ALLOWLIST", "true")

	target := newPanelDNATFailSafeTarget(nil)
	target.Cleanup(3, errors.New("panel probe failed"))

	health := getPanelFirewallHealth()
	if health.State != "AUTO_FAILSAFE" || !strings.Contains(health.LastReason, "allowlist removed: tcp/12083 removed, tcp/12087 removed") {
		t.Fatalf("unexpected health update: %+v", health)
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

// A failsafe off that could not remove the redirect says so: FAILED health
// and an ON transition, never AUTO_FAILSAFE / OFF while the panel DNAT is
// still live (that told the operator it was auto-disabled when it was not).
func TestPanelDNATFailSafeCleanupFailedOffIsNotAnOff(t *testing.T) {
	origOff := panelOffFn
	defer func() { panelOffFn = origOff }()
	setPanelFirewallHealth("OK", "", false)
	panelOffFn = func(bool) (panelOffResult, error) {
		return panelOffResult{}, errors.New("removing the panel DNAT redirect: nft busy")
	}
	target := newPanelDNATFailSafeTarget(nil)
	target.Cleanup(3, errors.New("panel down"))

	health := getPanelFirewallHealth()
	if health.State != "FAILED" || !strings.Contains(health.LastReason, "still on") || !strings.Contains(health.LastReason, "nft busy") {
		t.Fatalf("health = %+v, want FAILED naming the live redirect and the error", health)
	}
	if lt := GetLastTransition(ScopeCPanel); lt.State != "ON" || lt.Action != "failsafe-off-failed" {
		t.Fatalf("last transition = %+v, want state=ON action=failsafe-off-failed", lt)
	}
}
