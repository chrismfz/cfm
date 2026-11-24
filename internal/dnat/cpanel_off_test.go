package dnat

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func withPanelOffFakes(t *testing.T) *[]string {
	t.Helper()
	calls := []string{}
	origDelete := panelDeleteRedirectTableFn
	origRemove := panelRemoveAllowlistFn
	origPersist := panelPersistChallengeEnabledFn
	origApply := panelApplyChallengeModeToPathsFn
	origReload := panelReloadPanelListenerServiceFn
	origExec := execCommand
	t.Cleanup(func() {
		panelDeleteRedirectTableFn = origDelete
		panelRemoveAllowlistFn = origRemove
		panelPersistChallengeEnabledFn = origPersist
		panelApplyChallengeModeToPathsFn = origApply
		panelReloadPanelListenerServiceFn = origReload
		execCommand = origExec
	})

	panelDeleteRedirectTableFn = func() error {
		calls = append(calls, "delete table")
		return nil
	}
	panelRemoveAllowlistFn = func() ([]string, error) {
		calls = append(calls, "remove allowlist")
		return []string{"tcp/12083 removed", "tcp/12087 removed"}, nil
	}
	panelPersistChallengeEnabledFn = func(enabled bool) error {
		if enabled {
			t.Fatalf("expected persisted challenge=false")
		}
		calls = append(calls, "persist off")
		return nil
	}
	panelApplyChallengeModeToPathsFn = func(mode string, paths []string) error {
		if mode != "off" {
			t.Fatalf("mode=%q want off", mode)
		}
		if !reflect.DeepEqual(paths, panelListenerChallengeConfigPaths) {
			t.Fatalf("paths=%v want %v", paths, panelListenerChallengeConfigPaths)
		}
		calls = append(calls, "apply off")
		return nil
	}
	panelReloadPanelListenerServiceFn = func() error {
		calls = append(calls, "reload listener")
		return nil
	}
	// Keep unrelated mode auto-detection commands deterministic when runPanelCLI parses args.
	execCommand = func(string, ...string) *exec.Cmd { return exec.Command("sh", "-c", "exit 1") }
	return &calls
}

func TestPanelOffPerformsFullCleanup(t *testing.T) {
	calls := withPanelOffFakes(t)
	setPanelFirewallHealth("PARTIAL", "previous failure", true)

	changes, err := panelOff()
	if err != nil {
		t.Fatalf("panelOff returned error: %v", err)
	}
	wantCalls := []string{"delete table", "remove allowlist", "persist off", "apply off", "reload listener"}
	if !reflect.DeepEqual(*calls, wantCalls) {
		t.Fatalf("calls=%v want %v", *calls, wantCalls)
	}
	wantChanges := []string{"tcp/12083 removed", "tcp/12087 removed"}
	if !reflect.DeepEqual(changes, wantChanges) {
		t.Fatalf("changes=%v want %v", changes, wantChanges)
	}
	health := getPanelFirewallHealth()
	if health.State != "OK" || health.LastReason != "" || !health.Attempted {
		t.Fatalf("unexpected health after off: %+v", health)
	}
}

// A redirect that could not be removed stops the off: no allowlist removal
// under a live redirect (it would drop the panel traffic it still sends to the
// edge), no persisted OFF, and an error the CLI's exit code carries (it used
// to be dropped: `cfm edge panel off` returned 0 with the redirect in place).
func TestPanelOffStopsWhenTheRedirectStays(t *testing.T) {
	calls := withPanelOffFakes(t)
	setPanelFirewallHealth("OK", "", true)
	panelDeleteRedirectTableFn = func() error {
		*calls = append(*calls, "delete table")
		return errors.New("nft: Device or resource busy")
	}
	if _, err := panelOff(); err == nil || !strings.Contains(err.Error(), "resource busy") {
		t.Fatalf("panelOff() err = %v, want the delete's error", err)
	}
	if want := []string{"delete table"}; !reflect.DeepEqual(*calls, want) {
		t.Fatalf("calls=%v want %v (nothing after a failed delete)", *calls, want)
	}
	if h := getPanelFirewallHealth(); h.State != "FAILED" || !strings.Contains(h.LastReason, "resource busy") {
		t.Fatalf("health = %+v, want FAILED with the reason", h)
	}

	*calls = (*calls)[:0]
	if _, err := panelOffPreserveIntent(true); err == nil {
		t.Fatalf("panelOffPreserveIntent: want the delete's error")
	}
	if want := []string{"delete table"}; !reflect.DeepEqual(*calls, want) {
		t.Fatalf("failsafe off: calls=%v want %v", *calls, want)
	}
}

func TestPanelCLIOffUsesSharedCleanupOutput(t *testing.T) {
	calls := withPanelOffFakes(t)
	setPanelFirewallHealth("OK", "", true)

	out, errOut := captureStreams(t, func() {
		code := runPanelCLI([]string{"off"}, nil)
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
	})

	if errOut != "" {
		t.Fatalf("unexpected stderr: %s", errOut)
	}
	for _, token := range []string{"DNAT cpanel: OFF", "Firewall: tcp/12083 removed", "Firewall: tcp/12087 removed"} {
		if !strings.Contains(out, token) {
			t.Fatalf("output missing %q:\n%s", token, out)
		}
	}
	wantCalls := []string{"delete table", "remove allowlist", "persist off", "apply off", "reload listener"}
	if !reflect.DeepEqual(*calls, wantCalls) {
		t.Fatalf("calls=%v want %v", *calls, wantCalls)
	}
}
