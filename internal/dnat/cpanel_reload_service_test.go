package dnat

import (
	"cfm/internal/systemdunit"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReloadPanelListenerService_OpenrestyActivePrefersOpenresty(t *testing.T) {
	origExec := execCommand
	origDetect := panelListenerServiceDetector
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerServiceDetector = origDetect
	})

	panelListenerServiceDetector = func() string { return "openresty" }
	var calls []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "openresty" {
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}

	if err := reloadPanelListenerService(); err != nil {
		t.Fatalf("reload listener service: %v", err)
	}
	if len(calls) == 0 || calls[0] != "systemctl reload openresty" {
		t.Fatalf("expected first command to be openresty reload, got %v", calls)
	}
}

func TestReloadPanelListenerService_StaleAngieDetectionAcceptsConfirmedOpenrestyFallback(t *testing.T) {
	origExec := execCommand
	origDetect := panelListenerServiceDetector
	origProcDetect := panelListenerProcessDetector
	origProbe := panelSystemdUnitProbe
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerServiceDetector = origDetect
		panelListenerProcessDetector = origProcDetect
		panelSystemdUnitProbe = origProbe
	})

	panelListenerServiceDetector = func() string { return "angie" }
	panelListenerProcessDetector = func() string { return "" }
	probeCalled := false
	panelSystemdUnitProbe = func(unit string) (systemdunit.Status, bool) {
		if unit == "openresty.service" {
			probeCalled = true
			return systemdunit.Status{Active: true, Enabled: true, ActiveState: "active", EnabledState: "enabled"}, true
		}
		return systemdunit.Status{ActiveState: "inactive", EnabledState: "disabled"}, true
	}
	var calls []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "openresty" {
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}

	if err := reloadPanelListenerService(); err != nil {
		t.Fatalf("reload listener service: %v", err)
	}
	if len(calls) < 5 {
		t.Fatalf("expected angie failures then openresty reload, got %v", calls)
	}
	if calls[0] != "systemctl reload angie" {
		t.Fatalf("expected stale angie detection to try angie reload first, got %v", calls)
	}
	if calls[4] != "systemctl reload openresty" {
		t.Fatalf("expected fallback openresty reload after angie failures, got %v", calls)
	}
	if !probeCalled {
		t.Fatal("expected shared systemd probe before accepting fallback service success")
	}
}

func TestReloadPanelListenerService_UnconfirmedFallbackSuccessFails(t *testing.T) {
	origExec := execCommand
	origDetect := panelListenerServiceDetector
	origProcDetect := panelListenerProcessDetector
	origProbe := panelSystemdUnitProbe
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerServiceDetector = origDetect
		panelListenerProcessDetector = origProcDetect
		panelSystemdUnitProbe = origProbe
	})

	panelListenerServiceDetector = func() string { return "angie" }
	panelListenerProcessDetector = func() string { return "" }
	panelSystemdUnitProbe = func(string) (systemdunit.Status, bool) {
		return systemdunit.Status{ActiveState: "inactive", EnabledState: "disabled"}, true
	}
	var calls []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "openresty" {
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}

	err := reloadPanelListenerService()
	if err == nil {
		t.Fatalf("expected error when fallback service success is not confirmed active")
	}
	if !strings.Contains(err.Error(), "unconfirmed fallback service") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) < 5 {
		t.Fatalf("expected openresty fallback after angie failures, got %v", calls)
	}
	if calls[4] != "systemctl reload openresty" {
		t.Fatalf("expected openresty fallback, got %v", calls)
	}
}

func TestReloadPanelListenerService_UnknownFallsBackAndAcceptsSuccess(t *testing.T) {
	origExec := execCommand
	origDetect := panelListenerServiceDetector
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerServiceDetector = origDetect
	})

	panelListenerServiceDetector = func() string { return "" }
	var calls []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "openresty" {
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}

	if err := reloadPanelListenerService(); err != nil {
		t.Fatalf("reload listener service: %v", err)
	}
	if len(calls) < 5 {
		t.Fatalf("expected fallback commands to run, got %v", calls)
	}
	if calls[0] != "systemctl reload angie" {
		t.Fatalf("expected unknown detection to start with angie path, got %v", calls)
	}
}

func TestReloadPanelListenerService_AmbiguousActiveServicesReturnsClearError(t *testing.T) {
	origDetect := panelListenerServiceDetector
	t.Cleanup(func() { panelListenerServiceDetector = origDetect })
	panelListenerServiceDetector = func() string { return panelListenerServiceAmbiguous }

	err := reloadPanelListenerService()
	if err == nil {
		t.Fatalf("expected ambiguous listener service error")
	}
	if !strings.Contains(err.Error(), "ambiguous active panel listener services") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writePanelListenerTestConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func withPanelServiceDetectionTest(t *testing.T, states map[string]systemdunit.Status, systemdAvailable bool, process string, paths []string) {
	t.Helper()
	origProbe := panelSystemdUnitProbe
	origProc := panelListenerProcessDetector
	origPaths := panelListenerChallengeConfigPaths
	panelSystemdUnitProbe = func(unit string) (systemdunit.Status, bool) {
		if !systemdAvailable {
			return systemdunit.Status{}, false
		}
		if st, ok := states[unit]; ok {
			return st, true
		}
		return systemdunit.Status{ActiveState: "inactive", EnabledState: "disabled"}, true
	}
	panelListenerProcessDetector = func() string { return process }
	panelListenerChallengeConfigPaths = paths
	t.Cleanup(func() {
		panelSystemdUnitProbe = origProbe
		panelListenerProcessDetector = origProc
		panelListenerChallengeConfigPaths = origPaths
	})
}

func TestDetectActivePanelListenerService_ActiveEnabledOpenrestyOverridesStaleAngieConfig(t *testing.T) {
	tmp := t.TempDir()
	angiePath := filepath.Join(tmp, "etc/angie/cfm-panel-listeners.conf")
	openrestyPath := filepath.Join(tmp, "usr/local/openresty/nginx/conf/cfm-panel-listeners.conf")
	writePanelListenerTestConfig(t, angiePath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	writePanelListenerTestConfig(t, openrestyPath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	withPanelServiceDetectionTest(t, map[string]systemdunit.Status{
		"openresty.service": {Active: true, Enabled: true, ActiveState: "active", EnabledState: "enabled"},
	}, true, "", []string{angiePath, openrestyPath})

	if got := detectActivePanelListenerService(); got != "openresty" {
		t.Fatalf("service=%q, want openresty", got)
	}
}

func TestDetectActivePanelListenerService_BothActivePrefersOnlyEnabledActive(t *testing.T) {
	withPanelServiceDetectionTest(t, map[string]systemdunit.Status{
		"angie.service":      {Active: true, Enabled: false, ActiveState: "active", EnabledState: "disabled"},
		"openresty.service": {Active: true, Enabled: true, ActiveState: "active", EnabledState: "enabled"},
	}, true, "", nil)

	if got := detectActivePanelListenerService(); got != "openresty" {
		t.Fatalf("service=%q, want openresty", got)
	}
}

func TestDetectActivePanelListenerService_BothActiveEnabledIsAmbiguous(t *testing.T) {
	withPanelServiceDetectionTest(t, map[string]systemdunit.Status{
		"angie.service":      {Active: true, Enabled: true, ActiveState: "active", EnabledState: "enabled"},
		"openresty.service": {Active: true, Enabled: true, ActiveState: "active", EnabledState: "enabled"},
	}, true, "", nil)

	if got := detectActivePanelListenerService(); got != panelListenerServiceAmbiguous {
		t.Fatalf("service=%q, want ambiguous sentinel", got)
	}
}

func TestDetectActivePanelListenerService_NoActiveDoesNotGuessFromConfig(t *testing.T) {
	tmp := t.TempDir()
	angiePath := filepath.Join(tmp, "etc/angie/cfm-panel-listeners.conf")
	writePanelListenerTestConfig(t, angiePath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	withPanelServiceDetectionTest(t, map[string]systemdunit.Status{}, true, "", []string{angiePath})

	if got := detectActivePanelListenerService(); got != "" {
		t.Fatalf("service=%q, want none instead of stale-config guess", got)
	}
}

func TestDetectActivePanelListenerService_NoSystemdFallsBackToProcess(t *testing.T) {
	withPanelServiceDetectionTest(t, nil, false, "angie", nil)
	if got := detectActivePanelListenerService(); got != "angie" {
		t.Fatalf("service=%q, want angie process fallback", got)
	}
}
