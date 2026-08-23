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
	for _, call := range calls {
		if strings.Contains(call, "angie") {
			t.Fatalf("resolved OpenResty must never fall through to Angie, got %v", calls)
		}
	}
}

func TestReloadPanelListenerService_PrimaryFailureDoesNotStartInactivePeer(t *testing.T) {
	origExec := execCommand
	origDetect := panelListenerServiceDetector
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerServiceDetector = origDetect
	})

	panelListenerServiceDetector = func() string { return "angie" }
	var calls []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		call := strings.TrimSpace(name + " " + strings.Join(args, " "))
		calls = append(calls, call)
		if strings.Contains(call, "openresty") {
			// This would succeed if the implementation incorrectly crossed over.
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}

	err := reloadPanelListenerService()
	if err == nil {
		t.Fatal("expected Angie reload/restart failure to be returned")
	}
	for _, call := range calls {
		if strings.Contains(call, "openresty") {
			t.Fatalf("must not start/reload inactive peer after Angie failure, got %v", calls)
		}
	}
	if len(calls) != 4 {
		t.Fatalf("expected only the four Angie reload/restart candidates, got %v", calls)
	}
}

func TestReloadPanelListenerService_NoAuthoritativeServiceFailsWithoutGuessing(t *testing.T) {
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
		return exec.Command("sh", "-c", "exit 0")
	}

	err := reloadPanelListenerService()
	if err == nil {
		t.Fatal("expected unknown edge service to fail rather than start Angie/OpenResty arbitrarily")
	}
	if !strings.Contains(err.Error(), "no authoritative angie/openresty edge service") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("expected no reload/restart commands when service is unknown, got %v", calls)
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

func TestDetectActivePanelListenerService_NoActiveUsesUniqueEnabledIntent(t *testing.T) {
	withPanelServiceDetectionTest(t, map[string]systemdunit.Status{
		"angie.service":      {Active: false, Enabled: true, ActiveState: "inactive", EnabledState: "enabled"},
		"openresty.service": {Active: false, Enabled: false, ActiveState: "inactive", EnabledState: "disabled"},
	}, true, "", nil)

	if got := detectActivePanelListenerService(); got != "angie" {
		t.Fatalf("service=%q, want enabled Angie as intended edge", got)
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
