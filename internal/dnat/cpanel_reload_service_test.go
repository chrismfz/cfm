package dnat

import (
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

func TestReloadPanelListenerService_StaleAngieDetectionAcceptsActiveOpenrestySuccess(t *testing.T) {
	origExec := execCommand
	origDetect := panelListenerServiceDetector
	origProcDetect := panelListenerProcessDetector
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerServiceDetector = origDetect
		panelListenerProcessDetector = origProcDetect
	})

	panelListenerServiceDetector = func() string { return "angie" }
	panelListenerProcessDetector = func() string { return "" }
	var calls []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if name == "systemctl" && len(args) == 3 && args[0] == "is-active" && args[1] == "--quiet" && args[2] == "openresty" {
			return exec.Command("sh", "-c", "exit 0")
		}
		if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "openresty" {
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}

	if err := reloadPanelListenerService(); err != nil {
		t.Fatalf("reload listener service: %v", err)
	}
	if len(calls) < 6 {
		t.Fatalf("expected angie failures, openresty reload, and active check, got %v", calls)
	}
	if calls[0] != "systemctl reload angie" {
		t.Fatalf("expected stale angie detection to try angie reload first, got %v", calls)
	}
	if calls[4] != "systemctl reload openresty" {
		t.Fatalf("expected fallback openresty reload after angie failures, got %v", calls)
	}
	if calls[5] != "systemctl is-active --quiet openresty" {
		t.Fatalf("expected active check before accepting fallback success, got %v", calls)
	}
}

func TestReloadPanelListenerService_UnconfirmedFallbackSuccessFails(t *testing.T) {
	origExec := execCommand
	origDetect := panelListenerServiceDetector
	origProcDetect := panelListenerProcessDetector
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerServiceDetector = origDetect
		panelListenerProcessDetector = origProcDetect
	})

	panelListenerServiceDetector = func() string { return "angie" }
	panelListenerProcessDetector = func() string { return "" }
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
	if len(calls) < 6 {
		t.Fatalf("expected openresty fallback and active check after angie failures, got %v", calls)
	}
	if calls[5] != "systemctl is-active --quiet openresty" {
		t.Fatalf("expected active check before rejecting fallback success, got %v", calls)
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

func withPanelServiceDetectionTest(t *testing.T, active map[string]bool, paths []string) {
	t.Helper()
	origExec := execCommand
	origPaths := panelListenerChallengeConfigPaths
	execCommand = func(name string, args ...string) *exec.Cmd {
		if name == "systemctl" && len(args) == 3 && args[0] == "is-active" && args[1] == "--quiet" {
			if active[args[2]] {
				return exec.Command("sh", "-c", "exit 0")
			}
			return exec.Command("sh", "-c", "exit 3")
		}
		return exec.Command("sh", "-c", "exit 1")
	}
	panelListenerChallengeConfigPaths = paths
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerChallengeConfigPaths = origPaths
	})
}

func TestDetectActivePanelListenerService_ActiveOpenrestyOverridesStaleAngieConfig(t *testing.T) {
	tmp := t.TempDir()
	angiePath := filepath.Join(tmp, "etc/angie/cfm-panel-listeners.conf")
	openrestyPath := filepath.Join(tmp, "usr/local/openresty/nginx/conf/cfm-panel-listeners.conf")
	writePanelListenerTestConfig(t, angiePath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	writePanelListenerTestConfig(t, openrestyPath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	withPanelServiceDetectionTest(t, map[string]bool{"openresty": true}, []string{angiePath, openrestyPath})

	if got := detectActivePanelListenerService(); got != "openresty" {
		t.Fatalf("service=%q, want openresty", got)
	}
}

func TestDetectActivePanelListenerService_BothActiveUsesLoadedConfig(t *testing.T) {
	tmp := t.TempDir()
	angiePath := filepath.Join(tmp, "etc/angie/cfm-panel-listeners.conf")
	openrestyPath := filepath.Join(tmp, "usr/local/openresty/nginx/conf/cfm-panel-listeners.conf")
	writePanelListenerTestConfig(t, angiePath, `server { # stale config without panel lua guard }`)
	writePanelListenerTestConfig(t, openrestyPath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	withPanelServiceDetectionTest(t, map[string]bool{"angie": true, "openresty": true}, []string{angiePath, openrestyPath})

	if got := detectActivePanelListenerService(); got != "openresty" {
		t.Fatalf("service=%q, want openresty", got)
	}
}

func TestDetectActivePanelListenerService_BothActiveAmbiguousLoadedConfigs(t *testing.T) {
	tmp := t.TempDir()
	angiePath := filepath.Join(tmp, "etc/angie/cfm-panel-listeners.conf")
	openrestyPath := filepath.Join(tmp, "usr/local/openresty/nginx/conf/cfm-panel-listeners.conf")
	writePanelListenerTestConfig(t, angiePath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	writePanelListenerTestConfig(t, openrestyPath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	withPanelServiceDetectionTest(t, map[string]bool{"angie": true, "openresty": true}, []string{angiePath, openrestyPath})

	if got := detectActivePanelListenerService(); got != panelListenerServiceAmbiguous {
		t.Fatalf("service=%q, want ambiguous sentinel", got)
	}
}

func TestDetectActivePanelListenerService_NoActiveFallsBackToConfigPath(t *testing.T) {
	tmp := t.TempDir()
	angiePath := filepath.Join(tmp, "etc/angie/cfm-panel-listeners.conf")
	openrestyPath := filepath.Join(tmp, "usr/local/openresty/nginx/conf/cfm-panel-listeners.conf")
	writePanelListenerTestConfig(t, angiePath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	writePanelListenerTestConfig(t, openrestyPath, `server { access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`)
	withPanelServiceDetectionTest(t, map[string]bool{}, []string{angiePath, openrestyPath})

	if got := detectActivePanelListenerService(); got != "angie" {
		t.Fatalf("service=%q, want angie fallback", got)
	}
}
