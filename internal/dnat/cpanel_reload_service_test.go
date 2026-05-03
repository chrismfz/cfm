package dnat

import (
	"os/exec"
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

func TestReloadPanelListenerService_AngieActiveDoesNotAcceptOpenrestySuccess(t *testing.T) {
	origExec := execCommand
	origDetect := panelListenerServiceDetector
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerServiceDetector = origDetect
	})

	panelListenerServiceDetector = func() string { return "angie" }
	var calls []string
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if len(args) == 2 && args[1] == "openresty" {
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}

	err := reloadPanelListenerService()
	if err == nil {
		t.Fatalf("expected error when only fallback service commands succeed")
	}
	if !strings.Contains(err.Error(), "active service \"angie\" failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) < 5 {
		t.Fatalf("expected openresty fallback attempts after angie failures, got %v", calls)
	}
	if calls[0] != "systemctl reload angie" {
		t.Fatalf("expected first command to be angie reload, got %v", calls)
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
