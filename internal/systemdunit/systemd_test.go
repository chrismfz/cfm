package systemdunit

import (
	"os/exec"
	"testing"
)

func TestProbeActiveEnabled(t *testing.T) {
	oldLookPath := lookPath
	oldCommand := command
	t.Cleanup(func() {
		lookPath = oldLookPath
		command = oldCommand
	})
	lookPath = func(string) (string, error) { return "/usr/bin/systemctl", nil }
	command = func(_ string, args ...string) *exec.Cmd {
		switch args[0] {
		case "is-active":
			return exec.Command("sh", "-c", "printf active")
		case "is-enabled":
			return exec.Command("sh", "-c", "printf enabled")
		default:
			return exec.Command("sh", "-c", "exit 1")
		}
	}

	st, ok := Probe("angie.service")
	if !ok {
		t.Fatal("expected systemctl probe to be available")
	}
	if !st.Active || !st.Enabled || st.ActiveState != "active" || st.EnabledState != "enabled" {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestProbePreservesInactiveDisabledStates(t *testing.T) {
	oldLookPath := lookPath
	oldCommand := command
	t.Cleanup(func() {
		lookPath = oldLookPath
		command = oldCommand
	})
	lookPath = func(string) (string, error) { return "/usr/bin/systemctl", nil }
	command = func(_ string, args ...string) *exec.Cmd {
		switch args[0] {
		case "is-active":
			return exec.Command("sh", "-c", "printf inactive; exit 3")
		case "is-enabled":
			return exec.Command("sh", "-c", "printf disabled; exit 1")
		default:
			return exec.Command("sh", "-c", "exit 1")
		}
	}

	st, ok := Probe("openresty.service")
	if !ok {
		t.Fatal("expected systemctl probe to be available")
	}
	if st.Active || st.Enabled || st.ActiveState != "inactive" || st.EnabledState != "disabled" {
		t.Fatalf("unexpected status: %+v", st)
	}
}
