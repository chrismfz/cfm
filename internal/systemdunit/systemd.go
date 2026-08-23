package systemdunit

import (
	"os/exec"
	"strings"
)

// Status is the canonical systemd view used by host diagnostics. ActiveState
// and EnabledState preserve systemctl's textual result while Active/Enabled
// provide the common booleans used by health and routing diagnostics.
type Status struct {
	Active       bool
	Enabled      bool
	ActiveState  string
	EnabledState string
}

var lookPath = exec.LookPath
var command = exec.Command

// Probe returns the current systemd state for unit. ok is false when systemctl
// itself is unavailable or when the local systemd manager cannot be reached
// (for example inside WSL/chroots/containers that ship systemctl but do not run
// systemd as PID 1). Missing, disabled, inactive, or failed units still return a
// meaningful state with ok=true once the manager is reachable.
func Probe(unit string) (Status, bool) {
	if _, err := lookPath("systemctl"); err != nil {
		return Status{}, false
	}
	if !managerReachable() {
		return Status{}, false
	}

	activeState := strings.TrimSpace(string(combinedOutput(command("systemctl", "is-active", unit))))
	enabledState := strings.TrimSpace(string(combinedOutput(command("systemctl", "is-enabled", unit))))
	if activeState == "" {
		activeState = "unknown"
	}
	if enabledState == "" {
		enabledState = "unknown"
	}
	return Status{
		Active:       activeState == "active",
		Enabled:      enabledState == "enabled",
		ActiveState:  activeState,
		EnabledState: enabledState,
	}, true
}

func managerReachable() bool {
	out, err := command("systemctl", "show", "--property=Version", "--value").CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

func combinedOutput(cmd *exec.Cmd) []byte {
	out, _ := cmd.CombinedOutput()
	return out
}
