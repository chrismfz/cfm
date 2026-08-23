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

// Probe returns the current systemd state for unit. ok is false only when
// systemctl itself is unavailable; an installed, disabled, inactive, failed,
// or even missing unit still has a meaningful systemctl state and returns ok.
func Probe(unit string) (Status, bool) {
	if _, err := lookPath("systemctl"); err != nil {
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

func combinedOutput(cmd *exec.Cmd) []byte {
	out, _ := cmd.CombinedOutput()
	return out
}
