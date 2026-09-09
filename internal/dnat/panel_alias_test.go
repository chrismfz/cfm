package dnat

import (
	"strings"
	"testing"
)

// TestPanelAliasRoutesToPanelCLI pins that `cfm dnat panel …` is accepted as the
// panel-neutral alias of `cfm dnat cpanel …` and routes to the same runPanelCLI.
func TestPanelAliasRoutesToPanelCLI(t *testing.T) {
	be := panelStatusStub{} // non-nil firewall.Backend; help path calls no methods

	_, errOut := captureStreams(t, func() {
		if code := RunCLI([]string{"panel", "help"}, be); code != 0 {
			t.Fatalf("`dnat panel help` expected code 0, got %d", code)
		}
	})

	// panelHelp() is what `cpanel help` prints — its presence proves the alias
	// reached runPanelCLI rather than the web-DNAT help.
	if !strings.Contains(errOut, "Commands: status, on, off") {
		t.Fatalf("`dnat panel help` did not reach panel help:\n%s", errOut)
	}
	if !strings.Contains(errOut, "alias of `cfm dnat cpanel") {
		t.Fatalf("expected the alias note in panel help:\n%s", errOut)
	}
}

// TestCpanelSubcommandStillWorks guards that adding the alias did not break the
// original `cpanel` spelling.
func TestCpanelSubcommandStillWorks(t *testing.T) {
	be := panelStatusStub{}
	_, errOut := captureStreams(t, func() {
		if code := RunCLI([]string{"cpanel", "help"}, be); code != 0 {
			t.Fatalf("`dnat cpanel help` expected code 0, got %d", code)
		}
	})
	if !strings.Contains(errOut, "Commands: status, on, off") {
		t.Fatalf("`dnat cpanel help` regressed:\n%s", errOut)
	}
}
