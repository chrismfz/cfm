package lsm

import (
	"io"
	"os"
	"testing"
)

// Every `cfm lsm` subcommand answers -h, --help and help with its usage and
// runs nothing: `cfm lsm init --help` ran the bring-up (init never read its
// args) and `cfm lsm disable help` detached every program (the flag parse
// stopped at "help"). Every entry point is a fake that fails the test, so a
// regression cannot attach or detach BPF programs on the test host.
func TestCLIHelpWordsRunNothing(t *testing.T) {
	fail := func(name string) { t.Errorf("lsm %s ran on a help word", name) }
	sInit, sEnable, sDisable, sStatus, sPreview, sProbe := cliInit, cliEnable, cliDisable, cliStatus, cliPreview, cliProbe
	defer func() {
		cliInit, cliEnable, cliDisable, cliStatus, cliPreview, cliProbe = sInit, sEnable, sDisable, sStatus, sPreview, sProbe
	}()
	cliInit = func(io.Writer) int { fail("init"); return 0 }
	cliEnable = func(io.Writer, EnableOptions) int { fail("enable"); return 0 }
	cliDisable = func(io.Writer) int { fail("disable"); return 0 }
	cliStatus = func(io.Writer, StatusOptions) StatusResult { fail("status"); return StatusResult{} }
	cliPreview = func(io.Writer) int { fail("preview"); return 0 }
	cliProbe = func(io.Writer, bool) int { fail("probe"); return 0 }
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	subs := [][]string{{}, {"status"}, {"preview"}, {"probe"}, {"enable"}, {"enable", "--yes"}, {"disable"}, {"restart"}, {"init"}}
	for _, h := range []string{"-h", "--help", "help"} {
		for _, s := range subs {
			args := append(append([]string{}, s...), h)
			if rc := RunCLI(args); rc != 0 {
				t.Errorf("lsm %q: rc=%d, want 0 (usage)", args, rc)
			}
		}
	}
	for _, args := range [][]string{{"enable", "now"}, {"init", "x"}, {"disable", "all"}} {
		if rc := RunCLI(args); rc != 2 {
			t.Errorf("lsm %q: rc=%d, want 2", args, rc)
		}
	}
}
