package kernsec

import (
	"io"
	"os"
	"testing"
)

// Every `cfm kernsec` subcommand answers -h, --help and help with its usage
// and runs nothing. The flag parse stopped at a positional "help", so
// `cfm kernsec apply help` applied with every default (boot args, sysctls,
// module blacklist), and `kernsec init --help` wrote kernsec.conf (init
// never read its args). Every entry point is a fake that fails the test, so a
// regression cannot touch the test host.
func TestCLIHelpWordsRunNothing(t *testing.T) {
	defer swapCLIEntryPointsForTest(t)()
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()
	subs := [][]string{
		{}, {"live"}, {"text"}, {"status"}, {"preview"}, {"init"}, {"apply"}, {"apply", "--dry-run"},
		{"disable"}, {"disable", "--purge"}, {"monitor"}, {"monitor", "enable"}, {"monitor", "remove"},
		{"rollback"}, {"modules"}, {"modules", "audit"}, {"secure-tmp"}, {"secure-tmp", "--size", "16G"},
	}
	for _, h := range []string{"-h", "--help", "help"} {
		for _, s := range subs {
			args := append(append([]string{}, s...), h)
			if rc := RunCLI(args); rc != 0 {
				t.Errorf("kernsec %q: rc=%d, want 0 (usage)", args, rc)
			}
		}
	}
	// Another positional is refused, never run.
	for _, args := range [][]string{{"apply", "now"}, {"init", "x"}, {"disable", "all"}, {"rollback", "x"}} {
		if rc := RunCLI(args); rc != 2 {
			t.Errorf("kernsec %q: rc=%d, want 2", args, rc)
		}
	}
}

func swapCLIEntryPointsForTest(t *testing.T) func() {
	t.Helper()
	fail := func(name string) { t.Errorf("kernsec %s ran on a help word", name) }
	saved := []any{cliLive, cliInit, cliStatus, cliStatusJSON, cliPreview, cliApply, cliMonitor, cliSecureTmp, cliRollback, cliDisable, cliModuleAudit}
	cliLive = func() int { fail("live"); return 0 }
	cliInit = func(io.Writer) int { fail("init"); return 0 }
	cliStatus = func(io.Writer, StatusOptions) StatusResult { fail("status"); return StatusResult{OK: true} }
	cliStatusJSON = func(io.Writer) StatusResult { fail("status --json"); return StatusResult{OK: true} }
	cliPreview = func(io.Writer, PreviewOptions) int { fail("preview"); return 0 }
	cliApply = func(io.Writer, ApplyOptions) int { fail("apply"); return 0 }
	cliMonitor = func(io.Writer, MonitorOptions) int { fail("monitor"); return 0 }
	cliSecureTmp = func(io.Writer, SecureTmpOptions) int { fail("secure-tmp"); return 0 }
	cliRollback = func(io.Writer, bool) int { fail("rollback"); return 0 }
	cliDisable = func(io.Writer, DisableOptions) int { fail("disable"); return 0 }
	cliModuleAudit = func() *ModuleAudit { fail("modules audit"); return &ModuleAudit{} }
	return func() {
		cliLive = saved[0].(func() int)
		cliInit = saved[1].(func(io.Writer) int)
		cliStatus = saved[2].(func(io.Writer, StatusOptions) StatusResult)
		cliStatusJSON = saved[3].(func(io.Writer) StatusResult)
		cliPreview = saved[4].(func(io.Writer, PreviewOptions) int)
		cliApply = saved[5].(func(io.Writer, ApplyOptions) int)
		cliMonitor = saved[6].(func(io.Writer, MonitorOptions) int)
		cliSecureTmp = saved[7].(func(io.Writer, SecureTmpOptions) int)
		cliRollback = saved[8].(func(io.Writer, bool) int)
		cliDisable = saved[9].(func(io.Writer, DisableOptions) int)
		cliModuleAudit = saved[10].(func() *ModuleAudit)
	}
}
