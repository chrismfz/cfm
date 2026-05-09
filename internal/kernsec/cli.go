package kernsec

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// RunCLI is the entry point invoked from cmd/cfm/main.go.
//
// Phase 1 ships only "status" (read-only). enable / disable / preview
// land in later PRs. Returns the process exit code: 0 on success
// (including "status produced WARNs"; warnings are informational, not
// failure), 2 on argument errors.
func RunCLI(args []string) int {
	if len(args) == 0 {
		return runStatus(args, os.Stdout)
	}
	switch args[0] {
	case "status", "":
		return runStatus(args[1:], os.Stdout)
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "kernsec: unknown subcommand %q\n\n", args[0])
		printUsage(os.Stderr)
		return 2
	}
}

func runStatus(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("kernsec status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	skipAFAlg := fs.Bool("skip-af-alg", false, "skip AF_ALG bind probes")
	checkExit := fs.Bool("check", false, "exit non-zero on any WARN (for monitoring)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "kernsec status:", err)
		printUsage(os.Stderr)
		return 2
	}
	res := RunStatus(w, StatusOptions{SkipAFAlg: *skipAFAlg})
	if *checkExit && !res.OK {
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: cfm kernsec <subcommand> [flags]

Subcommands:
  status              Audit-only kernel-hardening status (Phase 1)
  help                Show this message

Status flags:
  --skip-af-alg       Skip AF_ALG bind probes
  --check             Exit non-zero on any WARN (suitable for monitoring)

See docs/kernsec.md for the full design. enable/disable land in a later
phase; this build is read-only.`)
}
