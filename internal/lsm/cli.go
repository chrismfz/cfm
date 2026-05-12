package lsm

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// RunCLI is the entry point invoked from cmd/cfm/main.go for `cfm lsm`.
//
// Scaffolding subcommands (this slice):
//
//	cfm lsm                  -> alias for `status`
//	cfm lsm status [--json]  -> preflight + per-policy state
//	cfm lsm preview          -> what would attach given conf + kernel
//	cfm lsm init             -> write default /etc/cfm/lsm.conf if absent
//	cfm lsm help / -h        -> usage
//
// Subcommands that mutate runtime state (`enable`, `disable`, `test`,
// `policy`) are deliberately absent until the BPF backend lands; they
// would have nothing to act on yet.
func RunCLI(args []string) int {
	if len(args) == 0 {
		return runStatusCmd(nil, os.Stdout)
	}
	switch args[0] {
	case "status", "text":
		return runStatusCmd(args[1:], os.Stdout)
	case "preview":
		return runPreviewCmd(args[1:], os.Stdout)
	case "init":
		return RunInit(os.Stdout)
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "lsm: unknown subcommand %q\n\n", args[0])
		printUsage(os.Stderr)
		return 2
	}
}

func runStatusCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("lsm status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON instead of text")
	checkExit := fs.Bool("check", false, "exit non-zero when preflight FAILs or lsm.conf is unreadable (for monitoring)")

	if rc, done := handleFlagErr("lsm status", fs.Parse(args), w); done {
		return rc
	}
	res := RunStatus(w, StatusOptions{JSON: *jsonOut})
	if *checkExit {
		if !res.PreflightOK || res.ConfError != "" {
			return 1
		}
	}
	return 0
}

func runPreviewCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("lsm preview", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if rc, done := handleFlagErr("lsm preview", fs.Parse(args), w); done {
		return rc
	}
	return RunPreview(w)
}

// handleFlagErr mirrors kernsec's pattern: --help renders usage to w
// and returns 0; a parse error renders the message to stderr plus
// usage and returns 2.
func handleFlagErr(name string, err error, w io.Writer) (int, bool) {
	if err == nil {
		return 0, false
	}
	if errors.Is(err, flag.ErrHelp) {
		printUsage(w)
		return 0, true
	}
	fmt.Fprintln(os.Stderr, name+":", err)
	printUsage(os.Stderr)
	return 2, true
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: cfm lsm [<subcommand>] [flags]

Subcommands:
  (default)           Alias for "status"
  status              Print kernel preflight + per-policy state
  preview             Show what would attach given conf + kernel (read-only dry run)
  init                Write default /etc/cfm/lsm.conf if absent
  help                Show this message

Status flags:
  --json              Emit machine-readable JSON (for fleet aggregation)
  --check             Exit non-zero when preflight FAILs or lsm.conf is unreadable

Notes:
  cfm-lsm is design-phase. This release ships only the preflight, config
  parser, and CLI scaffolding. The BPF programs that actually enforce
  CFML-EXEC-001 (memfd exec) and CFML-EXEC-003 (reverse shell) are not
  loaded yet -- operators can run 'cfm lsm status' to audit fleet
  readiness ahead of the rollout.

See docs/cfm-lsm.md for the full design.`)
}
