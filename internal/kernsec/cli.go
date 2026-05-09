package kernsec

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// RunCLI is the entry point invoked from cmd/cfm/main.go.
//
// Phase 1 ships only audit-only modes:
//
//	cfm kernsec            -> TUI when stdout is a TTY, else text
//	cfm kernsec live       -> explicit TUI
//	cfm kernsec text       -> plain-text status
//	cfm kernsec status     -> alias for "text" (also supports --check)
//	cfm kernsec help / -h  -> usage
//
// enable / disable / preview / apply land in later phases.
func RunCLI(args []string) int {
	if len(args) == 0 {
		return runDefault(os.Stdout)
	}
	switch args[0] {
	case "live", "tui", "ui":
		return runLive()
	case "text":
		return runText(args[1:], os.Stdout)
	case "status":
		return runText(args[1:], os.Stdout)
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "kernsec: unknown subcommand %q\n\n", args[0])
		printUsage(os.Stderr)
		return 2
	}
}

// runDefault picks TUI vs text based on whether stdout is a terminal,
// matching cfm health live's auto-fallback behaviour.
func runDefault(w io.Writer) int {
	if IsTTY() {
		return runLive()
	}
	return runText(nil, w)
}

func runLive() int {
	switchToText, err := RunTUI()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kernsec:", err)
		return 1
	}
	if switchToText {
		return runText(nil, os.Stdout)
	}
	return 0
}

func runText(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("kernsec status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	skipAFAlg := fs.Bool("skip-af-alg", false, "skip AF_ALG bind probes")
	checkExit := fs.Bool("check", false, "exit non-zero on any WARN (for monitoring)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "kernsec:", err)
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
	fmt.Fprintln(w, `Usage: cfm kernsec [<subcommand>] [flags]

Subcommands:
  (default)           Interactive TUI on a TTY; auto-falls back to text otherwise
  live                Force the interactive TUI
  text                Plain-text audit output
  status              Alias for "text" (supports --check for monitoring)
  help                Show this message

Status flags (text / status):
  --skip-af-alg       Skip AF_ALG bind probes
  --check             Exit non-zero on any WARN (suitable for monitoring)

TUI keys:
  q / Ctrl-C          Quit
  ↑/↓ or j/k          Move cursor
  Home/End or g/G     First / last row
  PgUp / PgDn         Page
  r                   Re-run audit
  t                   Drop to text mode
  e / d               (Phase 3 — enable / disable, not yet implemented)
  ?                   Toggle help

See docs/kernsec.md for the full design.`)
}
