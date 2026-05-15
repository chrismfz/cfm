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
// Subcommands:
//
//	cfm lsm                  -> alias for `status`
//	cfm lsm status [--json]  -> preflight + per-policy state (read-only)
//	cfm lsm preview          -> what would attach given conf + kernel (read-only)
//	cfm lsm probe            -> attach briefly to verify the kernel accepts; detach
//	cfm lsm enable           -> attach + pin to bpffs (survives daemon restart)
//	cfm lsm disable          -> unpin + detach all programs
//	cfm lsm init             -> write default /etc/cfm/lsm.conf if absent
//	cfm lsm help / -h        -> usage
//
// Three subcommands touch kernel state:
//   - `probe` loads + attaches + detaches; nothing persists. Use to
//     verify the kernel accepts the BPF programs without committing.
//   - `enable` loads + attaches + pins. Programs stay attached past
//     CLI and daemon exit; only `disable` detaches them.
//   - `disable` removes everything pinned under /sys/fs/bpf/cfm/.
//
// The cfm daemon does not auto-pin. It only adopts pre-existing
// pinned state (created by `cfm lsm enable`) to drain events into
// the notify pipeline.
func RunCLI(args []string) int {
	if len(args) == 0 {
		return runStatusCmd(nil, os.Stdout)
	}
	switch args[0] {
	case "status", "text":
		return runStatusCmd(args[1:], os.Stdout)
	case "preview":
		return runPreviewCmd(args[1:], os.Stdout)
	case "probe":
		return runProbeCmd(args[1:], os.Stdout)
	case "enable":
		return runEnableCmd(args[1:], os.Stdout)
	case "disable":
		return runDisableCmd(args[1:], os.Stdout)
	case "restart":
		return runRestartCmd(args[1:], os.Stdout)
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

func runEnableCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("lsm enable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "skip the enforce-mode confirmation prompt (required for unattended runs)")
	if rc, done := handleFlagErr("lsm enable", fs.Parse(args), w); done {
		return rc
	}
	return RunEnable(w, EnableOptions{AssumeYes: *yes})
}

func runDisableCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("lsm disable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if rc, done := handleFlagErr("lsm disable", fs.Parse(args), w); done {
		return rc
	}
	return RunDisable(w)
}

// runRestartCmd is the operator convenience for reloading /etc/cfm/lsm.conf:
// disable (no-op if not currently enabled) followed by enable. Picks up
// changes to allow_* lists, [events] / [kmsg] knobs, and per-policy modes
// in one go — the BPF program enforce-constants are baked at load time,
// so a process restart is the only way to re-rewrite them.
//
// Honours the same --yes / -y flag as `cfm lsm enable` so unattended
// reloads after a conf-management change (Ansible / Salt / cron) can skip
// the enforce-mode confirmation prompt.
func runRestartCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("lsm restart", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "skip the enforce-mode confirmation prompt (passed through to enable)")
	short := fs.Bool("y", false, "shorthand for --yes")
	if rc, done := handleFlagErr("lsm restart", fs.Parse(args), w); done {
		return rc
	}
	fmt.Fprintln(w, "===== CFM lsm RESTART =====")
	fmt.Fprintln(w)
	// Disable first. If cfm-lsm isn't currently enabled, RunDisable
	// is already idempotent (prints "Nothing to do." and returns 0) so
	// `restart` doubles as "ensure enabled with current conf".
	if rc := RunDisable(w); rc != 0 {
		return rc
	}
	fmt.Fprintln(w)
	return RunEnable(w, EnableOptions{AssumeYes: *yes || *short})
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

func runProbeCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("lsm probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	// --verbose / -v adds a "[BTF probe — LSM hook variant picks]"
	// section to the report so operators can confirm the loader picked
	// the right BPF program variant for their kernel (EL9 vs EL10 vs
	// Debian/Ubuntu signatures of inode_setattr / inode_setxattr).
	var verbose bool
	fs.BoolVar(&verbose, "verbose", false, "include BTF-probe drift-variant picks in the report")
	fs.BoolVar(&verbose, "v", false, "shorthand for --verbose")
	if rc, done := handleFlagErr("lsm probe", fs.Parse(args), w); done {
		return rc
	}
	if !requireRoot(w, "probe") {
		return 1
	}
	return RunProbe(w, verbose)
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
  status              Print kernel preflight + per-policy state (read-only)
  preview             Show what would attach given conf + kernel (read-only)
  probe [-v]          Briefly attach the BPF programs to verify the kernel
                      accepts them, then detach. Needs root.
                      -v / --verbose adds the BTF-probe drift-variant picks
                      (which inode_setattr / inode_setxattr variant the loader
                      chose for this kernel).
  enable [--yes]      Attach the BPF programs and pin them to /sys/fs/bpf/cfm so
                      they stay attached across daemon restarts and crashes.
                      Prompts for confirmation when any policy is set to
                      mode=enforce in lsm.conf; --yes skips the prompt for
                      unattended runs. Needs root.
  disable             Unpin and detach. Needs root.
  restart [--yes]     Reload /etc/cfm/lsm.conf: disable (no-op if not
                      enabled) then enable. Picks up changed allow_* lists,
                      [events] / [kmsg] knobs, and per-policy modes.
                      Needs root.
  init                Write default /etc/cfm/lsm.conf if absent
  help                Show this message

Status flags:
  --json              Emit machine-readable JSON (for fleet aggregation)
  --check             Exit non-zero when preflight FAILs or lsm.conf is unreadable

Notes:
  status / preview do not touch the kernel; they only read /proc, /sys, and
  /etc/cfm/lsm.conf. probe / enable / disable mutate kernel state. probe is
  ephemeral (attach + detach, no persistence). enable pins to bpffs so
  programs stay attached across daemon restarts; only disable detaches.

See docs/cfm-lsm.md for the full design.`)
}
