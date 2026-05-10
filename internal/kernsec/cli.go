package kernsec

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// handleFlagErr maps a flag.Parse error to a CLI exit code, printing
// either operator-facing help (-h / --help → ErrHelp; usage to stdout
// w, exit 0) or a parse error followed by usage (to stderr, exit 2).
// Returns (rc, true) if Parse failed and the caller should propagate
// rc; (0, false) when Parse succeeded.
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

// RunCLI is the entry point invoked from cmd/cfm/main.go.
//
// Phase 1 + Phase 2a (read-only):
//
//	cfm kernsec                  -> TUI when stdout is a TTY, else text
//	cfm kernsec live             -> explicit TUI
//	cfm kernsec text             -> plain-text status
//	cfm kernsec status           -> alias for "text" (also supports --check)
//	cfm kernsec preview          -> read-only diff: what apply would select
//	cfm kernsec init             -> write default tier=1 kernsec.conf
//	cfm kernsec apply            -> render + write managed files; sysctl --load + bootloader refresh
//	cfm kernsec disable          -> tier=0 + strip managed args (--purge for full uninstall)
//	cfm kernsec monitor <action> -> manage the periodic drift-check systemd timer
//	cfm kernsec help / -h        -> usage
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
	case "preview":
		return runPreviewCmd(args[1:], os.Stdout)
	case "init":
		return RunInit(os.Stdout)
	case "apply":
		return runApplyCmd(args[1:], os.Stdout)
	case "disable":
		return runDisableCmd(args[1:], os.Stdout)
	case "monitor":
		return runMonitorCmd(args[1:], os.Stdout)
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

	if rc, done := handleFlagErr("kernsec", fs.Parse(args), w); done {
		return rc
	}
	res := RunStatus(w, StatusOptions{SkipAFAlg: *skipAFAlg})
	if *checkExit && !res.OK {
		return 1
	}
	return 0
}

func runPreviewCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("kernsec preview", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	onlyApply := fs.Bool("only-apply", false, "hide rules that would be skipped")
	group := fs.String("group", "", "filter by group prefix (e.g. modules.net.legacy)")
	tier := fs.Int("tier", -1, "override conf.Tier for this preview (0|1|2; default: honor conf)")
	ids := fs.String("id", "", "comma-separated rule IDs to include")
	skip := fs.String("skip", "", "comma-separated rule IDs to ad-hoc skip (not persisted)")
	force := fs.String("force-id", "", "comma-separated rule IDs to ad-hoc force (not persisted)")

	if rc, done := handleFlagErr("kernsec preview", fs.Parse(args), w); done {
		return rc
	}
	if *tier < -1 || *tier > 2 {
		fmt.Fprintln(os.Stderr, "kernsec preview: --tier must be 0, 1, or 2")
		return 2
	}
	// Sentinel: -1 means "operator did not pass --tier"; PreviewOptions
	// signals this by leaving Tier at the zero value of a sentinel
	// distinct from the legitimate value 0. We use a TierOverride bool
	// to disambiguate without changing the int type on the option.
	po := PreviewOptions{
		OnlyApply: *onlyApply,
		Group:     *group,
		IDs:       splitCSV(*ids),
		Skips:     splitCSV(*skip),
		Forces:    splitCSV(*force),
	}
	if *tier >= 0 {
		po.Tier = Tier(*tier)
		po.TierOverride = true
	}
	return RunPreview(w, po)
}

func runApplyCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("kernsec apply", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dryRun := fs.Bool("dry-run", false, "show what would be written / refreshed without doing it")
	check := fs.Bool("check", false, "exit non-zero on drift; implies no writes (for monitoring)")
	noRefresh := fs.Bool("no-refresh", false, "skip the bootloader refresh step (proxmox-boot-tool / update-grub)")
	yes := fs.Bool("yes", false, "skip the interactive safety preview / confirmation (required for unattended runs)")

	if rc, done := handleFlagErr("kernsec apply", fs.Parse(args), w); done {
		return rc
	}
	return RunApply(w, ApplyOptions{
		DryRun:    *dryRun,
		Check:     *check,
		NoRefresh: *noRefresh,
		AssumeYes: *yes,
	})
}

func runMonitorCmd(args []string, w io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "kernsec monitor: missing action (enable | disable | remove | status)")
		printUsage(os.Stderr)
		return 2
	}
	action := args[0]
	rest := args[1:]

	fs := flag.NewFlagSet("kernsec monitor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	interval := fs.String("interval", "", "systemd OnCalendar expression (default \"daily\")")
	dryRun := fs.Bool("dry-run", false, "show what would happen without writing or running systemctl")
	if rc, done := handleFlagErr("kernsec monitor", fs.Parse(rest), w); done {
		return rc
	}
	return RunMonitor(w, MonitorOptions{
		Action:   action,
		Interval: *interval,
		DryRun:   *dryRun,
	})
}

func runDisableCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("kernsec disable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	purge := fs.Bool("purge", false, "also remove /etc/cfm/kernsec.conf and managed sysctl file")
	dryRun := fs.Bool("dry-run", false, "show what would happen without writing")
	noRefresh := fs.Bool("no-refresh", false, "skip the bootloader refresh step")
	force := fs.Bool("force", false, "proceed even if the existing kernsec.conf is malformed or unreadable (overrides will be lost)")
	yes := fs.Bool("yes", false, "skip the interactive safety preview / confirmation (required for unattended runs)")

	if rc, done := handleFlagErr("kernsec disable", fs.Parse(args), w); done {
		return rc
	}
	return RunDisable(w, DisableOptions{
		Purge:     *purge,
		DryRun:    *dryRun,
		NoRefresh: *noRefresh,
		Force:     *force,
		AssumeYes: *yes,
	})
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: cfm kernsec [<subcommand>] [flags]

Subcommands:
  (default)           Interactive TUI on a TTY; auto-falls back to text otherwise
  live                Force the interactive TUI
  text                Plain-text audit output
  status              Alias for "text" (supports --check for monitoring)
  preview             Show what `+"`apply`"+` would do given conf + host profile
  init                Write default tier=1 /etc/cfm/kernsec.conf if absent
  apply               Write managed sysctl + boot-arg files; run sysctl --load + bootloader refresh
  disable             Persistently disable kernsec (tier=0) and strip managed boot args + sysctl rules
  monitor             Manage the periodic drift-check systemd timer (enable | disable | remove | status)
  help                Show this message

Status / text flags:
  --skip-af-alg       Skip AF_ALG bind probes
  --check             Exit non-zero on any WARN (suitable for monitoring)

Preview flags:
  --only-apply        Hide skipped rules
  --group <prefix>    Filter by group prefix (e.g. modules.net.legacy)
  --tier <0|1|2>      Override conf.Tier for this preview (0 renders every rule as OFF; 1 hides Tier 2; 2 shows all)
  --id  <ids>         Comma-separated rule IDs to include
  --skip <ids>        Comma-separated ad-hoc skip overrides (not persisted)
  --force-id <ids>    Comma-separated ad-hoc force overrides (not persisted)

Apply flags:
  --dry-run           Show what would change without writing
  --check             Exit non-zero on drift (implies no writes; for monitoring)
  --no-refresh        Skip the bootloader refresh after writing the cmdline
  --yes               Skip the interactive safety preview + confirmation (required for unattended runs)

Disable flags:
  --purge             Also remove /etc/cfm/kernsec.conf and managed sysctl file (full uninstall)
  --dry-run           Show what would happen without writing
  --no-refresh        Skip the bootloader refresh step
  --force             Proceed even if /etc/cfm/kernsec.conf is malformed or unreadable (overrides will be lost)
  --yes               Skip the interactive safety preview + confirmation (required for unattended runs)

Monitor subcommands:
  cfm kernsec monitor enable [--interval=daily]   install + enable systemd timer
  cfm kernsec monitor disable                     stop + disable timer (leave files)
  cfm kernsec monitor remove                      stop + disable + remove unit files
  cfm kernsec monitor status                      show timer + last service runs

TUI keys:
  q / Ctrl-C          Quit
  ↑/↓ or j/k          Move cursor
  Home/End or g/G     First / last row
  PgUp / PgDn         Page
  r                   Re-run audit
  t                   Drop to text mode
  /                   Filter rows by substring (display, group, or rule ID)
  c                   Clear active filter
  e / d               Hint keys — flash a pointer to `+"`cfm kernsec apply`"+` / `+"`disable`"+` (TUI write-mode is intentionally not implemented)
  ?                   Toggle help

See docs/kernsec.md for the full design.`)
}
