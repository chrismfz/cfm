package kernsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// MonitorServicePath / MonitorTimerPath are where kernsec installs the
// systemd unit files for the periodic drift check. Both managed files
// — operator should not edit by hand.
//
// Declared as var so tests can redirect to t.TempDir().
var (
	MonitorServicePath = "/etc/systemd/system/cfm-kernsec-check.service"
	MonitorTimerPath   = "/etc/systemd/system/cfm-kernsec-check.timer"
)

// MonitorUnitName is what systemctl operates on (without the .timer
// suffix; both the .service and .timer share the prefix and the timer
// is what gets enabled).
const MonitorUnitName = "cfm-kernsec-check"

// MonitorOptions controls RunMonitor.
type MonitorOptions struct {
	// Action is one of "enable", "disable", "remove", "status".
	Action string
	// Interval is the systemd OnCalendar expression. "" → "daily".
	// Other useful values: "hourly", "weekly", "*-*-* 03:00:00".
	Interval string
	// CFMBinary overrides the path written into the service ExecStart.
	// Defaults to os.Executable() at runtime.
	CFMBinary string
	// DryRun prints what would happen without writing or running
	// systemctl.
	DryRun bool
}

// RunMonitor implements `cfm kernsec monitor <action>`.
//
//	enable   write unit files, daemon-reload, enable + start the timer
//	disable  stop + disable the timer; leave unit files in place
//	remove   stop + disable + remove unit files + daemon-reload
//	status   print systemctl + last-run summary
//
// "enable" and "remove" require root. "status" is read-only and works
// as any user. "disable" is idempotent on hosts where the timer was
// never installed.
func RunMonitor(w io.Writer, opts MonitorOptions) int {
	switch opts.Action {
	case "enable":
		return monitorEnable(w, opts)
	case "disable":
		return monitorDisable(w, opts)
	case "remove":
		return monitorRemove(w, opts)
	case "status":
		return monitorStatus(w)
	case "":
		fmt.Fprintln(w, "kernsec monitor: missing action (enable | disable | remove | status)")
		return 2
	default:
		fmt.Fprintf(w, "kernsec monitor: unknown action %q (enable | disable | remove | status)\n", opts.Action)
		return 2
	}
}

func monitorEnable(w io.Writer, opts MonitorOptions) int {
	if !opts.DryRun && os.Geteuid() != 0 {
		fmt.Fprintln(w, "kernsec monitor enable: must run as root (use --dry-run to inspect)")
		return 1
	}
	binary := opts.CFMBinary
	if binary == "" {
		got, err := os.Executable()
		if err != nil {
			fmt.Fprintln(w, "kernsec monitor enable: cannot resolve cfm binary path:", err)
			return 1
		}
		binary = got
	}
	interval := opts.Interval
	if interval == "" {
		interval = "daily"
	}

	// Validate before rendering — a bogus binary path or interval
	// would otherwise be written verbatim into the systemd unit file
	// and silently break the timer (or, worst case, smuggle extra
	// directives via newline injection from --interval).
	if err := validateMonitorBinary(binary); err != nil {
		fmt.Fprintln(w, "kernsec monitor enable:", err)
		return 1
	}
	if err := validateMonitorInterval(interval); err != nil {
		fmt.Fprintln(w, "kernsec monitor enable:", err)
		return 1
	}

	service := RenderMonitorService(binary)
	timer := RenderMonitorTimer(interval)

	fmt.Fprintln(w, "===== CFM kernsec MONITOR ENABLE =====")
	fmt.Fprintf(w, "binary:   %s\n", binary)
	fmt.Fprintf(w, "interval: %s\n", interval)
	fmt.Fprintf(w, "service:  %s\n", MonitorServicePath)
	fmt.Fprintf(w, "timer:    %s\n", MonitorTimerPath)
	if opts.DryRun {
		fmt.Fprintln(w, "mode:     --dry-run (no writes)")
	}
	fmt.Fprintln(w)

	if opts.DryRun {
		fmt.Fprintln(w, "[Service file content]")
		fmt.Fprintln(w, string(service))
		fmt.Fprintln(w, "[Timer file content]")
		fmt.Fprintln(w, string(timer))
		fmt.Fprintln(w, "(dry-run; nothing written)")
		return 0
	}

	if err := AtomicWriteFile(MonitorServicePath, service, 0o644); err != nil {
		fmt.Fprintln(w, "kernsec monitor enable: write service:", err)
		return 1
	}
	fmt.Fprintf(w, "wrote %s\n", MonitorServicePath)

	if err := AtomicWriteFile(MonitorTimerPath, timer, 0o644); err != nil {
		fmt.Fprintln(w, "kernsec monitor enable: write timer:", err)
		return 1
	}
	fmt.Fprintf(w, "wrote %s\n", MonitorTimerPath)

	if err := systemctl("daemon-reload"); err != nil {
		fmt.Fprintln(w, "kernsec monitor enable: daemon-reload:", err)
		return 1
	}
	fmt.Fprintln(w, "ran systemctl daemon-reload")

	if err := systemctl("enable", "--now", MonitorUnitName+".timer"); err != nil {
		fmt.Fprintln(w, "kernsec monitor enable: enable+start timer:", err)
		return 1
	}
	fmt.Fprintf(w, "enabled and started %s.timer\n", MonitorUnitName)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Drift check now runs", interval, "via systemd. Results land in the journal:")
	fmt.Fprintln(w, "  journalctl -u", MonitorUnitName+".service", "-n 50")
	return 0
}

func monitorDisable(w io.Writer, opts MonitorOptions) int {
	if !opts.DryRun && os.Geteuid() != 0 {
		fmt.Fprintln(w, "kernsec monitor disable: must run as root (use --dry-run to inspect)")
		return 1
	}
	if opts.DryRun {
		fmt.Fprintln(w, "[Disable] would run: systemctl disable --now", MonitorUnitName+".timer")
		fmt.Fprintln(w, "(dry-run; nothing executed)")
		return 0
	}
	if err := systemctl("disable", "--now", MonitorUnitName+".timer"); err != nil {
		// disable is idempotent — if the unit was never installed,
		// systemctl returns non-zero. Treat as informational rather
		// than failure when our unit files don't exist.
		if _, statErr := os.Stat(MonitorTimerPath); statErr != nil && errors.Is(statErr, os.ErrNotExist) {
			fmt.Fprintln(w, "monitor timer unit not installed; nothing to disable")
			return 0
		}
		fmt.Fprintln(w, "kernsec monitor disable:", err)
		return 1
	}
	fmt.Fprintf(w, "stopped and disabled %s.timer\n", MonitorUnitName)
	fmt.Fprintln(w, "Unit files left in place; run `cfm kernsec monitor remove` to delete them.")
	return 0
}

func monitorRemove(w io.Writer, opts MonitorOptions) int {
	if !opts.DryRun && os.Geteuid() != 0 {
		fmt.Fprintln(w, "kernsec monitor remove: must run as root (use --dry-run to inspect)")
		return 1
	}
	if opts.DryRun {
		fmt.Fprintln(w, "[Remove] would run: systemctl disable --now", MonitorUnitName+".timer")
		fmt.Fprintln(w, "[Remove] would remove:")
		fmt.Fprintln(w, "  ", MonitorServicePath)
		fmt.Fprintln(w, "  ", MonitorTimerPath)
		fmt.Fprintln(w, "[Remove] would run: systemctl daemon-reload")
		fmt.Fprintln(w, "(dry-run; nothing executed)")
		return 0
	}

	// Stop + disable. Idempotent on hosts where the timer was never
	// installed; on hosts where it WAS installed, surface real
	// failures so the operator can investigate inconsistent systemd
	// state — but proceed with file removal regardless. Operator
	// invoked `remove` and wants the files gone; orphan files are
	// worse than transient orphan systemd state, which the
	// daemon-reload at the end will reconcile.
	timerInstalled := false
	if _, err := os.Stat(MonitorTimerPath); err == nil {
		timerInstalled = true
	}
	if err := systemctl("disable", "--now", MonitorUnitName+".timer"); err != nil {
		if timerInstalled {
			fmt.Fprintf(w, "[!] systemctl disable %s.timer: %v — proceeding with file removal\n",
				MonitorUnitName, err)
		}
		// If the timer file wasn't installed, the disable error is
		// expected ("Unit ... does not exist") — don't pollute output.
	} else {
		fmt.Fprintf(w, "stopped and disabled %s.timer\n", MonitorUnitName)
	}

	for _, p := range []string{MonitorServicePath, MonitorTimerPath} {
		if err := os.Remove(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(w, "%s already absent\n", p)
				continue
			}
			fmt.Fprintln(w, "kernsec monitor remove:", err)
			return 1
		}
		fmt.Fprintf(w, "removed %s\n", p)
	}

	if err := systemctl("daemon-reload"); err != nil {
		fmt.Fprintln(w, "kernsec monitor remove: daemon-reload:", err)
		return 1
	}
	fmt.Fprintln(w, "ran systemctl daemon-reload")
	return 0
}

func monitorStatus(w io.Writer) int {
	fmt.Fprintln(w, "===== CFM kernsec MONITOR STATUS =====")

	for _, p := range []string{MonitorServicePath, MonitorTimerPath} {
		if _, err := os.Stat(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(w, "%s: not installed\n", p)
			} else {
				fmt.Fprintf(w, "%s: stat error %v\n", p, err)
			}
			continue
		}
		fmt.Fprintf(w, "%s: present\n", p)
	}
	fmt.Fprintln(w)

	out, err := exec.Command("systemctl", "status", MonitorUnitName+".timer", "--no-pager").CombinedOutput()
	fmt.Fprintln(w, "[systemctl status "+MonitorUnitName+".timer]")
	fmt.Fprint(w, string(out))
	if err != nil {
		// Non-zero from systemctl when the unit isn't loaded; not
		// a kernsec failure.
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[Last 5 service runs from journal]")
	jout, _ := exec.Command("journalctl",
		"-u", MonitorUnitName+".service",
		"-n", "5",
		"--no-pager",
		"-o", "short-iso",
	).CombinedOutput()
	fmt.Fprint(w, string(jout))
	return 0
}

// validateMonitorBinary returns an error if the cfm binary path would
// corrupt the systemd unit's ExecStart line. systemd command-line
// parsing is whitespace-separated; rather than emit fragile escaping
// we reject paths that need it and ask the operator to symlink to a
// clean path. Tightens the threat model: anyone who can pass a custom
// --cfm-binary can write whatever they want to the unit file by
// embedding control characters; this rejects that surface.
func validateMonitorBinary(p string) error {
	if p == "" {
		return errors.New("empty cfm binary path")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("cfm binary path must be absolute (got %q)", p)
	}
	for _, r := range p {
		switch {
		case r == ' ', r == '\t', r == '\n', r == '\r', r == 0:
			return fmt.Errorf("cfm binary path contains whitespace or control character (%q) — symlink to a clean path and pass that with --cfm-binary", p)
		case r == '"', r == '\\', r == '$':
			return fmt.Errorf("cfm binary path contains systemd-special character %q in %q — symlink to a clean path", string(r), p)
		}
	}
	return nil
}

// validateMonitorInterval returns an error if the OnCalendar value
// would corrupt the systemd unit. Allowed: ASCII letters, digits,
// space, and the calendar-spec separators `, - : * . /`. This is a
// superset of every shorthand systemd recognises (`daily`, `hourly`,
// `weekly`, `*-*-* 03:00:00`, `Mon..Fri 09:00`, etc.) and excludes
// anything that could smuggle a newline / NUL / shell metacharacter
// into the unit file. systemd's own validator runs at unit-load time
// and will reject syntactically-bad calendar specs even after this
// passes — operators get a clear `systemctl daemon-reload` failure
// then, distinct from the "you wrote garbage to a unit file" surface.
func validateMonitorInterval(s string) error {
	if s == "" {
		return errors.New("empty OnCalendar value")
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == ' ', r == ',', r == '-', r == ':', r == '*', r == '.', r == '/':
		default:
			return fmt.Errorf("OnCalendar value %q contains unsupported character %q — use a systemd calendar spec or shorthand (`daily`, `hourly`, `weekly`, `*-*-* 03:00:00`)",
				s, string(r))
		}
	}
	return nil
}

// RenderMonitorService produces the systemd .service file content
// referencing the cfm binary at the supplied path.
func RenderMonitorService(cfmBinary string) []byte {
	var b strings.Builder
	b.WriteString("# Managed by cfm kernsec — do not edit by hand.\n")
	b.WriteString("# Generated by `cfm kernsec monitor enable`.\n")
	b.WriteString("# See docs/kernsec.md.\n\n")

	b.WriteString("[Unit]\n")
	b.WriteString("Description=cfm kernsec drift check\n")
	b.WriteString("Documentation=https://github.com/chrismfz/cfm/blob/main/docs/kernsec.md\n")
	b.WriteString("After=network-online.target\n\n")

	b.WriteString("[Service]\n")
	b.WriteString("Type=oneshot\n")
	fmt.Fprintf(&b, "ExecStart=%s kernsec apply --check\n", cfmBinary)
	b.WriteString("StandardOutput=journal\n")
	b.WriteString("StandardError=journal\n")
	// `apply --check` exits 0 (no drift), 1 (drift), 2 (could not
	// determine state — retry later). Drift IS a failure (alert
	// surface); exit 2 is soft-failure that the next timer fire will
	// retry, so we tell systemd to treat it as success and not flag
	// the unit as Failed in `systemctl status`.
	b.WriteString("SuccessExitStatus=2\n")
	return []byte(b.String())
}

// RenderMonitorTimer produces the systemd .timer file content firing
// on the supplied OnCalendar expression. "" → "daily".
func RenderMonitorTimer(interval string) []byte {
	if interval == "" {
		interval = "daily"
	}
	var b strings.Builder
	b.WriteString("# Managed by cfm kernsec — do not edit by hand.\n")
	b.WriteString("# Generated by `cfm kernsec monitor enable`.\n")
	b.WriteString("# See docs/kernsec.md.\n\n")

	b.WriteString("[Unit]\n")
	b.WriteString("Description=cfm kernsec drift check (periodic)\n")
	b.WriteString("Documentation=https://github.com/chrismfz/cfm/blob/main/docs/kernsec.md\n\n")

	b.WriteString("[Timer]\n")
	fmt.Fprintf(&b, "OnCalendar=%s\n", interval)
	b.WriteString("Persistent=true\n")
	b.WriteString("RandomizedDelaySec=1h\n")
	fmt.Fprintf(&b, "Unit=%s.service\n\n", MonitorUnitName)

	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=timers.target\n")
	return []byte(b.String())
}

// systemctl runs `systemctl <args...>` and returns nil on success or
// an error including the combined output.
func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// MonitorInstalled reports whether the timer unit file is present on
// disk. Used by `disable --purge` to decide whether to also tear down
// the monitor units.
func MonitorInstalled() bool {
	_, err := os.Stat(MonitorTimerPath)
	return err == nil
}
