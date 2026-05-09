package kernsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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

	// Best-effort stop/disable — ignore failures from non-existent
	// unit since remove is meant to be idempotent.
	if err := systemctl("disable", "--now", MonitorUnitName+".timer"); err == nil {
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
	// SuccessExitStatus on 0 only — drift (1) is correctly a failure.
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
