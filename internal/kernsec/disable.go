package kernsec

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// DisableOptions controls RunDisable behaviour.
type DisableOptions struct {
	// Purge removes /etc/cfm/kernsec.conf and the managed sysctl file
	// after the apply pass completes. Without --purge, the conf is
	// rewritten with tier=0 so the disable persists across reboots
	// and re-running `cfm kernsec apply` is a no-op.
	Purge bool
	// DryRun shows what would happen without writing.
	DryRun bool
	// NoRefresh skips the bootloader refresh step. The cmdline file
	// is still updated; operator runs the refresh later.
	NoRefresh bool
	// NoUnload skips the post-write `modprobe -r` pass that the
	// inherited applyCore runs by default. See
	// ApplyOptions.NoUnload for the semantic.
	NoUnload bool
	// Force allows disable to proceed when the existing conf cannot
	// be read or parsed. Without --force a malformed or unreadable
	// conf aborts disable rather than silently overwriting it with a
	// clean tier=0 conf (which would lose all per-rule overrides).
	Force bool
	// AssumeYes skips the safety preview / confirmation gate that
	// applyCore inherits. Required for unattended runs. Phase 6
	// audit C1.
	AssumeYes bool
	// ForceUnsafe propagates to ApplyOptions so disable can also
	// proceed when the conf carries forced-but-host-profile-skipped
	// rules. Recovery path: `--purge` removes the conf entirely and
	// sidesteps the guard; `--force-unsafe` keeps the force overrides
	// while acknowledging the breakage.
	ForceUnsafe bool
}

// RunDisable is the friendly wrapper around `tier=0 + apply`. Strips
// every kernsec-managed boot arg from the next-boot cmdline, empties
// (or removes, with --purge) the managed sysctl file, refreshes the
// bootloader. Live sysctl values stay until reboot — see
// docs/kernsec.md "tier=0 disable semantics".
//
// Without --purge: persistent — re-running `cfm kernsec apply` later
// is a no-op until the operator re-enables a tier in the conf.
// With --purge: removes /etc/cfm/kernsec.conf and the managed sysctl
// file entirely. Re-running `cfm kernsec apply` would auto-create a
// tier=1 conf via the first-run path (operator should be aware).
func RunDisable(w io.Writer, opts DisableOptions) int {
	if !opts.DryRun && os.Geteuid() != 0 {
		fmt.Fprintln(w, "kernsec disable: must run as root (use --dry-run to inspect without writing)")
		return 1
	}

	if !opts.DryRun {
		release, err := acquireKernsecLock()
		if err != nil {
			fmt.Fprintln(w, "kernsec disable:", err)
			return 1
		}
		defer release()
	}

	conf, loadErr := loadConfForDisable()
	if loadErr != nil {
		// Existing conf is malformed / permission-denied / other
		// I/O. Without --force, refuse to overwrite — silently
		// replacing it would lose every per-rule override the
		// operator wrote. With --force or --purge the user has
		// explicitly opted into discarding the file.
		if !opts.Force && !opts.Purge {
			fmt.Fprintf(w, "kernsec disable: existing conf at %s is unreadable: %v\n", ConfPath, loadErr)
			fmt.Fprintln(w, "  Refusing to overwrite — re-run with --force to write tier=0 anyway")
			fmt.Fprintln(w, "  (every per-rule override in the existing file will be lost),")
			fmt.Fprintln(w, "  or --purge to remove the file entirely.")
			return 1
		}
		fmt.Fprintf(w, "kernsec disable: existing conf at %s unreadable (%v) — proceeding with --force\n", ConfPath, loadErr)
		conf = &Conf{Tier: 0, Overrides: map[string]RuleOverride{}, Source: fmt.Sprintf("(forced overwrite; original: %v)", loadErr)}
	}
	conf.Tier = 0

	// Persist tier=0 to disk before driving applyCore — unless we're
	// going to purge it next anyway, or this is a dry-run.
	if !opts.DryRun && !opts.Purge {
		if err := WriteConf(conf); err != nil {
			fmt.Fprintln(w, "kernsec disable: write conf:", err)
			return 1
		}
	}

	// applyCore owns the banner + mode line + the closing banner. We
	// pipe in DISABLE as the label so the operator sees the intent.
	rc := applyCore(w, conf, ApplyOptions{
		DryRun:      opts.DryRun,
		NoRefresh:   opts.NoRefresh,
		NoUnload:    opts.NoUnload,
		AssumeYes:   opts.AssumeYes,
		ForceUnsafe: opts.ForceUnsafe,
	}, "DISABLE")
	if rc != 0 {
		return rc
	}

	// Disable-specific post-pass: write-conf summary, purge, manual-
	// restore reminder. Printed AFTER applyCore's closing banner so
	// it doesn't fight the apply output structure.
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[Disable]")
	switch {
	case opts.DryRun && opts.Purge:
		fmt.Fprintln(w, "  --purge --dry-run: would remove")
		fmt.Fprintln(w, "    ", ConfPath)
		fmt.Fprintln(w, "    ", SysctlPath)
		fmt.Fprintln(w, "    ", ModprobePath)
		fmt.Fprintln(w, "  (.cfm-kernsec.bak files would be left in place)")
	case opts.DryRun:
		fmt.Fprintln(w, "  --dry-run: would write tier=0 to", ConfPath)
	case opts.Purge:
		if err := purgeManagedFiles(w); err != nil {
			fmt.Fprintln(w, "kernsec disable: purge:", err)
			return 1
		}
		fmt.Fprintln(w, "  Re-run `cfm kernsec init` to start fresh, or `cfm kernsec apply` to auto-create a tier=1 conf.")
	default:
		fmt.Fprintf(w, "  Persisted tier=0 to %s.\n", ConfPath)
		fmt.Fprintln(w, "  Re-enable by editing the conf (tier=1) and running `cfm kernsec apply`.")
	}
	fmt.Fprintln(w, "  Live sysctl values stay until reboot — `sysctl --system` does not revert them to kernel defaults.")
	return 0
}

// loadConfForDisable returns the current conf if one exists, an
// in-memory tier=0 placeholder if none does, or an error if the conf
// is on disk but cannot be read or parsed. Distinguishing the three
// matters for safety: silently overwriting a malformed conf with a
// clean tier=0 file (the previous behaviour) loses every per-rule
// override the operator wrote.
//
//	(*Conf, nil)            conf loaded successfully OR no conf on
//	                        disk (placeholder returned).
//	(nil,   non-nil)        conf is on disk but unreadable / malformed.
//	                        RunDisable refuses to overwrite without
//	                        --force.
func loadConfForDisable() (*Conf, error) {
	c, err := LoadConf(false)
	if err == nil {
		return c, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		// No conf on disk — use a clean slate. We're disabling
		// something that wasn't enabled persistently; effectively a
		// no-op apply that strips any kspp.sh-era managed args.
		return &Conf{
			Tier:      0,
			Overrides: map[string]RuleOverride{},
			Source:    "(no conf — using in-memory tier=0)",
		}, nil
	}
	// Permission denied, parse error, or other I/O — surface to caller.
	return nil, err
}

// purgeManagedFiles removes /etc/cfm/kernsec.conf, the managed sysctl
// file, and the managed modprobe file. Backup files
// (.cfm-kernsec.bak) are intentionally left in place so operators
// retain a manual-restore path even after a --purge. Idempotent:
// missing files are not errors.
//
// Also tears down the periodic-drift-check systemd timer if it's
// installed (Phase 5). Skipped silently if the timer was never set up.
func purgeManagedFiles(w io.Writer) error {
	if MonitorInstalled() {
		fmt.Fprintln(w, "  monitor timer is installed — running `monitor remove` first")
		// Lock-free path: RunDisable already holds the kernsec lock
		// at this point. Going through the public RunMonitor would
		// try to acquire the lock again and self-deadlock with
		// EWOULDBLOCK (each acquireKernsecLock opens its own fd, so
		// flock() in the same process is not re-entrant).
		if rc := monitorRemoveLocked(w); rc != 0 {
			return fmt.Errorf("monitor remove returned %d", rc)
		}
	}
	for _, p := range []string{ConfPath, SysctlPath, ModprobePath} {
		if err := os.Remove(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(w, "  %s already absent\n", p)
				continue
			}
			return fmt.Errorf("remove %s: %w", p, err)
		}
		fmt.Fprintf(w, "  removed %s\n", p)
	}
	fmt.Fprintln(w, "  .cfm-kernsec.bak files left in place for manual restore.")
	return nil
}
