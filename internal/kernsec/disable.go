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

	conf, _ := loadConfForDisable()
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
		DryRun:    opts.DryRun,
		NoRefresh: opts.NoRefresh,
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

// loadConfForDisable returns the current conf if one exists, else a
// fresh in-memory tier=0 placeholder. Distinguishes the two so the
// banner can be honest about whether any per-rule overrides are being
// preserved.
func loadConfForDisable() (*Conf, string) {
	c, err := LoadConf(false)
	if err == nil {
		return c, c.Source
	}
	if errors.Is(err, os.ErrNotExist) {
		// No conf on disk — use a clean slate. We're disabling
		// something that wasn't enabled persistently; effectively a
		// no-op apply that strips any kspp.sh-era managed args.
		return &Conf{
			Tier:      0,
			Overrides: map[string]RuleOverride{},
			Source:    "(no conf — using in-memory tier=0)",
		}, "(no conf — using in-memory tier=0)"
	}
	// Other I/O errors (permission etc.) — surface to caller via the
	// applyCore path which will report and exit; we still need to
	// return *something* so we use a clean tier=0.
	return &Conf{
		Tier:      0,
		Overrides: map[string]RuleOverride{},
		Source:    fmt.Sprintf("(conf load error: %v)", err),
	}, fmt.Sprintf("(conf load error: %v)", err)
}

// purgeManagedFiles removes /etc/cfm/kernsec.conf and the managed
// sysctl file. Backup files (.cfm-kernsec.bak) are intentionally left
// in place so operators retain a manual-restore path even after a
// --purge. Idempotent: missing files are not errors.
func purgeManagedFiles(w io.Writer) error {
	for _, p := range []string{ConfPath, SysctlPath} {
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
