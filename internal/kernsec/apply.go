package kernsec

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

// ApplyOptions controls RunApply behaviour.
type ApplyOptions struct {
	// DryRun prints what would happen without writing or running
	// sysctl --load / bootloader refresh.
	DryRun bool
	// Check exits non-zero if any managed file or cmdline differs
	// from what apply would write. Implies no writes — the command
	// is read-only. Suitable for monitoring agents.
	Check bool
	// NoRefresh skips the post-write bootloader refresh
	// (proxmox-boot-tool refresh / update-grub). The cmdline file
	// is still updated; operator runs the refresh later.
	NoRefresh bool
}

// RunApply is the main `cfm kernsec apply` orchestration:
//
//  1. Auto-create /etc/cfm/kernsec.conf with tier=1 if absent
//     (per the user's first-run UX choice).
//  2. Load conf + run host-profile probe + Resolve.
//  3. Render the sysctl file from rules whose Decision==Apply.
//  4. Render the desired managed-keys cmdline through BootBackend.
//  5. Compare to current state; if Check, exit 0/1 based on equality.
//  6. Otherwise (and not DryRun), write everything atomically with
//     one-shot backups, then run sysctl --load and Refresh().
//  7. Run BuildAuditRows for a post-write verify pass.
//
// Phase 2b applies sysctls + boot args. Modules deferred to Phase 3.
// Module rules pass through Resolve but are not written.
func RunApply(w io.Writer, opts ApplyOptions) int {
	mustWrite := !opts.DryRun && !opts.Check
	if mustWrite && os.Geteuid() != 0 {
		fmt.Fprintln(w, "kernsec apply: must run as root (use --dry-run or --check to inspect without writing)")
		return 1
	}

	if mustWrite {
		if _, err := os.Stat(ConfPath); os.IsNotExist(err) {
			created, werr := WriteDefaultConf()
			if werr != nil {
				fmt.Fprintln(w, "kernsec apply: write default conf:", werr)
				return 1
			}
			if created {
				fmt.Fprintf(w, "Created %s with tier=1.\n", ConfPath)
			}
		}
	}

	conf, err := LoadConf(true)
	if err != nil {
		fmt.Fprintln(w, "kernsec apply: load conf:", err)
		return 1
	}
	return applyCore(w, conf, opts, "APPLY")
}

// applyCore is the conf-agnostic apply orchestration. RunApply loads
// from disk first; RunDisable constructs an in-memory tier=0 conf and
// calls in directly. label is what appears in the banner ("APPLY" or
// "DISABLE") so operator output reflects the operator's intent.
func applyCore(w io.Writer, conf *Conf, opts ApplyOptions, label string) int {
	profile := DetectHostProfile()
	rs := Resolve(conf, profile)
	sysctls := rs.ApplySysctls()
	bootArgs := rs.ApplyBootArgs()

	fs := RealFS{}
	backend := DetectBackend(fs)

	fmt.Fprintf(w, "===== CFM kernsec %s =====\n", label)
	fmt.Fprintf(w, "Conf:    %s\n", confSource(conf))
	fmt.Fprintf(w, "Tier:    %d\n", conf.Tier)
	fmt.Fprintf(w, "Backend: %s\n", backend.Label())
	fmt.Fprintf(w, "Profile: %s\n", describeProfile(profile))
	fmt.Fprintf(w, "Rules:   sysctls=%d  boot=%d  modules=%d (Phase 3)  mounts=%d (audit)\n",
		len(sysctls), len(bootArgs), count(rs.Modules, Apply), count(rs.Mounts, Apply))
	switch {
	case opts.Check:
		fmt.Fprintln(w, "Mode:    --check (no writes; exit 1 if drift)")
	case opts.DryRun:
		fmt.Fprintln(w, "Mode:    --dry-run (no writes)")
	default:
		fmt.Fprintln(w, "Mode:    apply")
	}
	fmt.Fprintln(w)

	sysctlContent := RenderSysctlFile(sysctls)
	desiredCmdline, cmdlineErr := buildDesiredCmdline(backend, bootArgs)
	if cmdlineErr != nil {
		fmt.Fprintln(w, "kernsec apply:", cmdlineErr)
		fmt.Fprintln(w, "  cannot compute desired cmdline without reading current next-boot config")
		return 1
	}

	drift := computeDrift(sysctlContent, desiredCmdline, backend)

	fmt.Fprintln(w, "[Sysctl]")
	fmt.Fprintf(w, "  target:  %s\n", SysctlPath)
	switch {
	case drift.SysctlReadErr != nil:
		fmt.Fprintf(w, "  status:  ERROR reading existing file: %v\n", drift.SysctlReadErr)
	case drift.SysctlDiffers:
		fmt.Fprintf(w, "  status:  DRIFT (would write %d bytes)\n", len(sysctlContent))
	default:
		fmt.Fprintln(w, "  status:  in sync")
	}

	fmt.Fprintln(w, "[Boot args]")
	if drift.BootReadErr != nil {
		fmt.Fprintf(w, "  status:            ERROR reading next-boot cmdline: %v\n", drift.BootReadErr)
	} else {
		fmt.Fprintf(w, "  current next-boot: %s\n", strings.TrimSpace(drift.CurrentCmdline))
		fmt.Fprintf(w, "  desired:           %s\n", strings.TrimSpace(desiredCmdline))
		if drift.BootDiffers {
			fmt.Fprintln(w, "  status:            DRIFT (would rewrite cmdline)")
		} else {
			fmt.Fprintln(w, "  status:            in sync")
		}
	}
	fmt.Fprintln(w)

	if opts.Check {
		if drift.SysctlDiffers || drift.BootDiffers ||
			drift.SysctlReadErr != nil || drift.BootReadErr != nil {
			fmt.Fprintln(w, "[!] drift detected — exit 1")
			return 1
		}
		fmt.Fprintln(w, "[+] no drift")
		return 0
	}

	if opts.DryRun {
		fmt.Fprintln(w, "(dry-run; nothing written)")
		fmt.Fprintln(w, "===========================")
		return 0
	}

	if drift.BootReadErr != nil {
		fmt.Fprintln(w, "kernsec apply: refusing to write — cannot read current cmdline")
		return 1
	}

	// Write sysctl.
	if err := WriteSysctlFile(sysctlContent); err != nil {
		fmt.Fprintln(w, "kernsec apply: write sysctl:", err)
		return 1
	}
	if err := LoadSysctl(); err != nil {
		fmt.Fprintln(w, "kernsec apply: sysctl --load:", err)
		return 1
	}
	fmt.Fprintf(w, "[Sysctl] wrote %s and ran sysctl --load.\n", SysctlPath)

	// Write boot args.
	if err := backend.WriteCmdline(bootArgs); err != nil {
		fmt.Fprintln(w, "kernsec apply: write cmdline:", err)
		return 1
	}
	fmt.Fprintf(w, "[Boot args] rewrote next-boot cmdline via %s.\n", backend.Label())

	if !opts.NoRefresh {
		if err := backend.Refresh(); err != nil {
			fmt.Fprintln(w, "kernsec apply: bootloader refresh:", err)
			return 1
		}
		fmt.Fprintln(w, "[Boot args] bootloader refreshed.")
	} else {
		fmt.Fprintln(w, "[Boot args] --no-refresh: skipping bootloader refresh; run it yourself before reboot.")
	}

	// Post-write verify.
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[Verification]")
	verifyAfterApply(w)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[!] Boot-arg changes require reboot before they appear in /proc/cmdline.")
	fmt.Fprintln(w, "===========================")
	return 0
}

type driftResult struct {
	SysctlDiffers  bool
	BootDiffers    bool
	CurrentCmdline string
	// BootReadErr is non-nil when the next-boot cmdline could not be
	// read from the bootloader. The drift compare then defaults to
	// "differs" (apply will refuse) but the error is surfaced to the
	// operator so they don't think the system is in sync.
	BootReadErr error
	// SysctlReadErr is non-nil when the existing managed sysctl file
	// is unreadable for a reason other than absence (permission etc.).
	SysctlReadErr error
}

// computeDrift compares the desired sysctl content + cmdline against
// what's on disk / in the bootloader config right now.
func computeDrift(sysctlContent []byte, desiredCmdline string, backend BootBackend) driftResult {
	res := driftResult{}

	got, err := os.ReadFile(SysctlPath)
	switch {
	case err == nil:
		res.SysctlDiffers = !bytes.Equal(got, sysctlContent)
	case os.IsNotExist(err):
		res.SysctlDiffers = true
	default:
		res.SysctlDiffers = true
		res.SysctlReadErr = err
	}

	current, err := backend.NextBootCmdline()
	if err != nil {
		res.BootReadErr = err
		res.BootDiffers = true
		return res
	}
	res.CurrentCmdline = current
	res.BootDiffers = !sameTokens(ParseCmdline(current), ParseCmdline(desiredCmdline))

	return res
}

// buildDesiredCmdline computes what the next-boot cmdline would be
// after WriteCmdline ran, without actually writing anything. Used by
// preview / dry-run / check. Returns an error if the current cmdline
// cannot be read — silently defaulting to empty here would cause apply
// to compute a cmdline containing only managed args (dropping root=,
// ro, console=, etc).
func buildDesiredCmdline(backend BootBackend, args []BootArg) (string, error) {
	current, err := backend.NextBootCmdline()
	if err != nil {
		return "", fmt.Errorf("read current cmdline: %w", err)
	}
	tokens := rebuildManagedCmdline(ParseCmdline(current), args)
	return strings.Join(tokens, " "), nil
}

// sameTokens reports whether two token lists contain exactly the same
// elements in any order. Order on the kernel cmdline doesn't affect
// runtime behaviour, so we treat reordered cmdlines as identical.
func sameTokens(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := make(map[string]int, len(a))
	for _, x := range a {
		count[x]++
	}
	for _, x := range b {
		count[x]--
		if count[x] < 0 {
			return false
		}
	}
	return true
}

// verifyAfterApply runs the audit rows pass and reports pass/fail.
// Boot-arg rules will show as PEND/WARN until reboot — that's
// expected; we tag them clearly rather than treating them as a
// failure.
func verifyAfterApply(w io.Writer) {
	rows := BuildAuditRows()
	var sysctlBad, bootPending int
	for _, r := range rows {
		switch r.Kind {
		case KindSysctl:
			if r.State != StateOK && r.State != StateSKIP {
				sysctlBad++
			}
		case KindBoot:
			if r.State != StateOK {
				bootPending++
			}
		}
	}
	if sysctlBad == 0 {
		fmt.Fprintln(w, "  sysctl: all rules active (or not exposed by this kernel)")
	} else {
		fmt.Fprintf(w, "  sysctl: %d rules failed verification — investigate (sysctl --load output above)\n",
			sysctlBad)
	}
	if bootPending == 0 {
		fmt.Fprintln(w, "  boot:   all rules active in current /proc/cmdline (no reboot needed)")
	} else {
		fmt.Fprintf(w, "  boot:   %d rules pending reboot (configured for next boot, not yet active)\n",
			bootPending)
	}
}
