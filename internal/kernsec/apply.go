package kernsec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"cfm/internal/managedsysctl"
)

// ApplyOptions controls RunApply behaviour.
type ApplyOptions struct {
	// DryRun prints what would happen without writing or running
	// runtime sysctl apply / bootloader refresh.
	DryRun bool
	// Check exits non-zero if any managed file or cmdline differs
	// from what apply would write. Implies no writes — the command
	// is read-only. Suitable for monitoring agents.
	Check bool
	// NoRefresh skips the post-write bootloader refresh
	// (proxmox-boot-tool refresh / update-grub). The cmdline file
	// is still updated; operator runs the refresh later.
	NoRefresh bool
	// AssumeYes skips the safety preview + interactive confirmation
	// gate. Required for unattended (cron / Ansible / shell-script)
	// invocations. When false (default), interactive applies print
	// a "[!] about to mutate" preview and require a `y` answer
	// before any write happens. Phase 6 audit C1.
	AssumeYes bool
	// ForceUnsafe acknowledges that one or more rules in the conf
	// carry `state = force` overrides for groups the host-profile
	// would have skipped (e.g. forcing llc blacklist on a Docker
	// host, or forcing tier2.oops on a KVM hypervisor). Apply refuses
	// to proceed in that case unless this flag is set — the same
	// "I really mean it" pattern as --no-verify on a failing
	// pre-commit hook. Does NOT bypass any other safety check.
	ForceUnsafe bool
	// NoUnload disables the post-write `modprobe -r` pass over the
	// managed-and-loaded module set. By default kernsec calls
	// `modprobe -r` on every module it just blacklisted that is
	// currently in /proc/modules, so the running-kernel attack
	// surface closes the same minute apply runs (Fragnesia / Dirty
	// Frag class). BUSY modules (refcount > 0, an in-use IPsec host
	// that operator-forced through the HasIPsec gate, etc.) are
	// reported and otherwise ignored — the blacklist on disk
	// guarantees they don't come back, and reboot finishes the job.
	// Set NoUnload to keep the older "write config, operator unloads
	// manually" behaviour.
	NoUnload bool
	// Stdin is where the confirmation prompt reads from. Default
	// (nil) means os.Stdin via the prompt helper. Tests inject a
	// strings.Reader.
	Stdin io.Reader
}

// RunApply is the main `cfm kernsec apply` orchestration:
//
//  1. Auto-create /etc/cfm/kernsec.conf with tier=1 if absent
//     (per the user's first-run UX choice).
//  2. Load conf + run host-profile probe + Resolve.
//  3. Render the sysctl file from rules whose Decision==Apply.
//  4. Render the desired managed-keys cmdline through BootBackend.
//  5. Compare to current state; if Check, exit 0/1 based on equality.
//  6. Otherwise (and not DryRun), write managed files in
//     transaction-safe order — file writes first (reversible),
//     bootloader refresh next, runtime sysctl apply LAST. The sysctl apply
//     is the only step that mutates the running kernel; ordering it
//     last means a failure in the more-fragile bootloader path does
//     NOT leave Tier 2 sysctls (e.g. user.max_user_namespaces=0)
//     active in the running kernel with no drop-in file to roll
//     back from.
//  7. Run BuildAuditRows for a post-write verify pass.
func RunApply(w io.Writer, opts ApplyOptions) int {
	mustWrite := !opts.DryRun && !opts.Check
	if mustWrite && os.Geteuid() != 0 {
		fmt.Fprintln(w, "kernsec apply: must run as root (use --dry-run or --check to inspect without writing)")
		return 1
	}

	if mustWrite {
		release, err := acquireKernsecLock()
		if err != nil {
			fmt.Fprintln(w, "kernsec apply:", err)
			return 1
		}
		defer release()

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
	rc := applyCore(w, conf, opts, "APPLY")
	return rc
}

// applyCore is the conf-agnostic apply orchestration. RunApply loads
// from disk first; RunDisable constructs an in-memory tier=0 conf and
// calls in directly. label is what appears in the banner ("APPLY" or
// "DISABLE") so operator output reflects the operator's intent.
//
// BLS divergence (two installed kernels with mismatched managed args)
// is auto-reconciled: WriteCmdline writes the same desired managed set
// to every non-recovery kernel, so calling it on a divergent host
// aligns all entries. applyCore prints a RECONCILE note for visibility
// and proceeds with the write.
func applyCore(w io.Writer, conf *Conf, opts ApplyOptions, label string) int {
	profile := DetectHostProfile()
	rs := Resolve(conf, profile)
	sysctls := rs.ApplySysctls()
	bootArgs := rs.ApplyBootArgs()
	modules := rs.ApplyModules()

	fs := RealFS{}
	backend := DetectBackend(fs)

	fmt.Fprintf(w, "===== CFM kernsec %s =====\n", label)
	fmt.Fprintf(w, "Conf:    %s\n", confSource(conf))
	fmt.Fprintf(w, "Tier:    %d\n", conf.Tier)
	fmt.Fprintf(w, "Backend: %s\n", backend.Label())
	fmt.Fprintf(w, "Profile: %s\n", describeProfile(profile))
	if warnings := ValidateConfOverrideIDs(conf); len(warnings) > 0 {
		fmt.Fprintln(w)
		for _, msg := range warnings {
			fmt.Fprintf(w, "[!] %s\n", msg)
		}
		fmt.Fprintln(w)
	}
	reportCrossComponentConflicts(w, sysctls)
	fmt.Fprintf(w, "Rules:   sysctls=%d  boot=%d  modules=%d  mounts=%d (audit)\n",
		len(sysctls), len(bootArgs), len(modules), count(rs.Mounts, Apply))
	switch {
	case opts.Check:
		fmt.Fprintln(w, "Mode:    --check (no writes; exit 1 if drift)")
	case opts.DryRun:
		fmt.Fprintln(w, "Mode:    --dry-run (no writes)")
	default:
		fmt.Fprintln(w, "Mode:    apply")
	}
	fmt.Fprintln(w)

	// Safety guard: refuse to blacklist boot-critical modules even
	// if a future PR's curated rule data slipped one in. Runs BEFORE
	// any rendering so the operator sees the rejection immediately.
	if err := CheckSafeModuleRules(modules); err != nil {
		fmt.Fprintln(w, err)
		return 1
	}

	// Unsafe-force guard: refuse when the conf forces a rule the
	// host-profile gate would have skipped (e.g. force llc blacklist
	// on a Docker host, force tier2.oops on a KVM hypervisor).
	// Operator must add --force-unsafe to acknowledge the breakage
	// they're asking for. Mode==check / dry-run do NOT trigger the
	// refusal: they're read-only and the warning is still printed.
	unsafe := unsafeForcedRules(rs)
	if len(unsafe) > 0 {
		reportUnsafeForces(w, unsafe)
		if !opts.Check && !opts.DryRun && !opts.ForceUnsafe {
			fmt.Fprintln(w, "kernsec apply: refusing to apply unsafe forced rules without --force-unsafe.")
			fmt.Fprintln(w, "  Resolve by removing the [rule \"...\"] / state = force section(s) from kernsec.conf,")
			fmt.Fprintln(w, "  setting state = skip explicitly, or re-running with --force-unsafe to acknowledge the breakage.")
			return 1
		}
	}

	sysctlContent := RenderSysctlFile(sysctls)
	modprobeContent := RenderModprobeFile(modules)
	desiredCmdline, cmdlineErr := buildDesiredCmdlineWithConf(backend, bootArgs, conf)
	// BLS divergence is auto-reconciled — WriteCmdline writes the
	// desired managed set to every non-recovery kernel, aligning all
	// entries on the next pass. Other cmdline-read failures remain
	// fatal: writing a cmdline blind to current state is unsafe.
	var bootReconcileReason string
	if cmdlineErr != nil {
		if errors.Is(cmdlineErr, ErrBLSDivergence) {
			bootReconcileReason = cmdlineErr.Error()
		} else {
			fmt.Fprintln(w, "kernsec apply:", cmdlineErr)
			fmt.Fprintln(w, "  cannot compute desired cmdline without reading current next-boot config")
			return 1
		}
	}

	drift := computeDrift(sysctlContent, desiredCmdline, backend)
	drift.BootReconcileReason = bootReconcileReason
	drift.ModprobeDiffers, drift.ModprobeReadErr = modprobeDriftCheck(modprobeContent)
	// Foreign drop-in conflicts: leftover copies of a reconcile-eligible
	// key (e.g. fs.protected_regular=2 in the legacy 99-kspp.conf) that
	// would override kernsec on the next reboot. Detected read-only here;
	// neutralised in applyWrites. Folded into drift so `--check`/monitor
	// flag the latent revert even when kernsec's own file already matches.
	foreignConflicts := detectForeignSysctlConflicts(sysctls)
	drift.ForeignSysctlConflicts = len(foreignConflicts)
	loadedManaged := loadedAndManaged(modules)

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
	reportForeignConflicts(w, foreignConflicts)

	fmt.Fprintln(w, "[Boot args]")
	switch {
	case drift.BootReadErr != nil:
		fmt.Fprintf(w, "  status:            ERROR reading next-boot cmdline: %v\n", drift.BootReadErr)
	default:
		fmt.Fprintf(w, "  current next-boot: %s\n", strings.TrimSpace(drift.CurrentCmdline))
		fmt.Fprintf(w, "  desired:           %s\n", strings.TrimSpace(desiredCmdline))
		switch {
		case bootReconcileReason != "":
			fmt.Fprintln(w, "  status:            RECONCILE — BLS entries diverge; apply will align all kernels")
			fmt.Fprintf(w, "  detail:            %s\n", bootReconcileReason)
		case drift.BootDiffers:
			fmt.Fprintln(w, "  status:            DRIFT (would rewrite cmdline)")
		default:
			fmt.Fprintln(w, "  status:            in sync")
		}
	}

	fmt.Fprintln(w, "[Modules]")
	fmt.Fprintf(w, "  target:  %s\n", ModprobePath)
	switch {
	case drift.ModprobeReadErr != nil:
		fmt.Fprintf(w, "  status:  ERROR reading existing file: %v\n", drift.ModprobeReadErr)
	case drift.ModprobeDiffers:
		fmt.Fprintf(w, "  status:  DRIFT (would write %d bytes)\n", len(modprobeContent))
	default:
		fmt.Fprintln(w, "  status:  in sync")
	}
	if len(loadedManaged) > 0 {
		fmt.Fprintf(w, "  loaded:  %d managed modules currently loaded — reboot or rmmod required:\n", len(loadedManaged))
		for _, name := range loadedManaged {
			fmt.Fprintf(w, "             %s\n", name)
		}
	}
	fmt.Fprintln(w)

	if opts.Check {
		switch classifyCheckResult(drift) {
		case 2:
			fmt.Fprintln(w, "[!] could not determine state — exit 2 (retry later)")
			return 2
		case 1:
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

	// Phase 6 audit C1: interactive safety gate. Mutating operations
	// (apply, disable when not --dry-run / --check) print a summary
	// of every file kernsec is about to mutate, and require a `y`
	// answer before any write. --yes (or AssumeYes) skips the gate
	// for unattended runs (cron, Ansible, shell-script wrappers).
	//
	// Skip the gate when there's nothing to write (no drift) — the
	// apply call is then equivalent to a `--check` and shouldn't
	// pester the operator. drift.SysctlDiffers / BootDiffers /
	// ModprobeDiffers cover the three managed surfaces. A BLS
	// divergence forces a write even if drift.BootDiffers is false
	// for the first entry, since the stale entries still need aligning.
	// Mount rules that are about to be enabled (CanEnable + Apply
	// decision). Surfaced in the preflight summary so the operator
	// sees the planned fstab edit + live remount before approving.
	// Tracked here at top level so applyWrites can re-use the same
	// list and the disable path (tier=0 -> all SkipByTier) gets a
	// nil slice, suppressing the mount section in the summary.
	var mountsToEnable []MountRule
	if len(rs.Mounts) == len(Tier1Mounts) {
		for i, m := range Tier1Mounts {
			if !m.CanEnable {
				continue
			}
			if rs.Mounts[i].Decision == Apply {
				mountsToEnable = append(mountsToEnable, m)
			}
		}
	}
	mutating := drift.SysctlDiffers || drift.BootDiffers || drift.ModprobeDiffers || bootReconcileReason != "" || len(mountsToEnable) > 0 || len(foreignConflicts) > 0
	if mutating && !opts.AssumeYes {
		preflightSummary(w, label, sysctls, bootArgs, modules, profile, mountsToEnable)
		ok, err := confirmApply(w, opts.Stdin)
		if err != nil {
			fmt.Fprintln(w, "kernsec apply: confirmation read error:", err)
			return 1
		}
		if !ok {
			fmt.Fprintln(w, "kernsec apply: aborted by operator (no changes written).")
			return 0
		}
	}

	loader := func() error { return LoadSysctlTo(w) }
	if rc := applyWrites(w, backend, sysctlContent, modprobeContent, bootArgs, loadedManaged, opts, bootReconcileReason, loader, rs); rc != 0 {
		return rc
	}

	// Post-write verify.
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[Verification]")
	verifyAfterApply(w, conf, profile)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[!] Boot-arg changes require reboot before they appear in /proc/cmdline.")
	fmt.Fprintln(w, "===========================")
	return 0
}

// applyWrites runs the mutating phase of apply in transaction-safe
// order:
//
//  1. Write sysctl drop-in file (not applied yet — file on disk
//     is a no-op for the running kernel until apply parses it).
//  2. Write modprobe drop-in file (idempotent file write; reboot
//     required before blacklist takes effect anyway).
//  3. Write next-boot cmdline via the bootloader backend (writes a
//     config file or grubby invocation; takes effect on next boot).
//  4. Refresh the bootloader (rebuilds grub.cfg / runs
//     proxmox-boot-tool).  Skipped under --no-refresh.
//  5. Runtime sysctl apply LAST. This is the only step that mutates the
//     running kernel.  If anything in steps 1-4 fails the loader is
//     never invoked, so the host's runtime state is unchanged from
//     before apply ran. The drop-in files may exist on disk; the
//     operator can re-run apply (idempotent) or remove them by hand.
//
// `loader` is injected so fault-injection tests can verify the LAST
// invariant (LoadSysctl does NOT run when an earlier step fails).
// Production callers pass kernsec.LoadSysctl.
//
// Returns 0 on full success, 1 on any failure (after printing a
// human-readable error to w).
func applyWrites(
	w io.Writer,
	backend BootBackend,
	sysctlContent []byte,
	modprobeContent []byte,
	bootArgs []BootArg,
	loadedManaged []string,
	opts ApplyOptions,
	bootReconcileReason string,
	loader func() error,
	resolved ResolvedSet,
) int {
	// 1. Sysctl drop-in file.
	if err := WriteSysctlFile(w, sysctlContent); err != nil {
		fmt.Fprintln(w, "kernsec apply: write sysctl:", err)
		return 1
	}
	fmt.Fprintf(w, "[Sysctl] wrote %s (not yet applied).\n", SysctlPath)

	// 1b. Foreign drop-in reconcile. Neutralise conflicting copies of a
	// reconcile-eligible key (e.g. fs.protected_regular=2 in the legacy
	// 99-kspp.conf) so kernsec's value settles across reboot instead of
	// being overridden by a later-sorting foreign file. Best-effort:
	// never aborts apply (the loader below still sets the live value).
	neutraliseForeignSysctls(w, detectForeignSysctlConflicts(resolved.ApplySysctls()))

	// 2. Modprobe blacklist file.
	if err := WriteModprobeFile(w, modprobeContent); err != nil {
		fmt.Fprintln(w, "kernsec apply: write modprobe:", err)
		return 1
	}
	fmt.Fprintf(w, "[Modules] wrote %s.\n", ModprobePath)

	// 2b. Default-on unload pass: `modprobe -r` each managed module
	// that's currently loaded. Closes the running-kernel window
	// (Fragnesia / Dirty Frag class) the same minute apply runs.
	// BUSY/BUILTIN/ERROR rows are reported and ignored — the
	// blacklist on disk persists either way, and reboot finishes
	// any holdouts. NoUnload preserves the older "operator unloads
	// manually" behaviour for callers that need it.
	if len(loadedManaged) > 0 {
		if opts.NoUnload {
			fmt.Fprintf(w, "[Modules] %d managed modules already loaded — --no-unload set; reboot or `modprobe -r` required for them to be effective:\n",
				len(loadedManaged))
			for _, name := range loadedManaged {
				fmt.Fprintf(w, "            %s\n", name)
			}
		} else {
			renderUnloadReport(w, UnloadManaged(loadedManaged))
		}
	}

	// 3. Bootloader cmdline. On BLS divergence (managed args mismatched
	// across installed kernels), WriteCmdline writes the desired set to
	// every non-recovery kernel, so a single apply pass aligns all
	// entries. Recovery / debug entries are excluded by the backend.
	if bootReconcileReason != "" {
		fmt.Fprintln(w, "[Boot args] reconciling divergent BLS entries:")
		fmt.Fprintf(w, "  %s\n", bootReconcileReason)
	}
	if err := backend.WriteCmdline(bootArgs); err != nil {
		fmt.Fprintln(w, "kernsec apply: write cmdline:", err)
		fmt.Fprintln(w, "  sysctl drop-in is on disk but NOT applied; runtime state unchanged.")
		return 1
	}
	fmt.Fprintf(w, "[Boot args] rewrote next-boot cmdline via %s.\n", backend.Label())

	// 4. Bootloader refresh.
	switch {
	case !opts.NoRefresh:
		if err := backend.Refresh(); err != nil {
			fmt.Fprintln(w, "kernsec apply: bootloader refresh:", err)
			fmt.Fprintln(w, "  cmdline is written but bootloader has NOT picked it up.")
			// SAFETY (Phase 6 audit M1): for file-backed boot
			// backends, refresh is what propagates the just-written
			// next-boot cmdline into the bootloader state. If refresh
			// fails and we leave the modified source file on disk, the
			// NEXT legitimate operator/kernel-package refresh can pick
			// up the half-applied cmdline. Restore a safe source-file
			// state BEFORE returning the error — the operator sees the
			// failure and can retry from clean boot config.
			//
			// BLS backend has no rollback (grubby committed in
			// WriteCmdline; Refresh is a no-op there).
			switch backend.(type) {
			case *GRUBBackend:
				if rerr := restoreGrubFromBackup(); rerr != nil {
					fmt.Fprintf(w, "  WARNING: rollback of %s failed: %v\n", PathDefaultGrub, rerr)
					printManualGRUBRecovery(w)
				} else {
					fmt.Fprintf(w, "  rolled back %s from %s%s.\n", PathDefaultGrub, PathDefaultGrub, BackupSuffix)
				}
			case *ProxmoxBackend:
				if rerr := restoreProxmoxCmdlineAfterRefreshFailure(); rerr != nil {
					fmt.Fprintf(w, "  WARNING: rollback of %s failed: %v\n", PathPVECmdline, rerr)
					printManualProxmoxRecovery(w)
				} else {
					fmt.Fprintf(w, "  rolled back %s to a safe retry state.\n", PathPVECmdline)
				}
			}
			fmt.Fprintln(w, "  re-run `cfm kernsec apply` or refresh the bootloader manually before reboot.")
			fmt.Fprintln(w, "  sysctl drop-in is on disk but NOT applied; runtime state unchanged.")
			return 1
		}
		fmt.Fprintln(w, "[Boot args] bootloader refreshed.")
	default:
		fmt.Fprintln(w, "[Boot args] --no-refresh: skipping bootloader refresh; run it yourself before reboot.")
	}

	// 5. Runtime sysctl apply LAST: the only step that mutates the running kernel.
	if err := loader(); err != nil {
		fmt.Fprintln(w, "kernsec apply: runtime sysctl apply:", err)
		fmt.Fprintln(w, "  Only the key(s) named above were rejected; every other rule applied normally.")
		fmt.Fprintln(w, "  Files are on disk and the bootloader is updated, so the rejected key(s) are the only drift.")
		fmt.Fprintln(w, "  Inspect with `sysctl -a` / `cfm kernsec status` and re-run apply once the cause is fixed.")
		return 1
	}
	fmt.Fprintln(w, "[Sysctl] runtime sysctl apply completed via per-key sysctl -w (rules now live; any kernel-locked keys printed above will land after reboot).")

	// 6. Mount apply (CanEnable rules only). Strictly opt-in per-rule:
	// only mount rules whose .CanEnable is true get an automated
	// /etc/fstab edit + daemon-reload + remount. /tmp and /var/tmp
	// stay tip-only — only /dev/shm meets the safety bar today (no
	// on-disk state to migrate; tmpfs remount preserves contents;
	// kernel noexec is a soft flag).
	//
	// Resolver decision drives the direction:
	//   Apply        → EnableMount  (adds managed opts + remounts)
	//   SkipByTier
	//   SkipByConf   → DisableMount (strips managed opts + remounts)
	// SkipByHostProfile is also disable — the profile says don't apply
	// this rule on this host, so a previous apply's edits should be
	// rolled back. Keeps `cfm kernsec disable` and per-rule skips
	// symmetric without a separate disable code path.
	mountFailures := 0
	if len(resolved.Mounts) == len(Tier1Mounts) {
		for i, m := range Tier1Mounts {
			if !m.CanEnable {
				continue
			}
			rr := resolved.Mounts[i]
			switch rr.Decision {
			case Apply:
				if err := EnableMount(m, w, EnableMountOptions{}); err != nil {
					fmt.Fprintf(w, "kernsec apply: mount %s: %v\n", m.MountPoint, err)
					mountFailures++
				}
			case SkipByTier, SkipByConf, SkipByHostProfile:
				if err := DisableMount(m, w, EnableMountOptions{}); err != nil {
					fmt.Fprintf(w, "kernsec apply: mount %s (disable): %v\n", m.MountPoint, err)
					mountFailures++
				}
			}
		}
	}
	if mountFailures > 0 {
		fmt.Fprintln(w, "  Sysctl / boot / modules changes are persisted; mount apply(s) above failed.")
		fmt.Fprintln(w, "  Re-run apply once the mount cause is fixed (e.g. resolve the fstab conflict).")
		return 1
	}
	return 0
}

type driftResult struct {
	SysctlDiffers   bool
	BootDiffers     bool
	ModprobeDiffers bool
	CurrentCmdline  string
	// BootReconcileReason is non-empty when BLS entries could be read but
	// disagree on kernsec-managed arguments. That is actionable drift for
	// --check/monitor even if the first entry already matches desired state.
	BootReconcileReason string
	// BootReadErr is non-nil when the next-boot cmdline could not be
	// read from the bootloader. The drift compare then defaults to
	// "differs" (apply will refuse) but the error is surfaced to the
	// operator so they don't think the system is in sync.
	BootReadErr error
	// SysctlReadErr is non-nil when the existing managed sysctl file
	// is unreadable for a reason other than absence (permission etc.).
	SysctlReadErr error
	// ModprobeReadErr is non-nil when the existing managed modprobe
	// file is unreadable for a reason other than absence.
	ModprobeReadErr error
	// ForeignSysctlConflicts is the count of active assignments in
	// FOREIGN sysctl files (not kernsec's own drop-in) that set a
	// reconcile-eligible key to a value kernsec doesn't accept — e.g.
	// a leftover `fs.protected_regular=2` in the legacy 99-kspp.conf
	// that would override kernsec on the next reboot. Non-zero is
	// actionable drift: apply neutralises those lines.
	ForeignSysctlConflicts int
}

// classifyCheckResult maps a driftResult to the `apply --check` exit
// code:
//
//	0 — no drift; the host matches what apply would write.
//	1 — drift detected; an apply pass is needed.
//	2 — indeterminate; one of the sources of truth (sysctl drop-in,
//	    bootloader cmdline, modprobe drop-in) could not be read, so
//	    drift cannot be determined. Monitoring agents should retry on
//	    the next timer fire instead of paging operators.
//
// Read errors take precedence over drift: if the bootloader is
// unreadable we genuinely don't know whether drift exists, so
// reporting "drift detected" would be a lie. The systemd unit emitted
// by `cfm kernsec monitor enable` sets `SuccessExitStatus=2` so exit 2
// doesn't surface as a Failed unit.
func classifyCheckResult(d driftResult) int {
	switch {
	case d.SysctlReadErr != nil, d.BootReadErr != nil, d.ModprobeReadErr != nil:
		return 2
	case d.SysctlDiffers, d.BootDiffers, d.ModprobeDiffers, d.BootReconcileReason != "", d.ForeignSysctlConflicts > 0:
		return 1
	}
	return 0
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
	// BLS divergence is a recoverable signal, not a read error: the
	// backend still returns the first entry's args. applyCore handles
	// the auto-reconcile separately; here we just treat the read as
	// successful for drift accounting against the first entry.
	if err != nil && !errors.Is(err, ErrBLSDivergence) {
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
//
// BLS divergence is special: NextBootCmdline still returns the first
// entry's args alongside ErrBLSDivergence, so we propagate both the
// computed desired cmdline AND the wrapped error. Callers that want to
// auto-reconcile can ignore err==ErrBLSDivergence and proceed to write;
// callers that want to halt can check errors.Is(err, ErrBLSDivergence).
func buildDesiredCmdline(backend BootBackend, args []BootArg) (string, error) {
	return buildDesiredCmdlineWithConf(backend, args, nil)
}

// buildDesiredCmdlineWithConf is the conf-aware variant. KSEC-LSM-bpf-001
// is the only rule today that depends on conf overrides at cmdline-build
// time (it merges `bpf` into the existing lsm= value rather than
// replacing it via ManagedBootArgKeys), so the conf is plumbed in
// here. When conf is nil the merger is a no-op.
//
// Important: the not-forced branch is INTENTIONALLY a no-op. The `lsm`
// key is not in ManagedBootArgKeys (rebuildManagedCmdline preserves
// it byte-for-byte from the operator's current cmdline). Running
// UnmergeLSMBPF here on every apply would silently strip
// operator-added `bpf` from the lsm= value on Debian/Ubuntu hosts
// where the operator enabled BPF LSM manually before installing cfm,
// violating the contract in profile.go that operator args outside
// ManagedBootArgKeys are not rewritten. The unmerge is therefore
// only invoked from the explicit kernsec disable path (see
// disable.go), where the operator has asked us to roll back.
func buildDesiredCmdlineWithConf(backend BootBackend, args []BootArg, conf *Conf) (string, error) {
	current, err := backend.NextBootCmdline()
	if err != nil && !errors.Is(err, ErrBLSDivergence) {
		return "", fmt.Errorf("read current cmdline: %w", err)
	}
	tokens := rebuildManagedCmdline(ParseCmdline(current), args)
	if IsLSMBPFForced(conf) {
		tokens = MergeLSMBPF(tokens)
	}
	return strings.Join(tokens, " "), err
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

// modprobeDriftCheck compares the desired modprobe content with what's
// at ModprobePath. Returns (differs, readErr).
func modprobeDriftCheck(desired []byte) (bool, error) {
	got, err := os.ReadFile(ModprobePath)
	switch {
	case err == nil:
		return !bytes.Equal(got, desired), nil
	case os.IsNotExist(err):
		// Absent → differs (apply needs to write); not an error.
		return true, nil
	default:
		return true, err
	}
}

// loadedAndManaged returns the names of modules that the desired
// rule set blacklists AND that are currently loaded — i.e. the set
// the operator needs to rmmod or reboot to make the blacklist
// actually effective.
func loadedAndManaged(modules []ModuleRule) []string {
	if len(modules) == 0 {
		return nil
	}
	loaded := LoadedModules()
	out := make([]string, 0, len(modules))
	for _, m := range modules {
		if _, ok := loaded[m.Name]; ok {
			out = append(out, m.Name)
		}
	}
	return out
}

// unloadSummaryLine extracts the one-line unload summary that
// renderUnloadReport prints (e.g. "5 unloaded, 1 busy (will clear at
// reboot). Blacklist on disk persists across reboot."). Used by the
// TUI to surface the same status in its bottom-bar flash without
// dumping the full apply transcript on top of the rule table.
//
// Returns "" if no summary line is present (NoUnload set, no managed
// modules were loaded, etc.).
func unloadSummaryLine(applyOutput string) string {
	for _, ln := range strings.Split(applyOutput, "\n") {
		ln = strings.TrimSpace(ln)
		const marker = "[Modules]"
		if !strings.HasPrefix(ln, marker) {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(ln, marker))
		// Match the summary line specifically — both single-status
		// ("5 unloaded.") and multi-status ("5 unloaded, 1 busy …")
		// shapes start with a digit, which lets us skip the header
		// "[Modules] unload pass (modprobe -r) over N module(s):"
		// without parsing it.
		if body == "" || body[0] < '0' || body[0] > '9' {
			continue
		}
		return body
	}
	return ""
}

// renderUnloadReport prints the per-module rows from the default-on
// unload pass plus a one-line summary. Kept here (next to its only
// caller in applyWrites) so the formatting stays in sync with the
// rest of the [Modules] section. Builtin/error counts get their own
// summary tally so the operator notices them even in a noisy run.
func renderUnloadReport(w io.Writer, results []UnloadResult) {
	if len(results) == 0 {
		return
	}
	var unloaded, busy, builtin, notLoaded, errored int
	for _, r := range results {
		switch r.State {
		case UnloadStateUnloaded:
			unloaded++
		case UnloadStateBusy:
			busy++
		case UnloadStateBuiltin:
			builtin++
		case UnloadStateNotLoaded:
			notLoaded++
		case UnloadStateError:
			errored++
		}
	}
	fmt.Fprintf(w, "[Modules] unload pass (modprobe -r) over %d managed-and-loaded module(s):\n",
		len(results))
	for _, r := range results {
		if r.Detail != "" {
			fmt.Fprintf(w, "            %-10s %-16s %s\n", r.State, r.Name, r.Detail)
		} else {
			fmt.Fprintf(w, "            %-10s %s\n", r.State, r.Name)
		}
	}
	var parts []string
	if unloaded > 0 {
		parts = append(parts, fmt.Sprintf("%d unloaded", unloaded))
	}
	if busy > 0 {
		parts = append(parts, fmt.Sprintf("%d busy (will clear at reboot)", busy))
	}
	if builtin > 0 {
		parts = append(parts, fmt.Sprintf("%d builtin (kernel rebuild required)", builtin))
	}
	if notLoaded > 0 {
		parts = append(parts, fmt.Sprintf("%d already absent", notLoaded))
	}
	if errored > 0 {
		parts = append(parts, fmt.Sprintf("%d error", errored))
	}
	fmt.Fprintf(w, "[Modules] %s. Blacklist on disk persists across reboot.\n", strings.Join(parts, ", "))
	if busy > 0 || builtin > 0 {
		fmt.Fprintln(w, "          Reboot at convenience to clear any busy modules and sync the initramfs.")
	}
}

// verifyAfterApply runs the audit rows pass and reports pass/fail.
// Boot-arg rules will show as PEND/WARN until reboot — that's
// expected; we tag them clearly rather than treating them as a
// failure. Modules in LOADED state likewise need a reboot or rmmod
// for the blacklist to be effective. Rules whose decision is OFF or
// SKIP are excluded from the failure counts (operator chose to
// disable, or host profile blocks the rule).
func verifyAfterApply(w io.Writer, conf *Conf, profile HostProfile) {
	rows := BuildAuditRows(conf, profile)
	var sysctlBad, bootPending, modulesLoaded, modulesMissing int
	for _, r := range rows {
		if r.State == StateOFF || r.State == StateSKIP || r.State == StateEXT {
			continue
		}
		switch r.Kind {
		case KindSysctl:
			if r.State != StateOK {
				sysctlBad++
			}
		case KindBoot:
			if r.State != StateOK {
				bootPending++
			}
		case KindModule:
			switch r.State {
			case StateLOADED:
				modulesLoaded++
			case StateMISSING:
				modulesMissing++
			}
		}
	}
	if sysctlBad == 0 {
		fmt.Fprintln(w, "  sysctl: all rules active (or not exposed by this kernel)")
	} else {
		fmt.Fprintf(w, "  sysctl: %d rules failed verification — investigate the per-key sysctl -w output above\n",
			sysctlBad)
	}
	if bootPending == 0 {
		fmt.Fprintln(w, "  boot:   all rules active in current /proc/cmdline (no reboot needed)")
	} else {
		fmt.Fprintf(w, "  boot:   %d rules pending reboot (configured for next boot, not yet active)\n",
			bootPending)
	}
	switch {
	case modulesMissing > 0:
		fmt.Fprintf(w, "  module: %d rules failed to land in modprobe.d — investigate\n", modulesMissing)
	case modulesLoaded > 0:
		fmt.Fprintf(w, "  module: blacklist on disk; %d managed modules loaded — reboot/rmmod for effect\n",
			modulesLoaded)
	default:
		fmt.Fprintln(w, "  module: blacklist on disk; no managed modules currently loaded")
	}
}

// restoreGrubFromBackup is the M1 rollback path: when
// update-grub fails after WriteCmdline succeeded, restore
// /etc/default/grub from the BackupOnce-saved copy so the
// next legitimate run of update-grub (kernel package install
// etc.) doesn't propagate the half-applied state.
//
// No-op (returns nil) if the backup file doesn't exist —
// could happen on the very first apply if BackupOnce hadn't
// been called yet (it's called at the top of WriteCmdline,
// so in practice this is the always-have-a-backup path).
func restoreGrubFromBackup() error {
	bak := PathDefaultGrub + BackupSuffix
	if _, err := os.Stat(bak); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", bak, err)
	}
	data, err := os.ReadFile(bak)
	if err != nil {
		return fmt.Errorf("read %s: %w", bak, err)
	}
	if err := AtomicWriteFile(PathDefaultGrub, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", PathDefaultGrub, err)
	}
	return nil
}

// unsafeForcedRules returns every ResolvedRule in the set whose
// Decision is Apply but whose WouldSkipReason is non-empty — i.e. an
// operator `state = force` resurrected a rule the host-profile gate
// would otherwise have skipped. Empty when the conf is safe.
func unsafeForcedRules(rs ResolvedSet) []ResolvedRule {
	var out []ResolvedRule
	for _, group := range [][]ResolvedRule{rs.Sysctls, rs.BootArgs, rs.Modules, rs.Mounts} {
		for _, r := range group {
			if r.Decision == Apply && r.WouldSkipReason != "" {
				out = append(out, r)
			}
		}
	}
	return out
}

// reportUnsafeForces prints the operator-facing warning block for the
// unsafe-force guard. Always prints (check / dry-run / apply / etc.);
// the refuse decision is made by the caller.
func reportUnsafeForces(w io.Writer, unsafe []ResolvedRule) {
	fmt.Fprintln(w, "[!] UNSAFE FORCE detected — the following rules are state = force in kernsec.conf")
	fmt.Fprintln(w, "    but the host-profile gate would have auto-skipped them on this host:")
	for _, r := range unsafe {
		fmt.Fprintf(w, "      %-32s %s\n", r.ID, r.Display)
		fmt.Fprintf(w, "        gate would have skipped: %s\n", r.WouldSkipReason)
	}
	fmt.Fprintln(w)
}

// reportCrossComponentConflicts surfaces ownership disagreements that
// would otherwise be silent kernel-level fights between kernsec and
// another cfm component:
//
//  1. managedsysctl-registry conflicts: same key claimed by two
//     catalogs (an init-order coding bug or a sys_tweaks-vs-kernsec
//     misconfiguration).
//  2. operator force-overrides: rules where `state = force` resurrected
//     Apply for a key another component owns. Honoured per-design but
//     the operator should see a one-line summary so they know what
//     they're getting (kernsec will write the key on top of whatever
//     sys_tweaks writes; the last writer wins).
//
// Honouring docs/kernsec.md:1117 — Phase 6 promises this surfaces in
// apply output.
func reportCrossComponentConflicts(w io.Writer, applySysctls []SysctlRule) {
	any := false
	for _, c := range managedsysctl.Default().Conflicts() {
		if !any {
			fmt.Fprintln(w, "[!] cross-component sysctl ownership conflicts (registry):")
			any = true
		}
		owners := make([]string, len(c.Owners))
		for i, o := range c.Owners {
			owners[i] = string(o)
		}
		fmt.Fprintf(w, "    %s claimed by: %s\n", c.Key, strings.Join(owners, ", "))
	}
	for _, r := range applySysctls {
		owner := managedsysctl.Default().OwnerOf(r.Key)
		if owner == "" || owner == managedsysctl.OwnerKernsec {
			continue
		}
		if !any {
			fmt.Fprintln(w, "[!] cross-component sysctl ownership conflicts:")
			any = true
		}
		fmt.Fprintf(w, "    %s (rule %s): forced by operator; %s also writes this key — last writer wins at runtime\n",
			r.Key, r.ID, owner)
	}
	if any {
		fmt.Fprintln(w)
	}
}
