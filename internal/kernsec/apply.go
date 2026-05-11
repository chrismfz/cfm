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
	rc, _ := applyCore(w, conf, opts, "APPLY")
	return rc
}

// applyCore is the conf-agnostic apply orchestration. RunApply loads
// from disk first; RunDisable constructs an in-memory tier=0 conf and
// calls in directly. label is what appears in the banner ("APPLY" or
// "DISABLE") so operator output reflects the operator's intent.
// applyCore returns (rc, bootSkipped). bootSkipped is true when sysctl
// and modprobe writes succeeded but the boot section was skipped due
// to recoverable conditions (BLS divergence). Callers like the TUI use
// it to give the operator an accurate post-apply summary; CLI callers
// can ignore it — the human-readable output already flags the skip.
func applyCore(w io.Writer, conf *Conf, opts ApplyOptions, label string) (int, bool) {
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
		return 1, false
	}

	sysctlContent := RenderSysctlFile(sysctls)
	modprobeContent := RenderModprobeFile(modules)
	desiredCmdline, cmdlineErr := buildDesiredCmdline(backend, bootArgs)
	// BLS divergence (two installed kernels with mismatched managed args)
	// is recoverable: we can still write the sysctl drop-in, the
	// modprobe drop-in, and run runtime `sysctl -w`. We only skip the
	// boot section. Every other cmdline-read failure is still fatal —
	// writing a cmdline blind to current state is unsafe.
	skipBoot := false
	var bootSkipReason string
	if cmdlineErr != nil {
		if errors.Is(cmdlineErr, ErrBLSDivergence) {
			skipBoot = true
			bootSkipReason = cmdlineErr.Error()
		} else {
			fmt.Fprintln(w, "kernsec apply:", cmdlineErr)
			fmt.Fprintln(w, "  cannot compute desired cmdline without reading current next-boot config")
			return 1, false
		}
	}

	drift := computeDrift(sysctlContent, desiredCmdline, backend)
	drift.ModprobeDiffers, drift.ModprobeReadErr = modprobeDriftCheck(modprobeContent)
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

	fmt.Fprintln(w, "[Boot args]")
	switch {
	case skipBoot:
		fmt.Fprintln(w, "  status:            SKIPPED — BLS kernel entries diverge; reconcile with grubby and re-run apply")
		fmt.Fprintf(w, "  detail:            %s\n", bootSkipReason)
	case drift.BootReadErr != nil:
		fmt.Fprintf(w, "  status:            ERROR reading next-boot cmdline: %v\n", drift.BootReadErr)
	default:
		fmt.Fprintf(w, "  current next-boot: %s\n", strings.TrimSpace(drift.CurrentCmdline))
		fmt.Fprintf(w, "  desired:           %s\n", strings.TrimSpace(desiredCmdline))
		if drift.BootDiffers {
			fmt.Fprintln(w, "  status:            DRIFT (would rewrite cmdline)")
		} else {
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
			return 2, false
		case 1:
			fmt.Fprintln(w, "[!] drift detected — exit 1")
			return 1, false
		}
		fmt.Fprintln(w, "[+] no drift")
		return 0, false
	}

	if opts.DryRun {
		fmt.Fprintln(w, "(dry-run; nothing written)")
		fmt.Fprintln(w, "===========================")
		return 0, skipBoot
	}

	if drift.BootReadErr != nil && !skipBoot {
		fmt.Fprintln(w, "kernsec apply: refusing to write — cannot read current cmdline")
		return 1, false
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
	// ModprobeDiffers cover the three managed surfaces.
	mutating := drift.SysctlDiffers || (drift.BootDiffers && !skipBoot) || drift.ModprobeDiffers
	if mutating && !opts.AssumeYes {
		preflightSummary(w, label, sysctls, bootArgs, modules, profile)
		ok, err := confirmApply(w, opts.Stdin)
		if err != nil {
			fmt.Fprintln(w, "kernsec apply: confirmation read error:", err)
			return 1, false
		}
		if !ok {
			fmt.Fprintln(w, "kernsec apply: aborted by operator (no changes written).")
			return 0, false
		}
	}

	if rc := applyWrites(w, backend, sysctlContent, modprobeContent, bootArgs, loadedManaged, opts, skipBoot, LoadSysctl); rc != 0 {
		return rc, false
	}

	// Post-write verify.
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[Verification]")
	verifyAfterApply(w, conf, profile)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[!] Boot-arg changes require reboot before they appear in /proc/cmdline.")
	fmt.Fprintln(w, "===========================")
	return 0, skipBoot
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
	skipBoot bool,
	loader func() error,
) int {
	// 1. Sysctl drop-in file.
	if err := WriteSysctlFile(w, sysctlContent); err != nil {
		fmt.Fprintln(w, "kernsec apply: write sysctl:", err)
		return 1
	}
	fmt.Fprintf(w, "[Sysctl] wrote %s (not yet applied).\n", SysctlPath)

	// 2. Modprobe blacklist file.
	if err := WriteModprobeFile(w, modprobeContent); err != nil {
		fmt.Fprintln(w, "kernsec apply: write modprobe:", err)
		return 1
	}
	fmt.Fprintf(w, "[Modules] wrote %s.\n", ModprobePath)
	if len(loadedManaged) > 0 {
		fmt.Fprintf(w, "[Modules] %d managed modules already loaded — reboot or rmmod required for them to be effective:\n",
			len(loadedManaged))
		for _, name := range loadedManaged {
			fmt.Fprintf(w, "            %s\n", name)
		}
	}

	// 3. Bootloader cmdline. Skipped entirely on BLS divergence — we
	// don't know which entry is the canonical baseline, so writing
	// would risk codifying a stale set of managed args across all
	// kernels. Operator reconciles via grubby and re-runs apply.
	if skipBoot {
		fmt.Fprintln(w, "[Boot args] SKIPPED — divergent BLS entries; cmdline unchanged.")
		fmt.Fprintln(w, "  reconcile with `grubby --update-kernel=ALL` and re-run `cfm kernsec apply`.")
	} else {
		if err := backend.WriteCmdline(bootArgs); err != nil {
			fmt.Fprintln(w, "kernsec apply: write cmdline:", err)
			fmt.Fprintln(w, "  sysctl drop-in is on disk but NOT applied; runtime state unchanged.")
			return 1
		}
		fmt.Fprintf(w, "[Boot args] rewrote next-boot cmdline via %s.\n", backend.Label())
	}

	// 4. Bootloader refresh. Skipped when boot section was skipped.
	switch {
	case skipBoot:
		// already printed the SKIPPED line above; nothing to refresh.
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
		fmt.Fprintln(w, "  files are on disk and bootloader is updated; runtime sysctl values may be partially loaded.")
		fmt.Fprintln(w, "  inspect with `sysctl -a` and re-run apply once the cause is fixed.")
		return 1
	}
	fmt.Fprintln(w, "[Sysctl] runtime sysctl apply completed via per-key sysctl -w (rules now live).")
	return 0
}

type driftResult struct {
	SysctlDiffers   bool
	BootDiffers     bool
	ModprobeDiffers bool
	CurrentCmdline  string
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
	case d.SysctlDiffers, d.BootDiffers, d.ModprobeDiffers:
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
