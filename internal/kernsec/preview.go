package kernsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// PreviewOptions selects which rules / decisions are shown.
type PreviewOptions struct {
	OnlyApply bool   // hide SKIP-* rows (only show what would be applied)
	Group     string // filter by group prefix; "" = all
	// Tier overrides conf.Tier for this preview iff TierOverride is true.
	// Setting Tier alone is not enough — the zero value of Tier is the
	// legitimate value 0 ("resolve as if every rule were tier-gated
	// off"), so we need an explicit flag to distinguish "operator did
	// not pass --tier" from "operator passed --tier 0".
	Tier         Tier
	TierOverride bool
	IDs          []string
	Skips        []string // additional ad-hoc skips (not persisted)
	Forces       []string // additional ad-hoc forces (not persisted)
}

// RunPreview renders a read-only diff of what `cfm kernsec apply` would
// do given the current conf + host profile + ad-hoc selectors. It uses
// the same render helpers as apply --dry-run for sysctl, modprobe, and
// boot arguments, but never writes files or runs bootloader commands.
func RunPreview(w io.Writer, opts PreviewOptions) int {
	conf, err := LoadConf(true /* createDefault in memory */)
	if err != nil {
		fmt.Fprintln(w, "kernsec: load conf:", err)
		return 1
	}
	conf = applyAdHocOverrides(conf, opts)

	profile := DetectHostProfile()
	rs := Resolve(conf, profile)

	fmt.Fprintln(w, "===== CFM kernsec PREVIEW =====")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Conf:     %s\n", confSource(conf))
	fmt.Fprintf(w, "Tier:     %d\n", conf.Tier)
	fmt.Fprintf(w, "Profile:  %s\n", describeProfile(profile))
	if warnings := ValidateConfOverrideIDs(conf); len(warnings) > 0 {
		fmt.Fprintln(w)
		for _, msg := range warnings {
			fmt.Fprintf(w, "[!] %s\n", msg)
		}
	}
	fmt.Fprintln(w)

	printResolvedSection(w, "Sysctls", rs.Sysctls, opts)
	printResolvedSection(w, "Boot args", rs.BootArgs, opts)
	printResolvedSection(w, "Modules", rs.Modules, opts)
	printResolvedSection(w, "Mounts (audit-only)", rs.Mounts, opts)

	if risks := sysctl_impacting_risks(rs.ApplySysctls(), profile); len(risks) > 0 {
		fmt.Fprintln(w, "[!] Sysctl-impacting changes — read carefully:")
		for _, r := range risks {
			fmt.Fprintf(w, "    - %s\n", r)
		}
		fmt.Fprintln(w)
	}

	readErr := printPreviewApplyPlan(w, conf, rs)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[Summary]")
	fmt.Fprintf(w, "  apply: sysctls=%d  boot=%d  modules=%d  mounts=%d\n",
		count(rs.Sysctls, Apply),
		count(rs.BootArgs, Apply),
		count(rs.Modules, Apply),
		count(rs.Mounts, Apply),
	)
	fmt.Fprintf(w, "  skip:  conf=%d  tier=%d  host=%d\n",
		countAll(rs, SkipByConf),
		countAll(rs, SkipByTier),
		countAll(rs, SkipByHostProfile),
	)
	if extCount := countAll(rs, ManagedExternally); extCount > 0 {
		fmt.Fprintf(w, "  ext:   %d rules audited; managed by another cfm component\n", extCount)
	}
	fmt.Fprintln(w, "===============================")
	if readErr {
		return 1
	}
	return 0
}

func printResolvedSection(w io.Writer, label string, rs []ResolvedRule, opts PreviewOptions) {
	rs = filterRules(rs, opts)
	if len(rs) == 0 {
		return
	}
	fmt.Fprintf(w, "[%s]\n", label)
	for _, r := range rs {
		line := fmt.Sprintf("  %-9s  %-7s  %-26s  %s",
			r.Decision, "T"+r.Tier.label(), r.Group, r.Display)
		if r.Reason != "" {
			line += "    (" + r.Reason + ")"
		}
		fmt.Fprintln(w, line)
		for _, note := range r.Advisories {
			fmt.Fprintf(w, "        note: %s\n", note)
		}
	}
	fmt.Fprintln(w)
}

func filterRules(rs []ResolvedRule, opts PreviewOptions) []ResolvedRule {
	out := make([]ResolvedRule, 0, len(rs))
	idSet := stringSet(opts.IDs)
	for _, r := range rs {
		if opts.OnlyApply && r.Decision != Apply {
			continue
		}
		if opts.Group != "" && !strings.HasPrefix(r.Group, opts.Group) {
			continue
		}
		// Display filter: clip rules above an explicit tier ceiling.
		// When opts.Tier == 0 (either default or explicit `--tier 0`)
		// no clip is needed — the resolver itself classifies every
		// rule as SkipByTier under tier=0 conf, and the operator
		// wants to see those OFF rows.
		if opts.Tier > 0 && r.Tier > opts.Tier {
			continue
		}
		if len(idSet) > 0 {
			if _, ok := idSet[r.ID]; !ok {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func stringSet(s []string) map[string]struct{} {
	m := make(map[string]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}
	return m
}

func count(rs []ResolvedRule, d Decision) int {
	n := 0
	for _, r := range rs {
		if r.Decision == d {
			n++
		}
	}
	return n
}

func countAll(rs ResolvedSet, d Decision) int {
	return count(rs.Sysctls, d) + count(rs.BootArgs, d) + count(rs.Modules, d) + count(rs.Mounts, d)
}

func confSource(c *Conf) string {
	if c == nil || c.Source == "" {
		return "(no conf loaded)"
	}
	return c.Source
}

func describeProfile(p HostProfile) string {
	var parts []string
	if p.IsKVMHost {
		parts = append(parts, "kvm-host")
	}
	if p.HasLibvirt {
		parts = append(parts, "libvirt")
	}
	if p.HasContainers {
		parts = append(parts, "containers")
	}
	if p.UsesBridge {
		parts = append(parts, "uses-bridge")
	}
	if p.HasIPsec {
		parts = append(parts, "ipsec")
	}
	if p.HasDKMS {
		parts = append(parts, "dkms")
	}
	if p.IsCPanel {
		parts = append(parts, "cpanel")
	}
	if p.IsDirectAdmin {
		parts = append(parts, "directadmin")
	}
	if p.HasCloudLinuxLVE {
		parts = append(parts, "cloudlinux-lve")
	}
	if p.HasCageFS {
		parts = append(parts, "cagefs")
	}
	if p.HasImunify360 {
		parts = append(parts, "imunify360")
	}
	if p.HasKernelCare {
		parts = append(parts, "kernelcare")
	}
	if p.HasKsplice {
		parts = append(parts, "ksplice")
	}
	if p.HasLivePatchingModules {
		parts = append(parts, "livepatch-modules")
	}
	if p.IsProxmox {
		parts = append(parts, "proxmox")
	}
	if p.HasZFS {
		parts = append(parts, "zfs")
	}
	if p.HasNVIDIA {
		parts = append(parts, "nvidia")
	}
	if p.HasHostingPanelWorkload {
		parts = append(parts, "hosting-panel")
	}
	if p.HasBluetoothHardware {
		parts = append(parts, "bluetooth-hw")
	}
	if p.HasThunderbolt {
		parts = append(parts, "thunderbolt-hw")
	}
	if p.HasNFS {
		parts = append(parts, "nfs")
	}
	if len(parts) == 0 {
		return "no host-profile flags"
	}
	return strings.Join(parts, ", ")
}

func applyAdHocOverrides(conf *Conf, opts PreviewOptions) *Conf {
	if conf == nil {
		conf = DefaultConf()
	}
	if conf.Overrides == nil {
		conf.Overrides = map[string]RuleOverride{}
	}
	for _, id := range opts.Skips {
		conf.Overrides[id] = OverrideSkip
	}
	for _, id := range opts.Forces {
		conf.Overrides[id] = OverrideForce
	}
	if opts.TierOverride {
		// `--tier N` overrides whatever's in the conf for this preview
		// invocation. Operators use it both to clamp down (preview as
		// if I dropped to tier=1, or even tier=0 to see what disable
		// would render) and to bump up (preview as if I raised to
		// tier=2). Not persisted.
		conf.Tier = opts.Tier
	}
	return conf
}

// previewFSFactory is overridden by tests so preview can exercise backend
// detection/read paths without touching the real host bootloader state.
var previewFSFactory = func() FS { return RealFS{} }

func printPreviewApplyPlan(w io.Writer, conf *Conf, rs ResolvedSet) bool {
	sysctls := rs.ApplySysctls()
	bootArgs := rs.ApplyBootArgs()
	modules := rs.ApplyModules()

	fs := previewFSFactory()
	backend := DetectBackend(fs)
	sysctlContent := RenderSysctlFile(sysctls)
	modprobeContent := RenderModprobeFile(modules)

	fmt.Fprintln(w, "[Apply dry-run plan]")
	fmt.Fprintf(w, "  backend: %s\n", backend.Label())
	fmt.Fprintf(w, "  sysctl target:   %s\n", SysctlPath)
	fmt.Fprintf(w, "  modprobe target: %s\n", ModprobePath)
	printBootTarget(w, backend)

	// conf is threaded in so KSEC-LSM-bpf-001 (which is conf-gated via
	// IsLSMBPFForced) produces the same desired cmdline here as in
	// apply. Otherwise preview and apply silently disagree when the
	// rule is forced — preview would show `bpf` stripped while apply
	// would keep it, breaking preview's "faithful diff of apply"
	// contract.
	desiredCmdline, cmdlineErr := buildDesiredCmdlineWithConf(backend, bootArgs, conf)
	if cmdlineErr != nil && !errors.Is(cmdlineErr, ErrBLSDivergence) {
		fmt.Fprintf(w, "  boot read error: %v\n", cmdlineErr)
		fmt.Fprintln(w, "  status: cannot compute desired cmdline without reading current next-boot config")
		fmt.Fprintln(w)
		return true
	}
	if cmdlineErr != nil {
		fmt.Fprintf(w, "  note: BLS entries diverge — apply will auto-reconcile (%v)\n", cmdlineErr)
	}

	drift := computeDrift(sysctlContent, desiredCmdline, backend)
	drift.ModprobeDiffers, drift.ModprobeReadErr = modprobeDriftCheck(modprobeContent)

	readErr := false
	fmt.Fprintln(w, "  next-boot cmdline:")
	if drift.BootReadErr != nil {
		readErr = true
		fmt.Fprintf(w, "    current: ERROR reading next-boot cmdline: %v\n", drift.BootReadErr)
	} else {
		fmt.Fprintf(w, "    current: %s\n", strings.TrimSpace(drift.CurrentCmdline))
		fmt.Fprintf(w, "    desired: %s\n", strings.TrimSpace(desiredCmdline))
	}

	fmt.Fprintln(w, "  backups that would be created:")
	backups := plannedBackupPaths(backend, drift.CurrentCmdline)
	if len(backups) == 0 {
		fmt.Fprintln(w, "    (none; source files absent, already backed up, or no managed boot args to snapshot)")
	} else {
		for _, p := range backups {
			fmt.Fprintf(w, "    %s\n", p)
		}
	}

	fmt.Fprintln(w, "  bootloader refresh:")
	if cmd, err := plannedRefreshCommand(backend); err != nil {
		fmt.Fprintf(w, "    ERROR determining refresh command: %v\n", err)
	} else {
		fmt.Fprintf(w, "    %s\n", cmd)
	}

	fmt.Fprintln(w, "  planned mutations:")
	printMutationStatus(w, "sysctl", drift.SysctlDiffers, drift.SysctlReadErr)
	if drift.SysctlReadErr != nil {
		readErr = true
	}
	printIndentedBlock(w, string(sysctlContent))
	printMutationStatus(w, "modprobe", drift.ModprobeDiffers, drift.ModprobeReadErr)
	if drift.ModprobeReadErr != nil {
		readErr = true
	}
	printIndentedBlock(w, string(modprobeContent))
	if drift.BootReadErr == nil {
		printMutationStatus(w, "boot args", drift.BootDiffers, nil)
		fmt.Fprintf(w, "      %s\n", strings.TrimSpace(desiredCmdline))
	}
	fmt.Fprintln(w, "  (preview; nothing written and no refresh command run)")
	fmt.Fprintln(w)
	return readErr
}

func printBootTarget(w io.Writer, backend BootBackend) {
	switch b := backend.(type) {
	case *ProxmoxBackend:
		fmt.Fprintf(w, "  boot target:     %s\n", PathPVECmdline)
	case *GRUBBackend:
		fmt.Fprintf(w, "  boot target:     %s\n", PathDefaultGrub)
	case *BLSBackend:
		targets, err := blsTargetKernels(b)
		if err != nil {
			fmt.Fprintf(w, "  boot target:     ERROR reading grubby target kernels: %v\n", err)
			return
		}
		if len(targets) == 0 {
			fmt.Fprintln(w, "  boot target:     grubby target kernels: (none)")
			return
		}
		fmt.Fprintln(w, "  boot target:     grubby target kernels:")
		for _, k := range targets {
			fmt.Fprintf(w, "                   %s\n", k)
		}
	default:
		fmt.Fprintf(w, "  boot target:     %s\n", backend.Label())
	}
}

func blsTargetKernels(b *BLSBackend) ([]string, error) {
	out, err := b.FS.RunCapture("grubby", "--info=ALL")
	if err != nil {
		return nil, err
	}
	entries := parseGrubbyAll(out)
	if err := validateGrubbyEntries(entries); err != nil {
		return nil, err
	}
	return kernelPaths(nonRecoveryKernelEntries(entries)), nil
}

func plannedBackupPaths(backend BootBackend, currentCmdline string) []string {
	var out []string
	appendFileBackup := func(path string) {
		if _, err := os.Stat(path); err == nil {
			if _, berr := os.Stat(path + BackupSuffix); os.IsNotExist(berr) {
				out = append(out, path+BackupSuffix)
			}
		}
	}
	appendFileBackup(SysctlPath)
	appendFileBackup(ModprobePath)

	switch backend.(type) {
	case *ProxmoxBackend:
		appendFileBackup(PathPVECmdline)
		if len(KeepManagedArgs(ParseCmdline(currentCmdline))) > 0 {
			out = append(out, ProxmoxManagedBackupPath)
		}
	case *GRUBBackend:
		appendFileBackup(PathDefaultGrub)
		if len(KeepManagedArgs(ParseCmdline(currentCmdline))) > 0 {
			out = append(out, GRUBManagedBackupPath)
		}
	case *BLSBackend:
		if len(KeepManagedArgs(ParseCmdline(currentCmdline))) > 0 {
			out = append(out, BLSBackupPath)
		}
	}
	return out
}

func plannedRefreshCommand(backend BootBackend) (string, error) {
	switch b := backend.(type) {
	case *ProxmoxBackend:
		return "proxmox-boot-tool refresh", nil
	case *GRUBBackend:
		name, args, err := b.refreshCommand()
		if err != nil {
			return "", err
		}
		return grubRefreshDisplay(name, args), nil
	case *BLSBackend:
		return "(none; grubby commits updates immediately)", nil
	default:
		return backend.Label() + " refresh", nil
	}
}

func printMutationStatus(w io.Writer, label string, differs bool, err error) {
	if err != nil {
		fmt.Fprintf(w, "    %s: ERROR reading current state: %v\n", label, err)
		return
	}
	if differs {
		fmt.Fprintf(w, "    %s: would write\n", label)
		return
	}
	fmt.Fprintf(w, "    %s: already in sync (rendered content below)\n", label)
}

func printIndentedBlock(w io.Writer, content string) {
	content = strings.TrimRight(content, "\n")
	if content == "" {
		fmt.Fprintln(w, "      (empty)")
		return
	}
	for _, line := range strings.Split(content, "\n") {
		fmt.Fprintf(w, "      %s\n", line)
	}
}
