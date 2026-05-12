package kernsec

import (
	"os"
	"path/filepath"
	"strings"
)

// MountState describes the runtime state of one MountRule against
// /proc/mounts. Beyond plain OK/MISSING we distinguish:
//
//   - MountPartialOptions: some recommended options are present, some
//     aren't. The previous binary OK/MISSING render misled operators
//     into thinking a /tmp with `nosuid,noexec` but no `nodev` had no
//     hardening at all; PARTIAL surfaces the truth and lets the
//     remediation hint name only the truly-missing options.
//   - MountSymlink: the audit path is a symlink (typically
//     /var/tmp → /tmp on cPanel/CloudLinux). Inherits the target's
//     mount options and is not separately auditable.
//   - MountBindOfAnother: the audit path appears in /proc/mounts but
//     shares its source device with another audited mount point — it
//     is a bind mount and the operator should remount the source, not
//     this path.
type MountState int

const (
	// MountOK means the mount point is present and every recommended
	// option is active.
	MountOK MountState = iota
	// MountPartialOptions means the mount point is present and at
	// least one recommended option is present, but at least one is
	// not. Use CheckMountDetail to learn which.
	MountPartialOptions
	// MountMissingOptions means the mount point is present but none
	// of the recommended options is active. (Distinct from PARTIAL so
	// the renderer can emphasise that nothing has been applied yet.)
	MountMissingOptions
	// MountNotSeparate means the mount point is not a distinct mount
	// in /proc/mounts (e.g. /var/tmp on the root filesystem).
	// Recommendations don't apply: you can't add `nodev` to a
	// directory that isn't a mount.
	MountNotSeparate
	// MountSymlink means the path itself is a symlink — typical for
	// /var/tmp → /tmp on cPanel/CloudLinux. Audit defers to the
	// target's row instead of double-warning here.
	MountSymlink
	// MountBindOfAnother means the path is mounted but shares its
	// source with another audited mount point (e.g. cPanel binds
	// /usr/tmpDSK onto both /tmp and /var/tmp). Audit defers to the
	// "primary" mount point's row.
	MountBindOfAnother
)

// MountDetail is the rich per-rule probe result used by the status
// renderer. CheckMount returns the legacy (state, current) pair for
// callers that don't care about the per-option breakdown; CheckMountDetail
// adds the present/missing split, symlink target, and bind-mount sibling
// so the status output can render "PARTIAL /tmp has nosuid,noexec; still
// missing: nodev" plus a remediation hint that names only the missing
// options.
type MountDetail struct {
	State           MountState
	CurrentOptions  string   // raw options column from /proc/mounts
	Present         []string // recommended options actually live
	Missing         []string // recommended options NOT live
	Source          string   // /proc/mounts source column (device or label)
	SymlinkTarget   string   // resolved target when State == MountSymlink
	BindPrimaryPath string   // sibling mount point when State == MountBindOfAnother
}

// CheckMount preserves the previous (state, currentOptions) return
// shape used by audit.go's BuildAuditRows; the richer per-option
// breakdown lives in CheckMountDetail.
func CheckMount(rule MountRule) (state MountState, currentOptions string) {
	d := checkMountDetail(readProcMounts(), rule, Tier1Mounts, realLstat, realReadlink)
	return d.State, d.CurrentOptions
}

// CheckMountDetail is CheckMount with the full per-option breakdown,
// symlink resolution, and bind-mount detection used by the status
// renderer. peers lets the bind-mount check ignore non-audited mount
// points; production callers pass Tier1Mounts.
func CheckMountDetail(rule MountRule, peers []MountRule) MountDetail {
	return checkMountDetail(readProcMounts(), rule, peers, realLstat, realReadlink)
}

// checkMountDetail is the testable inner function. It operates on
// supplied /proc/mounts content plus injectable lstat / readlink so
// tests can drive symlink and bind-mount branches without touching
// the real filesystem.
//
// Resolution order:
//
//  1. Symlink check first: if the path itself is a symlink, the audit
//     can't apply mount options to a symlink — defer to the target's
//     row. (/var/tmp → /tmp is the documented common case.)
//  2. /proc/mounts lookup: missing → MountNotSeparate.
//  3. Bind-mount detection: if another peer rule's mount point has
//     the same source device as this one AND that peer appears first
//     in the rule list, this mount is the bind sibling — defer.
//  4. Option breakdown: compute present/missing against rule.Recommended.
//     all-present → MountOK; some-present → MountPartialOptions;
//     none-present → MountMissingOptions.
func checkMountDetail(
	procMounts string,
	rule MountRule,
	peers []MountRule,
	lstat func(string) (os.FileInfo, error),
	readlink func(string) (string, error),
) MountDetail {
	d := MountDetail{State: MountNotSeparate}

	if info, err := lstat(rule.MountPoint); err == nil && info.Mode()&os.ModeSymlink != 0 {
		target, lerr := readlink(rule.MountPoint)
		if lerr == nil {
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(rule.MountPoint), target)
			}
			d.SymlinkTarget = filepath.Clean(target)
		}
		d.State = MountSymlink
		return d
	}

	// Last-wins scan, mirroring the previous behaviour: a later mount
	// on the same point shadows the earlier one and the operator
	// cares about the currently-active options.
	mountByPath := map[string][2]string{} // path -> [source, opts]
	for _, line := range strings.Split(procMounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mountByPath[fields[1]] = [2]string{fields[0], fields[3]}
	}

	entry, ok := mountByPath[rule.MountPoint]
	if !ok {
		return d
	}
	d.Source = entry[0]
	d.CurrentOptions = entry[1]

	// Bind-mount detection: if a peer rule that comes earlier in the
	// list mounts the same source, this row is the bind sibling.
	// "Earlier in the list" gives us a deterministic primary so
	// /tmp/<-> /var/tmp tie-break the same way every audit run.
	if d.Source != "" && !isGenericMountSource(d.Source) {
		for _, p := range peers {
			if p.MountPoint == rule.MountPoint {
				break
			}
			if peer, ok := mountByPath[p.MountPoint]; ok && peer[0] == d.Source {
				d.BindPrimaryPath = p.MountPoint
				d.State = MountBindOfAnother
				return d
			}
		}
	}

	d.Present, d.Missing = splitMountOptions(d.CurrentOptions, rule.Recommended)
	switch {
	case len(d.Missing) == 0:
		d.State = MountOK
	case len(d.Present) == 0:
		d.State = MountMissingOptions
	default:
		d.State = MountPartialOptions
	}
	return d
}

// isGenericMountSource recognises the well-known pseudo-fs sources
// that legitimately appear under multiple mount points without those
// mounts being binds of each other. Treating tmpfs/devtmpfs/sysfs/proc
// as "shared source" would mis-flag /dev/shm and /run as binds.
func isGenericMountSource(src string) bool {
	switch src {
	case "tmpfs", "devtmpfs", "sysfs", "proc", "cgroup", "cgroup2", "mqueue",
		"hugetlbfs", "debugfs", "tracefs", "configfs", "fusectl", "securityfs",
		"pstore", "bpf", "binfmt_misc", "ramfs", "rpc_pipefs", "nsfs",
		"autofs", "overlay", "none":
		return true
	}
	return false
}

// splitMountOptions returns (present, missing) recommended options
// against the live options column. Both inputs are comma-separated
// option sets; ordering is irrelevant.
func splitMountOptions(current, recommended string) (present, missing []string) {
	have := make(map[string]struct{})
	for _, o := range strings.Split(current, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			have[o] = struct{}{}
		}
	}
	for _, o := range strings.Split(recommended, ",") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if _, ok := have[o]; ok {
			present = append(present, o)
		} else {
			missing = append(missing, o)
		}
	}
	return present, missing
}

// hasAllMountOptions remains for callers / tests that don't need the
// per-option split. Pure convenience wrapper around splitMountOptions.
func hasAllMountOptions(current, recommended string) bool {
	_, missing := splitMountOptions(current, recommended)
	return len(missing) == 0
}

// checkMountFromProc preserves the legacy two-arg signature relied on
// by older tests / callers. Computes MountDetail internally and
// projects down to (state, current).
func checkMountFromProc(procMounts string, rule MountRule) (MountState, string) {
	d := checkMountDetail(procMounts, rule, Tier1Mounts, realLstat, realReadlink)
	return d.State, d.CurrentOptions
}

// readProcMounts returns /proc/mounts contents (or "" on read error).
// Variable so tests can substitute fixture data.
var readProcMounts = func() string {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}
	return string(b)
}

// realLstat / realReadlink are the production filesystem hooks for
// symlink detection. var so tests can substitute deterministic stubs.
var realLstat = func(p string) (os.FileInfo, error) {
	return os.Lstat(p)
}
var realReadlink = func(p string) (string, error) {
	return os.Readlink(p)
}

// Tier1Mounts is the fstab audit set. kernsec **never** auto-mutates
// /etc/fstab — `noexec` on /tmp breaks several composer / pip / cPanel
// workflows. The rule rows surface in `cfm kernsec status` / TUI as
// audit-only "your /tmp would benefit from nodev,nosuid,noexec" hints
// that operators decide on themselves.
//
// /home is deliberately NOT audited here. Operator setups vary enough
// (panels that drop setuid helpers under /home, NFS-exported homes,
// per-user development trees, CageFS layouts) that a one-size
// recommendation produces more noise than signal — and the previous
// "missing nodev,nosuid" warning misled operators into thinking those
// options were universally safe. If a future host-profile-gated /home
// rule lands, it goes in this set with explicit profile gating, not
// as a blanket Tier 1 recommendation.
var Tier1Mounts = []MountRule{
	{
		ID: "KSEC-FS-mount.tmp-001", Group: "fs.mount.tmp", Tier: Tier1,
		MountPoint:  "/tmp",
		Recommended: "nodev,nosuid,noexec",
		Description: "Recommend nodev,nosuid,noexec on /tmp to neutralize world-writable exec attacks.",
		Affects:     "noexec breaks some composer / pip / cPanel workflows; review first.",
	},
	{
		ID: "KSEC-FS-mount.tmp-002", Group: "fs.mount.tmp", Tier: Tier1,
		MountPoint:  "/var/tmp",
		Recommended: "nodev,nosuid,noexec",
		Description: "Same protection family for /var/tmp.",
		Affects:     "Same compatibility considerations as /tmp.",
	},
	{
		ID: "KSEC-FS-mount.tmp-003", Group: "fs.mount.tmp", Tier: Tier1,
		MountPoint:  "/dev/shm",
		Recommended: "nodev,nosuid,noexec",
		// Auto-application is enabled for /dev/shm only:
		// - it is always tmpfs (no on-disk state to migrate);
		// - kernel tmpfs remount preserves contents;
		// - kernel `noexec` is a soft flag that takes effect for
		//   NEW exec calls only, not running processes;
		// - the realistic blast-radius workloads (Chromium headless
		//   sandbox, pre-15 PostgreSQL with JIT enabled) are easy to
		//   detect and roll back with one `mount -o remount,exec
		//   /dev/shm` if anything breaks.
		// /tmp and /var/tmp do NOT get CanEnable: live database temp
		// state, the /var/tmp-survives-reboot contract, and the
		// dedicated-filesystem provisioning step make auto-apply
		// unsafe. Those rows stay tip-only.
		CanEnable: true,
		// Every modern distro (EL, Alma, Debian, Ubuntu, Arch) has
		// systemd PID 1 mount /dev/shm with nosuid,nodev already on
		// — that's hard-coded in src/core/mount-setup.c. Disable
		// therefore reverts only the kernsec-added option (noexec)
		// rather than blindly remounting with dev,suid,exec, which
		// would land the host BELOW the distro baseline.
		DefaultLiveOptions: "nodev,nosuid",
		Description:        "Same protection family for /dev/shm (POSIX shared-memory tmpfs).",
		Affects:            "Mostly safe in practice; double-check JVM / Python multiprocessing usage.",
	},
}
