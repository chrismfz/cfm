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
//   - MountPending: the persistence layer (/etc/fstab line OR the
//     resolved systemd .mount Options=, including any .d/ drop-ins)
//     already carries every recommended option, but the live mount in
//     /proc/mounts hasn't been remounted with them yet. Typical state
//     between `cfm kernsec apply` and the next reboot for /tmp and
//     /var/tmp, where kernsec deliberately skips the live remount
//     (every service with PrivateTmp=yes has bind mounts rooted in
//     the current /tmp namespace; restarting tmp.mount mid-flight is
//     unsafe). Reboot clears it.
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
	// MountPending means the next-boot config (fstab line or systemd
	// .mount Options=, including drop-ins) already carries every
	// recommended option, but the live mount hasn't picked them up
	// yet. Resolved by reboot or an explicit `mount -o remount`.
	MountPending
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
	// NextBootOptions is the merged options column kernsec resolved
	// from /etc/fstab + systemd .mount unit (+ drop-ins). Empty if
	// neither source carries an entry for this mount point. Used by
	// MountPending detection: when NextBootOptions covers every
	// recommended option but CurrentOptions doesn't, the live state
	// will catch up at reboot and the row renders PEND, not MISSING.
	NextBootOptions string
	// PersistedSource describes which file the NextBootOptions came
	// from, for operator-facing rendering. One of "fstab",
	// "systemd-unit", or "" when neither is present.
	PersistedSource string
}

// CheckMount preserves the previous (state, currentOptions) return
// shape used by audit.go's BuildAuditRows; the richer per-option
// breakdown lives in CheckMountDetail.
func CheckMount(rule MountRule) (state MountState, currentOptions string) {
	d := checkMountDetail(readProcMounts(), rule, Tier1Mounts, realLstat, realReadlink, realFstabReader, realSystemdUnitFinderWithDropins)
	return d.State, d.CurrentOptions
}

// CheckMountDetail is CheckMount with the full per-option breakdown,
// symlink resolution, and bind-mount detection used by the status
// renderer. peers lets the bind-mount check ignore non-audited mount
// points; production callers pass Tier1Mounts.
func CheckMountDetail(rule MountRule, peers []MountRule) MountDetail {
	return checkMountDetail(readProcMounts(), rule, peers, realLstat, realReadlink, realFstabReader, realSystemdUnitFinderWithDropins)
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
	readFstab func() ([]fstabLine, error),
	findUnit func(unitName string) (path, options string, ok bool),
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
		// Not separately mounted at runtime. Before declaring
		// MountNotSeparate look at fstab: if an entry exists for
		// this mount point, the next reboot WILL materialise the
		// mount (typical case: kernsec just wrote a bind line for
		// /var/tmp via Enable; live state catches up at reboot).
		// Upgrade to MountPending and surface what the operator
		// configured.
		d.NextBootOptions, d.PersistedSource = resolveNextBootOptions(rule.MountPoint, readFstab, nil)
		if d.NextBootOptions != "" {
			d.State = MountPending
			d.Missing = splitCSV(rule.Recommended)
			if fl, found := findFstabBindSource(readFstab, rule.MountPoint); found {
				d.BindPrimaryPath = fl
			}
		}
		return d
	}
	d.Source = entry[0]
	d.CurrentOptions = entry[1]

	// Bind-mount detection: if a peer rule that comes earlier in the
	// list mounts the same source, this row is the bind sibling.
	// "Earlier in the list" gives us a deterministic primary so
	// /tmp/<-> /var/tmp tie-break the same way every audit run.
	//
	// We capture BindPrimaryPath here but DON'T early-return: a bind
	// sibling that inherits a fully-hardened option set from its
	// primary (e.g. `cfm kernsec secure-tmp` puts the same
	// nodev,nosuid,noexec on both /tmp and /var/tmp via the bind) is
	// effectively OK and should render as such. Only when the
	// inherited option set is incomplete do we fall back to the
	// MountBindOfAnother "fix the primary" guidance below.
	if d.Source != "" && !isGenericMountSource(d.Source) {
		for _, p := range peers {
			if p.MountPoint == rule.MountPoint {
				break
			}
			if peer, ok := mountByPath[p.MountPoint]; ok && peer[0] == d.Source {
				d.BindPrimaryPath = p.MountPoint
				break
			}
		}
	}

	d.Present, d.Missing = splitMountOptionsAware(d.CurrentOptions, rule.Recommended, rule.OptionAliases)

	// Resolve next-boot options from fstab + systemd unit + drop-ins.
	// readFstab/findUnit can be nil in legacy test callers; treat that
	// as "no persisted source" and fall through to the live-only logic.
	d.NextBootOptions, d.PersistedSource = resolveNextBootOptions(rule.MountPoint, readFstab, findUnit)

	switch {
	case len(d.Missing) == 0:
		// Fully hardened. If it's a bind sibling, BindPrimaryPath is
		// already populated and the renderer will note the inheritance;
		// otherwise this is just a plain OK mount.
		d.State = MountOK
	case d.BindPrimaryPath != "":
		// Bind sibling that's missing one or more recommended options.
		// Remediation guidance is "fix the primary row to inherit",
		// distinct from the standalone partial / missing cases.
		d.State = MountBindOfAnother
	case d.NextBootOptions != "" && nextBootCoversRecommended(d.NextBootOptions, rule.Recommended, rule.OptionAliases):
		// Next-boot config already carries every recommended option;
		// the live mount just hasn't been remounted yet. Reboot (or a
		// manual `mount -o remount`) clears this.
		d.State = MountPending
	case len(d.Present) == 0:
		d.State = MountMissingOptions
	default:
		d.State = MountPartialOptions
	}
	return d
}

// resolveNextBootOptions returns the merged options column kernsec
// expects to see on `mountPoint` after the next reboot, based on the
// persistence sources visible on disk. /etc/fstab wins if present
// (systemd's fstab generator gives fstab lines priority over .mount
// units). If no fstab line exists, we fall back to the systemd .mount
// unit's Options= line, with any /etc/systemd/system/<unit>.d/*.conf
// drop-ins layered on top in lexical order — same precedence systemd
// itself uses.
//
// Returns ("", "") when neither source exists (e.g. /dev/shm on a host
// where systemd PID 1 mounts it with its built-in defaults).
func resolveNextBootOptions(
	mountPoint string,
	readFstab func() ([]fstabLine, error),
	findUnit func(unitName string) (path, options string, ok bool),
) (opts, source string) {
	if readFstab != nil {
		if lines, err := readFstab(); err == nil {
			if fl, ok := findFstabEntry(lines, mountPoint); ok {
				return fl.Options, "fstab"
			}
		}
	}
	if findUnit != nil {
		unit := unitNameForMountPath(mountPoint)
		if _, unitOpts, ok := findUnit(unit); ok {
			return unitOpts, "systemd-unit"
		}
	}
	return "", ""
}

// nextBootCoversRecommended returns true when every comma-separated
// option in `recommended` is present in `nextBoot`. Honours the
// rule's OptionAliases — a next-boot config that carries
// `hidepid=invisible` covers a recommendation of `hidepid=2`.
func nextBootCoversRecommended(nextBoot, recommended string, aliases map[string][]string) bool {
	_, missing := splitMountOptionsAware(nextBoot, recommended, aliases)
	return len(missing) == 0
}

// findFstabBindSource returns the source column of the fstab line for
// `mountPoint` when the line declares a bind mount (`bind` in either
// the type or options column). Used by MountPending detection to
// surface "/var/tmp will bind to /tmp at reboot" cleanly. The second
// return is false when fstab is unreadable, the line isn't present,
// or the line isn't a bind.
func findFstabBindSource(readFstab func() ([]fstabLine, error), mountPoint string) (string, bool) {
	if readFstab == nil {
		return "", false
	}
	lines, err := readFstab()
	if err != nil {
		return "", false
	}
	fl, found := findFstabEntry(lines, mountPoint)
	if !found {
		return "", false
	}
	if fl.FSType != "bind" && !containsOption(splitCSV(fl.Options), "bind") {
		return "", false
	}
	return fl.Source, true
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
//
// Equivalent to splitMountOptionsAware with no alias map — kept as
// the simple two-arg signature for callers (and tests) that don't
// need alias-aware matching.
func splitMountOptions(current, recommended string) (present, missing []string) {
	return splitMountOptionsAware(current, recommended, nil)
}

// splitMountOptionsAware is splitMountOptions with a per-rule alias
// map: a recommended option is considered present when either the
// literal token OR any of its registered aliases appears in the
// live options column. See MountRule.OptionAliases for the use case
// (kernel rendering /proc hidepid=2 as "hidepid=invisible").
//
// When the recommendation IS satisfied by an alias rather than the
// canonical token, the alias string is what gets appended to
// `present` — that's what the operator actually sees on the host,
// and what `cfm kernsec status` should echo back to them.
//
// Caveat for downstream consumers: `present` is therefore NOT
// guaranteed to be a subset of the comma-tokens of `recommended` —
// it can contain alias tokens that the recommendation doesn't list
// literally. Today only the status renderer consumes it (via
// strings.Join for display, which is alias-agnostic). Any future
// consumer doing token-set arithmetic against `recommended` needs to
// fold aliases back in via this map.
func splitMountOptionsAware(current, recommended string, aliases map[string][]string) (present, missing []string) {
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
			continue
		}
		matched := ""
		for _, alt := range aliases[o] {
			alt = strings.TrimSpace(alt)
			if alt == "" {
				continue
			}
			if _, ok := have[alt]; ok {
				matched = alt
				break
			}
		}
		if matched != "" {
			present = append(present, matched)
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
		// Auto-application is enabled for /tmp. Persistence-only:
		// EnableMount writes either an /etc/fstab edit (EL / cPanel
		// / hosts with a /tmp line) or a systemd tmp.mount drop-in
		// (Debian / Ubuntu / Arch — systemd PID 1 owns /tmp via
		// /usr/lib/systemd/system/tmp.mount). The live `mount -o
		// remount` is deliberately skipped: every service with
		// PrivateTmp=yes (mysqld, named, php-fpm, nginx, exim, …)
		// has bind mounts rooted in the current /tmp namespace and
		// would either fail or end up pointing at a stale namespace
		// after a live remount. The row therefore reports PEND
		// until the next reboot converges live to next-boot.
		// MountNotSeparate /tmp (root-fs /tmp on a host without
		// either a fstab line or a tmp.mount unit, e.g. minimal EL)
		// is refused with a pointer to `cfm kernsec secure-tmp`.
		CanEnable:   true,
		Description: "Recommend nodev,nosuid,noexec on /tmp to neutralize world-writable exec attacks.",
		Affects:     "noexec breaks some composer / pip / cPanel workflows; review first. Reboot required to converge.",
	},
	{
		ID: "KSEC-FS-mount.tmp-002", Group: "fs.mount.tmp", Tier: Tier1,
		MountPoint:  "/var/tmp",
		Recommended: "nodev,nosuid,noexec",
		// Same persistence-only Enable contract as /tmp. When
		// /var/tmp is NOT separately mounted (live on /), Enable
		// adds a bind-mount fstab line: `/tmp /var/tmp none bind`
		// so /var/tmp inherits /tmp's hardening after reboot
		// without provisioning a second filesystem. Disable
		// removes the bind line. Existing content under /var/tmp
		// is shadowed by the bind (not deleted) — operators with
		// state they care about under /var/tmp should use
		// `cfm kernsec secure-tmp` instead, which provisions
		// genuine separate mounts.
		CanEnable:   true,
		Description: "Same protection family for /var/tmp.",
		Affects:     "Same compatibility considerations as /tmp. Reboot required to converge.",
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
		// /tmp and /var/tmp are CanEnable too, but persistence-only:
		// Enable writes an /etc/fstab edit (or a systemd tmp.mount
		// drop-in) and deliberately leaves the running kernel alone —
		// a live remount would break every PrivateTmp=yes service that
		// has bind mounts rooted in the current /tmp namespace, so
		// those rows report PEND until reboot. /dev/shm is the only row
		// that ALSO live-remounts (safe: tmpfs, no on-disk state). On a
		// cPanel securetmp host (/usr/tmpDSK) /var/tmp is left to
		// securetmp entirely — see EnableMount.
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

	// --- /proc hidepid (audit-only; CanEnable defaults to false) -----
	//
	// hidepid=2 hides /proc/<pid> entries from users who don't own them:
	// `ps aux` by a non-root user only shows their own processes,
	// /proc/<other-pid>/cmdline / status / environ / fd /maps become
	// unreadable. Root sees everything regardless. Closes a huge
	// reconnaissance channel for compromised vhost users — sshd
	// command-lines, mysql args, and admin sessions all leak through
	// /proc otherwise.
	//
	// gid=<group> is the escape valve: members of that group keep full
	// visibility. Needed for third-party monitoring agents (Munin node,
	// Netdata's apps.plugin, Zabbix agent, New Relic, Datadog) that
	// scrape /proc as non-root for per-process metrics. The operator
	// creates the group, adds the monitoring uids, then mounts with
	// gid=<gid>.
	//
	// CanEnable is intentionally FALSE here even though the same machinery
	// could mutate fstab and remount. The reason is the gid= escape: we
	// can't know the operator's monitoring layout at apply time, and
	// silently breaking metric collection on a production host erodes
	// trust faster than any single hardening can recover. Operators
	// review the recommendation, set up the group, then opt in via a
	// manual fstab edit. The audit hint surfaces in `cfm kernsec status`
	// alongside the /tmp / /var/tmp / /dev/shm rows.
	{
		ID: "KSEC-FS-mount.proc-001", Group: "fs.mount.proc", Tier: Tier1,
		MountPoint: "/proc",
		// Recommended carries ONLY the audit-checkable security
		// invariant (hidepid is on). gid=<group> is intentionally
		// excluded from the literal match: the operator's chosen
		// group name resolves to a numeric gid in /proc/mounts
		// (e.g. `hidepid=2,gid=1234`), so a literal `gid=cfmprocreaders`
		// in Recommended would render as permanent MISSING on every
		// correctly-configured host. The recipe in docs/kernsec.md
		// covers the group setup; here we just verify the kernel
		// stopped exposing other users' /proc entries.
		Recommended: "hidepid=2",
		// Kernels >= 5.8 render hidepid=2 as the literal token
		// `hidepid=invisible` in /proc/mounts (the symbolic name was
		// introduced in commit 24a71ce5c47f); hidepid=4 /
		// hidepid=ptraceable are strictly stricter. All three satisfy
		// the recommendation.
		OptionAliases: map[string][]string{
			"hidepid=2": {"hidepid=invisible", "hidepid=4", "hidepid=ptraceable"},
		},
		Description: "Recommend hidepid=2,gid=<group> on /proc to hide other users' processes from non-root readers. The single largest reconnaissance-channel reduction on shared hosting: vhost users can no longer enumerate sshd command-lines, mysql -p args, or other tenants' workloads via ps / /proc/*. Group escape valve preserves monitoring-agent visibility.",
		Affects:     "Third-party monitoring agents (Munin, Netdata, Zabbix, New Relic, Datadog) that scrape /proc as non-root stop collecting per-process metrics until their uid is added to the gid= group. cPanel / DirectAdmin / CloudLinux daemons all run as root and are unaffected. CageFS-confined users get correct narrower visibility (a feature, not a break). Operator opts in manually after creating the group and adding monitoring uids — kernsec does not auto-mutate fstab for this rule.",
	},
}
