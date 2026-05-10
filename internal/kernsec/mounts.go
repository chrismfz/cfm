package kernsec

import (
	"os"
	"strings"
)

// MountState describes the runtime state of one MountRule against
// /proc/mounts.
type MountState int

const (
	// MountOK means the mount point is present and every recommended
	// option is active.
	MountOK MountState = iota
	// MountMissingOptions means the mount point is present but at
	// least one recommended option is not active. Audit-only —
	// kernsec never auto-mutates /etc/fstab; operator chooses.
	MountMissingOptions
	// MountNotSeparate means the mount point is not a distinct mount
	// in /proc/mounts (e.g. /var/tmp on the root filesystem).
	// Recommendations don't apply: you can't add `nodev` to a
	// directory that isn't a mount.
	MountNotSeparate
)

// CheckMount reads /proc/mounts and reports whether the given rule's
// recommended options are active on its mount point. Returns the
// state plus the current options string (empty if not separately
// mounted) for display.
func CheckMount(rule MountRule) (state MountState, currentOptions string) {
	return checkMountFromProc(readProcMounts(), rule)
}

// checkMountFromProc is the testable inner function — operates on raw
// /proc/mounts content rather than the live file. Last matching entry
// wins; a later mount over the same point shadows the earlier one and
// the operator cares about the currently-active options.
func checkMountFromProc(procMounts string, rule MountRule) (MountState, string) {
	state := MountNotSeparate
	current := ""
	for _, line := range strings.Split(procMounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[1] != rule.MountPoint {
			continue
		}
		current = fields[3]
		if hasAllMountOptions(current, rule.Recommended) {
			state = MountOK
		} else {
			state = MountMissingOptions
		}
	}
	return state, current
}

// hasAllMountOptions returns true iff every comma-separated option in
// `recommended` is present in `current`. Both are treated as
// comma-separated sets; ordering and additional options in `current`
// don't matter.
func hasAllMountOptions(current, recommended string) bool {
	have := make(map[string]struct{})
	for _, o := range strings.Split(current, ",") {
		have[strings.TrimSpace(o)] = struct{}{}
	}
	for _, o := range strings.Split(recommended, ",") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if _, ok := have[o]; !ok {
			return false
		}
	}
	return true
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

// Tier1Mounts is the fstab audit set. kernsec **never** auto-mutates
// /etc/fstab — `noexec` on /tmp breaks several composer / pip / cPanel
// workflows. The rule rows surface in `cfm kernsec status` / TUI as
// audit-only "your /tmp would benefit from nodev,nosuid,noexec" hints
// that operators decide on themselves.
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
		Description: "Same protection family for /dev/shm (POSIX shared-memory tmpfs).",
		Affects:     "Mostly safe in practice; double-check JVM / Python multiprocessing usage.",
	},
	{
		ID: "KSEC-FS-mount.home-001", Group: "fs.mount.home", Tier: Tier1,
		MountPoint:  "/home",
		Recommended: "nodev,nosuid",
		Description: "nodev,nosuid on /home — noexec is intentionally NOT recommended (breaks too much).",
		Affects:     "Nothing in normal use. Do not add noexec.",
	},
}
