package kernsec

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
