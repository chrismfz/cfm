package lsm

// PolicyID is the stable identifier for one cfm-lsm policy.
//
// IDs use the CFML-<DOMAIN>-<NNN> shape from docs/cfm-lsm.md.
// They are stable across releases — operators reference them in
// /etc/cfm/lsm.conf, in alerts, and in audit logs, so renaming a
// policy ID is a breaking change.
type PolicyID string

const (
	// PolicyMemfdExec — CFML-EXEC-001: refuse execve when the
	// backing file has no on-disk path (memfd / anonymous shmem).
	PolicyMemfdExec PolicyID = "CFML-EXEC-001"

	// PolicyReverseShell — CFML-EXEC-003: detect a process about
	// to exec with fds 0/1/2 dup'd onto a remote-connected socket.
	PolicyReverseShell PolicyID = "CFML-EXEC-003"

	// PolicyDeletedFileExec — CFML-EXEC-004: detect a web-class
	// user (or later, web-origin task) executing a file whose backing
	// inode has been unlinked/deleted after open. Monitor-first by
	// default; enforce is opt-in only after telemetry.
	PolicyDeletedFileExec PolicyID = "CFML-EXEC-004"

	// PolicyInterpreterNetStdio — CFML-EXEC-005: monitor suspicious
	// interpreter / shell / socket-helper execs when one or two of
	// stdin/stdout/stderr point at established remote TCP sockets. This
	// is weak companion telemetry for CFML-EXEC-003, not a default
	// enforce policy.
	PolicyInterpreterNetStdio PolicyID = "CFML-EXEC-005"

	// PolicySensitiveWrite — CFML-FS-005: detect a web-class user
	// (apache / nginx / php-fpm / panel-managed account) attempting
	// to modify a host-sensitive file (/etc/passwd, /etc/shadow,
	// /etc/sudoers*, /etc/cron*, /etc/ssh/*, /root/.ssh/,
	// /home/<other>/.ssh/, /etc/pam.d/). Covers the post-exploit
	// cash-in after any privesc — including kernel 0-days like
	// Dirty Pipe / Dirty COW that bypass other LSM hooks.
	PolicySensitiveWrite PolicyID = "CFML-FS-005"

	// PolicyCredEscal — CFML-CRED-002: detect a process gaining
	// effective uid 0 from non-zero without going through a
	// recognised setuid binary in its mm->exe_file. The canonical
	// kernel-exploit-completion fingerprint. Monitor-only by
	// design: returning -EPERM from cred_prepare can deadlock
	// systemd helpers mid-transition.
	PolicyCredEscal PolicyID = "CFML-CRED-002"

	// PolicyDirectCredInstall — CFML-CRED-003: detect direct
	// commit_creds() installation of root credentials that bypassed
	// task_fix_setuid. Monitor-only by design because commit_creds()
	// is not an LSM decision point.
	PolicyDirectCredInstall PolicyID = "CFML-CRED-003"

	// PolicyUnexpectedBPF — CFML-BPF-001: detect unexpected use of
	// the bpf() syscall to create maps or load programs outside CFM
	// and a small set of trusted distro agents. Monitor-only advanced
	// threat telemetry; broad unprivileged BPF reduction belongs in
	// kernsec sysctls.
	PolicyUnexpectedBPF PolicyID = "CFML-BPF-001"

	// PolicyFdCredMismatch — CFML-FS-006: detect a non-root task
	// reading a sensitive file through a struct file whose f_cred
	// is root, i.e. the file was opened in a privileged context and
	// the descriptor is now being used by an unprivileged one. This
	// is the kernel-side fingerprint of the setuid-helper fd-leak
	// class — `pidfd_getfd()` exit-window race against ssh-keysign /
	// chage / unix_chkpwd, plus the older `CLONE_FILES` + setuid-exec
	// and `/proc/<pid>/fd/<n>` race variants. Kernsec already ships
	// `kernel.yama.ptrace_scope=2` (KSEC-SCT-kspp.kernel-006) which
	// kills the modern `pidfd_getfd()` primitive, but operators who
	// explicitly need same-uid debuggability (`gdb --attach`, `strace
	// -p`, `py-spy` without sudo) `state = skip` that rule and lose
	// the kernel-level block — CFML-FS-006 is their belt-and-braces
	// layer, and also catches future fd-leak variants that don't go
	// through ptrace at all.
	//
	// Hook: lsm/file_permission (every read/write through any fd).
	// Mechanism: compare `current_cred()->euid` against
	// `file->f_cred->euid`. When current is non-root, f_cred is root,
	// AND the dentry's (fs_id, ino) is in cfm_watched_inodes (the
	// same sensitive-path table FS-005 already maintains —
	// /etc/shadow, /etc/gshadow, /etc/sudoers*, /root/.ssh/*,
	// /etc/ssh/ssh_host_*_key, ...), emit a telemetry event.
	//
	// Mode: monitor-only by default and for the foreseeable future.
	// Several legitimate setuid helpers (passwd, pkexec, sudo,
	// unix_chkpwd, dovecot's auth worker pool, postfix's smtpd_pickup)
	// open these files as root in one task and read(2) from a worker
	// that has dropped privileges; those workers are legitimate
	// cross-cred consumers of the fd. Enforce mode would deny their
	// read and break authentication. Telemetry first; the allow-list
	// for enforce, if it ever lands, has to be scrubbed against
	// production data.
	PolicyFdCredMismatch PolicyID = "CFML-FS-006"

	// PolicyEphemeralExec — CFML-EXEC-006: detect a web-class user
	// executing a binary whose backing file is on an ephemeral /
	// writeable-by-web-user filesystem — /tmp/, /var/tmp/, /dev/shm/,
	// or /run/user/<uid>/. The execution-phase companion to Imunify
	// Proactive Defense's write-phase guard: if a webshell stages a
	// payload to /tmp/.<obfuscated> and the PHP-layer block is absent
	// or bypassed, the kernel still sees the execve and EXEC-006 fires.
	//
	// Hook: bprm_check_security. Monitor-first; enforce returns -EPERM.
	// Enforce on a host with operator-installed software that legitimately
	// extracts-and-execs from /tmp (package installers mid-transaction,
	// cPanel easyapache builds) needs allowlist tuning first — see
	// docs/cfm-lsm.md and the lsm.conf allow_exe / allow_path keys.
	PolicyEphemeralExec PolicyID = "CFML-EXEC-006"

	// PolicyPrivInstall — CFML-FS-007: detect a watched (web-class)
	// uid installing a privilege primitive on a file — either setting
	// the suid/sgid bit via chmod, or writing the security.capability
	// xattr via setcap. The post-exploit-persistence "drop a binary
	// the unprivileged shell can later use to re-acquire root without
	// re-exploiting" pattern. Companion to CFML-CRED-002, which catches
	// the *use* of the dropped primitive; FS-007 catches the *install*.
	//
	// Hooks: inode_setattr (suid/sgid bit) + inode_setxattr
	// (security.capability). No watched-inode gate — the target can be
	// any path; the privilege primitive itself is the signal.
	//
	// Mode: monitor by default. Enforce-capable — there is no
	// legitimate workflow for a web-class uid to set suid or
	// security.capability, so blocking the syscall is safe (returns
	// -EPERM out of chmod/setxattr; the dropper sees the failure and
	// the primitive never lands).
	PolicyPrivInstall PolicyID = "CFML-FS-007"

	// PolicyKernelModuleLoad — CFML-EXEC-007: detect a kernel module
	// being loaded from a non-trusted comm. Threat: kernel-rootkit
	// installer. Companion telemetry to the kernsec sysctl
	// kernel.modules_disabled=1 which actually blocks at the kernel
	// layer for hosts that don't load any modules post-boot.
	//
	// Hooks: tracepoint/syscalls/sys_enter_init_module +
	//        tracepoint/syscalls/sys_enter_finit_module
	//
	// The kernel-side allowlist matches comm names that legitimately
	// load modules: modprobe / insmod / kmod / systemd /
	// systemd-modules / systemd-udevd. Any other comm — or any of
	// those comms running from a watched uid (comm spoofing via
	// prctl by a web-class user) — fires the rule.
	//
	// Mode: monitor ONLY. Tracepoint hooks are observation-only —
	// the kernel ignores any return value the BPF program sets, so
	// enforce is structurally impossible here. Use
	// kernel.modules_disabled=1 to block at the kernel layer.
	PolicyKernelModuleLoad PolicyID = "CFML-EXEC-007"

	// PolicyKernelKnobWrite — CFML-FS-008: detect a write to one of
	// the small set of /proc/sys and /sys kernel knobs that every
	// public kernel exploit from the last five years pivots through
	// once it has the write primitive:
	//
	//   /proc/sys/kernel/core_pattern     — pipe-to-program on coredump
	//   /proc/sys/kernel/modprobe_path    — substitute modprobe binary
	//   /proc/sys/kernel/hotplug          — legacy uevent helper
	//   /proc/sysrq-trigger               — magic sysrq trigger
	//   /sys/kernel/uevent_helper         — modern uevent helper
	//   /proc/sys/fs/binfmt_misc/register — register binfmt exec handler
	//
	// Hook: file_permission. The userspace populator stats each path
	// at adoption time and puts its inode in cfm_kernel_knob_inodes;
	// paths absent on this kernel (CONFIG_MAGIC_SYSRQ=n etc.) skip
	// silently. Writer comms in the trusted set (cfm / sysctl /
	// systemd / systemd-sysctl) are suppressed.
	//
	// Mode: monitor by default. Enforce-capable but DEFAULT monitor —
	// an unanticipated legitimate writer would otherwise silently
	// fail. Promote to enforce after a 30-day monitor window confirms
	// no in-the-wild legitimate writer outside the trusted set.
	PolicyKernelKnobWrite PolicyID = "CFML-FS-008"
)

// Mode is the per-policy enforcement mode.
type Mode int

const (
	// ModeDisabled means the policy is not loaded.
	ModeDisabled Mode = iota
	// ModeMonitor means the policy is attached and emits events,
	// but does not block. This is the default for any policy that
	// has not yet completed its 30-day monitor window.
	ModeMonitor
	// ModeEnforce means the policy is attached and blocks matching
	// behaviour. Only safe after monitor-mode telemetry confirms a
	// near-zero false-positive rate.
	ModeEnforce
)

// String renders the mode as it appears in lsm.conf.
func (m Mode) String() string {
	switch m {
	case ModeMonitor:
		return "monitor"
	case ModeEnforce:
		return "enforce"
	}
	return "disabled"
}

// Policy is the static metadata for one CFM-LSM policy.
//
// Runtime state (whether the BPF program is actually attached,
// recent event counts, last failure reason) is intentionally
// separate — see RuntimeStatus when the BPF backend lands.
type Policy struct {
	ID          PolicyID
	Title       string
	Hook        string // LSM hook this policy attaches to
	DefaultMode Mode   // mode used when lsm.conf is silent on this ID
	Description string
}

// AllPolicies returns the MVP policy catalogue in display order.
// New policies require a separate design proposal; this list is
// the authoritative scope of cfm-lsm.
func AllPolicies() []Policy {
	return []Policy{
		{
			ID:          PolicyMemfdExec,
			Title:       "Block exec from memfd",
			Hook:        "bprm_check_security",
			DefaultMode: ModeDisabled,
			Description: "Refuse execve when the backing file is anonymous shmem (memfd_create).",
		},
		{
			ID:          PolicyReverseShell,
			Title:       "Reverse shell pattern",
			Hook:        "bprm_check_security",
			DefaultMode: ModeDisabled,
			Description: "Detect exec where stdin/stdout/stderr are dup'd to a remote-connected socket.",
		},
		{
			ID:          PolicyDeletedFileExec,
			Title:       "Deleted-file exec by web user",
			Hook:        "bprm_check_security",
			DefaultMode: ModeDisabled,
			Description: "Detect web-class users or web-origin tasks executing deleted/unlinked files; monitor-first, enforce only after telemetry.",
		},
		{
			ID:          PolicyInterpreterNetStdio,
			Title:       "Suspicious interpreter network stdio",
			Hook:        "bprm_check_security",
			DefaultMode: ModeDisabled,
			Description: "Monitor suspicious shell/interpreter/socket-helper execs when one or two stdio fds are established remote TCP sockets; companion telemetry to strict reverse-shell detection.",
		},
		{
			ID:          PolicySensitiveWrite,
			Title:       "Sensitive-file modification by web user",
			Hook:        "inode_{setattr,create,unlink,link,rename,setxattr}",
			DefaultMode: ModeDisabled,
			Description: "Detect a web-class user (apache/nginx/php-fpm/panel account) modifying host-sensitive files (/etc/passwd, /etc/shadow, /etc/sudoers*, /root/.ssh/, ...).",
		},
		{
			ID:          PolicyCredEscal,
			Title:       "Privilege escalation without setuid path",
			Hook:        "task_fix_setuid",
			DefaultMode: ModeDisabled,
			Description: "Detect uid → 0 transitions through code paths that did not go through a recognised setuid binary. Monitor-only by design.",
		},
		{
			ID:          PolicyDirectCredInstall,
			Title:       "Direct root credential install",
			Hook:        "fentry/commit_creds",
			DefaultMode: ModeDisabled,
			Description: "Detect direct commit_creds() installation of root credentials that bypassed task_fix_setuid. Monitor-only by design.",
		},
		{
			ID:          PolicyUnexpectedBPF,
			Title:       "Unexpected BPF use",
			Hook:        "tracepoint/syscalls/sys_enter_bpf",
			DefaultMode: ModeDisabled,
			Description: "Monitor-only telemetry for unexpected bpf() map creation and program load attempts outside CFM and trusted distro agents; use kernsec sysctls for broad unprivileged BPF reduction.",
		},
		{
			ID:          PolicyFdCredMismatch,
			Title:       "Sensitive read via root-owned fd from unprivileged task",
			Hook:        "file_permission",
			DefaultMode: ModeDisabled,
			Description: "Detect a non-root task reading a sensitive file (the FS-005 watched-inodes set: /etc/shadow, /etc/sudoers*, /root/.ssh/*, ...) through a struct file whose f_cred is root. Kernel-side fingerprint of the setuid-helper fd-leak class (pidfd_getfd exit-window race against ssh-keysign / chage / unix_chkpwd, plus CLONE_FILES + setuid-exec and /proc/<pid>/fd races). Belt-and-braces layer for hosts that `state = skip` kernel.yama.ptrace_scope=2 for same-uid debuggability. Monitor-only by design — passwd / pkexec / sudo / dovecot-auth / postfix workers legitimately read these files post-uid-drop.",
		},
		{
			ID:          PolicyEphemeralExec,
			Title:       "Web-user exec from ephemeral filesystem",
			Hook:        "bprm_check_security",
			DefaultMode: ModeDisabled,
			Description: "Detect a web-class user executing a binary whose backing file lives on tmpfs (/dev/shm, /run/user/<uid>/, distro /tmp mounted as tmpfs) or under /tmp/ or /var/tmp/ on a non-tmpfs root. Execution-phase companion to Imunify Proactive Defense's write-phase guard: catches the staged-payload-and-exec pattern at the kernel layer. Monitor-first; enforce returns -EPERM.",
		},
		{
			ID:          PolicyPrivInstall,
			Title:       "Privilege-primitive install by web user",
			Hook:        "inode_{setattr,setxattr}",
			DefaultMode: ModeDisabled,
			Description: "Detect a web-class user installing a privilege primitive — setting the suid/sgid bit via chmod, or writing the security.capability xattr via setcap — on any file. Install-step companion to CFML-CRED-002 which catches the use of the dropped primitive. Monitor-first; enforce returns -EPERM out of chmod/setxattr.",
		},
		{
			ID:          PolicyKernelModuleLoad,
			Title:       "Kernel module load by non-trusted comm",
			Hook:        "tracepoint/syscalls/sys_enter_{init,finit}_module",
			DefaultMode: ModeDisabled,
			Description: "Detect a kernel module being loaded from outside the small trusted-loader set (modprobe / insmod / kmod / systemd / systemd-modules / systemd-udevd). Catches kernel-rootkit installer primitives. Monitor-only by design — tracepoint hooks are observation-only; pair with kernel.modules_disabled=1 (kernsec) for actual block.",
		},
		{
			ID:          PolicyKernelKnobWrite,
			Title:       "Write to a sensitive kernel knob",
			Hook:        "file_permission",
			DefaultMode: ModeDisabled,
			Description: "Detect a write to /proc/sys/kernel/{core_pattern,modprobe_path,hotplug} / /proc/sysrq-trigger / /sys/kernel/uevent_helper / /proc/sys/fs/binfmt_misc/register from outside the trusted-writer set (cfm / sysctl / systemd / systemd-sysctl). Catches kernel-exploit completion pivots through these knobs. Monitor by default; enforce-capable but requires telemetry first.",
		},
	}
}

// PolicyByID returns the Policy with the given ID, or (zero, false)
// if the ID is unknown.
func PolicyByID(id PolicyID) (Policy, bool) {
	for _, p := range AllPolicies() {
		if p.ID == id {
			return p, true
		}
	}
	return Policy{}, false
}
