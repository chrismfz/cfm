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
