package lsm

import (
	"path/filepath"
	"strings"
	"sync/atomic"
)

// filter.go — userspace post-emission allowlist for cfm-lsm events.
//
// The BPF programs deliberately err on the side of "report and let
// userspace decide": adding map lookups or comm comparisons to every
// hook costs verifier complexity, takes effect only after `make bpf`
// regeneration, and can't see across containerised exe-file identities
// (the same daemon under a Docker overlayfs has a different inode every
// time the image is repulled).
//
// This filter lives entirely in the daemon. It consults a per-policy
// allowlist of known-legitimate triggers and silently drops matching
// events before they reach notify/log/kmsg. The allowlist is loaded
// from compiled-in defaults plus operator-configurable lsm.conf
// entries; the matcher is intentionally simple (basename equality for
// exe identities, exact match for comm names) to keep the suppression
// surface auditable.
//
// Two match dimensions:
//
//   - ExeBasenames: matches Event.Filename when it is either an
//     absolute path (CFML-EXEC-003 / CFML-EXEC-005 emit the bprm
//     filename) or a bare d_name (CFML-CRED-002 emits the exe
//     dentry's d_name). filepath.Base normalises both forms before
//     comparing against the allowlist.
//
//   - Comms: matches Event.Comm exactly. Comm strings come from
//     bpf_get_current_comm and are TASK_COMM_LEN (16) bytes — long
//     binary names get truncated to 15 chars, so the allowlist must
//     hold the truncated forms (e.g. "containerd-shim" not
//     "containerd-shim-runc-v2").
//
// The filter never observes pid/uid; that's deliberate. The default
// list covers daemons whose detector match is structural to the way
// the daemon implements privilege separation or inetd-style worker
// dispatch, not specific to one host's account layout.

// EventFilter encodes which events to silently drop. Construction is
// cheap; the daemon installs one global instance via SetEventFilter
// after parsing lsm.conf and consults it from emitNotify.
type EventFilter struct {
	rules map[PolicyID]policyAllow
}

type policyAllow struct {
	exeBasenames map[string]struct{}
	comms        map[string]struct{}
}

// defaultEventFilter is the package-internal singleton consulted by
// emitNotify. Atomic so ApplyConfig can swap a fresh filter in without
// racing against the drain goroutine.
var defaultEventFilter atomic.Pointer[EventFilter]

// SetEventFilter installs f as the global filter consulted by
// emitNotify. Safe to call from any goroutine; the swap is atomic.
// Pass nil to clear the filter (no suppression).
func SetEventFilter(f *EventFilter) {
	defaultEventFilter.Store(f)
}

// shouldSuppressEvent reports whether the globally-installed filter
// would drop ev. Returns false when no filter is installed.
func shouldSuppressEvent(ev Event) bool {
	f := defaultEventFilter.Load()
	if f == nil {
		return false
	}
	return f.Match(ev)
}

// Match reports whether ev is on f's allowlist for its policy. The
// match is conservative: only events whose policy has an explicit
// rule set are even consulted; everything else falls through to
// "report normally."
func (f *EventFilter) Match(ev Event) bool {
	if f == nil {
		return false
	}
	rule, ok := f.rules[ev.PolicyID]
	if !ok {
		return false
	}
	if len(rule.exeBasenames) > 0 && ev.Filename != "" {
		base := filepath.Base(ev.Filename)
		if _, hit := rule.exeBasenames[base]; hit {
			return true
		}
	}
	if len(rule.comms) > 0 && ev.Comm != "" {
		if _, hit := rule.comms[ev.Comm]; hit {
			return true
		}
	}
	return false
}

// BuildEventFilter constructs an EventFilter from compiled-in defaults
// merged with operator-supplied conf overrides. Conf may be nil, in
// which case only defaults apply.
//
// allow_exe entries are normalised to filepath.Base before storage so
// the matcher can compare against either bare d_name or absolute path
// emissions uniformly. allow_comm entries are stored as-is; the BPF
// side truncates to TASK_COMM_LEN, so operators copy the comm exactly
// as it appears in dmesg.
func BuildEventFilter(c *Conf) *EventFilter {
	f := &EventFilter{rules: map[PolicyID]policyAllow{}}
	for id, basenames := range defaultExeBasenames {
		f.addExeBasenames(id, basenames)
	}
	for id, comms := range defaultComms {
		f.addComms(id, comms)
	}
	if c != nil {
		for id, paths := range c.AllowExe {
			for _, p := range paths {
				f.addExeBasenames(id, []string{filepath.Base(p)})
			}
		}
		for id, comms := range c.AllowComm {
			f.addComms(id, comms)
		}
	}
	return f
}

func (f *EventFilter) addExeBasenames(id PolicyID, names []string) {
	if len(names) == 0 {
		return
	}
	r := f.rules[id]
	if r.exeBasenames == nil {
		r.exeBasenames = map[string]struct{}{}
	}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		r.exeBasenames[n] = struct{}{}
	}
	f.rules[id] = r
}

func (f *EventFilter) addComms(id PolicyID, names []string) {
	if len(names) == 0 {
		return
	}
	r := f.rules[id]
	if r.comms == nil {
		r.comms = map[string]struct{}{}
	}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		r.comms[n] = struct{}{}
	}
	f.rules[id] = r
}

// defaultExeBasenames lists the well-known exe basenames whose CFM-LSM
// match is structural to the daemon's normal operation rather than a
// real privilege-escalation or reverse-shell attempt.
//
// CFML-CRED-002: system daemons whose privilege model is "start as
// root → drop to a service uid → re-elevate to root for a specific
// operation" (sshd's privsep, postfix master switching between
// postfix/root, dovecot indexer-worker, systemd's sd-executor, the
// pam_systemd user-manager spawn). None of these binaries carry the
// suid bit on disk, so the on-disk cfm_setuid_inodes allowlist does
// not cover them; we suppress in userspace by basename to also catch
// the containerised variants (mailcow, official Postfix/Dovecot images)
// where the exe inode differs from any host-walked path.
//
// CFML-EXEC-003: `logger` is the canonical syslog helper exec'd from
// postfix spawn(8) inetd-style worker scripts. The worker's stdio is
// already wired to the accepted inet socket by master before exec, so
// every child trips the strict three-fd-remote detector. Operators
// add their site-specific spawn-helper scripts via allow_exe.
var defaultExeBasenames = map[PolicyID][]string{
	PolicyCredEscal: {
		"sshd",
		"sshd-session",
		"sshd-auth",
		"systemd",
		"systemd-executor",
		"(systemd)",
		"master",          // postfix master
		"pickup",          // postfix
		"qmgr",            // postfix
		"smtpd",           // postfix
		"cleanup",         // postfix
		"local",           // postfix local delivery
		"virtual",         // postfix virtual delivery
		"trivial-rewrite", // postfix
		"proxymap",        // postfix
		"tlsmgr",          // postfix
		"anvil",           // postfix
		"verify",          // postfix
		"bounce",          // postfix
		"oqmgr",           // postfix
		"showq",           // postfix
		"postdrop",
		"postqueue",
		"dovecot",
		"imap",
		"imap-login",
		"pop3",
		"pop3-login",
		"lmtp",
		"managesieve",
		"managesieve-login",
		"indexer",
		"indexer-worker",
		"auth",        // dovecot auth
		"auth-worker", // dovecot
		"director",    // dovecot
		"stats",       // dovecot
		"config",      // dovecot
		"log",         // dovecot
		"dict",        // dovecot
		"anvil",       // dovecot (shares name with postfix; both legitimate)
		"replicator",  // dovecot
		"script-login",
		"cron",
		"CRON",
		"crond",
		"atd",
		"agetty",
		"login",
		"su",
		"sudo",
		"polkitd",
		"pkexec",
		"dbus-daemon",
		"dbus-broker",
		"dbus-broker-lau", // truncated comm "dbus-broker-launch"
		"accounts-daemon",
		"unbound",
		"named",
		"rspamd",
		"clamd",
		"freshclam",
		"rpcbind",
		"snmpd",
		"chronyd",
		"ntpd",
		"qemu-ga",
		"syslog-ng",
		"rsyslogd",
		"supervisord",
	},
	PolicyReverseShell: {
		"logger", // postfix spawn(8) calls logger from inetd-style worker scripts
	},
	PolicyInterpreterNetStdio: {
		// EXEC-005 is the weak companion of EXEC-003; same logger
		// pattern dominates the noise on postfix hosts.
		"logger",
	},
}

// defaultComms lists comm names whose CFML-BPF-001 match is the
// container runtime's normal initialisation: runc / crun load seccomp
// programs and BPF maps on every container start, containerd-shim
// proxies the same calls, dockerd / podman / cri-o orchestrate them.
// The BPF-side cfm_comm_is_trusted_bpf_agent allowlist already
// suppresses systemd, NetworkManager, bpftool, and auditd; userspace
// adds the container-runtime layer without a BPF rebuild.
//
// Comm strings here must already be truncated to the kernel's
// TASK_COMM_LEN-1 width (15 chars). `containerd-shim-runc-v2` for
// instance presents as `containerd-shim` in bpf_get_current_comm.
var defaultComms = map[PolicyID][]string{
	PolicyUnexpectedBPF: {
		"runc",
		"runc:[1:CHILD]",
		"runc:[2:INIT]",
		"crun",
		"containerd",
		"containerd-shim",
		"dockerd",
		"docker",
		"docker-init",
		"docker-proxy",
		"docker-untar",
		"podman",
		"conmon",
		"crio",
		"cri-dockerd",
		"kubelet",
		"kube-proxy",
		"buildkitd",
		"buildah",
		"nerdctl",
	},
}
