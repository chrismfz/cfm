package lsm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ConfPath is the canonical location of the cfm-lsm config file.
// Declared as var (not const) so tests can redirect it to t.TempDir().
var ConfPath = "/etc/cfm/lsm.conf"

// ConfFileMode mirrors kernsec.conf — root-only. The file does not
// contain credentials, but it discloses which LSM hooks are active
// on the host and which policies the operator has enabled, which is
// information an attacker on the box can use to plan around them.
const ConfFileMode os.FileMode = 0o600

// defaultWatchedUidFallbackMin is the shipped default for the
// watched_uid_fallback_min conf knob. Matches /etc/login.defs UID_MIN
// on every modern distro. Both DefaultConf and ParseConf seed their
// zero-value Conf with this so an absent-key conf and a generated-
// default conf agree without drifting.
const defaultWatchedUidFallbackMin = 1000

// Conf is the parsed contents of /etc/cfm/lsm.conf.
type Conf struct {
	// Enabled is the global on/off switch. When false (the default),
	// cfm-lsm does not run preflight at startup and does not attach
	// any BPF programs even if individual policies have non-disabled
	// modes set. Operators opt in by setting `enabled = true`.
	Enabled bool

	// WatchedUidFallbackMin extends cfm_watched_uids with every uid in
	// /etc/passwd at or above this threshold. Layered on top of the
	// static WebUserNames and the panel-manifest uids — always additive,
	// never alternative.
	//
	// Valid values:
	//    0             disable the fallback entirely (rely on static
	//                  names + panel manifest only). Use this on
	//                  hosts where the panel manifest is the single
	//                  source of truth for "what is web-class" and
	//                  admin / sysadmin accounts at uid >= 1000
	//                  should NOT be watched.
	//   >0             explicit threshold. The default in the shipped
	//                  template is 1000 — the /etc/login.defs UID_MIN
	//                  on modern distros — which watches every regular
	//                  user account. Combine with ExcludeUsers /
	//                  ExcludeUIDs / ExcludeGIDs to opt-out known-
	//                  trusted admin accounts.
	//
	// Deprecated: -1 ("auto") used to mean "1000 when no panel manifest
	// is detected, disabled when one is present." That heuristic
	// silently created a coverage gap for admin accounts on panel
	// hosts (an `adduser chris` before DirectAdmin would not appear
	// in the DA vhost-owner manifest, and the auto-fallback would skip
	// the uid-range sweep that would otherwise watch them). Treated
	// as 1000 with a deprecation warning at adoption time; will become
	// a parse error in a future release.
	//
	// Watching extra uids is bounded by the per-detector secondary
	// filter (sensitive-inode for FS-005, deleted-file for EXEC-004,
	// ephemeral-path for EXEC-006), so a permissive fallback adds
	// candidates without flooding event volume.
	WatchedUidFallbackMin int

	// ExcludeUsers / ExcludeUIDs / ExcludeGIDs declare accounts that
	// should NOT be in cfm_watched_uids even when the fallback or
	// the panel manifest would otherwise include them. Each list is
	// applied after the watched set has been built. Used to opt-out
	// known-trusted admin / sysadmin / batch-job accounts on hosts
	// where the default uid-range fallback is broader than desired.
	//
	// Match dimensions are checked independently:
	//   - ExcludeUsers: resolved against /etc/passwd at adoption time.
	//     Missing names are skipped silently (no fatal error if a
	//     listed account doesn't exist on this host).
	//   - ExcludeUIDs: numeric uid match.
	//   - ExcludeGIDs: every uid whose /etc/passwd PRIMARY group
	//     (column 4) is in this set is excluded. Useful for "exclude
	//     everyone whose primary group is wheel" style policies.
	//     NOTE: supplementary groups in /etc/group are NOT consulted.
	//     `exclude_gid = 10` does NOT exclude every user listed in
	//     /etc/group's wheel entry — only those whose passwd primary
	//     gid is literally 10.
	//
	// CAVEAT: excludes apply to every uid produced by the three
	// additive layers, including Layer 1's static WebUserNames. An
	// exclude_user / exclude_uid / exclude_gid that happens to match
	// apache / nginx / nobody / etc WILL drop them from the watched
	// set, defeating Layer 1. Treated as an explicit operator
	// decision — verify with `bpftool map dump pinned
	// /sys/fs/bpf/cfm/maps/cfm_watched_uids` after `cfm lsm restart`.
	ExcludeUsers []string
	ExcludeUIDs  []uint32
	ExcludeGIDs  []uint32

	// Modes maps a policy ID to its configured mode. Policies absent
	// from this map fall back to the policy's DefaultMode (currently
	// always ModeDisabled).
	Modes map[PolicyID]Mode

	// FS005WebOriginMonitor enables CFML-FS-005 origin tracking in
	// monitor-only mode. When true, the BPF program records tasks whose
	// real/effective/fs uid matches cfm_watched_uids and reports later
	// sensitive writes by those tasks even after their current uid changes.
	FS005WebOriginMonitor bool

	// PersistencePaths is the operator-supplied per-policy list of additional
	// host-persistence paths to monitor. Today only CFML-FS-005 consumes it;
	// every configured path is treated as monitor-only even when FS-005 mode is
	// enforce. Paths are absolute, concrete paths resolved to (dev,inode) at
	// daemon start.
	PersistencePaths map[PolicyID][]string

	// AllowExe is the operator-supplied per-policy executable allowlist.
	// Each entry is an absolute path to a binary whose match should be
	// treated as legitimate for the policy.
	//
	// CFML-CRED-002 merges these into cfm_setuid_inodes alongside the
	// disk-walked suid-bit binaries so panel daemons (directadmin /
	// cpanel) that legitimately call setresuid(0,…) without the suid
	// bit on disk stop firing CRED-002. CFML-EXEC-003 / CFML-EXEC-005
	// use the basename of each entry as a userspace post-filter against
	// the event's bprm filename, so site-specific postfix spawn(8)
	// inetd-style helper scripts can be excluded from the strict
	// reverse-shell detector.
	AllowExe map[PolicyID][]string

	// AllowComm is the operator-supplied per-policy comm-name
	// allowlist. Each entry is matched literally against the event's
	// 16-byte TASK_COMM_LEN comm string. Used by the userspace
	// post-filter to suppress events from processes whose comm is
	// known-legitimate but whose exe path is not stable (containerised
	// daemons, kernel-thread-style helpers, runtimes whose argv0 the
	// operator controls).
	//
	// CFML-BPF-001 is the primary consumer today — operators add
	// container-runtime comm names that are not in the compiled-in
	// default list (custom orchestrators, vendor agents).
	AllowComm map[PolicyID][]string

	// GlobalAllowExe is the operator-supplied global executable
	// allowlist from the `[allow]` section. Every entry is fanned out
	// to every policy that consults an exe allowlist (CRED-002,
	// EXEC-003, EXEC-005) at read time via AllowExeFor. Stored
	// separately from the per-policy map so FormatConf can render a
	// clean roundtrip and operators can see at a glance which entries
	// are universal versus surgically scoped.
	//
	// Missing paths are silently skipped at daemon start: stat() that
	// fails just contributes nothing to the BPF-side cfm_setuid_inodes
	// map, while the userspace filter still suppresses by basename so
	// cross-distro path lists are safe to ship as defaults.
	GlobalAllowExe []string

	// GlobalAllowComm is the operator-supplied global comm allowlist
	// from the `[allow]` section. Every entry is fanned out to every
	// policy that consults a comm allowlist (BPF-001, plus the other
	// monitor-only-by-design policies for symmetry) at read time via
	// AllowCommFor.
	GlobalAllowComm []string

	// GlobalAllowPath is the operator-supplied global path-prefix
	// allowlist. Distinct dimension from GlobalAllowExe / GlobalAllowComm
	// because Python / Perl daemons share a generic exe (python3.11 /
	// perl) and a generic comm (python3) — neither of the other two
	// can identify them. The filter reads /proc/<pid>/cmdline at event
	// time and matches any argument against these prefixes; this also
	// covers plain binaries whose argv[0] starts with the prefix, so
	// one entry like `/usr/local/cpanel/` blankets every cPanel daemon.
	//
	// SECURITY TRADE-OFF: this is the broadest allowlist dimension and
	// the most dangerous to misuse. Adding `/tmp/` or `/home/` would
	// silence CRED-002 / EXEC-003 / EXEC-005 for anything launched from
	// those trees. Reserve for vendor-owned, root-managed directories
	// (CloudLinux / cPanel / Imunify360 trees); operator-writable paths
	// turn the detector into a no-op for that subtree.
	GlobalAllowPath []string

	// Kmsg controls dmesg emission. Populated from the `[kmsg]`
	// section of lsm.conf; defaults from DefaultKmsgConf() if the
	// section is absent.
	Kmsg KmsgConf

	// EventSink controls userspace DETECT emission (cfm.log + notify).
	// Populated from the `[events]` section of lsm.conf; defaults from
	// DefaultEventSinkConf() if absent. Independent of Kmsg — the two
	// sinks have separate per-policy rate caps.
	EventSink EventSinkConf

	// Source is the path the conf was loaded from, or a synthesised
	// description ("(default — no <path>)") when no file was present.
	Source string
}

// DefaultConf returns the default configuration that `cfm lsm init`
// writes on a fresh host: cfm-lsm globally disabled, every policy at
// its DefaultMode, kmsg emission on with the documented defaults, and
// a curated global allowlist that silences the structural detector
// matches every reasonably-configured Linux host exhibits.
func DefaultConf() *Conf {
	modes := map[PolicyID]Mode{}
	for _, p := range AllPolicies() {
		modes[p.ID] = p.DefaultMode
	}
	return &Conf{
		Enabled:               false,
		WatchedUidFallbackMin: defaultWatchedUidFallbackMin,
		Modes:                 modes,
		FS005WebOriginMonitor: true,
		PersistencePaths:      map[PolicyID][]string{},
		AllowExe:              map[PolicyID][]string{},
		AllowComm:             map[PolicyID][]string{},
		GlobalAllowExe:        append([]string{}, DefaultGlobalAllowExe...),
		GlobalAllowComm:       append([]string{}, DefaultGlobalAllowComm...),
		GlobalAllowPath:       append([]string{}, DefaultGlobalAllowPath...),
		Kmsg:                  DefaultKmsgConf(),
		EventSink:             DefaultEventSinkConf(),
	}
}

// DefaultGlobalAllowExe is the curated cross-distro list of exe paths
// whose detector match is structural to the daemon's normal operation
// rather than evidence of compromise. Shipped uncommented in the
// default lsm.conf via FormatConf; missing paths are silently skipped
// at daemon start, so the list stays safe across Debian / RHEL /
// Alpine path conventions and through panel installs that replace
// system daemons with vendor builds.
//
// Categories:
//
//   - OpenSSH privsep helpers (sshd, sshd-session, sshd-auth).
//   - systemd executor + unit-spawn shims.
//   - Postfix master and the standard service daemons that master
//     forks (pickup, qmgr, cleanup, smtpd, postscreen, spawn, ...);
//     the bare spawn(8) inetd-style worker scripts are NOT in this
//     list because they are site-specific (mailcow ships them under
//     /usr/local/bin/...), but well-known mailcow helpers are.
//   - Dovecot core daemons + indexer-worker (the noisiest CRED-002
//     match on mailcow/dovecot hosts).
//   - /usr/bin/logger — the canonical postfix spawn(8) descendant
//     whose stdio comes from master pre-exec.
//   - Package managers (apt, dpkg, dnf, yum, rpm) — drop to a
//     download-only user (_apt) and re-elevate to root mid-run, so
//     they routinely trip CRED-002 during system updates.
//   - Mailcow's stock spawn(8) helper scripts under /usr/local/bin/.
//   - CloudLinux CageFS server + control tools (legitimate uid
//     transitions into per-account cages), plus the per-cage PHP
//     session cleanup cron.
//   - cPanel server daemon and its variant entry points
//     (cpsrvd / webmaild / whostmgrd share the cpsrvd binary;
//     xml-api / cpdavd / queueprocd / cpanellogd are sibling binaries
//     with separate exe inodes), the quota-status helper, and the
//     update_quota_cache binary that the cron-driven cache updater
//     invokes.
//   - SpamAssassin's DCC client (dccproc).
//
// New entries should cover a widely-deployed host class. Missing paths
// are silently skipped at daemon start, so adding a CloudLinux- or
// cPanel-specific path costs zero on non-CloudLinux / non-cPanel
// hosts. Truly site-specific entries (one operator's custom helper
// script) belong in operator conf, not here.
var DefaultGlobalAllowExe = []string{
	// OpenSSH privsep
	"/usr/sbin/sshd",
	"/usr/lib/openssh/sshd",
	"/usr/lib/openssh/sshd-session",
	"/usr/lib/openssh/sshd-auth",
	"/usr/libexec/openssh/sshd-session",
	"/usr/libexec/openssh/sshd-auth",

	// systemd
	"/usr/lib/systemd/systemd",
	"/lib/systemd/systemd",
	"/usr/lib/systemd/systemd-executor",
	"/lib/systemd/systemd-executor",

	// Postfix master + standard service daemons (Debian + RHEL paths)
	"/usr/lib/postfix/sbin/master",
	"/usr/libexec/postfix/master",
	"/usr/lib/postfix/sbin/pickup",
	"/usr/libexec/postfix/pickup",
	"/usr/lib/postfix/sbin/qmgr",
	"/usr/libexec/postfix/qmgr",
	"/usr/lib/postfix/sbin/cleanup",
	"/usr/libexec/postfix/cleanup",
	"/usr/lib/postfix/sbin/smtpd",
	"/usr/libexec/postfix/smtpd",
	"/usr/lib/postfix/sbin/proxymap",
	"/usr/libexec/postfix/proxymap",
	"/usr/lib/postfix/sbin/trivial-rewrite",
	"/usr/libexec/postfix/trivial-rewrite",
	"/usr/lib/postfix/sbin/tlsmgr",
	"/usr/libexec/postfix/tlsmgr",
	"/usr/lib/postfix/sbin/anvil",
	"/usr/libexec/postfix/anvil",
	"/usr/lib/postfix/sbin/local",
	"/usr/libexec/postfix/local",
	"/usr/lib/postfix/sbin/virtual",
	"/usr/libexec/postfix/virtual",
	"/usr/lib/postfix/sbin/bounce",
	"/usr/libexec/postfix/bounce",
	"/usr/lib/postfix/sbin/postscreen",
	"/usr/libexec/postfix/postscreen",
	"/usr/lib/postfix/sbin/spawn",
	"/usr/libexec/postfix/spawn",
	"/usr/lib/postfix/sbin/error",
	"/usr/libexec/postfix/error",
	"/usr/lib/postfix/sbin/showq",
	"/usr/libexec/postfix/showq",
	"/usr/lib/postfix/sbin/scache",
	"/usr/libexec/postfix/scache",
	"/usr/lib/postfix/sbin/verify",
	"/usr/libexec/postfix/verify",
	"/usr/lib/postfix/sbin/oqmgr",
	"/usr/libexec/postfix/oqmgr",
	"/usr/lib/postfix/sbin/discard",
	"/usr/libexec/postfix/discard",
	"/usr/lib/postfix/sbin/lmtp",
	"/usr/libexec/postfix/lmtp",
	"/usr/lib/postfix/sbin/smtp",
	"/usr/libexec/postfix/smtp",
	"/usr/lib/postfix/sbin/pipe",
	"/usr/libexec/postfix/pipe",
	"/usr/lib/postfix/sbin/dnsblog",
	"/usr/libexec/postfix/dnsblog",
	"/usr/lib/postfix/sbin/tlsproxy",
	"/usr/libexec/postfix/tlsproxy",

	// Dovecot core
	"/usr/sbin/dovecot",
	"/usr/lib/dovecot/imap",
	"/usr/lib/dovecot/imap-login",
	"/usr/lib/dovecot/pop3",
	"/usr/lib/dovecot/pop3-login",
	"/usr/lib/dovecot/lmtp",
	"/usr/lib/dovecot/managesieve",
	"/usr/lib/dovecot/managesieve-login",
	"/usr/lib/dovecot/indexer",
	"/usr/lib/dovecot/indexer-worker",
	"/usr/lib/dovecot/auth",
	"/usr/lib/dovecot/anvil",
	"/usr/lib/dovecot/director",
	"/usr/lib/dovecot/replicator",
	"/usr/lib/dovecot/stats",
	"/usr/lib/dovecot/config",
	"/usr/lib/dovecot/log",
	"/usr/lib/dovecot/dict",
	"/usr/lib/dovecot/script-login",
	"/usr/libexec/dovecot/imap",
	"/usr/libexec/dovecot/imap-login",
	"/usr/libexec/dovecot/lmtp",
	"/usr/libexec/dovecot/indexer-worker",
	"/usr/libexec/dovecot/auth",

	// Postfix spawn(8) descendant — universal
	"/usr/bin/logger",
	"/bin/logger",

	// Package managers — drop to a download-only user (_apt on Debian)
	// then re-elevate to root mid-run; trips CRED-002 on every update.
	"/usr/bin/apt",
	"/usr/bin/apt-get",
	"/usr/bin/apt-cache",
	"/usr/bin/apt-key",
	"/usr/bin/aptitude",
	"/usr/bin/dpkg",
	"/usr/bin/dpkg-deb",
	"/usr/bin/dpkg-divert",
	"/usr/bin/dpkg-trigger",
	"/usr/bin/unattended-upgrade",
	"/usr/bin/unattended-upgrades",
	"/usr/bin/dnf",
	"/usr/bin/dnf-3",
	"/usr/bin/yum",
	"/usr/bin/rpm",
	"/usr/bin/rpmbuild",
	"/usr/bin/microdnf",
	"/usr/sbin/apk", // Alpine

	// System log maintenance — logrotate transitions to per-log uids
	// (e.g. dropping to `nginx` to rotate /var/log/nginx/*) and back
	// to root to install the rotated file. Stable across every distro
	// that ships logrotate.
	"/usr/sbin/logrotate",

	// Mailcow's stock spawn(8) helper scripts. The dockerized
	// postfix-mailcow image installs these under /usr/local/bin/ and
	// dispatches them via `master.cf` spawn entries, so every fork
	// inherits the accepted inet socket on stdin/stdout/stderr and
	// trips the strict three-fd-remote reverse-shell detector.
	"/usr/local/bin/whitelist_forwardinghosts.sh",
	"/usr/local/bin/postfix_sender_login_maps.sh",
	"/usr/local/bin/outgoing-from-tls.sh",
	"/usr/local/bin/outgoing-tls-policy.sh",

	// CloudLinux CageFS — its server and control tools transition uids
	// into per-account cages via setuid, which is the entire point of
	// the product. cagefsctl is a Python script; the kernel sees
	// python3.11 as the exe — its comm "cagefsctl" is allowlisted in
	// DefaultGlobalAllowComm below.
	"/usr/sbin/cagefs.server",
	"/usr/sbin/cagefsctl",

	// CloudLinux PHP-session cleanup cron — runs once per cage, also
	// invokes python3.11 as the exe. comm allowlist below covers the
	// kernel-side match (script name).
	"/usr/sbin/clean_user_php_sessions",
	"/usr/share/cagefs/clean_user_php_sessions",

	// cPanel server daemon and its variant entry points. cPanel ships
	// cpsrvd / webmaild / whostmgrd / cpdavd as the same Perl daemon
	// under different names; the exe the kernel reports is cpsrvd, so
	// one basename-match entry covers the family. xml-api / cpdavd /
	// queueprocd / cpanellogd are siblings that ship as separate
	// binaries (different exe inode) — covered by their own entries.
	"/usr/local/cpanel/cpsrvd",
	"/usr/local/cpanel/xml-api",
	"/usr/local/cpanel/cpdavd",
	"/usr/local/cpanel/queueprocd",
	"/usr/local/cpanel/cpanellogd",
	"/usr/local/cpanel/bin/autossl_check",
	"/usr/local/cpanel/bin/quota-status",
	"/usr/local/cpanel/bin/update_quota_cache",
	"/usr/local/cpanel/scripts/update_quota_cache",

	// SpamAssassin's DCC client — DCC (Distributed Checksum
	// Clearinghouse) ships a small C helper that legitimately calls
	// setuid as part of its reporting protocol.
	"/usr/bin/dccproc",
	"/usr/local/bin/dccproc",

	// CloudLinux Smart Advice agent. Ships under /opt/cloudlinux/ but
	// some distros symlink the entry point into /usr/{bin,sbin}/ — the
	// kernel resolves the symlink so the exe is the generic interpreter
	// (python3.11). Comm match below is the primary handle; we add
	// allow_exe for the wrapper paths so both layouts are covered.
	"/usr/bin/cl-smart-advice",
	"/usr/sbin/cl-smart-advice",

	// LiteSpeed Web Server's CGI daemon. Setuids into the per-vhost
	// uid for each CGI invocation, which is the entire point of the
	// product. The binary on disk is versioned (lscgid.6.3.2 etc) so
	// the comm allowlist below is the version-stable handle; the
	// allow_exe entries below cover known install layouts when LSWS
	// ships the unversioned symlink alongside.
	"/usr/local/lsws/fcgi-bin/lscgid",
	"/usr/local/lsws/bin/lscgid",

	// DirectAdmin control panel daemon. Architecturally similar to
	// cPanel's cpsrvd: a single root-owned daemon that handles every
	// panel HTTP request and setuids into the operating user for
	// per-account work (mail, FTP, file operations). Trips
	// CFML-CRED-002 on every account-touching request. Companion
	// allow_path = /usr/local/directadmin/ below covers the tree's
	// Perl / shell helpers (build / da-popb4smtp / dataskq cron).
	"/usr/local/directadmin/directadmin",

	// ProFTPD. The master listens on 21 and forks a child per session;
	// the child setuids to the authenticating user's uid before chroot
	// — that's the whole protocol, every login looks like CRED-002 by
	// design. Allow the parent exe path here; the comm allowlist below
	// also catches session children that share the comm "proftpd".
	"/usr/sbin/proftpd",
	"/usr/local/sbin/proftpd",

	// Pure-FTPd. Same architecture as ProFTPD — server master forks a
	// child on accept, child setuids to the per-account uid. Quiet on
	// hosts where nobody has authenticated during the observation
	// window, but every real login will trip CRED-002 once. The
	// (SERVER) suffix in `ps` is set via argv-rewriting; the kernel's
	// task->comm stays as "pure-ftpd" so the comm allowlist below
	// catches both master and per-session children uniformly.
	"/usr/sbin/pure-ftpd",
	"/usr/local/sbin/pure-ftpd",

	// Apache httpd with per-vhost UID switching (mod_ruid2 / mpm-itk /
	// suexec). Same privilege model as sshd: the worker runs as
	// `nobody` (in cfm_watched_uids when fallback or panel-manifest
	// covers it) but keeps root in the saved-uid so it can setresuid
	// back to 0 momentarily before dropping to the per-vhost user for
	// each request. That round-trip through uid 0 is what trips
	// CFML-CRED-002. Inode short-circuit via setuid_inodes is safe:
	// /usr/sbin/httpd is root-owned and an attacker with write access
	// to it already has root. Covers RHEL/CentOS (cPanel EA4) and
	// Debian/Ubuntu layouts plus the legacy /usr/local/apache prefix
	// some hosts keep for ad-hoc builds.
	"/usr/sbin/httpd",
	"/usr/sbin/apache2",
	"/usr/local/apache/bin/httpd",

	// LiteSpeed Web Server's HTTP daemon. Same per-vhost UID model as
	// Apache+mpm-itk — the request-serving worker setresuids back to
	// root before dropping to the per-account uid. Companion to the
	// lscgid allowlist entries earlier in this list. Three binary
	// names cover the commercial product (`lshttpd` / `litespeed`)
	// and OpenLiteSpeed (`openlitespeed`).
	"/usr/local/lsws/bin/lshttpd",
	"/usr/local/lsws/bin/litespeed",
	"/usr/local/lsws/bin/openlitespeed",

	// nginx is intentionally NOT listed here. Stock nginx drops
	// privileges at startup (root master → nginx-user workers) and
	// then stays put — there's no per-request setuid round-trip to
	// trigger CFML-CRED-002. Same for openresty / angie. If a host
	// runs a third-party nginx module that does per-vhost UID
	// switching (rare), add `allow_exe = /usr/sbin/nginx` locally
	// rather than baking it into the global list.
}

// DefaultGlobalAllowComm is the curated cross-distro list of comm
// names whose detector match is structural rather than evidence of
// compromise. Comm strings are truncated to TASK_COMM_LEN-1 (15
// chars) by the kernel — entries here must already be truncated.
//
// Two flavours of entry:
//
//   - Container runtimes (runc / crun / containerd-shim / dockerd /
//     podman / conmon / ...) that legitimately load BPF programs on
//     every container start. The BPF-side cfm_comm_is_trusted_bpf_agent
//     allowlist does not cover these, so userspace has to.
//
//   - BPF-side trusted agents (systemd / systemd-network /
//     systemd-udevd / NetworkManager / bpftool / auditd) mirrored
//     here for symmetry. The BPF program *bypasses* its own trust list
//     when the calling uid is in cfm_watched_uids, on the theory that
//     a web user shouldn't load BPF even under a trusted-looking comm.
//     In practice a per-user systemd manager (`systemd --user`) for a
//     panel-managed uid trips this on cgroup-v2 device-controller BPF
//     loads, which is not an attack. We silence the web-origin variant
//     in userspace where the trade-off is purely about noise, not
//     enforcement.
var DefaultGlobalAllowComm = []string{
	// Container runtimes
	"runc",
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

	// BPF-side trusted agents, mirrored for the web-origin case.
	"systemd",
	"systemd-network",
	"systemd-udevd",
	"NetworkManager",
	"bpftool",
	"auditd",

	// CloudLinux CageFS — cagefsctl is a Python script run by root
	// during account lifecycle ops; its task comm is "cagefsctl" but
	// the exe the kernel sees is "python3.11" (or similar). Allow_exe
	// on python3.11 would be far too broad — we pin on comm instead.
	"cagefsctl",

	// CloudLinux per-cage PHP session cleanup. Real name is
	// clean_user_php_sessions; TASK_COMM_LEN=16 truncates to 15 chars.
	// Runs python3.11; comm match is the only safe handle.
	"clean_user_php_",

	// cPanel quota cache updater. Real name update_quota_cache,
	// truncated by TASK_COMM_LEN.
	"update_quota_ca",

	// SpamAssassin daemons — master `spamd` and per-message children
	// `spamd child`. Both legitimately setuid as part of scanning.
	// The exe is "perl"; we deliberately do NOT allowlist perl, so
	// comm match is the handle.
	"spamd",
	"spamd child",

	// CloudLinux Smart Advice agent. Runs python3.11 as the exe and
	// trips CFML-CRED-002 each time it transitions uids while
	// gathering per-cage advice. Real comm is "cl-smart-advice"
	// (exactly TASK_COMM_LEN-1 = 15 chars, fits without truncation).
	"cl-smart-advice",

	// LiteSpeed Web Server's CGI daemon. The exe d_name is versioned
	// (e.g. "lscgid.6.3.2") so allow_exe basename match would need an
	// entry per LSWS upgrade; comm is the stable handle. Sets its own
	// comm via prctl on launch so it reports as plain "lscgid".
	"lscgid",

	// DirectAdmin control panel daemon. Comm handle for the version-
	// independent match — the allow_exe entry above covers the
	// canonical install path; this catches the case where DA ships
	// from a non-default prefix.
	"directadmin",

	// ProFTPD per-session children. The parent's comm is also
	// "proftpd"; children inherit it through fork+setuid. Allow_exe
	// above pins the master inode for the BPF-side setuid_inodes map;
	// this comm entry catches anything the userspace post-filter sees
	// where the per-session child's exe lookup races the d_name
	// resolution (rare but recorded in field reports).
	"proftpd",

	// Pure-FTPd master + per-session children. Same rationale as
	// proftpd: comm is the stable handle across master and forked
	// session workers.
	"pure-ftpd",

	// Apache httpd master + per-vhost worker children. Same comm on
	// both RHEL ("httpd") and Debian ("apache2") families. Pairs with
	// the allow_exe entries above; the comm match catches workers
	// whose exe lookup races against the d_name resolution path in
	// the userspace post-filter (the d_name we get from the BPF event
	// is "httpd"/"apache2" but if the inode isn't in setuid_inodes
	// yet — fresh build, daemon adopted before PopulateMaps — the
	// userspace filter still suppresses on comm).
	"httpd",
	"apache2",

	// LiteSpeed Web Server's HTTP daemon. Same per-vhost UID model as
	// Apache+mpm-itk: workers setresuid back to root via the saved
	// uid before dropping to the per-account uid for each request.
	// Companion to lscgid (already allowlisted above) which handles
	// the CGI subprocess; lshttpd handles the request-serving worker
	// itself. OpenLiteSpeed ships the same binary under
	// `openlitespeed`; the commercial product alternates between
	// `lshttpd` and `litespeed` depending on the release.
	"lshttpd",
	"litespeed",
	"openlitespeed",
}

// DefaultGlobalAllowPath lists path prefixes that identify legitimate
// root daemons by their argv. The userspace filter reads
// /proc/<pid>/cmdline at event time and matches any arg against
// these prefixes — so the dimension covers BOTH:
//
//   - interpreter+script daemons (cmdline = "python3.11 /usr/share/lve-stats/...")
//     where argv[1] is what identifies the legitimate caller
//   - plain binaries (cmdline = "/usr/local/cpanel/xml-api ...") where
//     argv[0] is the binary itself
//
// Needed because Python and Perl daemons share a generic exe
// (python3.11 / perl) and often a generic comm (python3 / perl), so
// allow_exe and allow_comm cannot distinguish CloudLinux LVE Stats
// from a malicious python3.11 invocation. The path is what's actually
// unique.
//
// Entries should be directory prefixes, trailing slash included, so
// `/usr/share/lve-stats/` matches `/usr/share/lve-stats/lvestats-server.py`
// but not `/tmp/lve-stats-fake.py`.
//
// SECURITY TRADE-OFF: this is the broadest allowlist dimension. An
// entry says "anything launched from this directory tree is fine to
// elevate to root without going through a setuid binary." Restrict
// to vendor-owned, root-managed trees (CloudLinux / cPanel / Imunify);
// `allow_path = /tmp/` or `allow_path = /home/` would turn CRED-002
// into a no-op for those trees, and the parser cannot detect intent.
var DefaultGlobalAllowPath = []string{
	// CloudLinux LVE Stats daemon (lvestats-server.py polls per-user
	// resource counters every ~30s and trips CFML-CRED-002 on each uid
	// transition).
	"/usr/share/lve-stats/",

	// CloudLinux internal Python tooling rooted at /opt/cloudlinux/
	// (lve-stats wrappers, cl-smart-advice, cloudlinux-config, etc.).
	"/opt/cloudlinux/",

	// cPanel tree — safety net for cPanel daemons / helpers not
	// individually listed in DefaultGlobalAllowExe. Specific binaries
	// we already know about (cpsrvd, xml-api, cpdavd, queueprocd,
	// cpanellogd, quota-status, update_quota_cache) have explicit
	// allow_exe entries so the BPF program short-circuits on the
	// inode; this prefix catches the rest at the userspace filter.
	"/usr/local/cpanel/",

	// DirectAdmin tree — mirror of the cPanel safety net for DA's
	// daemon and its helper scripts (build, da-popb4smtp, dataskq,
	// custombuild). The main `directadmin` binary is in
	// DefaultGlobalAllowExe above so the BPF map short-circuit
	// covers the hot path; this prefix catches the Perl / shell
	// helpers DA ships under the same tree.
	"/usr/local/directadmin/",

	// CloudLinux CageFS Python helpers (cagefsctl is comm-allowlisted
	// above; this catches any other CageFS-rooted Python tooling).
	"/usr/share/cagefs/",

	// Imunify360 agent + scanner Python components.
	"/opt/imunify360/",
	"/usr/share/imunify360/",
}

// PersistencePathsFor returns configured persistence_path additions for id, or nil
// when none are set. Safe on a nil receiver.
func (c *Conf) PersistencePathsFor(id PolicyID) []string {
	if c == nil || c.PersistencePaths == nil {
		return nil
	}
	return c.PersistencePaths[id]
}

// AllowExeFor returns the merged allow_exe paths for id — global
// `[allow]` entries plus the per-policy section's entries. Returns
// nil when id does not consume an exe allowlist or when nothing has
// been configured. Safe on a nil receiver.
//
// The global slice is prepended in declaration order so per-policy
// overrides land last and operators can read the final effective
// allowlist by scanning top-to-bottom.
func (c *Conf) AllowExeFor(id PolicyID) []string {
	if c == nil {
		return nil
	}
	if !allowExePolicy(id) {
		return nil
	}
	var out []string
	if len(c.GlobalAllowExe) > 0 {
		out = append(out, c.GlobalAllowExe...)
	}
	if c.AllowExe != nil {
		out = append(out, c.AllowExe[id]...)
	}
	return out
}

// AllowCommFor returns the merged allow_comm names for id — global
// `[allow]` entries plus the per-policy section's entries. Returns
// nil when id does not consume a comm allowlist or when nothing has
// been configured. Safe on a nil receiver.
func (c *Conf) AllowCommFor(id PolicyID) []string {
	if c == nil {
		return nil
	}
	if !allowCommPolicy(id) {
		return nil
	}
	var out []string
	if len(c.GlobalAllowComm) > 0 {
		out = append(out, c.GlobalAllowComm...)
	}
	if c.AllowComm != nil {
		out = append(out, c.AllowComm[id]...)
	}
	return out
}

// AllowPathFor returns the configured script-path-prefix
// allowlist for id. Only global entries today — per-policy script
// prefixes can be added later if a single policy needs to narrow
// further. Returns nil when id does not consume the script-prefix
// allowlist or when nothing has been configured.
func (c *Conf) AllowPathFor(id PolicyID) []string {
	if c == nil {
		return nil
	}
	if !allowPathPolicy(id) {
		return nil
	}
	if len(c.GlobalAllowPath) == 0 {
		return nil
	}
	return append([]string{}, c.GlobalAllowPath...)
}

// ModeFor returns the configured mode for id, falling back to the
// policy's DefaultMode when the conf is silent on it. Unknown IDs
// return ModeDisabled.
func (c *Conf) ModeFor(id PolicyID) Mode {
	if c == nil {
		return ModeDisabled
	}
	if m, ok := c.Modes[id]; ok {
		return m
	}
	if p, ok := PolicyByID(id); ok {
		return p.DefaultMode
	}
	return ModeDisabled
}

// LoadConf reads ConfPath and returns the parsed configuration. If the
// file is absent and createDefault is true, a default conf is
// synthesised in memory; otherwise os.ErrNotExist is returned for the
// caller to handle.
func LoadConf(createDefault bool) (*Conf, error) {
	b, err := os.ReadFile(ConfPath)
	if err != nil {
		if os.IsNotExist(err) && createDefault {
			c := DefaultConf()
			c.Source = "(default — no " + ConfPath + ")"
			return c, nil
		}
		return nil, err
	}
	c, err := ParseConf(strings.NewReader(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ConfPath, err)
	}
	c.Source = ConfPath
	return c, nil
}

// ParseConf parses lsm.conf from r. Format mirrors kernsec.conf:
//
//	# comments and blank lines OK
//	enabled = false
//
//	[policy "CFML-EXEC-001"]
//	mode = monitor
//
//	[policy "CFML-EXEC-003"]
//	mode = disabled
//
// Unknown policy IDs and unknown keys are rejected with a line number
// so merge artifacts and typos surface immediately instead of
// silently dropping rules at runtime.
// sectionKind classifies what kind of section the parser is currently
// in. Empty means top-level (before any section header).
type sectionKind int

const (
	sectionTopLevel sectionKind = iota
	sectionPolicy
	sectionKmsg
	sectionAllow
	sectionEvents
)

func ParseConf(r io.Reader) (*Conf, error) {
	c := &Conf{
		Enabled:               false,
		WatchedUidFallbackMin: defaultWatchedUidFallbackMin,
		Modes:                 map[PolicyID]Mode{},
		FS005WebOriginMonitor: false,
		PersistencePaths:      map[PolicyID][]string{},
		AllowExe:              map[PolicyID][]string{},
		AllowComm:             map[PolicyID][]string{},
		Kmsg:                  DefaultKmsgConf(),
		EventSink:             DefaultEventSinkConf(),
	}
	// Seed defaults for every known policy so the result is complete
	// even if the file declared a subset. Per-policy stanzas override.
	for _, p := range AllPolicies() {
		c.Modes[p.ID] = p.DefaultMode
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4*1024), 1<<20)

	var (
		current       sectionKind // which section we are inside
		currentPolicy PolicyID    // valid when current == sectionPolicy
		lineno        int
		seenPolicies  = map[PolicyID]int{}
		seenTopLevel  = map[string]int{}
		seenKmsgKeys   = map[string]int{}
		seenEventsKeys = map[string]int{}
		kmsgSeen       int
		allowSeen      int
		eventsSeen     int
	)

	for scanner.Scan() {
		lineno++
		raw := scanner.Text()
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			kind, id, err := parseSectionHeader(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineno, err)
			}
			switch kind {
			case sectionPolicy:
				if _, ok := PolicyByID(id); !ok {
					return nil, fmt.Errorf("line %d: unknown policy ID %q (known IDs: %s)",
						lineno, id, knownPolicyIDsList())
				}
				if firstLine, dup := seenPolicies[id]; dup {
					return nil, fmt.Errorf("line %d: duplicate policy section %q (first at line %d)",
						lineno, id, firstLine)
				}
				seenPolicies[id] = lineno
				current = sectionPolicy
				currentPolicy = id
			case sectionKmsg:
				if kmsgSeen > 0 {
					return nil, fmt.Errorf("line %d: duplicate [kmsg] section (first at line %d)",
						lineno, kmsgSeen)
				}
				kmsgSeen = lineno
				current = sectionKmsg
				currentPolicy = ""
			case sectionAllow:
				if allowSeen > 0 {
					return nil, fmt.Errorf("line %d: duplicate [allow] section (first at line %d)",
						lineno, allowSeen)
				}
				allowSeen = lineno
				current = sectionAllow
				currentPolicy = ""
			case sectionEvents:
				if eventsSeen > 0 {
					return nil, fmt.Errorf("line %d: duplicate [events] section (first at line %d)",
						lineno, eventsSeen)
				}
				eventsSeen = lineno
				current = sectionEvents
				currentPolicy = ""
			}
			continue
		}

		key, val, ok := splitKV(line)
		if !ok {
			return nil, fmt.Errorf("line %d: malformed (expected `key = value`): %q", lineno, line)
		}

		switch current {
		case sectionTopLevel:
			lk := strings.ToLower(key)
			// exclude_user / exclude_uid / exclude_gid are explicitly
			// repeatable — operators list one account per line. Every
			// other top-level key is single-valued and rejecting dups
			// catches conf editing errors.
			repeatable := lk == "exclude_user" || lk == "exclude_uid" || lk == "exclude_gid"
			if !repeatable {
				if firstLine, dup := seenTopLevel[lk]; dup {
					return nil, fmt.Errorf("line %d: duplicate top-level key %q (first at line %d)",
						lineno, lk, firstLine)
				}
				seenTopLevel[lk] = lineno
			}
			switch lk {
			case "enabled":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: enabled must be true|false|1|0|on|off (got %q)", lineno, val)
				}
				c.Enabled = b
			case "watched_uid_fallback_min":
				n, err := strconv.Atoi(strings.TrimSpace(val))
				if err != nil || n < -1 {
					return nil, fmt.Errorf("line %d: watched_uid_fallback_min must be an integer >= 0 (got %q; 0=disable, >0=threshold). -1 is deprecated (treat as 1000)", lineno, val)
				}
				c.WatchedUidFallbackMin = n
			case "exclude_user":
				name := strings.TrimSpace(val)
				if name == "" {
					return nil, fmt.Errorf("line %d: exclude_user requires a non-empty username", lineno)
				}
				c.ExcludeUsers = append(c.ExcludeUsers, name)
			case "exclude_uid":
				n, err := strconv.ParseUint(strings.TrimSpace(val), 10, 32)
				if err != nil {
					return nil, fmt.Errorf("line %d: exclude_uid must be a non-negative integer (got %q)", lineno, val)
				}
				c.ExcludeUIDs = append(c.ExcludeUIDs, uint32(n))
			case "exclude_gid":
				n, err := strconv.ParseUint(strings.TrimSpace(val), 10, 32)
				if err != nil {
					return nil, fmt.Errorf("line %d: exclude_gid must be a non-negative integer (got %q)", lineno, val)
				}
				c.ExcludeGIDs = append(c.ExcludeGIDs, uint32(n))
			default:
				return nil, fmt.Errorf("line %d: unknown top-level key %q", lineno, key)
			}
		case sectionPolicy:
			switch strings.ToLower(key) {
			case "mode":
				m, err := parseMode(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.Modes[currentPolicy] = m
			case "origin_tracking":
				if currentPolicy != PolicySensitiveWrite {
					return nil, fmt.Errorf("line %d: origin_tracking is only valid for %s", lineno, PolicySensitiveWrite)
				}
				monitor, err := parseOriginTracking(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.FS005WebOriginMonitor = monitor
			case "persistence_path":
				if currentPolicy != PolicySensitiveWrite {
					return nil, fmt.Errorf("line %d: persistence_path is only valid for %s", lineno, PolicySensitiveWrite)
				}
				p, err := parseAbsolutePath(val, "persistence_path")
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.PersistencePaths[currentPolicy] = append(c.PersistencePaths[currentPolicy], p)
			case "allow_exe":
				if !allowExePolicy(currentPolicy) {
					return nil, fmt.Errorf("line %d: allow_exe is only valid for %s, %s, %s, %s", lineno, PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio, PolicyEphemeralExec)
				}
				p, err := parseAllowExe(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.AllowExe[currentPolicy] = append(c.AllowExe[currentPolicy], p)
			case "allow_comm":
				if !allowCommPolicy(currentPolicy) {
					return nil, fmt.Errorf("line %d: allow_comm is only valid for %s, %s, %s, %s, %s", lineno, PolicyUnexpectedBPF, PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio, PolicyEphemeralExec)
				}
				comm, err := parseAllowComm(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.AllowComm[currentPolicy] = append(c.AllowComm[currentPolicy], comm)
			default:
				return nil, fmt.Errorf("line %d: unknown policy key %q (supported: `mode`; %s also supports `origin_tracking` and `persistence_path`; %s, %s, %s, %s also support `allow_exe`; %s, %s, %s, %s, %s also support `allow_comm`)", lineno, key, PolicySensitiveWrite, PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio, PolicyEphemeralExec, PolicyUnexpectedBPF, PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio, PolicyEphemeralExec)
			}
		case sectionKmsg:
			lk := strings.ToLower(key)
			if firstLine, dup := seenKmsgKeys[lk]; dup {
				return nil, fmt.Errorf("line %d: duplicate kmsg key %q (first at line %d)",
					lineno, lk, firstLine)
			}
			seenKmsgKeys[lk] = lineno
			switch lk {
			case "state_transitions":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: state_transitions must be true|false (got %q)", lineno, val)
				}
				c.Kmsg.StateTransitions = b
			case "detect_events":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: detect_events must be true|false (got %q)", lineno, val)
				}
				c.Kmsg.DetectEvents = b
			case "detect_rate_per_min":
				n, err := strconv.Atoi(strings.TrimSpace(val))
				if err != nil || n < 0 {
					return nil, fmt.Errorf("line %d: detect_rate_per_min must be a non-negative integer (got %q)", lineno, val)
				}
				c.Kmsg.DetectRatePerMin = n
			default:
				return nil, fmt.Errorf("line %d: unknown kmsg key %q (state_transitions | detect_events | detect_rate_per_min)", lineno, key)
			}
		case sectionAllow:
			switch strings.ToLower(key) {
			case "allow_exe":
				p, err := parseAllowExe(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.GlobalAllowExe = append(c.GlobalAllowExe, p)
			case "allow_comm":
				comm, err := parseAllowComm(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.GlobalAllowComm = append(c.GlobalAllowComm, comm)
			case "allow_path":
				p, err := parseAllowPath(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.GlobalAllowPath = append(c.GlobalAllowPath, p)
			default:
				return nil, fmt.Errorf("line %d: unknown [allow] key %q (allow_exe | allow_comm | allow_path)", lineno, key)
			}
		case sectionEvents:
			lk := strings.ToLower(key)
			if firstLine, dup := seenEventsKeys[lk]; dup {
				return nil, fmt.Errorf("line %d: duplicate [events] key %q (first at line %d)", lineno, lk, firstLine)
			}
			seenEventsKeys[lk] = lineno
			switch lk {
			case "detect_rate_per_min":
				n, err := strconv.Atoi(strings.TrimSpace(val))
				if err != nil || n < 0 {
					return nil, fmt.Errorf("line %d: detect_rate_per_min must be a non-negative integer (got %q)", lineno, val)
				}
				c.EventSink.DetectRatePerMin = n
			default:
				return nil, fmt.Errorf("line %d: unknown [events] key %q (detect_rate_per_min)", lineno, key)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// FormatConf renders c in lsm.conf format. The output is deterministic
// (policies appear in AllPolicies order) so write-modify-write round
// trips do not churn the file.
func FormatConf(c *Conf) string {
	var b strings.Builder
	b.WriteString("# /etc/cfm/lsm.conf — cfm-lsm runtime configuration.\n")
	b.WriteString("# See docs/cfm-lsm.md for the design.\n")
	b.WriteString("\n")
	b.WriteString("# Global on/off. cfm-lsm runs kernel preflight and attaches BPF\n")
	b.WriteString("# programs only when this is true AND preflight passes.\n")
	fmt.Fprintf(&b, "enabled = %t\n", c.Enabled)
	b.WriteString("\n")
	b.WriteString("# Watched-uid extension threshold. Every uid in /etc/passwd at or\n")
	b.WriteString("# above this value joins cfm_watched_uids alongside the static\n")
	b.WriteString("# WebUserNames (apache / nginx / www-data / nobody / lighttpd /\n")
	b.WriteString("# caddy / tomcat / php / lsphp / proxy / alt-php-*) and any\n")
	b.WriteString("# cPanel / DirectAdmin manifest contributions. Three layers\n")
	b.WriteString("# (static names, panel manifest, uid-range fallback) are always\n")
	b.WriteString("# additive — set this knob to 0 to disable the fallback layer.\n")
	b.WriteString("#\n")
	b.WriteString("#    0             disable the fallback (rely on static names +\n")
	b.WriteString("#                   panel manifest only — admin / sysadmin accounts\n")
	b.WriteString("#                   at uid >= 1000 will NOT be watched on a panel host)\n")
	b.WriteString("#   1000  (default) the /etc/login.defs UID_MIN convention — watches\n")
	b.WriteString("#                   every regular login account, including admins.\n")
	b.WriteString("#                   Pair with exclude_user / exclude_uid / exclude_gid\n")
	b.WriteString("#                   below to opt-out known-trusted admin accounts.\n")
	b.WriteString("#   >0             explicit threshold; any other positive value works.\n")
	b.WriteString("#\n")
	b.WriteString("# -1 is accepted as a deprecated alias for 1000 (the auto-detect\n")
	b.WriteString("# behaviour was removed because it silently created an admin-account\n")
	b.WriteString("# coverage gap on panel hosts). Adoption emits a one-time warning\n")
	b.WriteString("# when -1 is parsed; will become a parse error in a future release.\n")
	fmt.Fprintf(&b, "watched_uid_fallback_min = %d\n", c.WatchedUidFallbackMin)
	b.WriteString("\n")
	b.WriteString("# Opt-out: accounts to exclude from cfm_watched_uids even when the\n")
	b.WriteString("# fallback above or the panel manifest would otherwise include them.\n")
	b.WriteString("# Repeat the key per entry. Used to keep legitimate admin / sysadmin /\n")
	b.WriteString("# batch-job sessions quiet without dropping coverage of the rest of\n")
	b.WriteString("# the host's uid >= fallback range.\n")
	b.WriteString("#\n")
	b.WriteString("# Footgun: excludes apply to EVERY uid produced by the three layers,\n")
	b.WriteString("# including the static web-daemon names (apache, nginx, nobody, ...).\n")
	b.WriteString("# exclude_user = apache (or an exclude_gid that catches apache's primary\n")
	b.WriteString("# group) WILL drop apache from the watched set. Verify with:\n")
	b.WriteString("#   bpftool map dump pinned /sys/fs/bpf/cfm/maps/cfm_watched_uids\n")
	b.WriteString("# after cfm lsm restart.\n")
	b.WriteString("#\n")
	b.WriteString("# exclude_gid matches /etc/passwd PRIMARY gid (column 4) only;\n")
	b.WriteString("# supplementary groups in /etc/group are NOT consulted.\n")
	b.WriteString("#\n")
	b.WriteString("# exclude_user = chris        # by username (resolved at adoption time;\n")
	b.WriteString("#                             # missing names skip silently)\n")
	b.WriteString("# exclude_uid  = 1001         # by numeric uid\n")
	b.WriteString("# exclude_gid  = 10           # by primary gid (/etc/passwd col 4 only)\n")
	for _, n := range c.ExcludeUsers {
		fmt.Fprintf(&b, "exclude_user = %s\n", n)
	}
	for _, u := range c.ExcludeUIDs {
		fmt.Fprintf(&b, "exclude_uid = %d\n", u)
	}
	for _, g := range c.ExcludeGIDs {
		fmt.Fprintf(&b, "exclude_gid = %d\n", g)
	}
	for _, p := range AllPolicies() {
		mode := c.ModeFor(p.ID)
		b.WriteString("\n")
		fmt.Fprintf(&b, "# %s — %s\n", p.ID, p.Title)
		fmt.Fprintf(&b, "# Hook: %s\n", p.Hook)
		fmt.Fprintf(&b, "[policy %q]\n", string(p.ID))
		if isEnforceCapable(p.ID) {
			fmt.Fprintf(&b, "mode = %s  # disabled | monitor | enforce\n", mode)
		} else {
			fmt.Fprintf(&b, "mode = %s  # disabled | monitor; enforce is downgraded to monitor\n", mode)
		}
		if p.ID == PolicySensitiveWrite {
			state := "disabled"
			if c.FS005WebOriginMonitor {
				state = "monitor"
			}
			fmt.Fprintf(&b, "origin_tracking = %s  # disabled | monitor (origin-only matches never enforce yet)\n", state)
			paths := c.PersistencePathsFor(p.ID)
			if len(paths) == 0 {
				b.WriteString("# Add host-persistence locations to monitor. Repeat the key per entry;\n")
				b.WriteString("# absolute concrete paths only. Additions are monitor-only even if mode=enforce.\n")
				b.WriteString("# persistence_path = /etc/systemd/system\n")
				b.WriteString("# persistence_path = /usr/local/directadmin/scripts/custom\n")
			} else {
				for _, ap := range paths {
					fmt.Fprintf(&b, "persistence_path = %s\n", ap)
				}
			}
		}
		if allowExePolicy(p.ID) {
			// Only render the per-policy AllowExe map here. Global
			// [allow] entries live in their own section so a
			// write-modify-write round trip stays stable.
			perPolicy := c.AllowExe[p.ID]
			if len(perPolicy) == 0 {
				switch p.ID {
				case PolicyCredEscal:
					b.WriteString("# Narrow this policy further by adding allow_exe lines here, or use the\n")
					b.WriteString("# global [allow] section below to apply across every cfm-lsm detector.\n")
					b.WriteString("# allow_exe = /usr/local/directadmin/directadmin\n")
					b.WriteString("# allow_exe = /usr/local/cpanel/cpanel\n")
				case PolicyReverseShell, PolicyInterpreterNetStdio:
					b.WriteString("# Site-specific spawn(8) helper scripts (mailcow / custom inetd-style\n")
					b.WriteString("# services). Global cross-distro entries already live in [allow] below.\n")
					b.WriteString("# allow_exe = /usr/local/bin/whitelist_forwardinghosts.sh\n")
				case PolicyEphemeralExec:
					b.WriteString("# Allowlist legitimate ephemeral-fs execs (package installer extractions,\n")
					b.WriteString("# cPanel easyapache builds, distro ldconfig re-runs). The userspace\n")
					b.WriteString("# post-filter matches event basenames against the entries here.\n")
					b.WriteString("# allow_exe = /tmp/easyapache/build-helper\n")
				}
			} else {
				for _, ap := range perPolicy {
					fmt.Fprintf(&b, "allow_exe = %s\n", ap)
				}
			}
		}
		if allowCommPolicy(p.ID) {
			perPolicy := c.AllowComm[p.ID]
			if len(perPolicy) == 0 {
				if p.ID == PolicyUnexpectedBPF {
					b.WriteString("# Narrow this policy further by adding allow_comm lines here, or use\n")
					b.WriteString("# the global [allow] section below to apply across every cfm-lsm\n")
					b.WriteString("# detector that consults a comm allowlist.\n")
					b.WriteString("# allow_comm = my-orchestrator\n")
				}
			} else {
				for _, cc := range perPolicy {
					fmt.Fprintf(&b, "allow_comm = %s\n", cc)
				}
			}
		}
	}
	b.WriteString("\n")
	b.WriteString("# Global allowlist — applied to every cfm-lsm detector that consults\n")
	b.WriteString("# an exe / comm / script-prefix allowlist (today: CFML-CRED-002,\n")
	b.WriteString("# CFML-EXEC-003, CFML-EXEC-005, CFML-BPF-001).\n")
	b.WriteString("#   allow_exe            — matched by basename in the userspace post-filter;\n")
	b.WriteString("#                          also stat()'d into the BPF-side cfm_setuid_inodes\n")
	b.WriteString("#                          map for CFML-CRED-002 when the path exists.\n")
	b.WriteString("#   allow_comm           — exact-match against task->comm (kernel truncates\n")
	b.WriteString("#                          to TASK_COMM_LEN-1 = 15 chars).\n")
	b.WriteString("#   allow_path  — directory prefix matched against any arg of\n")
	b.WriteString("#                          /proc/<pid>/cmdline at event time. Needed for\n")
	b.WriteString("#                          Python / Perl daemons where exe is the generic\n")
	b.WriteString("#                          interpreter and comm is generic (e.g. `python3`)\n")
	b.WriteString("#                          — the script path is what actually identifies them.\n")
	b.WriteString("# Missing paths are silently skipped, so cross-distro lists are safe.\n")
	b.WriteString("[allow]\n")
	for _, p := range c.GlobalAllowExe {
		fmt.Fprintf(&b, "allow_exe = %s\n", p)
	}
	for _, cc := range c.GlobalAllowComm {
		fmt.Fprintf(&b, "allow_comm = %s\n", cc)
	}
	for _, p := range c.GlobalAllowPath {
		fmt.Fprintf(&b, "allow_path = %s\n", p)
	}
	b.WriteString("\n")
	b.WriteString("# dmesg / /dev/kmsg emission. Lines tagged `CFM-LSM:` show up\n")
	b.WriteString("# in `dmesg`, `journalctl -k`, and (on most distros) /var/log/messages.\n")
	b.WriteString("# Route to a dedicated file via /etc/rsyslog.d/99-cfm-lsm.conf — see\n")
	b.WriteString("# configs/rsyslog/cfm-lsm.conf for a ready-to-drop-in example.\n")
	b.WriteString("[kmsg]\n")
	fmt.Fprintf(&b, "state_transitions   = %t   # ALIVE / ADOPT / STATE / ISSUE on enable/disable/adopt/stop\n", c.Kmsg.StateTransitions)
	fmt.Fprintf(&b, "detect_events       = %t   # one DETECT line per detection (rate-limited below)\n", c.Kmsg.DetectEvents)
	fmt.Fprintf(&b, "detect_rate_per_min = %d   # cap DETECT lines per policy per minute; 0 disables cap (not recommended)\n", c.Kmsg.DetectRatePerMin)
	b.WriteString("\n")
	b.WriteString("# Userspace DETECT emission (cfm.log + notify pipeline) per-policy\n")
	b.WriteString("# rate cap. Independent of the [kmsg] cap above so an operator can\n")
	b.WriteString("# tighten cfm.log without losing dmesg signal (or vice versa). When\n")
	b.WriteString("# the cap is hit, surplus events accumulate and a single\n")
	b.WriteString("# `suppressed=N in_last=60s` summary line is emitted on window roll —\n")
	b.WriteString("# the operator sees the burst happened without being buried in detail.\n")
	b.WriteString("[events]\n")
	fmt.Fprintf(&b, "detect_rate_per_min = %d   # cap cfm.log + notify emissions per policy per minute; 0 disables cap\n", c.EventSink.DetectRatePerMin)
	return b.String()
}

// WriteDefaultConf writes the default configuration to ConfPath if it
// does not already exist. Returns (true, nil) when a new file was
// created, (false, nil) when the file already existed, or (false, err)
// on a write failure.
func WriteDefaultConf() (created bool, err error) {
	if _, err := os.Stat(ConfPath); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(ConfPath), 0o755); err != nil {
		return false, err
	}
	body := FormatConf(DefaultConf())
	if err := os.WriteFile(ConfPath, []byte(body), ConfFileMode); err != nil {
		return false, err
	}
	return true, nil
}

// parseAbsolutePath validates a config path value. The path must be non-empty,
// absolute, and free of NUL bytes. Existence is deliberately checked later, at
// map-population time, so one stale panel path does not invalidate lsm.conf.
func parseAbsolutePath(s, key string) (string, error) {
	p := strings.TrimSpace(s)
	if p == "" {
		return "", fmt.Errorf("%s must be a non-empty path", key)
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%s must be an absolute path (got %q)", key, p)
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%s must not contain NUL bytes", key)
	}
	return p, nil
}

// parseAllowExe validates one `allow_exe = …` value.
func parseAllowExe(s string) (string, error) {
	return parseAbsolutePath(s, "allow_exe")
}

// parseAllowPath validates one `allow_path = …` value.
//
// Be deliberate about what you put here — see the SECURITY TRADE-OFF
// note on DefaultGlobalAllowPath. The parser can only enforce shape
// (absolute, trailing slash, no NULs), not intent: it cannot tell
// `/usr/share/lve-stats/` from `/tmp/`. Reserve for vendor-owned,
// root-managed directories.
// The prefix must be absolute (so it cannot match arbitrary user-
// controlled relative paths) and should end with `/` to make
// "directory prefix" semantics unambiguous — `/usr/share/lve-stats`
// without a trailing slash would also match `/usr/share/lve-stats-fake`.
func parseAllowPath(s string) (string, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return "", fmt.Errorf("allow_path must be a non-empty path prefix")
	}
	if strings.ContainsRune(v, 0) {
		return "", fmt.Errorf("allow_path must not contain NUL bytes")
	}
	if !strings.HasPrefix(v, "/") {
		return "", fmt.Errorf("allow_path %q must be absolute (start with `/`)", v)
	}
	if !strings.HasSuffix(v, "/") {
		return "", fmt.Errorf("allow_path %q must end with `/` to be a directory prefix", v)
	}
	// `/` would allowlist every cmdline arg starting with `/` — i.e.
	// every absolute path on the system. Refuse rather than let an
	// operator footgun themselves into a fully no-op detector.
	if v == "/" {
		return "", fmt.Errorf("allow_path `/` would allowlist every absolute cmdline arg; pick a real prefix")
	}
	return v, nil
}

// parseAllowComm validates one `allow_comm = …` value. The kernel
// stores comm in a 16-byte TASK_COMM_LEN field; cap operator-supplied
// entries at 15 visible characters (1 reserved for NUL) so a typo
// can't silently fail to match.
func parseAllowComm(s string) (string, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return "", fmt.Errorf("allow_comm must be a non-empty comm name")
	}
	if strings.ContainsRune(v, 0) {
		return "", fmt.Errorf("allow_comm must not contain NUL bytes")
	}
	if len(v) > 15 {
		return "", fmt.Errorf("allow_comm %q exceeds 15 chars (kernel truncates comm to TASK_COMM_LEN-1)", v)
	}
	return v, nil
}

// allowExePolicy reports whether allow_exe is accepted under the
// given policy section. CRED-002 has used it since first ship; the
// strict and weak reverse-shell detectors gained it so operators can
// allow postfix spawn(8) inetd-style worker scripts. EXEC-006 needs
// it for the (small) set of legitimate ephemeral-fs execs: package
// installer extractions, cPanel easyapache builds, distro ldconfig
// re-runs that drop helpers under /tmp/.
func allowExePolicy(id PolicyID) bool {
	switch id {
	case PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio, PolicyEphemeralExec:
		return true
	}
	return false
}

// allowCommPolicy reports whether allow_comm is accepted under the
// given policy section. BPF-001 is the primary consumer (container
// runtimes); the other monitor-only-by-design policies expose it for
// symmetry with allow_exe so site-specific comms can be silenced
// without a BPF rebuild. EXEC-006 follows the same pattern so
// operators can allowlist a known-good tooling comm without pinning
// its (possibly versioned) exe path.
func allowCommPolicy(id PolicyID) bool {
	switch id {
	case PolicyUnexpectedBPF, PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio, PolicyEphemeralExec:
		return true
	}
	return false
}

// allowPathPolicy reports whether allow_path is
// honoured for the given policy. CRED-002 is the primary consumer
// (Python / Perl daemons that exec the interpreter and pass the script
// as argv[1]); the reverse-shell + interpreter-net-stdio policies
// expose it for the same reason — both fire on `interpreter argv[1]`
// shapes where argv[1] is what actually identifies the legit caller.
// EXEC-006 consumes it as a path-prefix allowlist for trusted
// ephemeral-root subtrees (e.g. operator-managed build directories).
func allowPathPolicy(id PolicyID) bool {
	switch id {
	case PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio, PolicyEphemeralExec:
		return true
	}
	return false
}

func parseOriginTracking(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "disabled", "off", "false", "0":
		return false, nil
	case "monitor", "observe", "on", "true", "1":
		return true, nil
	}
	return false, fmt.Errorf("invalid origin_tracking %q (want disabled|monitor)", s)
}

func parseSectionHeader(line string) (sectionKind, PolicyID, error) {
	inner := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
	inner = strings.TrimSpace(inner)

	// Bare-word sections.
	switch inner {
	case "kmsg":
		return sectionKmsg, "", nil
	case "allow":
		return sectionAllow, "", nil
	case "events":
		return sectionEvents, "", nil
	}

	if !strings.HasPrefix(inner, "policy") {
		return sectionTopLevel, "", fmt.Errorf("unknown section header: %q (expected `[allow]`, `[events]`, `[kmsg]`, or `[policy \"...\"]`)", line)
	}
	rest := strings.TrimSpace(strings.TrimPrefix(inner, "policy"))
	if !strings.HasPrefix(rest, `"`) || !strings.HasSuffix(rest, `"`) || len(rest) < 2 {
		return sectionTopLevel, "", fmt.Errorf("malformed policy section header: %q", line)
	}
	return sectionPolicy, PolicyID(rest[1 : len(rest)-1]), nil
}

func parseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "disabled", "off", "0", "false":
		return ModeDisabled, nil
	case "monitor", "observe":
		return ModeMonitor, nil
	case "enforce", "block":
		return ModeEnforce, nil
	}
	return ModeDisabled, fmt.Errorf("invalid mode %q (want disabled | monitor | enforce)", s)
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "on", "yes":
		return true, nil
	case "false", "0", "off", "no":
		return false, nil
	}
	if b, err := strconv.ParseBool(s); err == nil {
		return b, nil
	}
	return false, fmt.Errorf("not a boolean: %q", s)
}

func splitKV(line string) (string, string, bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:eq])
	val := strings.TrimSpace(line[eq+1:])
	if key == "" {
		return "", "", false
	}
	// Strip surrounding quotes so `mode = "monitor"` works.
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return key, val, true
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func knownPolicyIDsList() string {
	ids := make([]string, 0, len(AllPolicies()))
	for _, p := range AllPolicies() {
		ids = append(ids, string(p.ID))
	}
	return strings.Join(ids, ", ")
}
