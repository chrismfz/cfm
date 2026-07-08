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

// defaultFS005WebOriginMonitor is the shipped default for the FS-005
// `origin_tracking = monitor` per-policy knob. The conf parser
// accepts only `disabled | monitor` for this key (enforce isn't
// supported — origin-only matches never enforce yet). DefaultConf
// and ParseConf both seed from this so an operator whose lsm.conf
// has no origin_tracking line gets the same behaviour as the shipped
// configs/lsm.conf template.
const defaultFS005WebOriginMonitor = true

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

// DefaultConf returns the in-memory default configuration: cfm-lsm
// globally disabled, every policy at its DefaultMode, kmsg emission
// on with the documented defaults, and a curated global allowlist
// that silences the structural detector matches every reasonably-
// configured Linux host exhibits.
//
// Used by FormatConf round-trip tests and by callers that need a
// fully-populated Conf in code (no file). Not used by `cfm lsm init`
// anymore — init now refuses to write a generated default and relies
// on the shipped configs/lsm.conf template instead, removing the
// historical divergence between init-output and package-installed
// conf.
func DefaultConf() *Conf {
	modes := map[PolicyID]Mode{}
	for _, p := range AllPolicies() {
		modes[p.ID] = p.DefaultMode
	}
	return &Conf{
		Enabled:               false,
		WatchedUidFallbackMin: defaultWatchedUidFallbackMin,
		Modes:                 modes,
		FS005WebOriginMonitor: defaultFS005WebOriginMonitor,
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

	// Exim MTA. Setuid-root mail binary that completes the mail stack
	// alongside postfix + dovecot above. The receiving / delivery
	// processes drop to the per-account uid (to run .forward pipes,
	// write to a user mailbox, evaluate per-user filters) and then
	// setuid back to root for the next delivery — every message that
	// touches an unprivileged uid round-trips through root and trips
	// CFML-CRED-002. Covers RHEL / cPanel ("exim") and Debian/Ubuntu
	// ("exim4") binary names; the companion comm entries in
	// DefaultGlobalAllowComm catch forked delivery children whose exe
	// d_name lookup races the userspace post-filter.
	"/usr/sbin/exim",
	"/usr/sbin/exim4",

	// sudo / su — the canonical setuid-root privilege tools. sudo
	// lowers its euid to the invoking user to safely stat files in
	// that user's home and read per-user config, then seteuid(0) to
	// restore root before exec'ing the target command; su performs
	// the equivalent drop/restore during PAM authentication. Both are
	// setuid-on-disk so the inode walk normally short-circuits them,
	// but the walk is a one-shot snapshot taken at daemon start: when
	// the package manager upgrades sudo/su between cfm restarts the
	// rename-into-place gives the path a NEW inode the cached map
	// doesn't hold, so every subsequent invocation misses and fires
	// CRED-002 — and on a busy panel host sudo runs constantly (cron,
	// monitoring, panel helpers), which is the reported FP burst.
	// Where these paths exist the inode is re-pinned here on the next
	// start, giving an exact short-circuit for the REAL binary; for an
	// attacker-dropped /tmp/sudo there is no inode pin, only the
	// basename layer, which is spoofable — acceptable because CRED-002
	// is monitor-only and a dropper at that point has already reached
	// root, so this is post-privesc telemetry, not a boundary.
	"/usr/bin/sudo",
	"/bin/sudo",
	"/usr/bin/su",
	"/bin/su",

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

	// CloudLinux LVE Stats v4 — the Rust rewrite of lvestats-server.
	// Polls per-user LVE resource counters and transitions uid into
	// each watched account and back to root, tripping CFML-CRED-002 on
	// every cycle. The legacy Python daemon (lvestats-server.py) is
	// covered by the allow_path = /usr/share/lve-stats/ prefix in
	// DefaultGlobalAllowPath, but the Rust binary's tokio worker
	// threads report comm "tokio-runtime-worker" (truncated to
	// "tokio-runtime-w") and its argv often doesn't carry the
	// /usr/share/lve-stats/ prefix the cmdline matcher needs, so the
	// path prefix alone doesn't suppress it. The exe d_name is the
	// stable handle: matching basename "lvestats-server.rust" silences
	// the worker-thread events regardless of install path. Listed as a
	// concrete path so the BPF inode short-circuit also fires where the
	// binary is installed here; the basename post-filter covers other
	// layouts.
	"/usr/share/lve-stats/lvestats-server.rust",

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

	// Per-user systemd's transitional-exec comm form. The kernel
	// briefly sets a forked task's comm to `(name)` between
	// copy_process and the new exec landing — see
	// fs/proc/array.c:get_task_comm and the SIGCHLD-with-CLD_TRAPPED
	// formatting in kernel/exit.c. cfm-lsm hooks fire during this
	// window (commit_creds / ptrace_access_check both run before
	// the new comm is finalised), so the calling task's `current->comm`
	// is literally "(systemd)" not "systemd" — the userspace filter
	// needs both spellings to suppress the noise cleanly.
	"(systemd)",

	// Bubblewrap sandbox runtime. Used by flatpak, snap's namespace
	// shim, and various distro-portable apps to set up user
	// namespaces. bwrap legitimately does ptrace + setuid + ambient
	// cap-raise on its sandboxed children during sandbox setup —
	// that's the entire job of the program. CRED-002 / CRED-004 /
	// OBS-004 all fire on the same legitimate sequence; allowlist
	// here because the alternative (per-policy entries) would
	// duplicate the rationale four times.
	"bwrap",

	// /bin/readlink. The kernel routes /proc/PID/exe symlink
	// resolution through ptrace_may_access(), which fires our
	// OBS-004 ptrace_access_check hook even though no actual
	// ptrace(2) syscall was issued. Every status-page health
	// check, supervisor probe, lsphp respawn detector, or
	// post-fork bash launcher that reads /proc/N/exe of a sibling
	// process triggers this. Allowlisting `readlink` for the
	// monitor-only ptrace + cred rules is harmless: /bin/readlink
	// has no credential-escalation primitive and no bpf() call
	// path, so the other policies that consume allow_comm can't
	// be evaded by a process pretending to be readlink.
	"readlink",

	// /usr/bin/crontab and its mid-exec transitional comm. Setuid-
	// root binary that renames a temp file (#tmp.HOST.XXXXXX) into
	// /var/spool/cron/<user> on every panel-UI "Cron Jobs" edit by
	// a watched uid — three FS-005 events per edit (create + rename
	// + setattr). The BPF-side cfm_comm_is_trusted_auth_helper
	// gates the enforce decision; this entry is the matching
	// userspace silencer for monitor mode. Threat model: a webshell
	// could exec `crontab evil.txt` to drop a persistence cron, so
	// the rule's intent is real — but the kernel can't tell that
	// from a user opening their cron in the panel UI, and the
	// false-positive volume on a panel host is dominated by the
	// legitimate case. Operators who want CFML-FS-005 to catch
	// crontab-based persistence drops can remove this entry and
	// the (crontab) sibling below.
	"crontab",
	"(crontab)",

	// `at` and `(at)` are NOT in the static default list — they're
	// added at AllowCommFor lookup time only when /usr/bin/at (or
	// the Debian /usr/sbin/at variant) is actually installed. See
	// presenceGatedAllowComm() below for the rationale: `at` is a
	// 2-char comm, the easiest possible prctl(PR_SET_NAME) spoof
	// target across the entire allow_comm surface, so on hosts that
	// don't ship the at(1) package we leave that surface closed.

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

	// Exim MTA master + forked delivery children. The allow_exe
	// entries above (/usr/sbin/exim, /usr/sbin/exim4) pin the inode
	// for the BPF-side short-circuit; this comm handle catches the
	// per-delivery children whose exe d_name lookup races the
	// userspace post-filter, same rationale as the proftpd / httpd
	// entries below. RHEL/cPanel report comm "exim"; Debian/Ubuntu
	// report "exim4".
	"exim",
	"exim4",

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

// AllowExeFor returns the merged allow_exe paths for id — the
// compile-in default global list (DefaultGlobalAllowExe) plus the
// operator's [allow] block plus the per-policy section. Returns
// nil when id does not consume an exe allowlist.
//
// Nil-receiver contract: a nil *Conf returns the compile-in
// defaults (still filtered through allowExePolicy(id)). This is
// a behaviour change from pre-merge-at-lookup, where a nil
// receiver short-circuited to nil — kept intentionally so
// callers in early-startup paths that don't yet have a parsed
// Conf still see the baseline allowlist instead of an empty
// one. BuildEventFilter explicitly handles nil before reaching
// here, so the new semantics are not currently exercised in
// production but matter for future callers (e.g. a `cfm lsm
// allowlist --effective` dump command).
//
// Merging defaults at lookup time (rather than at parse time)
// closes the upgrade gap that bit PR #944 in the field: an
// operator's existing /etc/cfm/lsm.conf is preserved by rpm
// `%config(noreplace)` across upgrades, so a newer build's
// additions to DefaultGlobalAllowExe / DefaultGlobalAllowComm
// were silently ignored until the operator hand-edited the file.
// With the merge here, a fresh daemon start on an upgraded build
// picks up new defaults transparently; the operator file retains
// its role as "what's been customised on top of the defaults".
//
// Upgrade asymmetry — removals do not propagate. The merge only
// adds. If a future build REMOVES an entry from
// DefaultGlobalAllowExe (e.g. because it turned out to be too
// broad), an upgraded host whose existing lsm.conf has that
// entry rendered into the [allow] block will keep the entry in
// the effective list, because ParseConf re-reads it from the
// file. Closing this side of the gap requires either a
// "deprecated_default" list the merge filters out, or a
// `[allow] disable_default = X` syntax. Not implemented today;
// the current trade-off matches the existing static
// WebUserNames carve-out (apache / nginx / nobody / etc., which
// also can't be excluded via lsm.conf).
//
// Order in the returned slice: defaults first, then operator
// global, then per-policy. dedupePreservingOrder collapses
// duplicates so an operator file that explicitly re-lists a
// default doesn't produce a doubled entry.
func (c *Conf) AllowExeFor(id PolicyID) []string {
	if !allowExePolicy(id) {
		return nil
	}
	var out []string
	out = append(out, DefaultGlobalAllowExe...)
	if c != nil {
		if len(c.GlobalAllowExe) > 0 {
			out = append(out, c.GlobalAllowExe...)
		}
		if c.AllowExe != nil {
			out = append(out, c.AllowExe[id]...)
		}
	}
	return dedupePreservingOrder(out)
}

// AllowCommFor returns the merged allow_comm names for id — the
// compile-in default global list (DefaultGlobalAllowComm) plus the
// operator's [allow] block plus the per-policy section. Returns nil
// when id does not consume a comm allowlist. See AllowExeFor for
// the upgrade-gap rationale; this function mirrors that shape so
// the merge semantics are consistent across all three allow_*
// surfaces.
func (c *Conf) AllowCommFor(id PolicyID) []string {
	if !allowCommPolicy(id) {
		return nil
	}
	var out []string
	out = append(out, DefaultGlobalAllowComm...)
	// Presence-gated extras (today: `at` only when /usr/bin/at is
	// installed). See presenceGatedAllowComm() for the threat-model
	// rationale — short comms like `at` are easy spoof targets so
	// we keep their allow_comm surface closed on hosts that don't
	// actually run the underlying binary.
	out = append(out, presenceGatedAllowComm()...)
	if c != nil {
		if len(c.GlobalAllowComm) > 0 {
			out = append(out, c.GlobalAllowComm...)
		}
		if c.AllowComm != nil {
			out = append(out, c.AllowComm[id]...)
		}
	}
	return dedupePreservingOrder(out)
}

// AllowPathFor returns the configured script-path-prefix
// allowlist for id. Only global entries today — per-policy script
// prefixes can be added later if a single policy needs to narrow
// further. Returns nil when id does not consume the script-prefix
// allowlist or when nothing has been configured.
func (c *Conf) AllowPathFor(id PolicyID) []string {
	if !allowPathPolicy(id) {
		return nil
	}
	var out []string
	out = append(out, DefaultGlobalAllowPath...)
	if c != nil && len(c.GlobalAllowPath) > 0 {
		out = append(out, c.GlobalAllowPath...)
	}
	if len(out) == 0 {
		return nil
	}
	return dedupePreservingOrder(out)
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
		FS005WebOriginMonitor: defaultFS005WebOriginMonitor,
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
		current        sectionKind // which section we are inside
		currentPolicy  PolicyID    // valid when current == sectionPolicy
		lineno         int
		seenPolicies   = map[PolicyID]int{}
		seenTopLevel   = map[string]int{}
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
					return nil, fmt.Errorf("line %d: allow_exe is only valid for %s", lineno, joinPolicyIDs(allowExePolicies()))
				}
				p, err := parseAllowExe(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.AllowExe[currentPolicy] = append(c.AllowExe[currentPolicy], p)
			case "allow_comm":
				if !allowCommPolicy(currentPolicy) {
					return nil, fmt.Errorf("line %d: allow_comm is only valid for %s", lineno, joinPolicyIDs(allowCommPolicies()))
				}
				comm, err := parseAllowComm(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineno, err)
				}
				c.AllowComm[currentPolicy] = append(c.AllowComm[currentPolicy], comm)
			default:
				return nil, fmt.Errorf("line %d: unknown policy key %q (supported: `mode`; %s also supports `origin_tracking` and `persistence_path`; %s also support `allow_exe`; %s also support `allow_comm`)", lineno, key, PolicySensitiveWrite, joinPolicyIDs(allowExePolicies()), joinPolicyIDs(allowCommPolicies()))
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
			case "enrich":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: enrich must be true|false|1|0|on|off (got %q)", lineno, val)
				}
				c.EventSink.Enrich = b
			case "enrich_hash":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: enrich_hash must be true|false|1|0|on|off (got %q)", lineno, val)
				}
				c.EventSink.EnrichHash = b
			case "enrich_peers":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: enrich_peers must be true|false|1|0|on|off (got %q)", lineno, val)
				}
				c.EventSink.EnrichPeers = b
			case "enrich_capture":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: enrich_capture must be true|false|1|0|on|off (got %q)", lineno, val)
				}
				c.EventSink.EnrichCapture = b
			case "capture_dir":
				dir := strings.TrimSpace(val)
				if dir != "" && !filepath.IsAbs(dir) {
					return nil, fmt.Errorf("line %d: capture_dir must be an absolute path (got %q)", lineno, val)
				}
				c.EventSink.CaptureDir = dir
			default:
				return nil, fmt.Errorf("line %d: unknown [events] key %q (detect_rate_per_min | enrich | enrich_hash | enrich_peers | enrich_capture | capture_dir)", lineno, key)
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
	// Union the three allow-* policy lists so the rendered comment always
	// matches the gate functions. Order follows AllPolicies() for stable
	// output across FormatConf calls.
	seen := map[PolicyID]struct{}{}
	var consumers []PolicyID
	for _, p := range AllPolicies() {
		if allowExePolicy(p.ID) || allowCommPolicy(p.ID) || allowPathPolicy(p.ID) {
			if _, dup := seen[p.ID]; !dup {
				seen[p.ID] = struct{}{}
				consumers = append(consumers, p.ID)
			}
		}
	}
	fmt.Fprintf(&b, "# an exe / comm / script-prefix allowlist (today: %s).\n", joinPolicyIDs(consumers))
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
	b.WriteString("\n")
	b.WriteString("# Forensic enrichment. When a detection fires the daemon snapshots\n")
	b.WriteString("# the caller's /proc (user, real exe path + deleted flag, cwd,\n")
	b.WriteString("# cmdline, parent pid/exe, loginuid) and folds it into the cfm.log\n")
	b.WriteString("# line and the notify email — the BPF event alone carries only the\n")
	b.WriteString("# spoofable comm. Best-effort: a caller that already exited shows\n")
	b.WriteString("# `proc=gone`, in which case the parent is usually still resolvable.\n")
	fmt.Fprintf(&b, "enrich              = %t   # snapshot /proc for the caller into log + email\n", c.EventSink.Enrich)
	fmt.Fprintf(&b, "enrich_hash         = %t   # include exe SHA-256 (IDs the binary, incl. deleted; VirusTotal-ready)\n", c.EventSink.EnrichHash)
	b.WriteString("# enrich_peers: list every process sharing the caller's real uid\n")
	b.WriteString("# (pid/comm/real-exe) — the whole malware swarm, whose pids are gone\n")
	b.WriteString("# by the time a 3am alert is read. enrich_capture: copy the offending\n")
	b.WriteString("# binary out of /proc/<pid>/exe (readable even after it is unlinked)\n")
	b.WriteString("# into capture_dir, but only for suspicious images (deleted, or under\n")
	b.WriteString("# /tmp,/var/tmp,/dev/shm,/run,/home); saved <sha256>.bin, root-only,\n")
	b.WriteString("# never executed, deduplicated, and bounded.\n")
	fmt.Fprintf(&b, "enrich_peers        = %t   # append the uid swarm roster to log + email\n", c.EventSink.EnrichPeers)
	fmt.Fprintf(&b, "enrich_capture      = %t   # preserve suspicious caller/peer binaries before they self-delete\n", c.EventSink.EnrichCapture)
	captureDir := c.EventSink.CaptureDir
	if captureDir == "" {
		captureDir = DefaultCaptureDir
	}
	fmt.Fprintf(&b, "capture_dir         = %s   # where preserved binaries land (<sha256>.bin)\n", captureDir)
	return b.String()
}

// WriteDefaultConf writes the default configuration to ConfPath if it
// does not already exist. Returns (true, nil) when a new file was
// created, (false, nil) when the file already existed, or (false, err)
// on a write failure.
//
// Currently called only from the FormatConf round-trip test. The
// `cfm lsm init` path no longer auto-generates a conf — see
// DefaultConf's godoc and internal/lsm/init.go for the rationale.
// Kept exported because external callers (packaging scripts, custom
// bootstrappers) may still want a deterministic Conf-to-disk path.
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

// atBinaryPaths is the set of paths where /usr/bin/at lives across
// supported distros. Probed once at first AllowCommFor call (see
// presenceGatedAllowComm) to decide whether to allowlist the `at`
// comm; cached via the var below so the 17-policy BuildEventFilter
// sweep doesn't stat() repeatedly.
var atBinaryPaths = []string{"/usr/bin/at", "/usr/sbin/at", "/bin/at"}

// hostHasAtBinary is the package-level hook tests stub to control
// the at-presence outcome deterministically. Production uses
// statAnyExists; tests override the var to force true/false without
// touching the host filesystem. Reset to statAnyExists in test
// teardown if needed.
var hostHasAtBinary = func() bool { return statAnyExists(atBinaryPaths) }

// statAnyExists reports whether any of paths can be stat'd. Used to
// gate presence-conditional allowlist entries without coupling the
// caller to os.Stat directly (so tests can override the parent hook).
func statAnyExists(paths []string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// presenceGatedAllowComm returns the runtime-conditional extras
// to merge into AllowCommFor's effective list. Today: `at` /
// `(at)` only when the at(1) binary is actually installed on the
// host.
//
// Rationale: `at` is a 2-character comm — the easiest possible
// prctl(PR_SET_NAME) spoof target on the entire allow_comm
// surface. On hosts that ship and use at(1), the FP suppression
// is worth the comm-spoof attack-surface cost (same trade-off as
// every other allowlist entry). On hosts where at(1) isn't
// installed at all, there's no legitimate `at` comm to suppress,
// so allowlisting it is pure attack surface — we omit it.
//
// Symmetric gating for `crontab` was considered and rejected:
// /usr/bin/crontab is on essentially every Linux host that runs
// cfm-lsm, and the 7-character comm is enough harder to spoof
// than `at` that the asymmetry is justified.
func presenceGatedAllowComm() []string {
	if hostHasAtBinary() {
		return []string{"at", "(at)"}
	}
	return nil
}

// dedupePreservingOrder returns a copy of in with later duplicates
// removed; the first occurrence of each string is kept. Used by
// AllowExeFor / AllowCommFor / AllowPathFor when merging compile-in
// defaults with operator-supplied entries — an operator who
// explicitly re-lists a default value (or a future FormatConf round-
// trip that re-emits both) must produce a single effective entry.
func dedupePreservingOrder(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// joinPolicyIDs renders ids as a comma-separated string. Used by the
// parser error paths to enumerate the set of policies that accept a
// given allow_* key — the alternative is hardcoded lists in fmt.Errorf
// that drift out of sync with the allowExePolicy / allowCommPolicy /
// allowPathPolicy switches whenever a new policy is added (PR #944
// exposed this when it extended allow_comm to CRED-004 / OBS-004 but
// the error message kept naming the five originals).
func joinPolicyIDs(ids []PolicyID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = string(id)
	}
	return strings.Join(parts, ", ")
}

// allowExePolicies / allowCommPolicies / allowPathPolicies enumerate
// the policy IDs whose corresponding allow_* gate function returns
// true. Single source of truth for both the gate (allow*Policy()) and
// the operator-facing error messages — adding a policy to the gate
// switch is enough; the error strings + FormatConf preamble pick up
// the new entry on the next ParseConf call.
func allowExePolicies() []PolicyID {
	var out []PolicyID
	for _, p := range AllPolicies() {
		if allowExePolicy(p.ID) {
			out = append(out, p.ID)
		}
	}
	return out
}

func allowCommPolicies() []PolicyID {
	var out []PolicyID
	for _, p := range AllPolicies() {
		if allowCommPolicy(p.ID) {
			out = append(out, p.ID)
		}
	}
	return out
}

func allowPathPolicies() []PolicyID {
	var out []PolicyID
	for _, p := range AllPolicies() {
		if allowPathPolicy(p.ID) {
			out = append(out, p.ID)
		}
	}
	return out
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
//
// CRED-004 / OBS-004 use allow_comm to suppress the per-user
// `systemd --user` session-setup fanout. Modern systemd spawns a
// systemd-user instance under every login uid; on cPanel / DA /
// Plesk hosts that's hundreds of instances, each doing legitimate
// session-init work (cap_ambient raise for CAP_WAKE_ALARM on every
// minute-boundary timer tick, ptrace-during-fork-setup against
// freshly-cloned children) that matches the threat patterns these
// two rules detect. The same applies to `bwrap` (bubblewrap sandbox
// runtime used by flatpak / portable apps, which ptraces its own
// sandboxed children at startup). `readlink` on /proc/PID/exe is
// the third case — the kernel routes /proc/PID/exe symlink
// resolution through ptrace_may_access, so `readlink /proc/N/exe`
// from a webshell uid (status pages, supervisor health checks,
// LiteSpeed lsphp respawn detection) fires OBS-004 even though
// no actual ptrace syscall was issued.
//
// FS-005 uses allow_comm for the per-user crontab / at workflow.
// /usr/bin/crontab and /usr/bin/at are setuid-root binaries that
// legitimately rename a temp file into /var/spool/cron/<user> or
// /var/spool/at/<jobid> on behalf of an unprivileged caller.
// /var/spool/cron and /var/spool/at are in DefaultPersistencePaths,
// so every panel-UI "Cron Jobs" edit by a watched uid trips FS-005
// (create + rename + setattr on the spool directory). The BPF-side
// trusted-comm allowlist (cfm_comm_is_trusted_auth_helper) was
// extended to cover the enforce path; this knob is the userspace
// half that silences the monitor-mode noise.
func allowCommPolicy(id PolicyID) bool {
	switch id {
	case PolicyUnexpectedBPF, PolicyCredEscal, PolicyReverseShell, PolicyInterpreterNetStdio, PolicyEphemeralExec, PolicyCapRaise, PolicyPtraceAccess, PolicySensitiveWrite:
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
