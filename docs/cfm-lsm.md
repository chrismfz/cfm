# cfm-lsm — Userspace Behaviour Enforcement

## Status

Seventeen policies ship, all compiled into one BPF object
(`internal/lsm/bpf/cfmlsm.bpf.c`) and listed in `AllPolicies()`
(`internal/lsm/policy.go`). That list is the authoritative scope of
cfm-lsm; anything beyond it needs a separate, named proposal.

- **Off unless configured.** The code defaults are `enabled = false`
  and `mode = disabled` for every policy (`DefaultConf`). The packaged
  `configs/lsm.conf` (installed as `/etc/cfm/lsm.conf`,
  `%config(noreplace)`) currently ships `enabled = true` with every
  policy at `mode = monitor`. A new install therefore attaches all
  available policies in monitor mode.
- **Monitor first.** `monitor` reports and never blocks. `enforce`
  returns `-EPERM` from the hook on a match.
- **Enforce-capable:** `CFML-EXEC-001`, `CFML-EXEC-003`,
  `CFML-EXEC-004`, `CFML-EXEC-006`, `CFML-FS-005`, `CFML-FS-007`,
  `CFML-FS-008`, `CFML-NET-002`.
- **Monitor-only telemetry policies:** `CFML-EXEC-005`,
  `CFML-EXEC-007`, `CFML-EXEC-008`, `CFML-BPF-001` (tracepoint hooks:
  the kernel ignores the program's return value), `CFML-CRED-003`,
  `CFML-CRED-004` (`fentry/commit_creds` is a trace probe, not a
  decision point), `CFML-CRED-002`, `CFML-FS-006`, `CFML-OBS-004`
  (LSM hooks where `-EPERM` would break legitimate userspace). The
  single source of truth is `isEnforceCapable`. `cfm lsm enable` and
  the daemon's auto-enable downgrade `mode = enforce` on these to
  `monitor` with a warning.

The enforce/monitor choice is a `volatile const` per policy, rewritten
at load time (`rewriteConstants` in `loader.go`), so it is baked into
the program and costs no runtime branch. Changing a mode needs
`cfm lsm restart` (disable, then enable), which briefly detaches the
programs. Recovery from a false-positive block is `cfm lsm disable`.

`enabled = true` in `lsm.conf` is the durable state. `/sys/fs/bpf` is
RAM-only, so a reboot drops every pin; on start the daemon finds no
pins and runs preflight, load, attach and pin itself. Detection lives
in the kernel and survives daemon restarts and crashes within a boot;
event collection needs the daemon.

Companion kernsec rule `KSEC-LSM-bpf-001` (Tier 2, opt-in with
`state = force` in `/etc/cfm/kernsec.conf`) merges `bpf` into the
existing `lsm=` boot argument without dropping other LSMs. It is needed
where `bpf` is not in the kernel's default LSM list (typically Debian /
Ubuntu) and takes effect on the next reboot.

## Overview

`cfm-lsm` catches the post-exploit consequences of a userspace
compromise: a webshell that execs a payload from memory or from `/tmp`,
a hijacked process that turns into a reverse shell, a web user writing
`/etc/shadow` after a kernel privesc, a dropped setuid binary. These are
invisible to the other CFM layers: `webdetector` has already returned by
the time exec happens, and `kernsec` reduces the kernel surface ahead of
time (sysctls, boot arguments, module blacklists, mount audit) rather
than deciding at runtime.

`cfm-lsm` is not a generic syscall observer (Tetragon's space), not a
replacement for CageFS, LVE or Imunify360 (it sits beside them), and not
an outbound network policy engine (that is the per-uid NFLOG path in
`internal/outbound/`).

## Position in the CFM stack

```
HTTP layer        webdetector / WAF  (request analysis, challenge, block)
                       ↓
Userspace layer   cfm-lsm            (process behaviour at the syscall boundary)
                       ↓
Kernel layer      kernsec            (sysctls, boot args, modules, mounts —
                                      preemptive surface reduction)
```

`cfm-lsm` covers the band between the HTTP request that caused the
compromise and the kernel surface the operator already removed: the
moment a compromised process does what the attacker came for.

## Scope rationale

The first draft proposed fifteen policies across exec, credential,
filesystem, network, rate-limit, self-protection and observability.
Measured against the stacks CFM targets (cPanel + CloudLinux +
KernelCare, DirectAdmin + CloudLinux + KernelCare, Proxmox Debian KVM
ZFS), most duplicated CageFS, LVE, Imunify360 Proactive Defense,
`kernsec` or `internal/outbound/`, and some conflicted with them
(KernelCare / Ksplice module reloads vs a module-load lockdown). The
shipped set keeps the policies no other layer covers; the rejected ones
are recorded under [Out of scope](#out-of-scope-with-rationale).

**Why BPF LSM, in the daemon.** CO-RE BPF loaded by the existing Go
daemon through [`cilium/ebpf`](https://github.com/cilium/ebpf): no
kernel module, no DKMS, no clang on the customer host, `CGO_ENABLED=0`
stays true. A DKMS module across KernelCare-patched RHEL kernels would
be a permanent maintenance tax, and a second daemon would invite version
skew and IPC for no gain.

**Why PHP-function interception is out of scope.** Blocking dangerous
PHP calls happens in the Zend VM, a different layer from kernel LSM
hooks. For hosts without Imunify360 Proactive Defense, that layer is
planned as CFM-managed Snuffleupagus
([`roadmaps/php-runtime-defense.md`](./roadmaps/php-runtime-defense.md));
CFM writes no PHP extension of its own.

**Stack notes.**

- **cPanel / DirectAdmin + CloudLinux.** All policies apply. CageFS
  hides the FS-005 paths from caged users, so an FS-005 event from a
  caged user means caging was bypassed. The watched-uid set comes from
  `/etc/userdomains` (cPanel) or `/etc/virtual/domainowners`
  (DirectAdmin).
- **Proxmox hypervisors.** Little PHP workload; the value is a reverse
  shell, memfd exec, sensitive write or unexpected root credential on
  the hypervisor itself. Admin SSH consoles widen the legitimate
  remote-stdio baseline, so operators there often leave EXEC-003 /
  EXEC-005 disabled.

## Allowlist semantics — read before enabling enforce on any rule

`lsm.conf` has three allowlist primitives:

- `allow_exe` — basename match against the event's filename
  (`filepath.Base` of the bprm path or the exe dentry name).
- `allow_comm` — exact match against `task->comm` (truncated to 15
  characters by the kernel; list the truncated form).
- `allow_path` — directory-prefix match against any argv element of
  `/proc/<pid>/cmdline` at event time.

**Allowlists are a userspace post-filter.** `BuildEventFilter()`
(`internal/lsm/filter.go`) drops matching events in the daemon's drain
goroutine, before the log, notify and kmsg sinks. They do **not** gate
the kernel decision: an enforce-capable program returns `-EPERM` inside
the hook before userspace sees the event, so an allowlisted binary is
still denied in enforce mode. An entry that silences a noisy build in
monitor mode does not stop that build being blocked in enforce mode.
The safe enforce rollout is monitor-mode telemetry that shows zero
legitimate matches on the host, not "allowlist everything first".

**Where each primitive is accepted.** Per-policy sections take
`allow_exe` and `allow_comm`; `allow_path` exists only in the global
`[allow]` section. A global entry applies to every policy that accepts
that primitive. Compiled-in defaults (`DefaultGlobalAllowExe`,
`DefaultGlobalAllowComm`, `DefaultGlobalAllowPath`,
`DefaultPolicyAllowComm` in `conf.go`) merge at lookup time, so an
upgrade over an older `lsm.conf` still gets them. Coverage
(`allowExePolicy` / `allowCommPolicy` / `allowPathPolicy`):

| Rule | allow_exe | allow_comm | allow_path (global) |
|---|:-:|:-:|:-:|
| `CFML-EXEC-003` (reverse shell) | ✓ | ✓ | ✓ |
| `CFML-EXEC-005` (interpreter net stdio) | ✓ | ✓ | ✓ |
| `CFML-EXEC-006` (ephemeral exec) | ✓ | ✓ | ✓ |
| `CFML-CRED-002` (privesc without setuid) | ✓ | ✓ | ✓ |
| `CFML-BPF-001` (unexpected BPF) | — | ✓ | — |
| `CFML-OBS-004` (ptrace by web user) | — | ✓ ¹ | — |
| `CFML-CRED-004` (cap raise) | — | ✓ | — |
| `CFML-FS-005` (sensitive write) | — | ✓ | — |

¹ OBS-004 also has a compiled-in comm list (`DefaultPolicyAllowComm`:
`ps`, `pgrep`, `pkill`, `pidof`, `killall`, the cPanel / CloudLinux API
comms, `cloudlinux-stat`). A comm match only ever hides a ptrace READ:
an event carrying `PTRACE_MODE_ATTACH` always reports, because
`task->comm` is spoofable and none of the listed tools attaches. That
includes operator `allow_comm` lines; to silence a known attach (an
operator gdb'ing a tenant's worker), use `exclude_user` for that
account.

Rules absent from the table (`CFML-EXEC-001` / `004` / `007` / `008`,
`CFML-FS-006` / `007` / `008`, `CFML-CRED-003`, `CFML-NET-002`) ignore
every allowlist entry. A per-policy `allow_exe` / `allow_comm` under
them is a parse error.

**The CRED-002 exception.** CRED-002's `allow_exe` paths are also
`stat()`'d into the BPF map `cfm_setuid_inodes` at adoption. For that
rule an allowlisted path does gate the kernel-side decision.

## Policy catalogue

Every policy defaults to `disabled` in code. "Watched uid" means the
calling task's real uid is in `cfm_watched_uids` (see
[Watched-uid model](#watched-uid-model)). Every LSM-hook program returns
early when an earlier LSM already denied (`ret != 0`).

### `CFML-EXEC-001` — Block exec from memfd

**Hook** `bprm_check_security` · **Enforce** capable · **Gate** none (any uid, root included)

**Catches** `execve` of a file on a tmpfs superblock whose dentry name
starts with `memfd:`, i.e. a `memfd_create()` payload. This is the
canonical fileless step after a webshell downloads a binary into memory.
Legitimate uses on a hosting server are rare.

**FP sources and knobs.** Container start-up on hypervisors (podman /
systemd-nspawn) can exec from anonymous fds. No allowlist applies; the
only knob is the mode. This is the rule to enable first and promote to
enforce after a short monitor window.

### `CFML-EXEC-003` — Reverse shell pattern

**Hook** `bprm_check_security` · **Enforce** capable · **Gate** effective uid ≠ 0

**Catches** an exec where fds 0, 1 and 2 are all `AF_INET` / `AF_INET6`
sockets in `TCP_ESTABLISHED`, whatever the binary (`bash`, `nc`,
`socat`, `python -c`). Unix sockets and listening / connecting sockets
are skipped. Event flag `CFM_LSM_F_REVSHELL_STRICT`. Imunify PD blocks
the PHP call that launches `bash -i >& /dev/tcp/…`; this rule catches
the resulting process, including launchers that never went through PHP.

**Exemptions.** Effective uid 0 returns before the fd walk: root reverse
shells (admin SSH `nc` sessions, inetd-style root services, rescue
shells) emit nothing and are never blocked. There is no watched-uid
gate: any non-root caller with all three fds on remote TCP is reported.
Rare legitimate non-root inetd-style helpers (`spawn(8)` scripts) can be
silenced with `allow_exe` / `allow_comm` / `allow_path`, monitor mode
only.

### `CFML-EXEC-005` — Suspicious interpreter network stdio

**Hook** `bprm_check_security` · **Enforce** monitor-only · **Gate** basename in a fixed set

**Catches** the weak case next to EXEC-003: exactly one or two of fds
0/1/2 are established remote TCP and the exec basename is `sh`, `bash`,
`dash`, `zsh`, `python`, `python3`, `perl`, `php`, `ruby`, `node`, `nc`,
`ncat` or `socat`. All three remote is EXEC-003's event. Flags
`CFM_LSM_F_INTERP_STDIO_WEAK` plus `CFM_LSM_F_STDIO_ONE_REMOTE` or
`CFM_LSM_F_STDIO_TWO_REMOTE`.

**Monitor-only because** the pattern is often legitimate: inetd-style
socket activation, admin one-liners over `nc` / `socat`, live debugging.
It is triage context, not a block. Silence known helpers with
`allow_exe` / `allow_comm` / `allow_path`.

### `CFML-EXEC-004` — Deleted-file exec by web user

**Hook** `bprm_check_security` · **Enforce** capable (current-uid matches only) · **Gate** watched uid, or web-origin task

**Catches** a watched uid executing a file whose inode has link count
zero or whose dentry is unhashed: stage a binary, open it, unlink it to
evade scanners, exec the open file. Flags `CFM_LSM_F_UNLINKED_INODE` /
`CFM_LSM_F_UNHASHED_DENTRY`.

**Web origin.** The program also matches tasks marked web-origin by the
FS-005 tracker (`origin_tracking`). Origin-only matches carry
`CFM_LSM_F_WEB_ORIGIN` and are never blocked, even in enforce mode.

**FP sources.** Panel helpers, backup tools, deploy systems or AV /
updater workflows that exec unlinked files under a watched uid. No
allowlist applies, so confirm a clean monitor baseline before enforce.

### `CFML-EXEC-006` — Web-user exec from ephemeral filesystem

**Hook** `bprm_check_security` · **Enforce** capable · **Gate** watched uid

**Catches** a watched uid executing a binary that is either on a tmpfs
superblock (`/dev/shm`, `/run/user/<uid>/`, `/tmp` on tmpfs; flag
`CFM_LSM_F_TMPFS_BACKED`) or under `/tmp/` or `/var/tmp/` on a non-tmpfs
root such as EL9 / CloudLinux 9 (flag `CFM_LSM_F_EPHEMERAL_DIR`). memfd
payloads are skipped (EXEC-001). This is the execution-phase companion
to Imunify PD's write-phase guard: PD blocks the PHP write to
`/tmp/.<hidden>`, EXEC-006 sees the `execve` if the write got through.
EXEC-004 misses a payload that was not unlinked; this rule does not.

**Depth limit.** The `/tmp` dentry walk is unrolled to 16 levels. A
deeper path fails closed (no match) rather than treating the deepest
dentry reached as the top, which would misread a mid-path `tmp`
directory. The tmpfs check does not depend on depth.

**FP sources and knobs.** Package-manager extractions, cPanel
EasyApache build steps, `ldconfig` re-runs, container helpers. Run
monitor for about a week on a representative host. `allow_exe` /
`allow_comm` / `allow_path` silence those events in monitor mode but
**do not** stop the kernel denying them in enforce mode (see Allowlist
semantics). Promote only when monitor shows no legitimate ephemeral-fs
exec, or when the operator accepts that those workflows break.

### `CFML-FS-005` — Sensitive-file modification by web user

**Hook** `inode_setattr`, `inode_create`, `inode_link`, `inode_unlink`, `inode_rename`, `inode_setxattr`; origin markers on `bprm_check_security`, `task_fix_setuid`, `task_alloc` · **Enforce** capable (current-uid matches on core paths only) · **Gate** watched uid, or web-origin task

**Catches** a watched uid modifying a watched path. The daemon `stat()`s
each path and stores `(fs, inode)` in `cfm_watched_inodes`; for
directories the create / link / rename / unlink hooks match the parent
directory, so `/etc/sudoers.d/backdoor` matches without BPF path walking.
Globs are not supported; missing paths are skipped, so one config can be
shared across cPanel, DirectAdmin, Debian / Ubuntu and EL hosts. This is
the cash-in after any privesc, including kernel 0-days that bypass other
hooks: the attacker still has to write `/etc/shadow`, `/etc/sudoers` or
`authorized_keys` through the normal syscall path.

**Two path classes** (`internal/lsm/maps.go`):

- **Core, enforceable** (`DefaultCoreSensitivePaths`): `/etc/passwd`,
  `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`.
- **Persistence, monitor-only even in enforce mode**
  (`DefaultPersistencePaths`, plus operator `persistence_path` lines):
  systemd unit dirs, cron dirs and `crontab`, `cron.allow/deny`,
  `at.allow/deny`, `/var/spool/cron{,/crontabs}`, `/etc/sudoers.d`,
  `/etc/pam.d`, `sshd_config{,.d}`, `/root/.ssh`, root's
  `.bashrc` / `.profile`, `/etc/ld.so.preload`, `ld.so.conf{,.d}`,
  `/etc/profile{,.d}`, `/etc/bashrc`, `/etc/bash.bashrc`,
  `/etc/environment`, the cPanel hook / include paths and the
  DirectAdmin custom hook dirs.

```ini
[policy "CFML-FS-005"]
mode = monitor
origin_tracking = monitor           # disabled | monitor (default monitor)
persistence_path = /opt/vendor-panel/hooks
```

**Web-origin tracking** (`origin_tracking`, default `monitor`) uses
task-local storage to mark tasks whose real, effective or fs uid is
watched, refreshes the mark on exec and setuid-family transitions, and
copies it to children in `task_alloc`. A later sensitive write still
matches after the process has become uid 0. Origin-only events carry
`CFM_LSM_F_WEB_ORIGIN` and are never blocked. They are broader: root
helpers or panel maintenance started from a panel account can show up.

**Auth-helper exemption in enforce mode.** The gate keys on the real
uid, so a watched admin running `passwd` or `sudo visudo` still matches.
When the task has euid 0 **and** its comm is in the fixed set in
`cfm_comm_is_trusted_auth_helper` (`sudo`, `sudoedit`, `visudo`, `vipw`,
`vigr`, `passwd`, `chage`, `gpasswd`, `chsh`, `chfn`, `newgrp`,
`pkexec`, `unix_chkpwd`, `usermod`, `useradd`, `userdel`, `groupadd`,
`groupmod`, `groupdel`, `pwconv`, `grpconv`, `pwck`, `grpck`), the event
is still emitted but `-EPERM` is not returned. **This gate is
spoofable**: a task at euid 0 can set its comm to `passwd` with one
`prctl(PR_SET_NAME)`. FS-005 enforce stops opportunistic exploit code,
not a targeted attacker who knows the policy. The event is the real
forensic signal. An `exe_file` inode check would be the stronger gate
(not built).

**FP profile.** Very low on CageFS hosts, low to medium on plain hosts
for current-uid matches. `allow_comm` (per-policy or global) silences
known writers in monitor mode.

### `CFML-FS-006` — Sensitive read via root-owned fd from unprivileged task

**Hook** `file_permission` · **Enforce** monitor-only · **Gate** real uid ≠ 0, euid ≠ 0, `file->f_cred` euid 0, inode in `cfm_watched_inodes`

**Catches** an unprivileged task reading a FS-005 watched inode through
a `struct file` opened by root: the setuid-helper fd-leak class. The
modern variant is the `pidfd_getfd()` exit-window race against
`ssh-keysign` / `chage` / `unix_chkpwd` (Qualys; kernel fix in Linus
commit `31e62c2ebbfd`), which Yama `ptrace_scope=1` lets through because
the attacker is the helper's parent. Older variants: `CLONE_FILES` +
setuid exec, `/proc/<pid>/fd/<n>` with `fs.suid_dumpable=1`.
`file_permission` is the only hook that sees both `current_cred()` and
`file->f_cred`; it runs on every read and write, so the program returns
on uid 0 before any map lookup.

**Relationship to kernsec.** kernsec ships
`kernel.yama.ptrace_scope=2` (`KSEC-SCT-kspp.kernel-006`, Tier 1), which
closes the `pidfd_getfd()` primitive. FS-006 is for hosts that
`state = skip` that rule for same-uid `gdb` / `strace -p` / `py-spy`,
and for future fd-leak variants that do not go through ptrace.

**Monitor-only because** PAM chains do exactly this legitimately:
`passwd`, `pkexec`, `sudo`, `unix_chkpwd`, dovecot-auth workers and
postfix workers open the watched files as root and read them after
dropping privileges. Denying would break authentication. The legitimate
`(comm, exe inode)` set varies by distro, PAM stack, MTA and panel, so
any enforce allowlist would have to be built from production telemetry.
Expect mid-volume events on hosts with interactive `su`, `sshd` password
auth or `crond` PAM sessions.

### `CFML-FS-007` — Privilege-primitive install by web user

**Hook** `inode_setattr`, `inode_setxattr` · **Enforce** capable · **Gate** watched uid

**Catches** a watched uid setting the suid / sgid bit (`chmod 4755`) or
writing `security.capability` (`setcap`) on any file. Flags
`CFM_LSM_F_PRIV_SUID`, `_SGID`, `_FILECAP`. This is the persistence
install step; CRED-002 catches the later use. There is no watched-inode
gate: the primitive itself is the signal.

**Enforce** is safe in principle (no legitimate workflow has a web-class
uid set suid or file caps); `chmod` / `setxattr` get `-EPERM` and the
primitive never lands. No allowlist applies.

### `CFML-FS-008` — Write to a sensitive kernel knob

**Hook** `file_permission` (write / append only) · **Enforce** capable · **Gate** inode in `cfm_kernel_knob_inodes`; comm not trusted

**Catches** a write to `/proc/sys/kernel/core_pattern`,
`/proc/sys/kernel/modprobe_path`, `/proc/sys/kernel/hotplug`,
`/proc/sysrq-trigger`, `/sys/kernel/uevent_helper` or
`/proc/sys/fs/binfmt_misc/register` (`DefaultKernelKnobPaths`): the
pivots public kernel exploits use once they have a write primitive.
Paths absent on the running kernel are skipped. There is **no**
watched-uid gate: any writer, root included, is reported unless its comm
is `cfm`, `sysctl`, `systemd-sysctl` or `systemd`.

**Enforce** is capable but needs a monitor window first: an unexpected
legitimate writer would fail silently. No allowlist applies.

### `CFML-CRED-002` — Privilege escalation without setuid path

**Hook** `task_fix_setuid` · **Enforce** monitor-only · **Gate** euid non-root → root

**Catches** a setuid-family syscall that takes euid from non-zero to 0
in a process whose `mm->exe_file` does not carry the suid bit: the
fingerprint of an exploit that installed root and pivots through
`setresuid(0,0,0)`. The program checks the exe inode's live mode
(`S_ISUID`), which stays correct across package upgrades, then falls
back to `cfm_setuid_inodes`: the daemon's walk of `/usr/bin`,
`/usr/sbin`, `/usr/libexec`, `/bin`, `/sbin` plus the operator's
`allow_exe` paths, for daemons that reach euid 0 without a suid bit
(`directadmin`, `cpanel`, `crond`, lvestats). No watched-uid gate.

**Hook choice.** `cred_prepare` runs before the caller sets
`new->euid`, so a non-root → root test there can never match;
`task_fix_setuid` runs after. This hook does not see a direct
`commit_creds()` install; that is CRED-003.

**Monitor-only because** denying a credential transition can wedge
systemd helpers and pkexec mid-transition. The packaged `lsm.conf`
carries per-policy `allow_exe` / `allow_comm` entries for known panel
and `sssd` paths.

### `CFML-CRED-003` — Direct root credential install

**Hook** `fentry/commit_creds` · **Enforce** monitor-only · **Gate** non-root → uid and euid 0

**Catches** `commit_creds()` installing root credentials for a task
whose current uid and euid are non-zero, when that cred pointer was not
just seen by `task_fix_setuid` (CRED-002 owns those). This is the
`commit_creds(prepare_kernel_cred(NULL))` kernel-exploit path. Flag
`CFM_LSM_F_DIRECT_CRED_INSTALL`. Enable it together with CRED-002.

**Monitor-only because** `fentry` is tracing, not a decision point. If
`commit_creds` is not a usable tracing target, or the kernel lacks
task-local storage, preflight reports only this policy (and CRED-002 for
the latter) unavailable.

### `CFML-CRED-004` — Capability-set raise by web user

**Hook** `fentry/commit_creds` · **Enforce** monitor-only · **Gate** watched uid; new uid and euid ≠ 0

**Catches** a watched uid gaining bits in `cap_ambient` or
`cap_inheritable`: capability hoarding through
`prctl(PR_CAP_AMBIENT_RAISE)`, after which the cap survives every
`execve`. `cap_effective` is not compared (every setuid binary changes
it). Transitions to uid 0 belong to CRED-002 / CRED-003. Flags
`CFM_LSM_F_CAP_RAISE_AMBIENT` / `_INHERITABLE`; the filename field is
`cap=NN`, the lowest newly raised bit (`cap=7` is `CAP_SETUID`).

**FP sources.** The per-user `systemd --user` instance (comm
`(systemd)`) raises ambient caps during session setup on every login
uid; `bwrap` does similar. Silence with `allow_comm`; the packaged
global `[allow]` lists both. Operator-side hygiene: audit
`getcap -r /home /var` for unexpected file caps.

### `CFML-EXEC-007` — Kernel module load by non-trusted comm

**Hook** `tracepoint/syscalls/sys_enter_{init,finit}_module` · **Enforce** monitor-only · **Gate** comm not trusted, or watched uid

**Catches** a module load whose comm is not `modprobe`, `insmod`,
`kmod`, `systemd`, `systemd-modules` (truncated
`systemd-modules-load`) or `systemd-udevd`, or any load from a watched
uid (comm spoofing). Rootkit-installer telemetry.

**Monitor-only because** the kernel ignores a tracepoint program's
return value. kernsec does not manage `kernel.modules_disabled` (it
needs a late unit after CFM loads its own modules, and live-patch agents
load modules post-boot).

### `CFML-EXEC-008` — kexec load by non-trusted comm

**Hook** `tracepoint/syscalls/sys_enter_{kexec_load,kexec_file_load}` · **Enforce** monitor-only · **Gate** comm not `kexec` / `systemctl`, or watched uid

**Catches** loading a replacement kernel post-boot, a persistence path
that bypasses firmware and on-disk kernel audits.

**Monitor-only because** it is a tracepoint. The block is kernsec's
`kernel.kexec_load_disabled=1` (`KSEC-SCT-kspp.kexec-001`, Tier 1,
skipped on kdump hosts). Preflight reports the policy unavailable when
the kexec tracepoints are not exposed.

### `CFML-BPF-001` — Unexpected BPF use

**Hook** `tracepoint/syscalls/sys_enter_bpf` · **Enforce** monitor-only · **Gate** `BPF_MAP_CREATE` / `BPF_PROG_LOAD`; comm not trusted, or watched uid

**Catches** BPF map creation or program loading outside CFM and a small
trusted set (`cfm`, `systemd`, `systemd-udevd`, `systemd-network…`,
`NetworkManager`, `bpftool`, `auditd`). Watched-uid callers are always
reported (flag `CFM_LSM_F_WEB_ORIGIN`). The filename field is
`BPF_MAP_CREATE` or `BPF_PROG_LOAD`. Advanced-threat telemetry: attackers
use eBPF for stealth and credential capture once they have local
execution.

**FP sources.** Observability and security agents and container
runtimes that load BPF; the packaged global `[allow]` lists container
runtime comms. Silence others with `allow_comm`. Broad unprivileged-BPF
reduction is kernsec's job (`kernel.unprivileged_bpf_disabled`, JIT
hardening).

### `CFML-OBS-004` — ptrace from web-class user

**Hook** `ptrace_access_check` · **Enforce** monitor-only · **Gate** watched uid; target ≠ self

**Catches** a watched uid ptracing another task (`PTRACE_MODE_READ` or
`_ATTACH`): a compromised vhost user reading or injecting into a sibling
PHP-FPM worker or cron job. Flags `CFM_LSM_F_PTRACE_READ`, `_ATTACH`,
`_SAMEUID` (cross-uid is the higher-severity case). The event carries
the target's pid and euid (`target_pid=` / `target_uid=`).

**Coverage depends on Yama.** BPF is last in the LSM chain (kernsec's
`bpf` merge appends it). On `ptrace_scope ≤ 1` hosts OBS-004 sees every
attempt. With kernsec's `ptrace_scope=2` applied, Yama denies first and
OBS-004 never sees those attempts; the kernel block is the protection
there.

**FP sources.** Reading `/proc/<pid>/{stat,exe,status}` goes through
`ptrace_may_access`, so every process lister trips the hook once per
target. The compiled-in comm list covers them (see Allowlist
semantics); a READ by a listed comm is hidden, an ATTACH never is. Notify
mail for OBS-004 is keyed on caller identity, so one sweep is one mail
(see [Event enrichment](#event-enrichment--making-an-alert-actionable)).

**Monitor-only because** Yama is the block layer, and denying here
would break operators debugging a tenant's worker with `gdb`.

### `CFML-NET-002` — Raw / packet socket from web-class user

**Hook** `socket_create` · **Enforce** capable · **Gate** user socket; `AF_PACKET`, or `AF_INET`/`AF_INET6` + `SOCK_RAW`; watched real uid; euid ≠ 0

**Catches** a scanner, sniffer or spoofing tool dropped by a compromised
vhost user. The filename field is `proto=NN`.

**FP sources.** Unprivileged ping (`SOCK_DGRAM`) never matches, and
legacy setuid-root `ping` is skipped by the euid 0 check. A
file-capability `ping` / `traceroute` / `mtr` (`cap_net_raw+ep`, common
on Debian / Ubuntu / EL9+) runs at the user's euid and **does** match.
No allowlist applies. Keep the rule in monitor and triage those, or open
`net.ipv4.ping_group_range` so iputils uses `SOCK_DGRAM`. Enforce only
where vhost users do not run cap_net_raw binaries.

## Event enrichment — making an alert actionable

The ringbuf event (`internal/lsm/events.go`, 124 bytes) carries
pid / tgid / uid / gid, the 16-byte `comm`, a 64-byte policy-specific
`filename`, flags, and `ppid` / `aux_pid` / `aux_uid`. `comm` is
spoofable and the process is often gone by the time someone reads the
alert, so the daemon reads the caller's `/proc` within milliseconds of
the event (`emitNotify` → `gatherEnrichment` in `procsnap.go`). All of
it is best-effort and bounded, and controlled from `[events]` in
`lsm.conf`; every knob defaults on, and an older `lsm.conf` inherits the
defaults.

| Knob | Default | Adds |
|---|---|---|
| `detect_rate_per_min` | 30 | Per-policy cap on log + notify emissions; drops are summarised (`lsm_detect_summary`). The decision is made before any `/proc` work. |
| `enrich` | on | Caller snapshot: user, real `exe` (with `(deleted)`), `cwd`, `cmdline`, ppid with parent comm / exe, `loginuid`. For an exited caller the parent comes from the in-kernel `ppid`, so the launcher survives (best-effort if the parent's pid was recycled). |
| `enrich_hash` | on | SHA-256 of the exe bytes via `/proc/<pid>/exe` (works for an unlinked binary). |
| `enrich_peers` | on | Every process with the caller's real uid (pid, comm, real exe): the swarm a compromised account runs under spoofed comms. Skipped for uid 0. |
| `enrich_capture` | on | Copies a suspicious exe (unlinked, or on `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`; not `/home`) to `capture_dir` (default `/var/lib/cfm/lsm/capture`) as `<sha256>.bin`, `0600`, deduplicated, capped per event and by a file count. Covers the caller and suspicious peers. |

**Where it lands.** The full per-event line goes to
`/var/log/cfm/lsm.log` (`LSM_LOG_FILE` in `cfm.conf`). Notify events are
`kind=lsm_detect`, `section=lsm`. For `CFML-OBS-004` only, the notify
reason is caller-identity-stable (title, uid, comm, exe / short sha, no
pid or target), so the deduper collapses a `/proc` sweep into one mail
(`collapsesToCallerIdentity` in `lifecycle.go`). Other policies keep
the per-event reason. `[kmsg]` (`state_transitions`, `detect_events`,
`detect_rate_per_min`, default 10) writes ALIVE / ADOPT / STATE / ISSUE
and DETECT lines to the kernel log, visible in `dmesg` and
`journalctl -k`.

**Injection-safe.** Exe paths, cwd, comm and peer paths are
attacker-controlled and may contain newlines; composed lines go through
`stripCtl` so a crafted path cannot forge a log line or break the mail.

**Cost.** Snapshots are cached per pid (keyed with start time, so a
recycled pid is never served stale data), rosters per uid, captures per
exe path. Hashing and capture read at most 32 MiB synchronously on the
drain goroutine.

**Wire-format guardrails.** The Go parser accepts the 112-byte base and
reads the tail when present, so it can drain a ringbuf pinned by an
older build until the version marker forces a re-pin.
`TestBPFEventStructMatchesWireSize` checks the C struct size against
`wireEventSize`; `TestBPFEmitSitesInitializeTail` checks that every
reserve site calls `cfm_event_fill_kin()`. CI does not run the BPF
verifier, so after deploying a build that changed BPF code, confirm it
loads with `cfm lsm status`: a verifier rejection fails the whole object.

**Not a security boundary.** Enrichment is forensics. `comm` and argv
can be faked; the `exe` inode, its SHA-256 and the captured image
cannot, which is why they are the high-value fields.

## Out of scope (with rationale)

These are standing decisions, not TODOs. A policy beyond the catalogue
needs its own named proposal.

- **`CFML-EXEC-002` (Trusted Path Execution).** Composer, npm, pip,
  yarn, wp-cli, drush and cPanel's installer exec from user-writable
  directories; the allowlist would be a permanent treadmill. The
  realistic vector (PHP execs a dropped binary) is covered by Imunify PD,
  CageFS, kernsec's `noexec` mount audit and now EXEC-006.
- **`CFML-OBS-001` (ptrace lockdown).** kernsec ships
  `kernel.yama.ptrace_scope=2` (`KSEC-SCT-kspp.kernel-006`, Tier 1). A
  sysctl does this without a new hook. OBS-004 is the telemetry beside
  it.
- **`CFML-NET-001` (outbound per vhost).** `internal/outbound/` already
  observes outbound traffic per uid over NFLOG with thresholds and
  forensics, and works without DKMS. Promoting that path is the right
  home, not a parallel BPF implementation.
- **`CFML-FS-001` (SSH backdoor injection), `CFML-FS-002` (cron
  persistence).** A compromised PHP worker on CloudLinux is inside
  CageFS and cannot reach other users' `~/.ssh` or cron. The host-level
  part (`/root/.ssh`, cron dirs) is covered by FS-005's persistence
  paths.
- **`CFML-FS-003` (web-root suspicious file creation).** Correlating a
  `.php` drop with a suspicious POST is HTTP-layer logic for
  `webdetector`; an LSM hook would only emit. Revisited as a design
  proposal, not shipped: [`lsm-php-drop-detection.md`](./lsm-php-drop-detection.md)
  (`CFML-FS-009`), with the hook only emitting and the daemon scanning,
  attributing and deciding.
- **`CFML-CRED-001` (capability watch).** LVE and CageFS constrain the
  per-user capability surface; the root-credential cash-in is CRED-002 /
  CRED-003, and capability hoarding without a uid change is CRED-004.
- **`CFML-RATE-001`, `CFML-RATE-002` (segfault / fork rate).** LVE owns
  per-user resource limits on CloudLinux; carrying rate-limit machinery
  for two host classes is not worth it.
- **`CFML-SELF-001` (CFM self-protection).** A `fanotify` watch on the
  CFM binary and config tree gives the same signal more cheaply than an
  LSM hook.
- **`CFML-SELF-002` (module-load lockdown).** Conflicts with KernelCare
  and Ksplice live-patch module loads, a core part of the target stack;
  the whitelist of live-patch module names would be brittle. EXEC-007
  observes module loads without blocking them.

## Architecture

`cfm-lsm` is an in-binary subsystem, like `internal/outbound/` and
`internal/kernsec/`: no separate daemon, no log file another process
tails.

### Build model — no CGO, no clang on the install target

- BPF C lives in `internal/lsm/bpf/` (`cfmlsm.bpf.c`, `common.bpf.h`,
  committed CO-RE `vmlinux.h`).
- `bpf2go` (`bpf_generate.go`, run by `make bpf`) compiles it with clang
  into `cfmlsm_{x86,arm64}_bpfel.{go,o}`, which are committed.
- `cilium/ebpf` is pure Go and talks to the kernel through `bpf(2)`, so
  `CGO_ENABLED=0` holds. At runtime it CO-RE-relocates the embedded
  object for the running kernel. No clang or kernel headers on the host.
- `make build` runs `verify-bpf-bindings`; `make release` regenerates
  the objects. Do not bypass either: stale bytecode ships otherwise.
- Contributors who change BPF C need clang and libbpf-dev (plus
  `bpftool` for debugging). Everyone else needs nothing extra.

### In-tree layout

```
internal/lsm/
├── bpf/cfmlsm.bpf.c, common.bpf.h, vmlinux.h
├── cfmlsm_{x86,arm64}_bpfel.{go,o}   # bpf2go output
├── policy.go        # PolicyID constants, AllPolicies(), isEnforceCapable
├── conf.go          # lsm.conf parser + FormatConf writer, compiled-in allowlists
├── loader.go        # NewLoader / AdoptPinned / UnpinAll, programsFor, pin names
├── btfprobe.go      # per-kernel program variant picks (BTF drift)
├── perflink_probe.go# tracepoint policies vs kernels without perf links
├── maps.go          # watched uids / inodes, setuid inodes, kernel knobs
├── enable.go        # `cfm lsm enable`
├── lifecycle.go     # daemon auto-enable / adopt, drain, notify
├── events.go        # wire format parser
├── filter.go        # userspace allowlist post-filter
├── procsnap.go      # /proc enrichment and capture
├── eventsink.go     # rate cap + log/notify emission
├── kmsg.go          # /dev/kmsg lines
├── preflight.go, probe.go, status.go, preview.go, cli.go, init.go
└── version_marker.go
```

End-to-end PoC scenarios for every policy live in `tests/lsm-poc/`
(test hosts only; see its README).

### Runtime — single daemon, single unit, single config

The subsystem runs inside `cfm.service`. The ringbuf reader is a
goroutine; events go to the LSM log, the notify pipeline and kmsg. One
config file, `/etc/cfm/lsm.conf`.

### Privileges

Loading needs `CAP_BPF` + `CAP_PERFMON`, or `CAP_SYS_ADMIN`. The daemon
runs as root. If it ever drops privileges, the clean split is a one-shot
loader helper that attaches and exits, not a second long-running daemon.

### Config

`/etc/cfm/lsm.conf`, INI-style like `kernsec.conf`. Keys
(`ParseConf` in `conf.go`; unknown keys are parse errors):

| Section | Keys |
|---|---|
| top level | `enabled`, `watched_uid_fallback_min`, `exclude_user`, `exclude_uid`, `exclude_gid` (the three exclude keys repeat) |
| `[policy "<ID>"]` | `mode` (`disabled` / `monitor` / `enforce`); `allow_exe`, `allow_comm` where accepted; FS-005 only: `origin_tracking`, `persistence_path` |
| `[allow]` | `allow_exe`, `allow_comm`, `allow_path` |
| `[kmsg]` | `state_transitions`, `detect_events`, `detect_rate_per_min` |
| `[events]` | `detect_rate_per_min`, `enrich`, `enrich_hash`, `enrich_peers`, `enrich_capture`, `capture_dir` |

`FormatConf` renders the per-mode comment from `isEnforceCapable`. The
file is `0600 root` because it shows which policies are active.

### Watched-uid model

`CFML-FS-005`, `CFML-FS-007`, `CFML-EXEC-004`, `CFML-EXEC-006`,
`CFML-NET-002`, `CFML-OBS-004` and `CFML-CRED-004` gate on
`cfm_watched_uids`; `CFML-BPF-001`, `CFML-EXEC-007` and `CFML-EXEC-008`
use it to override their trusted-comm lists. The set is built at
adoption from three additive layers (`maps.go`):

1. **Static names**, always applied: `apache`, `nginx`, `www-data`,
   `http`, `httpd`, `lighttpd`, `caddy`, `tomcat`, `php`, `lsphp`,
   `proxy`, `nobody`, plus the `alt-php-` / `alt-php-fpm-` prefixes.
2. **Panel manifests**, best-effort: owners in `/etc/userdomains`
   (cPanel) and `/etc/virtual/domainowners` (DirectAdmin).
3. **`watched_uid_fallback_min`**: every `/etc/passwd` uid at or above
   it. Default `1000` (the `UID_MIN` convention), which includes admin
   accounts; `0` disables the layer. `-1` (the removed "auto" mode) is a
   deprecated alias for `1000` with a one-time warning. Auto was removed
   because an admin account created before the panel was missing from
   the manifest and silently went unwatched.

Then the excludes apply, to every layer:

```ini
watched_uid_fallback_min = 1000
exclude_user = chris        # resolved at adoption; missing names skip
exclude_uid  = 1001
exclude_gid  = 10           # /etc/passwd PRIMARY gid only
```

A uid is excluded if any list matches. `exclude_user = apache`, or an
`exclude_gid` that catches apache's primary group, drops apache too.
`exclude_gid` does not read supplementary groups in `/etc/group`. Check
the result with
`bpftool map dump pinned /sys/fs/bpf/cfm/maps/cfm_watched_uids` after
`cfm lsm restart`. The model fails closed: new accounts are watched
until explicitly excluded.

## How it works — lifecycle, CLI, and kernel preflight

Detection (BPF programs on kernel hooks) is separate from collection
(the daemon draining the ringbuf). Block decisions happen in the kernel
whether or not userspace is alive.

### Default state — off

With no `lsm.conf`, or `enabled = false`, nothing attaches. With
`enabled = true` the daemon auto-enables on start and on each
config-reload tick when no pins exist. Only `cfm lsm disable` detaches.

### Kernel preflight

`RunPreflight` (`preflight.go`) runs seven component-wide checks.
`cfm lsm status` shows each with PASS / FAIL / UNKNOWN and a remediation
hint; `status --check` exits non-zero on a FAIL.

1. **`kernel-version`** — informational only. RHEL-family vendor kernels
   backport BPF LSM to 4.18, so a version compare is the wrong test.
2. **`kernel-config`** — `CONFIG_BPF_LSM=y` from `/proc/config.gz` or
   `/boot/config-$(uname -r)`. Necessary, not sufficient.
3. **`bpf-in-lsm-list`** — `bpf` in `/sys/kernel/security/lsm`. EL
   kernels include it by default; Debian / Ubuntu usually need it added
   to `lsm=` (the remediation prints the line for the detected
   bootloader; kernsec `KSEC-LSM-bpf-001` can do it).
4. **`btf-available`** — `/sys/kernel/btf/vmlinux` (CO-RE).
5. **`capabilities`** — `CAP_SYS_ADMIN`, or `CAP_BPF` + `CAP_PERFMON`.
6. **`bpffs-mounted`** — `/sys/fs/bpf` is type `bpf`. The only FAIL the
   daemon treats as transient.
7. **`bpf-lsm-program-type`** — the authoritative gate: a tiny
   `BPF_PROG_TYPE_LSM` load. Some CloudLinux 8 lve kernels set
   `CONFIG_BPF_LSM=y` but reject the program type here.

The remediation text names the accepting targets: AlmaLinux 8.6+ / 9+ /
10, CloudLinux 9+, RHEL 9+, Debian 12+, Ubuntu 22.04+.

**Per-policy availability** is reported separately and never fails the
component; the rest attaches:

- **`CFML-CRED-002`, `CFML-CRED-003`** — need task-local storage maps
  (`BPF_MAP_TYPE_TASK_STORAGE`, upstream 5.11). Without them the loader
  swaps both task-storage maps for placeholders
  (`selectTaskStorageVariant`), drops these two policies and turns off
  FS-005 origin tracking; FS-005's inode hooks still attach.
- **`CFML-CRED-003`** — `commit_creds` must be a usable tracing target.
- **`CFML-EXEC-008`** — the kexec syscall tracepoints must exist.
- **`CFML-BPF-001`, `CFML-EXEC-007`, `CFML-EXEC-008`** — need BPF
  perf-event links (upstream 5.15; EL9's 5.14 backports them). Without
  them the tracepoint attachment cannot be pinned, so these three are
  reported unavailable (`perflink_probe.go`). This is the state of the
  CloudLinux 8 lve 4.18 fleet hosts, which run the remaining policies.

An inconclusive probe (for example EPERM without caps) counts as
available; the loader makes the final call.

After a failed fresh activation (preflight FAIL, load or attach error)
the daemon backs off 1 minute, doubling to 30 minutes, instead of
retrying every tick. Adopting pins created by `cfm lsm enable` is never
gated.

### CLI surface

`RunCLI` in `internal/lsm/cli.go`:

| Command | Behaviour |
|---|---|
| `cfm lsm` | Alias for `status`. |
| `cfm lsm status [--json] [--check]` | Preflight, `lsm.conf` state and live pinned state. Read-only. |
| `cfm lsm preview` | What `enable` would attach for this conf and kernel. Read-only. |
| `cfm lsm probe [-v]` | Attach briefly and detach, to verify the kernel accepts the programs. `-v` shows the BTF drift-variant picks. Needs root. |
| `cfm lsm enable [--yes]` | Load, attach and pin under `/sys/fs/bpf/cfm/`. Prompts when any policy is `enforce`; `--yes` skips the prompt. Needs root. |
| `cfm lsm disable` | Remove every pin; the kernel detaches the programs. Needs root. |
| `cfm lsm restart [--yes]` | Disable (no-op if not enabled), then enable. Picks up mode, allowlist, `[events]` and `[kmsg]` changes. Needs root. |
| `cfm lsm init` | Preflight, enable, status. Requires `/etc/cfm/lsm.conf`. Skips enable when already pinned. |
| `cfm lsm help` | Usage. |

### Two-process model

Either process can create the pins:

**The CLI** (`cfm lsm enable` / `restart` / `init`) loads the object,
attaches each enabled policy's programs, pins programs, the ringbuf and
the daemon-populated maps under `/sys/fs/bpf/cfm/`, and exits. The bpffs
entries hold their own kernel references, so the programs stay attached
with no process holding an fd.

**The daemon** (`lifecycle.go`) checks on every config-reload tick that
`enabled = true`. If pins exist it adopts them (`AdoptPinned`), refreshes
the maps (new accounts, new setuid binaries), and starts the drain
goroutine that feeds the log, notify and kmsg. If none exist it runs
preflight and creates them itself. The build that pinned is recorded in
`/var/lib/cfm/lsm-build-version`; after a package upgrade the daemon
tears the old pins down and re-enables with the new BPF. Daemon shutdown
closes its fds; the pinned programs stay attached.

### What survives daemon downtime

| State | Detection / enforce | Event collection |
|---|---|---|
| daemon running | works | live |
| daemon stopped or crashed | **still works** | events wait in the ringbuf, dropped when full |
| `cfm lsm disable` | stopped | n/a |
| reboot | restored by the daemon's auto-enable | from then on |

Event emission is best-effort and never changes a verdict: if
`bpf_ringbuf_reserve()` fails, monitor mode still allows and enforce mode
still denies. The ringbuf is 256 KiB, about 1 900 events at 124 bytes
each plus the record header.

### Pin layout on disk

```
/sys/fs/bpf/cfm/
├── maps/
│   ├── cfm_events               # shared ringbuf
│   ├── cfm_watched_uids         # watched uids
│   ├── cfm_watched_inodes       # FS-005 / FS-006 (fs, inode) keys
│   ├── cfm_setuid_inodes        # CRED-002 setuid + allow_exe inodes
│   └── cfm_kernel_knob_inodes   # FS-008 knob inodes
└── links/                       # one per attached program; per policy:
    EXEC-001 cfm_memfd_exec     EXEC-003 cfm_revshell       EXEC-004 cfm_deleted_file_exec
    EXEC-005 cfm_interp_net_stdio                           EXEC-006 cfm_ephemeral_exec
    EXEC-007 cfm_exec007_{init,finit}                       EXEC-008 cfm_exec008_{kexec,kexec_file}
    FS-005   cfm_fs005_{setattr,create,unlink,link,rename,setxattr},
             cfm_fs005_mark_{exec,setuid,task_alloc}   (origin markers)
    FS-006   cfm_fs006          FS-007 cfm_fs007_{setattr,setxattr}           FS-008 cfm_fs008
    CRED-002 cfm_cred002        CRED-003 cfm_cred003        CRED-004 cfm_cred004
    BPF-001  cfm_bpf001         OBS-004  cfm_obs004         NET-002  cfm_net002
```

Pin names are the `pinFile*` constants in `loader.go`. Removing a link
file detaches that program once the last reference drops. Inspect with
`ls -la`, `bpftool prog show`, `bpftool link show`.

### Failure modes and what happens

| Condition | Behaviour |
|---|---|
| Any component-wide preflight FAIL | cfm-lsm does not load; the daemon runs normally and backs off before retrying. |
| Optional per-policy prerequisite missing | That policy is reported unavailable; the rest attach. |
| Verifier rejects a program | The whole object fails to load (`LoadAndAssign`), so no policy attaches. Check `cfm lsm status` after deploying changed BPF. |
| One policy's attach fails | That policy is marked failed; the others continue. |
| Ringbuf full | The kernel drops the event; there is no counter. The verdict is unaffected. |
| Rate cap hit | Excess log / notify lines are dropped and summarised. |

The principle, shared with kernsec: never break the host. An
unsupported or misconfigured cfm-lsm is a no-op with a clear log line,
never a crashed daemon.

## Coexistence

**Imunify360 Proactive Defense.** PD hooks the Zend VM and sees PHP
calls only. cfm-lsm sits one layer below. PD blocks the call that
launches a reverse shell or writes a payload; cfm-lsm sees the process
or exec if PD missed it or was not loaded into that SAPI.

**CageFS / LVE.** EXEC-001 / 003 and CRED-002 / 003 are orthogonal to
CageFS. FS-005 complements it: a caged user reaching a watched path means
caging was bypassed. LVE limits are untouched.

**KernelCare / Ksplice.** cfm-lsm does not constrain module loading
(EXEC-007 only reports), so live patching keeps working.

**Stacked LSMs.** Each LSM can deny and all must permit. SELinux /
AppArmor denials happen before cfm-lsm and are honoured (`ret != 0`
returns early). Yama runs before BPF on hosts where kernsec merged
`bpf` into `lsm=` (see OBS-004). Lockdown is recommended at `integrity`
but not required. Tomoyo and Smack are untested.

## Adding a new policy

One PR, shaped like the existing ones:

1. `PolicyID` constant and `AllPolicies()` entry in `policy.go`
   (`DefaultMode: ModeDisabled`). If it cannot enforce, add it to
   `isEnforceCapable`.
2. `CFM_LSM_POLICY_*` value in `bpf/common.bpf.h` and the matching
   mapping in `events.go` (`TestPolicyByID_BPFConstantsMatchGoConstants`).
   Values are stable; operators see them in logs.
3. The program in `cfmlsm.bpf.c`. Reuse the ringbuf, `cfm_event_fill_kin`
   and the existing maps before adding new ones.
4. Wire it in `loader.go` (`programsFor`, `pinLinkFiles`, a `pinFile*`
   constant). A tracepoint program also goes in `tracepointPolicies`
   (`perflink_probe.go`).
5. `make bpf`; both per-arch `cfmlsm_*_bpfel.{go,o}` must change.
6. A stanza in `configs/lsm.conf`. The `FormatConf` round-trip tests
   iterate `AllPolicies()`.
7. If the hook may be missing on some kernels, report it as a
   per-policy availability in preflight, not a component FAIL.
8. A PoC scenario in `tests/lsm-poc/scenarios/`.
9. Budget a tuning pass: new LSM rules ship noisy (CLAUDE.md §6).

`probe`, `enable`, `disable` and the daemon's adopt path iterate
`AllPolicies()` and need no further change.

## Open questions

- **cgroup → vhost attribution under CloudLinux LVE.** LVE entities are
  not stock cgroups v2. No shipped policy is vhost-keyed; this matters
  only for a future policy that needs per-vhost attribution.

## References

- [`kernsec.md`](./kernsec.md) — kernel-surface reduction (sibling
  component).
- [`lsm-php-drop-detection.md`](./lsm-php-drop-detection.md) — the
  `CFML-FS-009` proposal (PHP file written under a docroot).
- [`roadmaps/php-runtime-defense.md`](./roadmaps/php-runtime-defense.md)
  — the PHP-VM layer above this one (CFM-managed Snuffleupagus).
- `internal/outbound/` — owner of outbound network policy.
- `tests/lsm-poc/` — PoC harness.
- Kernel: `Documentation/bpf/prog_lsm.rst`.
