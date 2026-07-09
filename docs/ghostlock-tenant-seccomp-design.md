# Tenant futex-PI seccomp filter — design guide (GhostLock / CVE-2026-43499)

> **Status: DESIGN ONLY — not implemented, and deliberately NOT for
> panel hosts.** There is no code behind this note. It documents the one
> runtime control that could actually *prevent* (not just degrade or
> detect) the public GhostLock local-root exploit, why it cannot be a
> BPF-LSM rule, and how a future `cfm`-managed **per-tenant seccomp
> filter** would look on the hosts CFM could own it for: **bare metal /
> empty VM / custom installs** with a clear "web-tier uid range".
>
> On **cPanel / DirectAdmin / CloudLinux** this belongs to the tenant
> confinement layer already in the stack (CageFS / LVE), not to CFM —
> see [Scope](#scope-where-this-applies-and-where-it-must-not) below.
> The two shipping defence-in-depth levers for those hosts are
> `kernsec`'s `randomize_kstack_offset=on` boot arg and `cfm-lsm`'s
> `CFML-FS-008` — this note does not replace them.

## TL;DR

GhostLock (CVE-2026-43499, plus its follow-up CVE-2026-53166) is a
use-after-free on the kernel's **futex priority-inheritance** path
(`kernel/locking/rtmutex.c`). The vendor advisory is correct that there
is **no fix short of the patched kernel / KernelCare livepatch** — the
UAF itself has no runtime switch (`CONFIG_FUTEX_PI` is build-time, no
sysctl, no module).

But "no mitigation for the bug" is not the same as "no control anywhere
on the exploit chain." Walking the public PoC stage by stage, exactly
**one** point is both **mandatory** and **before kernel compromise**: the
futex-PI system call that triggers the UAF. And the only in-kernel
mechanism that can gate a syscall by its *operation argument* is
**seccomp** — **not** BPF LSM, because the kernel exposes **no LSM hook
on `futex()`**.

A seccomp filter that blocks the PI futex operations closes the trigger.
Host-wide that breaks legitimate priority-inheritance mutexes (the
advisory rightly dismisses it). But CFM's threat model is a **compromised
web-tier process** (PHP-FPM worker, low-trust shell account) — a
population that essentially never uses PI mutexes. Scoped to just that
uid range, the filter becomes defensible: it denies PI futex ops **only
inside the tenant sandbox**, where nothing legitimate needs them.

## Why this is the only "prevent" point

To *prevent* root (rather than degrade reliability or detect after the
fact) a control must break the chain where it is **(a) mandatory** and
**(b) before the attacker holds a kernel arbitrary write + control-flow
hijack**. After that point the attacker owns ring 0 and any userspace
LSM/seccomp check is either bypassable or moot.

Public GhostLock chain (from the Nebula Security write-up), with the
CFM control surface at each stage:

| Stage | Kernel action | Can a CFM control break it, mandatorily + pre-compromise? |
|---|---|---|
| prefetch KASLR leak | userspace timing side-channel | No — no syscall to gate. |
| **futex-PI trigger (the bug)** | `futex(FUTEX_LOCK_PI / WAIT_REQUEUE_PI / CMP_REQUEUE_PI)` | **Yes — seccomp only** (this note). |
| stack reclaim | `prctl(PR_SET_MM_MAP)` — *or* `clone`/`setsockopt`/`pselect`/`keyctl` | No — the write-up says other syscalls "work the same way"; whack-a-mole. |
| rb-tree write → `inet6_protos` | in-kernel memory write | No — pure kernel memory, no hook. |
| CEA / ROP → CFH | in-kernel | No. |
| IPv6 loopback trigger | `connect`+`write` to `::1` | Would need `socket_sendmsg`; breaks normal traffic and another trigger is available. |
| DirtyMode / `core_pattern` | userspace `write()` | `cfm-lsm` FS-008 catches it — but **post-compromise and bypassable** (see below). |

Two consequences fall out of the table:

- **`randomize_kstack_offset=on` is pre-compromise but probabilistic.**
  It attacks the *reclaim* stage: with kstack randomization on, the
  freed waiter frame and the later `user_auxv` frame no longer overlap
  deterministically, so the step becomes a ~1/32 (5-bit) guess and most
  misses **panic the box**. That turns a stealthy 5-second root into a
  noisy lottery — a real deterrent, and it practically kills a drive-by
  that cannot survive the reboot — but a targeted retry loop still wins
  eventually. Degrades reliability; not a wall. (Shipped: `kernsec`
  Tier-1 `KSEC-BOOT-kspp-004`, `Affects: "Nothing."`.)

- **FS-008 is mandatory-looking but post-compromise, hence bypassable.**
  Its `file_permission` hook fires on the userspace `write()` that the
  PoC uses to install `|/proc/%P/fd/666 %P` into `core_pattern`, so in
  enforce mode it breaks the *unmodified* public exploit and is a loud
  tripwire. But by then the attacker already holds a kernel arbitrary
  write; they can complete instead by overwriting the current task's
  `cred` struct **directly in kernel memory** (no syscall, no
  `file_permission` hook, invisible to FS-008), or write the same knob
  via the kernel primitive rather than the VFS. Excellent detection and
  a real speed-bump for the stock PoC; not prevention.

The futex-PI trigger is the only row that is both mandatory and strictly
*before* the write primitive exists.

## Why not a BPF-LSM rule

`cfm-lsm` is a BPF **LSM**. LSM programs attach to kernel LSM hook
points, and **there is no LSM hook on the futex path** — `kernel/futex/`
calls into `kernel/locking/rtmutex.c` without any `security_*` callout.
So no BPF-LSM program (monitor *or* enforce) can see or deny a futex
operation.

A **tracepoint** on `sys_enter_futex` *can* observe PI ops from watched
uids, but tracepoints cannot block — the kernel ignores the BPF return
value — and reacting from userspace (kill the process on the ring-buffer
event) is a race against a ~5-second exploit whose UAF has already
happened. That is detection, not prevention.

The only in-kernel gate that can deny a syscall **by its op argument**
before it executes is **seccomp** (which sees `futex_op` as `args[1]`, a
scalar — filterable, unlike pointer args). CFM has **no seccomp
mechanism today** (`grep -rn seccomp internal/` is empty); this would be
a new capability, not a new `lsm.conf` line.

## The filter

Block the futex **PI acquire / requeue-PI** operations. These are the
ones that can establish or roll back a PI waiter, i.e. reach the
vulnerable `remove_waiter()` path:

| Op | Value | Block? | Note |
|---|---|---|---|
| `FUTEX_LOCK_PI` | 6 | yes | PI mutex acquire. |
| `FUTEX_UNLOCK_PI` | 7 | optional | Moot once acquire is denied; include for completeness. |
| `FUTEX_TRYLOCK_PI` | 8 | yes | Non-blocking PI acquire. |
| `FUTEX_WAIT_REQUEUE_PI` | 11 | yes | Requeue-to-PI wait — on the trigger path. |
| `FUTEX_CMP_REQUEUE_PI` | 12 | yes | Requeue-to-PI — on the trigger path. |
| `FUTEX_LOCK_PI2` | 13 | yes | Newer clock-selectable PI acquire (kernels that have it). |

The op is carried in the low bits of `args[1]`; the flags
`FUTEX_PRIVATE_FLAG` (0x80) and `FUTEX_CLOCK_REALTIME` (0x100) are OR-ed
on top, so match against `args[1] & FUTEX_CMD_MASK` where
`FUTEX_CMD_MASK = ~(0x80 | 0x100)`. Only the classic `futex(2)` syscall
matters — `futex_waitv(2)` has no PI operations, so it needs no rule.

libseccomp sketch (one rule per op; `no_new_privs` must be set first so
an unprivileged process may install it):

```c
/* FUTEX_CMD_MASK = ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME) */
#define FUTEX_CMD_MASK  (~(0x80U | 0x100U))

prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

scmp_filter_ctx c = seccomp_init(SCMP_ACT_ALLOW);   /* default: allow */
const int pi_ops[] = { 6 /*LOCK_PI*/, 8 /*TRYLOCK_PI*/,
                       11 /*WAIT_REQUEUE_PI*/, 12 /*CMP_REQUEUE_PI*/,
                       13 /*LOCK_PI2*/ };
for (size_t i = 0; i < sizeof(pi_ops)/sizeof(*pi_ops); i++)
    seccomp_rule_add(c, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(futex), 1,
                     SCMP_A1(SCMP_CMP_MASKED_EQ, FUTEX_CMD_MASK, pi_ops[i]));
seccomp_load(c);
```

**Fail mode.** `SCMP_ACT_ERRNO(EPERM)` denies cleanly and is
audit-legible. `ENOSYS` is an alternative (some libraries fall back to a
non-PI mutex on "unsupported"), but glibc's `PTHREAD_PRIO_INHERIT` mutex
does not fall back — either way a genuine PI-mutex user *fails*, which is
exactly why scoping matters. Do **not** use `SECCOMP_RET_KILL_*`: a
single stray PI call would kill the tenant.

**Burn-in mode (CFM-idiomatic monitor→enforce).** Ship first with
`SECCOMP_RET_LOG` instead of `ERRNO`: the kernel logs every matching call
(`auditctl`/`dmesg`) and *allows* it, so an operator can discover any
real PI-mutex user in the tenant range before flipping to `ERRNO`. This
mirrors `cfm-lsm`'s `monitor` → `enforce` rollout and `FS-008`'s 30-day
window.

## Scope: where this applies, and where it must NOT

**Applies (the CFM angle):** bare metal / empty VM / custom installs with
a definable web-tier uid range and **no CageFS/LVE**. There, CFM could
legitimately own tenant confinement and this filter has a clear home.

**Does NOT apply — cPanel / DirectAdmin / CloudLinux.** On those hosts
the tenant sandbox is **CageFS / LVE**, and `docs/cfm-lsm.md` records the
standing decision to *not* reimplement protections the confinement layer
already owns (duplicating it caused conflicts — e.g. KernelCare/Ksplice
module reloads vs a proposed module-load lockdown). A futex-PI seccomp
profile is precisely a tenant-confinement control, so on CloudLinux it
belongs to CloudLinux (who can also ship it faster and fleet-wide via
CageFS). CFM on those hosts stays with `randomize_kstack_offset` +
`FS-008` and defers the trigger-level block to the panel/OS vendor.

**uid scoping.** Reuse the model `cfm-lsm` already has: `cfm_watched_uids`
plus `watched_uid_fallback_min` (default 1000, matching
`/etc/login.defs UID_MIN`) is the existing source of truth for
"web-class" (`internal/lsm/conf.go`). The seccomp profile should target
exactly that set so system daemons (uid < 1000) that might legitimately
use PI mutexes are never touched.

## Enforcement / attach point (the hard part)

Deciding the filter is easy; **installing** it is the real work, and it
is why this is a subsystem and not a config line.

- **systemd `SystemCallFilter=` cannot do this.** It filters by syscall
  *name* only, not by argument — blocking `futex` wholesale breaks every
  mutex on the machine. Op-level filtering **requires a raw
  argument-aware seccomp filter** (libseccomp or cBPF).
- **exec-time wrapper (most robust for tenants).** A tiny helper that
  sets `no_new_privs`, installs the filter, then `execve()`s the tenant
  shell / PHP-FPM master. seccomp filters are **inherited across `fork`
  and `execve`**, so filtering a PHP-FPM pool master covers every worker
  it forks. Wire it as the login shell / service `ExecStart` prefix for
  the tenant range.
- **PAM module** at `session open` for interactive/shell tenants
  (a `pam_seccomp`-style hook), for uid ≥ the web-tier floor.
- **Future `cfm` seccomp injector** — the clean long-term home: `cfm`
  renders the profile from `watched_uids` and installs it at the tenant
  exec boundary, with the same monitor/enforce knob the rest of CFM uses.
- **Not** `LD_PRELOAD` — a constructor-installed filter is trivially
  bypassable (`LD_PRELOAD=` unset, static binary) and unfit for a
  security boundary.

## Limits — read before assuming this "solves" GhostLock

- **It does not close the UAF.** It denies the *trigger* to a scoped set
  of processes. The vulnerability is still in the kernel; the patched
  kernel / livepatch remains the only actual fix. This is a stopgap for
  the exposure window and for hosts that cannot reboot immediately.
- **Only covers the tenant uid range.** A compromised system service
  running as its own uid **below** the web-tier floor still has clean
  futex-PI. This narrows, not eliminates, local-root exposure.
- **Breaks any tenant that genuinely uses PI mutexes** (some JVM
  configs, native Node addons, audio/RT workloads co-located on the
  web-tier uids). That is why the burn-in `SECCOMP_RET_LOG` phase is
  mandatory before `ERRNO`, and why it is opt-in per host.
- **Still the advisory's "test before deploying" class**, just scoped to
  the sandbox instead of host-wide.
- **Layer it, don't rely on it alone.** Pair with
  `randomize_kstack_offset=on` (degrades the reclaim step for everyone,
  including sub-1000 uids the filter misses) and `FS-008` monitor/enforce
  (tripwire on the completion stage).

## Verification (when/if implemented)

1. **Blocks the trigger:** run the public PoC as a web-tier uid with the
   filter loaded; the PI futex call returns `EPERM` and the chain never
   reaches the reclaim stage. Confirm the same PoC as a sub-1000 uid is
   unaffected (documents the scope limit honestly).
2. **No tenant breakage:** during the `SECCOMP_RET_LOG` burn-in, audit
   for any web-tier process hitting a PI op. Zero hits across a
   representative window → safe to promote to `ERRNO`. Any hits →
   investigate that workload before enforcing.
3. **Inheritance:** verify a PHP-FPM worker forked from a filtered master
   is itself filtered (`grep Seccomp /proc/<worker>/status`).

## References

- Nebula Security, "IonStack part II: GhostLock" (public write-up + PoC).
- CVE-2026-43499 (primary) and CVE-2026-53166 (follow-up fix) — both
  required.
- Upstream fix: commit `3bfdc63936dd` + `74e144274af3`
  (`kernel/locking/rtmutex.c`, `remove_waiter()` passes the owning task
  instead of reading `waiter->task`).
- Shipping CFM levers referenced here: `docs/kernsec.md`
  (`randomize_kstack_offset`), `docs/cfm-lsm.md` (`CFML-FS-008`,
  `cfm_watched_uids`).
