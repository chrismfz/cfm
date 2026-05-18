# CFM kernsec — Kernel Attack Surface Reduction

## Overview

kernsec is cfm's preemptive kernel attack-surface reduction layer. Rather than
waiting for a CVE to drop and chasing a patched kernel through the fleet,
kernsec disables surface that has no business being reachable on a hosting box
in the first place: dead network protocols, recently-exploited modules with no
use case, userspace crypto APIs nobody calls, side-channel power telemetry,
and filesystems no server mounts. The component combines four mechanisms —
sysctls, boot arguments, module blacklists, and a drift monitor — with a
tiered config model and host-profile gating so the same ruleset behaves
correctly on cPanel, DirectAdmin, Proxmox, KVM hypervisors,
KernelCare-patched kernels, and ZFS storage hosts.

`cfm kernsec` audits and, when requested, applies these reductions across
sysctls, kernel boot arguments, kernel module blacklists, and periodic drift
monitoring.

The component currently manages:

- `/etc/sysctl.d/99-cfm-kernsec.conf` for kernsec-owned sysctls.
- Kernel boot arguments for the detected bootloader backend.
- `/etc/modprobe.d/cfm-kernsec.conf` for module blacklists.
- `cfm-kernsec-check.timer` / `.service` for periodic drift checks.

`/etc/fstab` is **report-only**. kernsec audits mount options and tells the
operator what is missing, but it never edits fstab because `noexec` and related
options can break real hosting workflows.

## KSPP script relationship

`scripts/kspp.sh` remains in the tree as a standalone hardening script and
reference. For cfm-managed hosts, use `cfm kernsec`.

kernsec covers the KSPP sysctls, boot arguments, bootloader backends, status
checks, and Copy Fail mitigation from the standalone script, plus additional
cfm-managed features such as the rule registry, config model, module blacklist
writer, fstab audit, and monitor timer.

## Relationship to upstream killswitch

Upstream Linux is gaining a `killswitch` primitive
(`Documentation/admin-guide/killswitch.rst`) that lets a privileged operator
make a chosen kernel function short-circuit and return a fixed value — a
temporary "stop calling the buggy code" lever for when a CVE drops but a
patched kernel isn't yet built or rebooted into. The canonical targets named
in the patch series are AF_ALG, ksmbd, nf_tables, vsock, and ax25.

kernsec attacks the same problem from the opposite end: it disables the
surface *before* a CVE drops, so the same code paths are unreachable without
needing a runtime mitigation. For the modules named as killswitch candidates,
kernsec already ships rules:

- **ksmbd** → blacklisted (`modules.recent_cves`).
- **vsock** → blacklisted on bare-metal hosts, skipped on KVM hypervisors so
  `vhost_vsock` stays available for guest↔host comms (`modules.net.virt`,
  host-profile gated on `IsKVMHost`).
- **ax25** → blacklisted (`modules.net.legacy`).
- **AF_ALG** → boot-time `initcall_blacklist=algif_aead_init` plus
  modprobe-blacklisted `algif_hash` / `algif_skcipher` / `algif_rng` /
  `algif_akcipher` / `algif_aead` (`modules.crypto_userapi`).
- **nf_tables** → deliberately NOT disabled. cfm's firewall is nftables-based,
  and disabling the core would brick the firewall itself. This is the one
  killswitch candidate where the trade-off inverts on a cfm host: the cost of
  "firewall stops working for the day" is higher than running a known-vulnerable
  nft path until the fix lands. Operators wanting belt-and-braces coverage can
  engage upstream killswitch on the specific buggy `nft_*` function once the
  interface ships.

The two approaches are complementary. When upstream killswitch is widely
available, cfm can drive it as a fast-rollout lever for the rare module or
function we *can't* preemptively blacklist (nftables core, NFS client,
`io_uring` on NVMe hosts).

## Commands

`cfm kernsec` with no subcommand opens the interactive TUI on a TTY and falls
back to text output when stdout is not a terminal.

### CLI surface as shipped

| Command | Purpose | Mutation behavior |
|---|---|---|
| `cfm kernsec` | TUI on a TTY; text audit otherwise. | Read-only. |
| `cfm kernsec live` | Force the interactive TUI. Aliases: `tui`, `ui`. | Read-only. |
| `cfm kernsec text` | Plain-text audit output. | Read-only. |
| `cfm kernsec status --check` | Run the text audit in check mode for automation. | Read-only; check modes do not write. |
| `cfm kernsec status --json` | Emit machine-readable status output. | Read-only. |
| `cfm kernsec preview --tier <0|1|2> --group <prefix> --id <ids> --skip <ids> --force-id <ids> --only-apply` | Show what `apply` would select after config, tier, host-profile gates, and per-rule overrides. | Read-only; preview never writes. |
| `cfm kernsec init` | Write default `/etc/cfm/kernsec.conf` with `tier = 1` if absent. | Mutates only when creating the missing config. |
| `cfm kernsec apply --dry-run --check --no-refresh --yes` | Render managed sysctl/modprobe state, update boot args, refresh the bootloader unless `--no-refresh`, then apply runtime sysctls per key. `--check` is the drift-check mode used by the monitor timer. | Mutates when not `--dry-run` or `--check`; dry-run and check modes do not write. |
| `cfm kernsec disable --purge --dry-run --no-refresh --force` | Persist `tier = 0`, strip kernsec-managed boot args, empty managed sysctl/modprobe output, and optionally purge managed files/units. | Mutates when not `--dry-run`; dry-run does not write. |
| `cfm kernsec rollback --dry-run` | Remove kernsec-managed boot args, restore saved managed values when a managed snapshot exists, and refresh the bootloader. | Mutates when not `--dry-run`; dry-run does not write. |
| `cfm kernsec monitor enable --interval <OnCalendar> --cfm-binary <path> --dry-run` | Write and enable the periodic systemd drift-check timer using the requested schedule and cfm binary path. | Mutates when not `--dry-run`; dry-run does not write. |
| `cfm kernsec monitor disable` | Stop and disable the timer while leaving unit files in place. | Mutates systemd timer state. |
| `cfm kernsec monitor remove` | Stop and disable the timer, remove managed unit files, and reload systemd. | Mutates installed monitor state. |
| `cfm kernsec monitor status` | Show timer status and recent service runs. | Read-only. |

Status, preview, check, and dry-run modes are non-mutating: `status`,
`preview`, `status --check`, `apply --check`, and every `--dry-run` invocation
do not write files, change boot arguments, refresh bootloaders, apply runtime
sysctls, or alter systemd state. `apply`, `disable`, `rollback`,
`monitor enable`, and `monitor remove` mutate managed host state when run without
their dry-run/check guard.

Check-mode exit codes:

| Exit code | Meaning |
|---|---|
| `0` | Clean: no drift or audit warnings were found. |
| `1` | Drift or warnings were found. |
| `2` | Indeterminate result for `apply --check`. The monitor service treats this as a soft success. |

## Config

The config file is `/etc/cfm/kernsec.conf`. It is root-only (`0600`) and uses a
small sectioned format:

```ini
# /etc/cfm/kernsec.conf
tier = 1

[rule "KSEC-MOD-net.legacy-014"]
state = skip

[rule "KSEC-SCT-tier2.namespace-001"]
state = force
```

Top-level `tier` controls the highest tier selected by default:

- `tier = 0` — audit-only / disabled; apply writes no selected rules.
- `tier = 1` — default safe-everywhere hardening profile.
- `tier = 2` — opt-in server-aggressive profile layered on top of Tier 1.

Per-rule `state` values:

- `default` — follow tier and host-profile decisions.
- `skip` — do not apply this rule even when tier/profile would select it.
- `force` — apply this rule even when a host-profile gate would skip it.

`state = force` can also override cross-component sysctl ownership. When a
sysctl key is normally owned by another cfm component, forcing a kernsec rule can
create an ownership conflict; `apply` reports the conflict instead of silently
hiding it.

## Files managed

| Path | Managed by | Notes |
|---|---|---|
| `/etc/cfm/kernsec.conf` | `init`, `disable`, operator edits | Primary kernsec config. |
| `/etc/sysctl.d/99-cfm-kernsec.conf` | `apply`, `disable`, `--purge` | kernsec-owned sysctl drop-in. `apply` renders this file, then parses the rendered key/value lines for runtime application. The drop-in persists settings for boot-time loading by the system sysctl service. Unsupported kernel keys are emitted as commented skipped lines. |
| `/etc/modprobe.d/cfm-kernsec.conf` | `apply`, `disable`, `--purge` | Emits both `blacklist <module>` and `install <module> /bin/false`. |
| `/etc/default/grub` | GRUB backend | Only `GRUB_CMDLINE_LINUX` is written; `_DEFAULT` is read for audit/drift but not written. |
| `/etc/kernel/cmdline` | Proxmox/systemd-boot backend | Updated and followed by `proxmox-boot-tool refresh`. |
| BLS entries via `grubby` | BLS backend | Updated with `grubby --update-kernel`; rescue/debug kernels are excluded. |
| `/etc/systemd/system/cfm-kernsec-check.service` | `monitor enable/remove` | Runs `cfm kernsec apply --check`. |
| `/etc/systemd/system/cfm-kernsec-check.timer` | `monitor enable/remove` | Periodic drift-check timer. |
| `/run/lock/cfm-kernsec.lock` | mutating commands | Advisory lock to prevent concurrent kernsec writers. |

Runtime sysctl apply:

- `cfm kernsec apply` first renders `/etc/sysctl.d/99-cfm-kernsec.conf`; the rendered drop-in remains the persistent source of truth for boot.
- After file writes and bootloader refresh succeed, `apply` parses the rendered drop-in and applies each active key at runtime with `sysctl -w key=value`.
- Runtime sysctl failures are continue-on-error: later keys are still attempted, and failures are accumulated into one report with `/etc/sysctl.d/99-cfm-kernsec.conf:<line>`, key, value, and kernel error context.
- Commented skipped lines and malformed/non-key lines are not applied at runtime.

## Cross-component sysctl ownership

`internal/managedsysctl` owns the cfm-wide sysctl ownership registry. The
registry records which cfm component is authoritative for each managed key; it
is ownership metadata, not a promise that every component uses one shared
render/apply pipeline.

Current behavior:

- `cfm-sysctl-tweaks` publishes its owned keys by registering its catalog with
  `internal/managedsysctl`.
- kernsec consults that registry during rule resolution. If another cfm
  component owns a key, kernsec marks the row as `EXT`, audits the live value,
  and reports whether it matches the kernsec recommendation.
- `EXT` rows are audit-only for kernsec: kernsec does not render them into
  `/etc/sysctl.d/99-cfm-kernsec.conf` and does not apply them at runtime with
  `sysctl -w`.
- `state = force` is the explicit operator override. A forced kernsec rule can
  take over a key that the registry says is owned by another component, and
  `apply` reports that ownership conflict rather than hiding it.

The `cfm-sysctl-tweaks` apply-path migration is not part of kernsec behavior.
kernsec's sysctl path renders and applies the kernsec-owned drop-in described
above; `cfm-sysctl-tweaks` keeps its own apply path unless its code is changed
separately.

Backups and rollback snapshots:

- Managed sysctl and modprobe files use one-shot `.cfm-kernsec.bak` backups
  before the first edit.
- If operator-edited lines are detected in a managed sysctl or modprobe file,
  kernsec preserves an additional timestamped backup and warns.
- GRUB and Proxmox backends store managed-argument snapshots under
  `/var/lib/cfm/`. Legacy `.cfm-kernsec.bak` bootloader-file backups are used
  only as fallback data for older rollback records.
- When legacy byte-restore fallback is considered, kernsec refuses to restore
  the entire saved file if the current bootloader file contains operator
  changes since the legacy backup was made.
- The BLS backend builds its pre-apply snapshot from `grubby --info=ALL`
  and stores it at `/var/lib/cfm/kernsec-bls-cmdline.cfm-kernsec.bak`.
  The snapshot contains only kernsec-managed boot arguments, keyed by kernel
  image path; unmanaged args are intentionally not captured.
- `disable --purge` removes the config, managed sysctl file, managed modprobe
  file, and installed monitor units, but intentionally leaves backups in place.

## Rule tiers

| Tier | Meaning | Operator expectation |
|---|---|---|
| 0 | Disabled/audit-only | No rule is selected for apply; status still audits. |
| 1 | Default hardening | Intended to be safe across typical hosting, KVM, cPanel, EL, and Debian hosts. |
| 2 | Server-aggressive | Opt-in; can affect availability, diagnostics, containers, seccomp-heavy workloads, or hosting panels. Host-profile gates skip known-risk hosts unless forced. |

Rule status states shown by status/TUI include applied/OK, warning/mismatch,
skipped by tier, skipped by config, skipped by host profile, missing kernel
support, and externally managed (`EXT`) for sysctls owned by another cfm
component.

## Rule catalog

Rule IDs are stable and use `KSEC-<class>-<group>-<NNN>`:

- `KSEC-SCT-*` — sysctl rules.
- `KSEC-BOOT-*` — kernel boot-argument rules.
- `KSEC-MOD-*` — module blacklist rules.
- `KSEC-FS-*` — fstab/mount audit rules.

### Sysctl rules applied by kernsec

| Group | Tier | Rules / settings | Operator impact |
|---|---:|---|---|
| `kspp.kernel` | 1 | `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=2` (accepts `=1`), `kernel.randomize_va_space=2`, `kernel.perf_event_paranoid=3` (accepts `=2` for mainline-vanilla kernels and `=4` for hardened forks), `kernel.yama.ptrace_scope=2`, `vm.mmap_min_addr=65536` (accepts `=131072` / `=262144`) | Restricts unprivileged kernel visibility, BPF, perf, and ptrace. Profiling/debug attach generally needs root. Mode 2 of `ptrace_scope` closes the same-uid `pidfd_getfd()` exit-window race against setuid helpers (ssh-keysign / chage `/etc/shadow` disclosure chain — Linus commit `31e62c2ebbfd`); `=1` was previously accepted as also-green but is no longer, because the residual race is a working exploit primitive. Hosts that need same-uid debuggability without sudo must `state = skip` `KSEC-SCT-kspp.kernel-006` in `kernsec.conf`. `vm.mmap_min_addr=65536` blocks NULL-deref-to-userspace exploit primitives and is the default on modern distros. |
| `kspp.fs` | 1 | `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`, `fs.protected_fifos=2`, `fs.protected_regular=2` | Protects sticky/world-writable directories; normally no production impact. |
| `kspp.net` | 1 | `net.core.bpf_jit_harden=2` | Minor BPF JIT performance cost. |
| `sysctl.mem.exploit` | 1 | `vm.unprivileged_userfaultfd=0`, `vm.mmap_rnd_bits=32`, `vm.mmap_rnd_compat_bits=16`, `kernel.warn_limit=10`, `kernel.oops_limit=10`, `fs.suid_dumpable=0` | Removes common LPE primitives; unusual debugging/checkpointing may need overrides. Unsupported keys are skipped. |
| `tier2.oops` | 2 | `kernel.panic_on_oops=1`, `kernel.panic=10` | Any kernel oops can become a reboot; opt-in only. |
| `sysctl.kernel.surface` | 1 | `dev.tty.ldisc_autoload=0`, `kernel.sysrq=0` | Disables automatic TTY line-discipline loading and Magic SysRq. |
| `sysctl.kernel.coredump` | 2 | `kernel.core_pattern=|/bin/false` | Suppresses userspace core dumps globally; skipped for hosting panels, backup agents, and crash-diagnostic monitoring. kdump is independent (kexec/vmcore) and does not gate this rule. |
| `sysctl.kernel.kexec` | 1 | `kernel.kexec_load_disabled=1` | Locks out the `kexec_load(2)` / `kexec_file_load(2)` syscalls so a compromised process cannot load a replacement kernel post-boot — a long-standing rootkit-persistence vector. Once written non-zero the knob is sticky until reboot (kernel-enforced). **Not** a KernelCare / Ksplice conflict (both live-patch via kernel modules, not kexec) and **not** a standard-kernel-update conflict (`yum`/`dnf` use bootloader entries). The one real conflict is kdump, which preloads a crash kernel via the same syscall; auto-skipped on hosts where `/proc/cmdline` carries `crashkernel=` or `kdump.service` is installed (HasKdump host-profile gate). |
| `tier2.namespace` | 2 | `user.max_user_namespaces=0`, `kernel.unprivileged_userns_clone=0` | Breaks rootless containers, bubblewrap, Chromium sandbox, and some hosting isolation; skipped when containers/hosting panels are detected. |
| `sysctl.net.harden` | 1 | `net.ipv4.icmp_echo_ignore_broadcasts=1`, `net.ipv4.conf.all.accept_source_route=0`, `net.ipv4.conf.default.accept_source_route=0`, `net.ipv4.conf.all.log_martians=1`, `net.ipv4.tcp_rfc1337=1` | Static-IP servers should be unaffected. |

### Sysctl rules audited as externally managed

`sysctl.net` rules are audited by kernsec but normally owned by
`cfm-sysctl-tweaks` through the `internal/managedsysctl` ownership
registry. They render as `EXT`; kernsec audits their live values but does not
write persistent or runtime values for them unless the operator explicitly uses
`state = force` on a rule.

Audited keys are `net.ipv4.conf.all.rp_filter=1`,
`net.ipv4.conf.all.accept_redirects=0`,
`net.ipv4.conf.all.send_redirects=0`, `net.ipv4.tcp_syncookies=1`, and
`net.ipv6.conf.all.accept_redirects=0`.

### Boot-argument rules

| Group | Tier | Args | Operator impact |
|---|---:|---|---|
| `kspp.boot` | 1 | `slab_nomerge`, `init_on_alloc=1`, `page_alloc.shuffle=1`, `randomize_kstack_offset=on`, `initcall_blacklist=algif_aead_init` | Memory-safety hardening. `init_on_alloc=1` can have modest alloc-heavy overhead. The `initcall_blacklist` entry is a temporary Copy Fail / CVE-2026-31431 mitigation affecting AEAD AF_ALG use. |
| `boot.bug-detection` | 1 | `kfence.sample_interval=100` | Enables low-overhead KFENCE sampling. |
| `boot.dma` | 1 | `efi=disable_early_pci_dma` | EFI-only pre-IOMMU DMA hardening; skipped on non-EFI hosts. |
| `boot.sidechannel` | 1 | `tsx=off` | Disables Intel TSX side-channel surface; no expected hosting impact. |
| `boot.bpf` | 1 | `unprivileged_bpf_disabled=2` | Pairs with the `kernel.unprivileged_bpf_disabled=2` sysctl. On kernels built with `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y` (RHEL/Alma 9-10, recent stable) the sysctl is locked at boot — only this boot arg can land the value at 2. |
| `tier2.oops` | 2 | `oops=panic` | Pairs with Tier 2 panic-on-oops sysctls; can reboot on kernel oops. |
| `tier3.mempaint` | 3 | `init_on_free=1` | Stacks with Tier 1 `init_on_alloc=1` to fully eliminate UAF-read primitives (the afflicted.sh writeup names `INIT_ON_FREE=off` as the kernel gap that keeps UAF-read viable). Combined perf ceiling ~3-8% in the worst case; brick-safe. Operator opt-in only — `conf.Tier = 3`. |

kernsec only owns the managed boot-argument keys listed above. It strips stale
instances of those keys before appending the desired managed set and preserves
operator-provided arguments outside the managed set. A per-rule `state = force`
entry only affects rule IDs that are still present in the kernsec catalog; it
does not resurrect removed IDs or make kernsec own boot/sysctl/module keys that
are no longer registered here.

### Module blacklist rules

`apply` writes one `blacklist` line and one `install <module> /bin/false` line
per selected rule. This prevents both alias-based autoloading and direct
`modprobe` loads.

After the modprobe drop-in is written, `apply` also runs a **default-on
unload pass**: for every managed module currently in `/proc/modules` it
invokes `modprobe -r <name>` and prints a per-row status table:

```
[Modules] unload pass (modprobe -r) over N managed-and-loaded module(s):
            UNLOADED   esp4
            UNLOADED   esp6
            BUSY       rxrpc            in use by another holder — will clear at reboot
            BUILTIN    sctp             compiled into the kernel — modprobe.d blacklist has no effect; needs kernel rebuild or cmdline change
[Modules] 2 unloaded, 1 busy (will clear at reboot), 1 builtin (kernel rebuild required). Blacklist on disk persists across reboot.
          Reboot at convenience to clear any busy modules and sync the initramfs.
```

This closes the running-kernel window (Fragnesia / Dirty Frag class) the
same minute apply runs, while the blacklist on disk guarantees the
module stays gone across the next boot. Host-profile-gated rules
(`modules.ipsec` on a host with active IPsec policies, `modules.bus.*`
on a host with matching hardware, etc.) are filtered out of the apply
set upstream, so the unload pass never touches a module that the
profile says is in legitimate use. `BUSY` modules are reported and
otherwise ignored — apply does not fail on refcount-busy unloads, since
the blacklist on disk prevents them coming back and reboot finishes the
job.

Operators who need the older "write config, unload manually" behaviour
can pass `--no-unload` to `cfm kernsec apply` or `cfm kernsec disable`.
Initramfs rebuild is not run automatically: for the modules shipped
today none are loaded by the initramfs phase, so `/etc/modprobe.d/`
alone is sufficient. Operators who want a tidy `lsinitrd | grep
cfm-kernsec.conf` can run `dracut --force` (RHEL family) or
`update-initramfs -u` (Debian family) by hand after apply.

The TUI's per-rule / per-group disable action calls the same apply
path, so the unload pass also runs there. The bottom-bar flash
includes a one-line summary (e.g. "applied 7 change(s) — 5 unloaded, 2
busy (will clear at reboot)") so the operator sees the running-kernel
status without dropping back to the shell.

| Group | Tier | Modules | Notes |
|---|---:|---|---|
| `modules.recent_cves` | 1 | `n_hdlc`, `vivid`, `watch_queue`, `binfmt_aout`, `nfc`, `nfcsim`, `pn533`, `pn533_usb`, `kcm`, `n_gsm`, `n_r3964` | Recently exploited or no normal server use. |
| `modules.recent_cves.ksmbd` | 1 | `ksmbd` | Kernel SMB server with multiple LPE CVEs 2023-2025. Auto-skipped on hosts running ksmbd deliberately (host-profile gated on `HasKSMBDServer`: module loaded, `/sys/class/ksmbd` populated, or ksmbd-tools / `/etc/ksmbd` installed). |
| `modules.net.legacy` | 1 | Legacy protocols such as `dccp`, `ax25`, `netrom`, `x25`, `rose`, `decnet`, `econet`, `ipx`, `appletalk`, LLC/SNAP variants, `phonet`, `caif`, `caif_socket`, `hsr`, `smc`, `smc_diag`, `slip`, `slhc`, and similar dead network stacks | Intended to be safe on normal hosting servers. Override per-rule if the host actually uses SMC / PPP. |
| `modules.net.legacy.sctp` | 1 | `sctp`, `sctp_diag` | Telecom signalling (SS7 / Diameter / M3UA), K8s Services with `protocol: SCTP`, and lksctp-tools-based monitoring. Auto-skipped on hosts with any SCTP workload evidence (host-profile gated on `HasSCTPWorkload`: sctp module loaded, `/proc/net/sctp` present, `sctp_darn` / Nagios `check_sctp` / `*sctp*.service` installed). WebRTC's usrsctp runs in userspace and is **not** a gate signal. |
| `modules.net.legacy.tipc` | 1 | `tipc` | Cluster IPC; legitimate users are Pacemaker / Corosync HA clusters and Erlang/OTP distribution. Auto-skipped on hosts with TIPC workload evidence (host-profile gated on `HasTIPCWorkload`: tipc loaded, `/proc/net/tipc`, tipc tooling, or any `*tipc*.service`). |
| `modules.net.legacy.rxrpc` | 1 | `rxrpc` | AFS RPC transport; entry point for CVE-2026-31635 (DirtyDecrypt). Auto-skipped on hosts running AFS clients (host-profile gated on `HasAFS`: rxrpc / kafs / openafs loaded, `/afs` mounted, or OpenAFS tooling). |
| `modules.net.legacy.l2tp` | 1 | `l2tp_core`, `l2tp_ip`, `l2tp_ip6`, `l2tp_eth`, `l2tp_netlink`, `l2tp_ppp` | L2TP VPN kernel data path. Auto-skipped on hosts terminating L2TP (host-profile gated on `HasL2TPWorkload`: l2tp_* loaded, `/proc/net/l2tp*`, or xl2tpd / kl2tpd / accel-ppp installed). |
| `modules.net.legacy.pptp` | 1 | `pptp` | PPTP VPN protocol. Auto-skipped on hosts terminating PPTP (host-profile gated on `HasPPTPWorkload`: pptp loaded, `/etc/pptpd.conf`, or pptpd / accel-ppp installed). |
| `modules.net.legacy.rds` | 1 | `rds` | Oracle RAC interconnect transport. Auto-skipped on hosts running Oracle Database (host-profile gated on `HasRDSWorkload`: rds loaded, `/proc/net/rds*`, or Oracle indicators — `oratab`, `lsnrctl`, `/u01/app/oracle`). |
| `modules.ipsec` | 1 | `esp4`, `esp6`, `ah4`, `ah6`, `ipcomp`, `ipcomp6`, `xfrm_interface`, `af_key` | Kernel XFRM/ESP transforms, the routing-based XFRM virtual interface, and the PF_KEYv2 keying socket family. Mitigates the XFRM/ESP LPE class (CVE-2026-46300 "Fragnesia" and the related "Dirty Frag") and pre-empts future bugs in adjacent transforms. Skipped on hosts with active IPsec policies (host-profile gated on `HasIPsec`). |
| `modules.net.virt` | 1 | `vsock` | Skipped on KVM hypervisors (host-profile gated on `IsKVMHost`) so `vhost_vsock` remains available for guest↔host comms. |
| `modules.net.iot` | 1 | `ieee802154`, `mac802154`, `6lowpan` | IEEE 802.15.4 / low-power wireless PAN stack — no 802.15.4 radios on hosting boxes. |
| `modules.fs.unused` | 1 | `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `qnx4`, `qnx6`, `omfs`, `befs`, `ufs`, `affs`, `sysv`, `nilfs2`, `gfs2`, `ocfs2`, `coda`, `reiserfs`, `adfs`, `hpfs`, `minix`, `bfs` | Auto-skipped on hosts where any of these filesystems is currently mounted (`/proc/mounts`) or declared in `/etc/fstab` (host-profile gated on `HasMountedDeadFS`). The skip reason names the matching FS so the audit row identifies the trigger. |
| `modules.fs.container` | 1 | `erofs` | Skipped on hosts running containers (host-profile gated on `HasContainers`) since some container image layers use it. |
| `modules.bus.bluetooth` | 1 | `bluetooth`, `btusb`, `bnep`, `hci_uart` | Host-profile gated when Bluetooth hardware is detected. |
| `modules.bus.firewire` | 1 | `firewire-core`, `firewire-ohci`, `firewire-net`, `firewire-sbp2` | Auto-skipped on hosts with FireWire hardware (host-profile gated on `HasFirewireHardware`: `/sys/bus/firewire/devices` non-empty). |
| `modules.bus.thunderbolt` | 1 | `thunderbolt` | Skipped when Thunderbolt devices are detected. |
| `modules.bus.misc` | 1 | `joydev`, `pcspkr`, `floppy` | No typical server use. |
| `modules.mctp` | 1 | `mctp`, `mctp-i2c`, `mctp-serial` | In-band MCTP (OpenBMC / NVMe-MI / PCIe VDM sideband). Classic Supermicro IPMI and Dell iDRAC ride their own NIC and do not use this stack. Skipped automatically when in-band MCTP endpoints are registered (host-profile gated on `HasMCTPInBand`), so OpenBMC platforms like the Supermicro H13SRD-F MicroCloud keep the sideband intact. |
| `modules.input.userspace` | 1 | `uinput`, `uhid` | Userspace virtual input / HID devices — no use case on servers, non-trivial historical exploit surface. |
| `modules.sidechannel` | 1 | `intel_rapl_common`, `intel_rapl_msr` | Removes RAPL power telemetry to avoid power side-channel surface. |
| `modules.crypto_userapi` | 1 | `algif_hash`, `algif_skcipher`, `algif_rng`, `algif_akcipher`, `algif_aead` | Extends the AF_ALG hardening; `algif_aead` is also covered at boot via `initcall_blacklist=algif_aead_init`. |

NFS, CIFS/SMB clients, `io_uring`, and wifi modules are intentionally not
blacklisted by the shipped registry. These have legitimate operator-managed use
cases on some hosts.

IPsec/XFRM modules (`esp4`, `esp6`, `ah4`, `ah6`, `ipcomp`, `ipcomp6`,
`xfrm_interface`) are shipped in `modules.ipsec` and blacklisted by
default in response to the XFRM/ESP LPE class (CVE-2026-46300
"Fragnesia" and the related "Dirty Frag"). The AH and IPcomp transforms
ride the same XFRM data path as ESP and would be reachable by future
bugs in the same layer; `xfrm_interface` adds net-new XFRM surface with
no hosting use outside IPsec. The whole group is auto-skipped on hosts
where the IPsec host-profile gate fires (`/proc/net/xfrm_policy` or
`/proc/net/pfkey` non-empty), so hosts that actually terminate or
transit IPsec tunnels keep the kernel data path.

### fstab / mount audit rules

These rules are **audit-only**. kernsec reports missing mount options but never
edits `/etc/fstab`.

| Rule ID | Group | Mount point | Recommendation | Notes |
|---|---|---|---|---|
| `KSEC-FS-mount.tmp-001` | `fs.mount.tmp` | `/tmp` | `nodev,nosuid,noexec` | Review before enabling; `noexec` can break composer, pip, and hosting-panel workflows. |
| `KSEC-FS-mount.tmp-002` | `fs.mount.tmp` | `/var/tmp` | `nodev,nosuid,noexec` | Same compatibility considerations as `/tmp`. |
| `KSEC-FS-mount.tmp-003` | `fs.mount.tmp` | `/dev/shm` | `nodev,nosuid,noexec` | Usually safe, but review JVM/Python multiprocessing workloads. |
| `KSEC-FS-mount.proc-001` | `fs.mount.proc` | `/proc` | `hidepid=2` (recipe also sets `gid=<group>`) | Hides other users' `/proc/<pid>` entries from non-root readers — single largest reconnaissance-channel reduction on shared hosting. Strictly audit-only (`CanEnable=false`); operator opts in manually after creating the escape group. The audit checks the `hidepid` token only — the operator-chosen `gid=<group>` resolves to a numeric gid in `/proc/mounts` and is not literally matchable, so kernsec validates the security invariant (hidepid is on) and trusts the recipe for the gid= escape valve. Kernel renderings `hidepid=invisible` (>=5.8), `hidepid=4`, and `hidepid=ptraceable` all satisfy the recommendation. See below for the full recipe. |

`/home` was previously audited for `nodev,nosuid`. It was removed because operator setups vary too widely (panels with setuid helpers under `/home`, NFS-exported homes, CageFS layouts) for a one-size recommendation to produce more signal than noise.

The mount audit renders one of: `OK` (every recommended option live), `PARTIAL` (some live, some missing — the remediation hint names only the missing options), `MISSING` (mount exists but no recommended options live), or `SKIP` (path is not a separate mount, is a symlink to another audited mount point, or is a bind sibling of another audited mount point). For PARTIAL and MISSING rows the audit prints the exact `mount -o remount,…` command and the matching `/etc/fstab` or systemd `.mount` change.

For `/tmp` and `/var/tmp` the audit is strictly informational — kernsec never mutates fstab for them via the regular `apply` path. Live MySQL temp tables, the `/var/tmp`-survives-reboot contract, and the dedicated-filesystem provisioning step (loop file vs tmpfs) make those changes too operator-specific for the unattended apply flow. Operators who want to harden them can run `cfm kernsec secure-tmp --size <N>G` as a separate explicit step — see the dedicated section below.

#### `/proc hidepid=2,gid=<group>` — operator-applied process-table hiding

The `KSEC-FS-mount.proc-001` rule is strictly **audit-only**: kernsec does not auto-edit `/etc/fstab` for `/proc` even at conf.Tier 2/3, because the third-party-monitoring blast radius is uncatalogueable in advance (every site has some `ps`-scraping agent we haven't profiled). The rule's value is the recommendation surfaced in `cfm kernsec status` — operators apply it manually after setting up the escape group.

Why it matters on shared hosting: without `hidepid`, every vhost user can `ps aux` and read other tenants' `/proc/<pid>/cmdline`, `/proc/<pid>/status`, `/proc/<pid>/environ`, `/proc/<pid>/fd`, and `/proc/<pid>/maps`. That leaks sshd command-lines, `mysql -p<password>` arguments, the contents of process address space layouts (KASLR-leak primitive), open file descriptors, and admin sessions. `hidepid=2` makes every `/proc/<other-pid>` directory invisible to non-root non-group-member users; root sees everything regardless.

Recipe:

1. **Create the escape group.** Pick any free gid (the convention this doc uses is the symbolic name `cfmprocreaders`, but the gid number is what `/proc` mounts with):
   ```
   groupadd --system cfmprocreaders
   ```
2. **Add monitoring uids to the group** (the agents that legitimately scrape `/proc` as non-root). Common candidates: `netdata`, `munin`, `zabbix`, `nrpe`. Skip cPanel / DirectAdmin / CloudLinux daemons — they all run as root and don't need the group.
   ```
   usermod -aG cfmprocreaders netdata
   usermod -aG cfmprocreaders zabbix
   # restart the agents so the new supplementary group lands in their session
   systemctl restart netdata zabbix-agent
   ```
3. **Edit `/etc/fstab`** to mount `/proc` with the options. If a `proc` line already exists, append the options; otherwise add the line:
   ```
   proc   /proc   proc   defaults,hidepid=2,gid=cfmprocreaders   0 0
   ```
4. **Apply live without reboot:**
   ```
   mount -o remount,hidepid=2,gid=cfmprocreaders /proc
   ```
5. **Verify:** as a non-root non-group user, `ps aux` should show only their own processes; as root or as a group member, `ps aux` continues to show everything.

What stays correct after `hidepid=2`:

- cPanel / WHM "Process Manager" UI: runs as root, sees everything.
- DirectAdmin's `dataskq`, `directadmin` daemon, mail helpers: all root.
- cPanel-user-facing "Process Manager" inside the user's cPanel UI: only sees that user's own processes — that IS the intended hardening (previously, vhost A could enumerate vhost B's processes).
- CageFS-confined users: continue to see only their own; the cage's own `/proc` bind-mount is a separate namespace and is not affected by the host's `hidepid` setting.
- lve-stats / cl-smart-advice / Imunify360 / KernelCare: all run as root, unaffected.

What needs the escape group (or breaks if you forget):

- Munin's `proc_*` plugins, Netdata's `apps.plugin`, Zabbix-agent's per-process discovery, New Relic / Datadog process metrics — anything that reads `/proc/<pid>/status` for non-self pids as a non-root user.

#### `cfm kernsec secure-tmp` — operator-invoked /tmp + /var/tmp hardening

`cfm kernsec secure-tmp --size <N>G` carves `/tmp` and `/var/tmp` out into a dedicated hardened filesystem in one command. It is intentionally a separate verb (not part of `apply`) because activating the new mounts requires a reboot, and that's a decision the operator should make explicitly.

What it does:

1. **Pre-flights.** Refuses if `/tmp` or `/var/tmp` is already a separate mount, if `/etc/fstab` already has an entry for either path, if `/var/tmpDSK` already exists, if free space on `/var` is less than `<size> + 1G` headroom, or if `<size>` would consume more than 50% of available free space.
2. **Creates the backing file.** `fallocate -l <size> /var/tmpDSK` (mode `0600`), then `mkfs.ext4 -F -L cfm-securetmp /var/tmpDSK`.
3. **Stages `/var/tmp` contents.** Mounts the new filesystem at `/mnt/.cfm-newtmp`, `chmod 1777`, copies every top-level entry of `/var/tmp` into it (skipping `systemd-private-*` directories — those are recreated by systemd when each service restarts after boot). `/tmp` is intentionally *not* copied since `systemd-tmpfiles` wipes `/tmp` on every boot by design.
4. **Unmounts the scratch path** and removes the empty `/mnt/.cfm-newtmp` directory.
5. **Appends `/etc/fstab`** with a `BackupOnce` of the original to `/etc/fstab.cfm-kernsec.bak`:
   ```
   /var/tmpDSK  /tmp      ext4  loop,nodev,nosuid,noexec,rw  0 0
   /tmp         /var/tmp  none  bind                          0 0
   ```
6. **Stops.** The operator reboots when convenient. Activation is reboot-only; the subcommand never tries to `umount /tmp` on the running host.

Why reboot-only: every service with `PrivateTmp=yes` (`mysqld`, `named`, `nginx`, `php-fpm`, `exim`, `memcached`, `dbus-broker`, `chronyd`, `irqbalance`, `systemd-logind`, …) holds a kernel bind mount that pins the live `/tmp` inode. `umount /tmp` returns `EBUSY` until every one of those services is restarted, and remounting under them risks stale file descriptors for in-flight temp files. The reboot is the only clean way to clear both problems at once and pick up the new fstab entries.

`--dry-run` previews the plan (size, device path, fstab lines, staged entry count) without creating the loop file or editing fstab.

To revert a `secure-tmp` install:

1. `cp /etc/fstab.cfm-kernsec.bak /etc/fstab`
2. `umount /var/tmp /tmp` (or `systemctl reboot`)
3. `rm /var/tmpDSK`

`/dev/shm` is the narrow exception: `MountRule.CanEnable=true` lets `cfm kernsec apply` edit `/etc/fstab` and live-remount it. Auto-application is gated on tmpfs (no on-disk state to migrate), preserved options like `size=` and `mode=` are kept untouched, and an explicit `exec`/`suid`/`dev` set by the operator aborts with a clear error rather than being silently overwritten.

Disable for `/dev/shm` reverts only the options kernsec actually added on top of the distro baseline. Every modern distro mounts `/dev/shm` with `nosuid,nodev` already on (systemd PID 1's `mount-setup.c`), so the kernsec-effective addition is `noexec` alone — disable's runtime revert is `mount -o remount,exec /dev/shm`, never `dev,suid,exec` which would land the host below the distro baseline. The set of "already a default" options per rule lives in `MountRule.DefaultLiveOptions`. If kernsec authored the fstab line, the whole line is removed (so PID 1's built-in defaults take over on next boot); if the line is operator-owned, only the kernsec-effective additions are stripped and the operator's other options stay.

## Intentionally unsupported

`kernel.modules_disabled=1` is intentionally unsupported. It is a one-way
runtime switch until reboot and requires very careful late-boot orchestration so
cfm, the kernel, and host-specific services can finish loading required modules
before module loading is disabled globally.

NFS, CIFS/SMB clients, `io_uring`, and wifi modules are also intentionally not
blacklisted by the shipped registry. These have legitimate operator-managed use
cases on some hosts.

## Considered but not shipped

The following three knobs from the afflicted.sh "every kernel mitigation on
Resolute" writeup were prototyped, reviewed, and **held back** because the
auto-skip probes that gate them are not yet reliable enough to ship without
hurting more operators than they help. Each entry below records the rule, the
probe approach that was tried, and the specific issues that need to be solved
before re-landing.

### `kernel.io_uring_disabled=2` — Tier 2

Closes the io_uring substitute primitive named in the writeup (once
`unprivileged_bpf_disabled=2` blocks BPF maps, io_uring's SQE/CQE rings and
registered-buffer allocations otherwise replace them as a controllable
kernel-spray primitive). Sysctl added in kernel 6.6.

**Held back because:** the auto-skip probe walked `/proc/[0-9]*/fd/*` on every
`kernsec` invocation looking for `anon_inode:[io_uring]` symlinks. Correctness
is fine but the cost runs on every `status`, `apply`, `preview`, and TUI call
via `DetectHostProfile()`. On a busy host (10k+ pids) that is hundreds of
thousands of `readlink()` syscalls per invocation.

**Re-land when:** the host-profile probe layer supports lazy / on-demand probes
(only run the io_uring walk when `tier2.iouring` is actually being decided, not
on every CLI call), or `DetectHostProfile()` gains a result cache with mtime
invalidation.

### `vsyscall=none` — Tier 3

Disables the legacy fixed-address vsyscall page at `0xffffffffff600000` — a
small but historically-abused ROP target. The kernel default `vsyscall=xonly`
still mitigates the worst patterns; `=none` is the strict step.

**Held back because:** the legacy-binary probe (`legacyBinaryProbe` in the
prototype) opened up to 4000 ELFs in `/usr/bin` + `/usr/local/bin` per
`DetectHostProfile()` call and flagged every static binary as "potentially
legacy." That false-positives on every modern Go binary (`kubectl`, `docker`,
`runc`, `containerd`, `cfm` itself) because Go statics have no `PT_DYNAMIC`.
The follow-up plan to "only flag dynamic binaries with pre-2.14 glibc
references" is also unreliable: binaries reference *all* glibc symbol versions
they use, so even modern dynamic binaries carry `GLIBC_2.0` strings in their
`.dynstr`. The probe needs proper `Elf_Verneed` table walking to pick the
*highest* glibc version each library is bound at — that's the only signal that
actually correlates with vsyscall-page reliance. Additionally, on cPanel /
CloudLinux / CageFS hosts the binaries that would actually break live in
customer chroots (`/home/*/public_html`, CageFS images), not `/usr/bin` — the
probe missed those entirely.

**Re-land when:** the probe is rewritten to parse `Elf_Verneed` properly, the
scan paths are extended to cover hosting-panel chroots, and the per-invocation
cost is bounded (mtime pre-filter, lazy probe, or result cache).

### `debugfs=off` — Tier 3

Refuses to expose the `debugfs` filesystem at all — removes a broad
kernel-internal attack surface (debug-only hooks across drivers / subsystems
that have historically harboured info-leak and UAF bugs). `tracefs` at
`/sys/kernel/tracing` is a separate mount since kernel 4.1 and is not affected.

**Held back because:** the rule was added to `ManagedBootArgKeys` so kernsec
would strip stale instances on apply. That regresses the contract that
operator-set boot args outside the managed set are preserved — a host that
deliberately set `debugfs=` for diagnostics would have it silently stripped on
the next `kernsec apply`, even when Tier 3 wasn't enabled. The companion
`debugfsConsumerProbe` was correct but inherited the same
`DetectHostProfile()` per-invocation cost issue as the io_uring probe.

**Re-land when:** the apply path can strip a managed key only when its
governing rule is actually being applied (or the boot-arg writer gains a "this
rule is held by Tier N — don't touch the key unless tier >= N" flag), and the
probe is moved to the on-demand path described under io_uring above.

## Host-profile gates

Host-profile gates prevent high-risk rules from applying on hosts where they are
likely to break production workloads. `preview`, `status`, and the TUI show when
a rule is skipped by host profile. Operators can override with `state = force`
when they accept the risk.

The current host profile is a set of detected signals. kernsec treats these
signals conservatively: a positive signal skips the known-risk rule group, and
the operator can force a rule only after accepting the workload impact.

| Profile category | Detected signal | Host-profile effect |
|---|---|---|
| Containers | Container daemons, shims, runtime sockets, or systemd-nspawn machines (`runc`, `containerd`, `dockerd`, `crio`, `podman`, `kubelet`, LXC/LXD, Kata, gVisor, Docker/CRI-O/containerd/Podman sockets). | Skips Tier 2 namespace kill rules. |
| cPanel | `/usr/local/cpanel`. | Counts as hosting-panel workload; skips Tier 2 namespace kill rules and global coredump suppression. |
| DirectAdmin | `/usr/local/directadmin`. | Counts as hosting-panel workload; skips Tier 2 namespace kill rules and global coredump suppression. |
| CloudLinux/LVE | `/proc/lve` or loaded `lve`/`kmodlve` module. | Counts as hosting-panel workload and out-of-tree/vendor module evidence; skips Tier 2 namespace kill rules and global coredump suppression. |
| CageFS | `/etc/cagefs` or `cagefsctl`. | Counts as hosting-panel workload and CloudLinux-style workload evidence; skips Tier 2 namespace kill rules and global coredump suppression. |
| Imunify360 | Imunify360 agent, service, config, package, repository, or data paths. | Counts as hosting-panel/vendor workload; skips Tier 2 namespace kill rules and global coredump suppression. |
| KernelCare | `kcarectl`, KernelCare install/cache/sysconfig paths, or `kcare.service`. | Recorded as live-patching and out-of-tree module evidence. |
| Ksplice | `uptrack-upgrade`, Uptrack paths, or `uptrack.service`. | Recorded as live-patching and out-of-tree module evidence. |
| Live-patching modules | Loaded `kcare`, `kpatch`, `kgraft`, `uptrack`, `ksplice`, `livepatch*`, `kpatch_*`, or `ksplice_*` modules. | Recorded as live-patching module evidence. |
| DKMS/akmods/out-of-tree modules | Non-empty `/var/lib/dkms`, `akmods` binary, `/usr/src/*-dkms*`, or non-empty `/lib/modules/*/{extra,updates}`. | Recorded as out-of-tree module evidence. |
| ZFS/NVIDIA | Loaded ZFS/NVIDIA modules or ZFS tooling/paths (`/sys/module/zfs`, `/etc/zfs`, `zpool`). | Recorded as out-of-tree module evidence. |
| Proxmox | `/etc/pve`, Proxmox boot UUIDs, `proxmox-boot-tool`, or Proxmox EFI path. | Recorded as host context. |
| Backup workloads | Common backup agents or backup-named systemd services, including Veeam, Acronis, JetBackup, Bareos, Bacula, and UrBackup indicators. | Skips global coredump suppression to preserve vendor diagnostics. |
| Monitoring/crash-diagnostic workloads | Common monitoring or crash-diagnostic agents, including node_exporter, Zabbix, Datadog, Elastic Agent, Telegraf, ABRT, Apport, and systemd-coredump indicators. | Skips global coredump suppression. |
| IPsec | Non-empty `/proc/net/xfrm_policy` or `/proc/net/pfkey`. | Skips the `modules.ipsec` blacklist (`esp4`, `esp6`, `ah4`, `ah6`, `ipcomp`, `ipcomp6`, `xfrm_interface`, `af_key`) so the kernel XFRM data path stays available on hosts that actually use it. |
| Bluetooth | Non-empty `/sys/class/bluetooth`. | Skips Bluetooth bus module blacklists. |
| Thunderbolt | Non-empty `/sys/bus/thunderbolt/devices`. | Skips Thunderbolt module blacklist. |
| In-band MCTP | Non-empty `/sys/bus/mctp/devices` or `/sys/class/mctp`, or any netdev with `type=290` (ARPHRD_MCTP). | Skips `modules.mctp` (`mctp`, `mctp-i2c`, `mctp-serial`) so OpenBMC platforms (e.g. Supermicro H13SRD-F MicroCloud) and NVMe-MI / PCIe VDM sideband users keep the kernel mctp stack. Classic Supermicro IPMI and Dell iDRAC are out-of-band and not affected. |
| SCTP workload | `sctp` module loaded in `/proc/modules`, `/proc/net/sctp` present, `sctp.service` / `sctp_darn` binary / Nagios `check_sctp` plugin / any `*sctp*.service` unit installed. | Skips `modules.net.legacy.sctp` (`sctp`, `sctp_diag`) so telecom signalling, K8s `protocol: SCTP` Services, and lksctp-tools-based monitoring keep the kernel SCTP data path. WebRTC's usrsctp is userspace and is intentionally not a gate signal. |
| TIPC workload | `tipc` loaded, `/proc/net/tipc`, `tipc` / `tipc-config` tooling, or any `*tipc*.service`. | Skips `modules.net.legacy.tipc` so Pacemaker / Corosync HA clusters and Erlang/OTP distribution keep the kernel transport. |
| AFS | `rxrpc` / `kafs` / `openafs` loaded, `/proc/net/rxrpc`, `/afs` mount, or OpenAFS tooling (`/etc/openafs`, `fs`, `pts`, `vos`). | Skips `modules.net.legacy.rxrpc` so AFS clients keep working. |
| L2TP workload | `l2tp_*` loaded, `/proc/net/l2tp*`, `xl2tpd` / `kl2tpd` / accel-ppp installed. | Skips `modules.net.legacy.l2tp` so hosts terminating L2TP tunnels keep the kernel data path. |
| PPTP workload | `pptp` loaded, `/etc/pptpd.conf`, or pptpd / accel-ppp installed. | Skips `modules.net.legacy.pptp` so hosts terminating PPTP tunnels keep the kernel data path. |
| Oracle / RDS workload | `rds` loaded, `/proc/net/rds*`, or Oracle indicators (`/etc/oratab`, `lsnrctl`, `/u01/app/oracle`, `/opt/oracle`). | Skips `modules.net.legacy.rds` so Oracle RAC interconnect keeps working. |
| Dead-FS in use | Any module from `modules.fs.unused` listed in `/proc/mounts` or `/etc/fstab`. | Skips the entire `modules.fs.unused` group; the audit row names the matching FS. Same defensive flavour as the `llc` / Docker bridge gate. |
| FireWire | Non-empty `/sys/bus/firewire/devices`. | Skips `modules.bus.firewire` so bare-metal hosts with FireWire hardware keep the transport. |
| ksmbd in use | `ksmbd` loaded, `/sys/class/ksmbd` non-empty, `ksmbd.mountd` binary or `/etc/ksmbd` present, or `ksmbd.service` installed. | Skips `modules.recent_cves.ksmbd` so operators deliberately running the kernel SMB server keep it. |
| NFS | Active `nfs` or `nfs4` mounts in `/proc/mounts`. | Recorded as host context; shipped NFS modules are intentionally not blacklisted. |
| EFI boot | `/sys/firmware/efi`. | Allows EFI-specific DMA boot hardening; non-EFI hosts skip `efi=disable_early_pci_dma` as a no-op. |

Current risky Tier 2 skip reasons:

| Tier 2 group | Current skip reason |
|---|---|
| Namespace rules (`tier2.namespace`) | Skip hosting/container workloads because disabling unprivileged user namespaces breaks rootless containers, container sandboxes, cPanel jails, CloudLinux/CageFS isolation, and similar hosting isolation. |
| Panic-on-oops rules (`tier2.oops`) | Skip multi-tenant and uptime-priority hosts because `oops=panic` + `kernel.panic_on_oops=1` + `kernel.panic=10` turn any kernel oops into a reboot. Auto-skipped on KVM hypervisors, libvirt hosts, Proxmox, container runtimes, hosts with live-patching modules (KernelCare / Ksplice / kpatch / kgraft), and hosts running a hosting panel (cPanel / DirectAdmin / CloudLinux LVE / CageFS / Imunify360). |
| Coredump suppression (`sysctl.kernel.coredump`) | Skip hosting, backup, and monitoring diagnostics because `kernel.core_pattern=|/bin/false` suppresses userspace coredumps globally and can break vendor troubleshooting. kdump (kexec/vmcore) is independent of `core_pattern` and is not a gate reason. |

Mutating commands also run a pre-flight safety summary before risky applies.
Use `--yes` only for unattended runs where that preview has already been
reviewed operationally.

### Advisories — soft warnings on Apply decisions

In addition to the hard-skip `HostProfile.SkipReason` mechanism above,
kernsec surfaces soft advisories via `HostProfile.Advisories(id, group)`.
These do NOT change the rule's decision — the rule still applies — but
they print in `cfm kernsec preview` (`note:` lines) and in the TUI
detail pane (`Note:` lines) so the operator knows about workload-specific
side-effects.

Shipped advisories:

| Rule ID | Triggers when | Advisory |
|---|---|---|
| `KSEC-SCT-kspp.kernel-003` (`unprivileged_bpf_disabled=2`) | `HasDevTools` (gdb / strace / py-spy / bpftrace / bcc-tools / perf installed) | Developer tooling detected — it runs as root and remains functional; unprivileged eBPF and non-root `bpftool` are blocked. |
| `KSEC-SCT-kspp.kernel-006` (`yama.ptrace_scope=2`) | `HasDevTools` | Developer tooling detected — `gdb --attach`, `strace -p`, `py-spy`, `bpftrace -p` against your own processes will need sudo. |
| `KSEC-SCT-kspp.kexec-001` (`kexec_load_disabled=1`) | `HasLivePatchingModules` or `HasKernelCare` or `HasKsplice` | Live-patching active — `kexec_load_disabled` is compatible (live-patches don't use kexec) but doesn't add to live-patching's protection. |
| `KSEC-BOOT-tier3.mempaint-001` (`init_on_free=1`) | `HasZFS` or `HasNVIDIA` | ZFS / NVIDIA detected — `init_on_free` stacks ~1-3% alloc cost on those subsystems; benchmark before production. |

Advisories appear in the `cfm kernsec status --json` output under the
per-rule `advisories` field (omitted when empty).

## Bootloader backends

kernsec detects and uses one of these bootloader backends:

| Backend | Detection / write path | Refresh behavior |
|---|---|---|
| Proxmox/systemd-boot | `/etc/kernel/cmdline` with `proxmox-boot-tool` | Writes `/etc/kernel/cmdline`, then runs `proxmox-boot-tool refresh`. |
| BLS/grubby | `/boot/loader/entries` plus `grubby` | Enumerates entries with `grubby --info=ALL` and updates explicit non-rescue/non-debug kernel paths with `grubby --update-kernel`; refresh is a no-op because `grubby` updates entries directly. Rescue/debug kernels are intentionally excluded. |
| GRUB | `/etc/default/grub` fallback | Rewrites `GRUB_CMDLINE_LINUX`, then runs `update-grub` or equivalent grub-mkconfig path. |

Behavior that matters during operations:

- Existing non-kernsec boot args are preserved.
- Only managed keys are removed/replaced by kernsec.
- `GRUB_CMDLINE_LINUX_DEFAULT` is read for status/drift, but kernsec does not
  write it; managed args found there are reported as drift because kernsec only
  remediates `GRUB_CMDLINE_LINUX`.
- Backends take a pre-change backup/snapshot so `rollback` can restore the
  previous managed-argument state. These snapshots are scoped to kernsec-managed
  boot args, not full kernel command lines.
- If bootloader refresh fails after a write, kernsec attempts to roll the file
  back to a safe retry state and prints manual recovery steps if rollback also
  fails.

## Rollback/disable/purge

Use `cfm kernsec rollback` when the last boot-argument apply needs to be undone
without changing the rest of the kernsec config. Rollback removes
kernsec-managed boot args first, restores saved managed values when a
backend-specific managed snapshot exists, and refreshes the bootloader where
needed. It does **not** replay a full saved default-kernel command line.

Backend-specific rollback behavior:

- GRUB rewrites `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, then refreshes
  `grub.cfg` with `update-grub` or the detected `grub-mkconfig` path.
- Proxmox rewrites `/etc/kernel/cmdline`, then runs
  `proxmox-boot-tool refresh`.
- BLS uses `grubby` to update explicit non-rescue/non-debug kernels. It
  enumerates kernels with `grubby --info=ALL`, strips kernsec-managed args from
  every non-rescue/non-debug kernel, then restores the saved managed args for
  kernels whose image path matches the snapshot.

BLS snapshots are keyed by kernel image path and contain only kernsec-managed
args; unmanaged per-kernel args are left untouched. Rescue and debug BLS entries
are intentionally excluded from snapshot, apply, drift, and rollback operations
so a bad managed arg does not remove the recovery path.

Legacy `.cfm-kernsec.bak` bootloader-file backups are fallback data only for
older rollback records that predate managed-argument snapshots. kernsec refuses
the legacy whole-file byte-restore if the current file has operator changes
relative to the legacy backup, preventing rollback from overwriting unrelated
bootloader edits.

Rollback only changes next-boot boot arguments. It does not revert live sysctl
values changed by an earlier `apply`; those remain active until reboot or until
an operator changes them manually with `sysctl`.

Use `cfm kernsec disable --yes` to persistently turn kernsec apply mode off:

- Writes `tier = 0` to `/etc/cfm/kernsec.conf`.
- Removes kernsec-managed boot arguments.
- Writes empty managed sysctl and modprobe files.
- Leaves backups and snapshots in place.

Use `cfm kernsec disable --purge --yes` for a fuller uninstall:

- Removes `/etc/cfm/kernsec.conf`.
- Removes `/etc/sysctl.d/99-cfm-kernsec.conf`.
- Removes `/etc/modprobe.d/cfm-kernsec.conf`.
- Removes installed monitor units.
- Leaves backup files in place for manual recovery.

Add `--dry-run` to inspect either operation before writing. Add `--no-refresh`
only when the bootloader refresh will be handled separately.

## Monitor timer

`cfm kernsec monitor enable` writes and enables a systemd timer that periodically
runs:

```sh
cfm kernsec apply --check
```

Default interval is `daily`; pass any systemd `OnCalendar` expression with
`--interval`, for example `hourly`, `weekly`, or `*-*-* 03:00:00`.

Timer management commands:

- `cfm kernsec monitor enable [--interval=daily]` — write unit files,
  daemon-reload, enable, and start the timer.
- `cfm kernsec monitor disable` — stop and disable the timer, leaving unit files.
- `cfm kernsec monitor remove` — stop, disable, remove unit files, and
  daemon-reload.
- `cfm kernsec monitor status` — show timer status and recent service runs.

The service treats exit code `2` from `apply --check` as a soft success so
transient indeterminate checks retry on the next timer fire. Drift remains a
failure and is visible through `systemctl is-failed` and the journal.

## Coexistence with cfm-lsm

`kernsec` (preemptive kernel-surface reduction) and `cfm-lsm`
(runtime userspace-behaviour enforcement via BPF LSM) are paired
defence layers — each catches what the other structurally cannot.
The two components do not overlap on managed surface:

- `kernsec` manages **sysctls, boot args, modules, mounts**. It
  shapes the kernel ahead of time so that even a successful
  userspace compromise has less to pivot through.
- `cfm-lsm` manages **BPF LSM hooks at runtime**. It detects (and
  in enforce mode blocks) post-exploit patterns — memfd exec,
  reverse-shell fd patterns — that no sysctl can express.

A few intentional non-overlaps worth recording:

- `kernel.yama.ptrace_scope=2` is shipped by kernsec (Tier 1). `=1`
  was previously accepted as also-green but was removed once the
  ssh-keysign / chage `pidfd_getfd()` exit-window race was confirmed
  to be a working `/etc/shadow` disclosure primitive against mode 1
  hosts. Operators who need same-uid debuggability must `state = skip`
  `KSEC-SCT-kspp.kernel-006` in `kernsec.conf` and accept the
  residual setuid-helper fd-leak race. The `CFML-OBS-001`
  ptrace-lockdown idea from cfm-lsm's original scope was dropped
  specifically because kernsec already covers that ground at a
  cheaper layer.
- The `lsm=…,bpf` kernel command-line argument is **not yet
  managed by kernsec**. cfm-lsm's preflight detects when `bpf` is
  absent from `/sys/kernel/security/lsm` and prints the exact
  remediation line for the operator's bootloader. A follow-up
  proposal will add a new kernsec rule (`KSEC-LSM-bpf-001`,
  Tier 2, default not forced) that appends `bpf` to the existing
  `lsm=` value via the same backend that already manages
  `unprivileged_bpf_disabled` and friends. Tracked in
  [`docs/cfm-lsm.md`](./cfm-lsm.md) under "Phased roadmap → Future
  kernsec integration."
- `kernsec`'s module-load lockdown rules (and the broader
  CFML-SELF-002 idea from the original cfm-lsm draft) are
  deliberately excluded because they conflict with
  KernelCare / Ksplice live-patch module reloads. The component
  boundary is: kernsec hardens what can stay static; cfm-lsm
  watches what has to stay live.

Reading order: when both components are active, an operator should
expect to see kernsec rules in `cfm kernsec status` and cfm-lsm
state in `cfm lsm status`. Events from cfm-lsm flow through the
same notify pipeline as outbound and detector events.
[`docs/cfm-lsm.md`](./cfm-lsm.md) is the design+ops doc for the
runtime layer.

## Compatibility notes

- Unsupported sysctl keys are commented as skipped in the managed drop-in rather
  than failing the whole apply. A later kernel that exposes the key can then use
  the same config intent.
- kernsec-owned network hardening rules are written by kernsec, but the legacy
  `sysctl.net` group is normally owned by `cfm-sysctl-tweaks` and shown as
  `EXT`.
- If `cfm-sysctl-tweaks` is disabled in the main cfm config, the ownership
  registry still treats its keys as externally owned. Force individual kernsec
  rules only if you want kernsec to take over those keys and accept the reported
  conflict.
- Tier 2 oops/panic rules trade availability for fail-closed behavior.
- `kernel.core_pattern=|/bin/false` suppresses core dumps globally.
- `initcall_blacklist=algif_aead_init` and the `algif_*` module blacklists can
  affect userspace AF_ALG consumers.

## Operator runbook

1. Inspect current state:

   ```sh
   cfm kernsec status
   cfm kernsec status --json
   ```

2. Create the default config if needed:

   ```sh
   sudo cfm kernsec init
   ```

3. Preview the default Tier 1 apply:

   ```sh
   sudo cfm kernsec preview
   sudo cfm kernsec preview --only-apply
   ```

4. Review host-profile skips and add explicit per-rule overrides only where the
   host owner accepts the compatibility impact.

5. Apply interactively, or use `--yes` only for approved unattended runs:

   ```sh
   sudo cfm kernsec apply
   sudo cfm kernsec apply --yes
   ```

6. Reboot when boot-argument changes need to take effect, then verify:

   ```sh
   cfm kernsec status --check
   ```

7. Enable drift monitoring:

   ```sh
   sudo cfm kernsec monitor enable --interval=daily
   cfm kernsec monitor status
   ```

8. To opt into Tier 2, edit `/etc/cfm/kernsec.conf`, set `tier = 2`, then repeat
   preview and apply. Treat Tier 2 as a per-host change request.

9. If a boot-argument apply must be undone:

   ```sh
   sudo cfm kernsec rollback --dry-run
   sudo cfm kernsec rollback
   ```

10. To disable kernsec-managed state without removing backups:

    ```sh
    sudo cfm kernsec disable --yes
    ```

11. To uninstall kernsec-managed config/files while preserving backups:

    ```sh
    sudo cfm kernsec disable --purge --yes
    ```
