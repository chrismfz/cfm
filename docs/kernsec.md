# CFM kernsec — Kernel Attack Surface Reduction

## Overview

`cfm kernsec` is cfm's canonical kernel-hardening component for cfm-managed
hosts. It audits and, when requested, applies a curated set of kernel attack
surface reductions across sysctls, kernel boot arguments, kernel module
blacklists, and periodic drift monitoring.

The component currently manages:

- `/etc/sysctl.d/99-cfm-kernsec.conf` for kernsec-owned sysctls.
- Kernel boot arguments for the detected bootloader backend.
- `/etc/modprobe.d/cfm-kernsec.conf` for module blacklists.
- `cfm-kernsec-check.timer` / `.service` for periodic drift checks.

`/etc/fstab` is **report-only**. kernsec audits mount options and tells the
operator what is missing, but it never edits fstab because `noexec` and related
options can break real hosting workflows.

`scripts/kspp.sh` remains in the tree as a standalone hardening script and as a
reference implementation. For cfm-managed hosts, **use `cfm kernsec`**; it is the
canonical interface and includes the cfm-specific rule registry, config model,
status output, bootloader backends, module blacklist writer, fstab audit, and
monitor timer.

`kernel.modules_disabled=1` is intentionally unsupported. It is a one-way
runtime switch until reboot and requires very careful late-boot orchestration so
cfm, the kernel, and host-specific services can finish loading required modules
before module loading is disabled globally.

## Commands

`cfm kernsec` with no subcommand opens the interactive TUI on a TTY and falls
back to text output when stdout is not a terminal.

| Command | Purpose |
|---|---|
| `cfm kernsec` | TUI on a TTY; text audit otherwise. |
| `cfm kernsec live` | Force the interactive TUI. Aliases: `tui`, `ui`. |
| `cfm kernsec text` | Plain-text audit output. |
| `cfm kernsec status` | Alias for `text`. Add `--json` for machine-readable output or `--check` for monitoring exits. |
| `cfm kernsec preview` | Show what `apply` would select after config, tier, and host-profile gates. Read-only. |
| `cfm kernsec init` | Write default `/etc/cfm/kernsec.conf` with `tier = 1` if absent. |
| `cfm kernsec apply` | Render managed sysctl and modprobe files, apply sysctls, update boot args, and refresh the bootloader. |
| `cfm kernsec disable` | Persist `tier = 0`, strip kernsec-managed boot args, and empty managed sysctl/modprobe output. |
| `cfm kernsec rollback` | Restore bootloader cmdline state from kernsec's pre-apply backup/snapshot and refresh the bootloader. |
| `cfm kernsec monitor` | Manage the periodic systemd drift-check timer. |

Useful flags:

- `status` / `text`: `--skip-af-alg`, `--check`, `--json`.
- `preview`: `--only-apply`, `--group <prefix>`, `--tier <0|1|2>`,
  `--id <ids>`, `--skip <ids>`, `--force-id <ids>`.
- `apply`: `--dry-run`, `--check`, `--no-refresh`, `--yes`.
- `disable`: `--purge`, `--dry-run`, `--no-refresh`, `--force`, `--yes`.
- `rollback`: `--dry-run`.
- `monitor enable`: `--interval=<OnCalendar>`, `--dry-run`.

`apply --check` is the drift-check mode used by the timer: it performs no writes
and exits non-zero when desired managed state differs from live/next-boot state.
`status --check` exits non-zero on audit warnings.

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
| `/etc/sysctl.d/99-cfm-kernsec.conf` | `apply`, `disable`, `--purge` | kernsec-owned sysctl drop-in. Unsupported kernel keys are emitted as commented skipped lines. |
| `/etc/modprobe.d/cfm-kernsec.conf` | `apply`, `disable`, `--purge` | Emits both `blacklist <module>` and `install <module> /bin/false`. |
| `/etc/default/grub` | GRUB backend | Only `GRUB_CMDLINE_LINUX` is written; `_DEFAULT` is read for audit/drift but not written. |
| `/etc/kernel/cmdline` | Proxmox/systemd-boot backend | Updated and followed by `proxmox-boot-tool refresh`. |
| BLS entries via `grubby` | BLS backend | Updated with `grubby --update-kernel`; rescue/debug kernels are excluded. |
| `/etc/systemd/system/cfm-kernsec-check.service` | `monitor enable/remove` | Runs `cfm kernsec apply --check`. |
| `/etc/systemd/system/cfm-kernsec-check.timer` | `monitor enable/remove` | Periodic drift-check timer. |
| `/run/lock/cfm-kernsec.lock` | mutating commands | Advisory lock to prevent concurrent kernsec writers. |

Backups and rollback snapshots:

- Managed files use one-shot `.cfm-kernsec.bak` backups before the first edit.
- If operator-edited lines are detected in a managed sysctl or modprobe file,
  kernsec preserves an additional timestamped backup and warns.
- GRUB and Proxmox backends store managed-argument snapshots under
  `/var/lib/cfm/` and retain legacy `.cfm-kernsec.bak` files for recovery.
- The BLS backend stores its pre-apply snapshot at
  `/var/lib/cfm/kernsec-bls-cmdline.cfm-kernsec.bak`.
- `disable --purge` removes the config, managed sysctl file, managed modprobe
  file, and installed monitor units, but intentionally leaves backups in place.

## Rule tiers

| Tier | Meaning | Operator expectation |
|---|---|---|
| 0 | Disabled/audit-only | No rule is selected for apply; status still audits. |
| 1 | Default hardening | Intended to be safe across typical hosting, KVM, cPanel, EL, and Debian hosts. |
| 2 | Server-aggressive | Opt-in; can affect availability, diagnostics, containers, DKMS/vendor modules, kdump, SCTP, seccomp-heavy workloads, or hosting panels. Host-profile gates skip known-risk hosts unless forced. |

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
| `kspp.kernel` | 1 | `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=1`, `kernel.randomize_va_space=2`, `kernel.perf_event_paranoid=3`, `kernel.yama.ptrace_scope=1` | Restricts unprivileged kernel visibility, BPF, perf, and ptrace. Profiling/debug attach generally needs root. |
| `kspp.fs` | 1 | `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`, `fs.protected_fifos=2`, `fs.protected_regular=2` | Protects sticky/world-writable directories; normally no production impact. |
| `kspp.net` | 1 | `net.core.bpf_jit_harden=2` | Minor BPF JIT performance cost. |
| `sysctl.mem.exploit` | 1 | `vm.unprivileged_userfaultfd=0`, `vm.mmap_rnd_bits=32`, `vm.mmap_rnd_compat_bits=16`, `kernel.warn_limit=10`, `kernel.oops_limit=10`, `fs.suid_dumpable=0` | Removes common LPE primitives; unusual debugging/checkpointing may need overrides. Unsupported keys are skipped. |
| `tier2.oops` | 2 | `kernel.panic_on_oops=1`, `kernel.panic=10` | Any kernel oops can become a reboot; opt-in only. |
| `sysctl.kernel.surface` | 1 | `dev.tty.ldisc_autoload=0`, `kernel.sysrq=0` | Disables automatic TTY line-discipline loading and Magic SysRq. |
| `sysctl.kernel.kexec` | 2 | `kernel.kexec_load_disabled=1` | Irreversible until reboot; skipped on kdump, Proxmox, and live-patching evidence unless forced. |
| `sysctl.kernel.coredump` | 2 | `kernel.core_pattern=|/bin/false` | Suppresses core dumps globally; skipped for kdump, hosting panels, backup agents, and crash-diagnostic monitoring. |
| `tier2.namespace` | 2 | `user.max_user_namespaces=0`, `kernel.unprivileged_userns_clone=0` | Breaks rootless containers, bubblewrap, Chromium sandbox, and some hosting isolation; skipped when containers/hosting panels are detected. |
| `sysctl.net.harden` | 1 | Broadcast ICMP ignore, source-route rejection, martian logging, TCP RFC1337, IPv6 RA rejection | Static-IP servers should be unaffected; skip IPv6 RA rules if the host relies on SLAAC. |

### Sysctl rules audited as externally managed

`sysctl.net` rules are audited by kernsec but normally owned by
`cfm-sysctl-tweaks` through the shared sysctl ownership registry. They render as
`EXT`; kernsec does not write them unless the operator explicitly uses
`state = force` on a rule.

Audited keys include `rp_filter`, IPv4/IPv6 redirect handling, and
`net.ipv4.tcp_syncookies`.

### Boot-argument rules

| Group | Tier | Args | Operator impact |
|---|---:|---|---|
| `kspp.boot` | 1 | `slab_nomerge`, `init_on_alloc=1`, `page_alloc.shuffle=1`, `randomize_kstack_offset=on`, `initcall_blacklist=algif_aead_init` | Memory-safety hardening. `init_on_alloc=1` can have modest alloc-heavy overhead. The `initcall_blacklist` entry is a temporary Copy Fail / CVE-2026-31431 mitigation affecting AEAD AF_ALG use. |
| `boot.bug-detection` | 1 | `kfence.sample_interval=100` | Enables low-overhead KFENCE sampling. |
| `boot.dma` | 1 | `efi=disable_early_pci_dma` | EFI-only pre-IOMMU DMA hardening; skipped on non-EFI hosts. |
| `boot.sidechannel` | 1 | `tsx=off` | Disables Intel TSX side-channel surface; no expected hosting impact. |
| `tier2.ssbd` | 2 | `spec_store_bypass_disable=seccomp` | Can cost syscall throughput on seccomp-heavy workloads; host-profile gated. |
| `tier2.oops` | 2 | `oops=panic` | Pairs with Tier 2 panic-on-oops sysctls; can reboot on kernel oops. |
| `tier2.lockdown` | 2 | `lockdown=integrity` | Can break unsigned/vendor/DKMS modules; host-profile gated. |
| `tier2.module-sig-enforce` | 2 | `module.sig_enforce=1` | Requires signed kernel modules; host-profile gated for DKMS/vendor modules. |

kernsec only owns the managed boot-argument keys listed above. It strips stale
instances of those keys before appending the desired managed set and preserves
operator-provided arguments outside the managed set.

### Module blacklist rules

`apply` writes one `blacklist` line and one `install <module> /bin/false` line
per selected rule. This prevents both alias-based autoloading and direct
`modprobe` loads.

| Group | Tier | Modules | Notes |
|---|---:|---|---|
| `modules.recent_cves` | 1 | `ksmbd`, `n_hdlc`, `vivid`, `watch_queue`, `binfmt_aout`, `nfc`, `nfcsim`, `pn533`, `pn533_usb` | Recently exploited or no normal server use. |
| `modules.net.legacy` | 1 | Legacy protocols such as `dccp`, `tipc`, `rds`, `rxrpc`, `ax25`, `netrom`, `x25`, `rose`, `decnet`, `econet`, `ipx`, `appletalk`, LLC/SNAP variants, and similar dead network stacks | Intended to be safe on normal hosting servers. |
| `modules.fs.legacy` | 1 | Obsolete or uncommon filesystems such as `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `squashfs`, `udf` | Override if the host genuinely mounts one of these filesystems. |
| `modules.bus.bluetooth` | 1 | Bluetooth stack modules | Host-profile gated when Bluetooth hardware is detected. |
| `modules.bus.thunderbolt` | 1 | `thunderbolt` | Skipped when Thunderbolt devices are detected. |
| `modules.bus.misc` | 1 | `joydev`, `pcspkr`, `floppy`, DVB/media/tuner modules | No typical server use. |
| `modules.sidechannel` | 1 | `intel_rapl_common`, `intel_rapl_msr` | Removes RAPL power telemetry to avoid power side-channel surface. |
| `modules.ipsec` | 1 | `esp4`, `esp6`, `ah4`, `ah6`, `xfrm_user`, `xfrm6_tunnel`, `xfrm4_tunnel` | Skipped if IPsec/XFRM policy is detected. |
| `modules.crypto_userapi` | 1 | `algif_hash`, `algif_skcipher`, `algif_rng`, `algif_akcipher` | Extends the AF_ALG hardening beyond the boot-time `algif_aead` mitigation. |
| `tier2.modules.sctp` | 2 | `sctp` | Opt-in; skipped when SCTP use is detected. |

NFS, CIFS/SMB clients, `io_uring`, and wifi modules are intentionally not
blacklisted by the shipped registry. These have legitimate operator-managed use
cases on some hosts.

### fstab / mount audit rules

These rules are **audit-only**. kernsec reports missing mount options but never
edits `/etc/fstab`.

| Rule | Recommendation | Notes |
|---|---|---|
| `/tmp` | `nodev,nosuid,noexec` | Review before enabling; `noexec` can break composer, pip, and hosting-panel workflows. |
| `/var/tmp` | `nodev,nosuid,noexec` | Same compatibility considerations as `/tmp`. |
| `/dev/shm` | `nodev,nosuid,noexec` | Usually safe, but review JVM/Python multiprocessing workloads. |
| `/home` | `nodev,nosuid` | `noexec` is intentionally not recommended for `/home`. |

## Host-profile gates

Host-profile gates prevent high-risk rules from applying on hosts where they are
likely to break production workloads. `preview`, `status`, and the TUI show when
a rule is skipped by host profile. Operators can override with `state = force`
when they accept the risk.

Important gates:

- Containers / rootless-container tooling / hosting isolation: skip namespace
  kill rules.
- DKMS, vendor modules, live patching, ZFS, NVIDIA, CloudLinux/LVE/CageFS, and
  similar evidence: skip lockdown and module-signature enforcement.
- kdump, Proxmox, and live patching: skip `kernel.kexec_load_disabled=1`.
- kdump, hosting panels, backup agents, and monitoring/crash-diagnostic agents:
  skip global core-dump suppression.
- seccomp-heavy container, hosting, backup, or monitoring workloads: skip SSBD
  seccomp mode unless forced.
- EFI detection: apply `efi=disable_early_pci_dma` only on EFI-booted hosts.
- IPsec/XFRM policy: skip IPsec module blacklists.
- Bluetooth / Thunderbolt hardware: skip the corresponding bus module
  blacklists.
- SCTP evidence: skip the Tier 2 SCTP module blacklist.

Mutating commands also run a pre-flight safety summary before risky applies.
Use `--yes` only for unattended runs where that preview has already been
reviewed operationally.

## Bootloader backends

kernsec detects and uses one of these bootloader backends:

| Backend | Detection / write path | Refresh behavior |
|---|---|---|
| Proxmox/systemd-boot | `/etc/kernel/cmdline` with `proxmox-boot-tool` | Writes `/etc/kernel/cmdline`, then runs `proxmox-boot-tool refresh`. |
| BLS/grubby | `/boot/loader/entries` plus `grubby` | Uses `grubby --update-kernel`; refresh is a no-op because `grubby` updates entries directly. Rescue/debug kernels are excluded. |
| GRUB | `/etc/default/grub` fallback | Rewrites `GRUB_CMDLINE_LINUX`, then runs `update-grub` or equivalent grub-mkconfig path. |

Behavior that matters during operations:

- Existing non-kernsec boot args are preserved.
- Only managed keys are removed/replaced by kernsec.
- `GRUB_CMDLINE_LINUX_DEFAULT` is read for status/drift, but kernsec does not
  write it; managed args found there are reported as drift because kernsec only
  remediates `GRUB_CMDLINE_LINUX`.
- Backends take a pre-change backup/snapshot so `rollback` can restore the
  previous managed-argument state.
- If bootloader refresh fails after a write, kernsec attempts to roll the file
  back to a safe retry state and prints manual recovery steps if rollback also
  fails.

## Rollback/disable/purge

Use `cfm kernsec rollback` when the last boot-argument apply needs to be undone
without changing the rest of the kernsec config. It restores the bootloader
cmdline from the backend-specific `.cfm-kernsec.bak` file or managed-argument
snapshot and refreshes the bootloader where needed.

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

## Compatibility notes

- Unsupported sysctl keys are commented as skipped in the managed drop-in rather
  than failing the whole apply. A future kernel that exposes the key can then use
  the same config intent.
- kernsec-owned network hardening rules are written by kernsec, but the legacy
  `sysctl.net` group is normally owned by `cfm-sysctl-tweaks` and shown as
  `EXT`.
- If `cfm-sysctl-tweaks` is disabled in the main cfm config, the ownership
  registry still treats its keys as externally owned. Force individual kernsec
  rules only if you want kernsec to take over those keys and accept the reported
  conflict.
- `kernel.kexec_load_disabled=1` cannot be undone until reboot after it is set.
- Tier 2 oops/panic rules trade availability for fail-closed behavior.
- Tier 2 module-signature and lockdown rules can break DKMS/vendor modules.
- `kernel.core_pattern=|/bin/false` suppresses core dumps globally.
- `net.ipv6.conf.*.accept_ra=0` can break hosts that rely on SLAAC for IPv6.
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
   host owner accepts the compatibility impact:

   ```ini
   [rule "KSEC-SCT-net.harden-006"]
   state = skip
   ```

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
