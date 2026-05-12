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
| 2 | Server-aggressive | Opt-in; can affect availability, diagnostics, containers, kdump, seccomp-heavy workloads, or hosting panels. Host-profile gates skip known-risk hosts unless forced. |

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
| `kspp.kernel` | 1 | `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=2`, `kernel.randomize_va_space=2`, `kernel.perf_event_paranoid=3`, `kernel.yama.ptrace_scope=1` | Restricts unprivileged kernel visibility, BPF, perf, and ptrace. Profiling/debug attach generally needs root. |
| `kspp.fs` | 1 | `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`, `fs.protected_fifos=2`, `fs.protected_regular=2` | Protects sticky/world-writable directories; normally no production impact. |
| `kspp.net` | 1 | `net.core.bpf_jit_harden=2` | Minor BPF JIT performance cost. |
| `sysctl.mem.exploit` | 1 | `vm.unprivileged_userfaultfd=0`, `vm.mmap_rnd_bits=32`, `vm.mmap_rnd_compat_bits=16`, `kernel.warn_limit=10`, `kernel.oops_limit=10`, `fs.suid_dumpable=0` | Removes common LPE primitives; unusual debugging/checkpointing may need overrides. Unsupported keys are skipped. |
| `tier2.oops` | 2 | `kernel.panic_on_oops=1`, `kernel.panic=10` | Any kernel oops can become a reboot; opt-in only. |
| `sysctl.kernel.surface` | 1 | `dev.tty.ldisc_autoload=0`, `kernel.sysrq=0` | Disables automatic TTY line-discipline loading and Magic SysRq. |
| `sysctl.kernel.coredump` | 2 | `kernel.core_pattern=|/bin/false` | Suppresses core dumps globally; skipped for kdump, hosting panels, backup agents, and crash-diagnostic monitoring. |
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

| Group | Tier | Modules | Notes |
|---|---:|---|---|
| `modules.recent_cves` | 1 | `ksmbd`, `n_hdlc`, `vivid`, `watch_queue`, `binfmt_aout`, `nfc`, `nfcsim`, `pn533`, `pn533_usb`, `kcm`, `n_gsm`, `n_r3964` | Recently exploited or no normal server use. |
| `modules.net.legacy` | 1 | Legacy protocols such as `dccp`, `tipc`, `rds`, `rxrpc`, `ax25`, `netrom`, `x25`, `rose`, `decnet`, `econet`, `ipx`, `appletalk`, LLC/SNAP variants, `phonet`, `caif`, `caif_socket`, `hsr`, and similar dead network stacks | Intended to be safe on normal hosting servers. |
| `modules.net.virt` | 1 | `vsock` | Skipped on KVM hypervisors (host-profile gated on `IsKVMHost`) so `vhost_vsock` remains available for guest↔host comms. |
| `modules.net.iot` | 1 | `ieee802154`, `mac802154`, `6lowpan` | IEEE 802.15.4 / low-power wireless PAN stack — no 802.15.4 radios on hosting boxes. |
| `modules.fs.unused` | 1 | `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `qnx4`, `qnx6`, `omfs`, `befs`, `ufs`, `affs`, `sysv`, `nilfs2`, `gfs2`, `ocfs2`, `coda`, `reiserfs` | Override if the host genuinely mounts one of these filesystems. |
| `modules.fs.container` | 1 | `erofs` | Skipped on hosts running containers (host-profile gated on `HasContainers`) since some container image layers use it. |
| `modules.bus.bluetooth` | 1 | `bluetooth`, `btusb`, `bnep`, `hci_uart` | Host-profile gated when Bluetooth hardware is detected. |
| `modules.bus.firewire` | 1 | `firewire-core`, `firewire-ohci`, `firewire-net`, `firewire-sbp2` | No typical server use. |
| `modules.bus.thunderbolt` | 1 | `thunderbolt` | Skipped when Thunderbolt devices are detected. |
| `modules.bus.misc` | 1 | `joydev`, `pcspkr`, `floppy` | No typical server use. |
| `modules.input.userspace` | 1 | `uinput`, `uhid` | Userspace virtual input / HID devices — no use case on servers, non-trivial historical exploit surface. |
| `modules.sidechannel` | 1 | `intel_rapl_common`, `intel_rapl_msr` | Removes RAPL power telemetry to avoid power side-channel surface. |
| `modules.crypto_userapi` | 1 | `algif_hash`, `algif_skcipher`, `algif_rng`, `algif_akcipher`, `algif_aead` | Extends the AF_ALG hardening; `algif_aead` is also covered at boot via `initcall_blacklist=algif_aead_init`. |

NFS, CIFS/SMB clients, `io_uring`, and wifi modules are intentionally not
blacklisted by the shipped registry. These have legitimate operator-managed use
cases on some hosts.

### fstab / mount audit rules

These rules are **audit-only**. kernsec reports missing mount options but never
edits `/etc/fstab`.

| Rule ID | Group | Mount point | Recommendation | Notes |
|---|---|---|---|---|
| `KSEC-FS-mount.tmp-001` | `fs.mount.tmp` | `/tmp` | `nodev,nosuid,noexec` | Review before enabling; `noexec` can break composer, pip, and hosting-panel workflows. |
| `KSEC-FS-mount.tmp-002` | `fs.mount.tmp` | `/var/tmp` | `nodev,nosuid,noexec` | Same compatibility considerations as `/tmp`. |
| `KSEC-FS-mount.tmp-003` | `fs.mount.tmp` | `/dev/shm` | `nodev,nosuid,noexec` | Usually safe, but review JVM/Python multiprocessing workloads. |

`/home` was previously audited for `nodev,nosuid`. It was removed because operator setups vary too widely (panels with setuid helpers under `/home`, NFS-exported homes, CageFS layouts) for a one-size recommendation to produce more signal than noise.

The mount audit renders one of: `OK` (every recommended option live), `PARTIAL` (some live, some missing — the remediation hint names only the missing options), `MISSING` (mount exists but no recommended options live), or `SKIP` (path is not a separate mount, is a symlink to another audited mount point, or is a bind sibling of another audited mount point). For PARTIAL and MISSING rows the audit prints the exact `mount -o remount,…` command and the matching `/etc/fstab` or systemd `.mount` change.

For `/tmp` and `/var/tmp` the audit is strictly informational — kernsec never mutates fstab for them. Live MySQL temp tables, the `/var/tmp`-survives-reboot contract, and the dedicated-filesystem provisioning step (loop file vs tmpfs) make those changes too operator-specific for automation.

`/dev/shm` is the narrow exception: `MountRule.CanEnable=true` lets `cfm kernsec apply` edit `/etc/fstab` and live-remount it. Auto-application is gated on tmpfs (no on-disk state to migrate), preserved options like `size=` and `mode=` are kept untouched, an explicit `exec`/`suid`/`dev` set by the operator aborts with a clear error rather than being silently overwritten, and `cfm kernsec disable` strips only the kernsec-managed options (or removes the whole line if kernsec authored it).

## Intentionally unsupported

`kernel.modules_disabled=1` is intentionally unsupported. It is a one-way
runtime switch until reboot and requires very careful late-boot orchestration so
cfm, the kernel, and host-specific services can finish loading required modules
before module loading is disabled globally.

NFS, CIFS/SMB clients, `io_uring`, wifi modules, and IPsec/XFRM modules are
also intentionally not blacklisted by the shipped registry. These have
legitimate operator-managed use cases on some hosts.

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
| kdump | Crash-kernel/kdump indicators. | Skips global coredump suppression so crash capture remains available. |
| Backup workloads | Common backup agents or backup-named systemd services, including Veeam, Acronis, JetBackup, Bareos, Bacula, and UrBackup indicators. | Skips global coredump suppression to preserve vendor diagnostics. |
| Monitoring/crash-diagnostic workloads | Common monitoring or crash-diagnostic agents, including node_exporter, Zabbix, Datadog, Elastic Agent, Telegraf, ABRT, Apport, and systemd-coredump indicators. | Skips global coredump suppression. |
| IPsec | Non-empty `/proc/net/xfrm_policy` or `/proc/net/pfkey`. | Recorded as host context; shipped IPsec/XFRM modules are intentionally not blacklisted. |
| Bluetooth | Non-empty `/sys/class/bluetooth`. | Skips Bluetooth bus module blacklists. |
| Thunderbolt | Non-empty `/sys/bus/thunderbolt/devices`. | Skips Thunderbolt module blacklist. |
| NFS | Active `nfs` or `nfs4` mounts in `/proc/mounts`. | Recorded as host context; shipped NFS modules are intentionally not blacklisted. |
| EFI boot | `/sys/firmware/efi`. | Allows EFI-specific DMA boot hardening; non-EFI hosts skip `efi=disable_early_pci_dma` as a no-op. |

Current risky Tier 2 skip reasons:

| Tier 2 group | Current skip reason |
|---|---|
| Namespace rules (`tier2.namespace`) | Skip hosting/container workloads because disabling unprivileged user namespaces breaks rootless containers, container sandboxes, cPanel jails, CloudLinux/CageFS isolation, and similar hosting isolation. |
| Coredump suppression (`sysctl.kernel.coredump`) | Skip kdump, hosting, backup, and monitoring diagnostics because `kernel.core_pattern=|/bin/false` suppresses coredumps globally and can break crash capture or vendor troubleshooting. |

Mutating commands also run a pre-flight safety summary before risky applies.
Use `--yes` only for unattended runs where that preview has already been
reviewed operationally.

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
