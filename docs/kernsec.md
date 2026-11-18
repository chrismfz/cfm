# CFM kernsec — Kernel Attack Surface Reduction

## Overview

kernsec reduces kernel attack surface before a CVE lands, instead of chasing
patched kernels after it. It disables surface a hosting box has no use for:
dead network protocols, recently exploited modules, userspace crypto APIs,
power side-channel telemetry, and filesystems no server mounts.

It has five mechanisms: sysctls, kernel boot arguments, module blacklists,
mount options, and a drift monitor. A tiered config and host-profile gates let
the same rule set run on cPanel, DirectAdmin, CloudLinux, Proxmox, KVM
hypervisors, live-patched kernels and ZFS hosts.

Code: `internal/kernsec/` (rule registry in `profile.go`, `modules.go`,
`mounts.go`; CLI in `cli.go`). Sysctl ownership across components:
`internal/managedsysctl`.

Managed state:

- `/etc/sysctl.d/99-cfm-kernsec.conf` — kernsec-owned sysctls.
- Kernel boot arguments, through the detected bootloader backend.
- `/etc/modprobe.d/cfm-kernsec.conf` — module blacklists.
- `/etc/fstab` (or a systemd `.mount` drop-in) for `/tmp`, `/var/tmp` and
  `/dev/shm` mount options, and the explicit `cfm kernsec secure-tmp` verb.
  `/proc` `hidepid` is audit-only.
- `cfm-kernsec-check.timer` / `.service` — periodic drift checks.

## KSPP script relationship

`scripts/kspp.sh` stays in the tree as a standalone hardening script and
reference. On cfm-managed hosts, use `cfm kernsec`. kernsec covers the
script's KSPP sysctls, boot arguments, bootloader backends, status checks and
Copy Fail mitigation, and adds the rule registry, config model, module
blacklists, mount handling and the monitor timer.

## Relationship to upstream killswitch

Upstream Linux is gaining a `killswitch` primitive
(`Documentation/admin-guide/killswitch.rst`): a privileged operator makes a
chosen kernel function return a fixed value until a patched kernel is booted.
kernsec removes surface before a CVE drops, and already covers most named
targets: ksmbd, vsock (except on KVM hosts) and ax25 are blacklisted; AF_ALG
is cut by `initcall_blacklist=algif_aead_init` plus the `algif_*` blacklist.
nf_tables is deliberately NOT disabled: cfm's firewall is nftables, and a
dead firewall costs more than a known-vulnerable nft path until the fix
lands. Killswitch suits what kernsec cannot blacklist (nftables core, NFS
client, `io_uring` on NVMe hosts).

## Commands

`cfm kernsec` with no subcommand opens the TUI on a TTY and prints the text
audit otherwise.

| Command | Purpose | Writes? |
|---|---|---|
| `cfm kernsec` | TUI on a TTY; text audit otherwise. | No (TUI: see below). |
| `cfm kernsec live` (`tui`, `ui`) | Force the TUI. | No (TUI: see below). |
| `cfm kernsec text` / `status` | Text audit. `--check` exits non-zero on WARN; `--json` emits JSON; `--skip-af-alg` skips the AF_ALG bind probes. | No. |
| `cfm kernsec preview` | What `apply` would select after config, tier, host-profile gates and overrides. Flags: `--tier <0-3>`, `--group <prefix>`, `--id <ids>`, `--skip <ids>`, `--force-id <ids>` (ad-hoc, not persisted), `--only-apply`. | No. |
| `cfm kernsec init` | Write the default `tier = 1` `/etc/cfm/kernsec.conf` if absent. | Only when creating it. |
| `cfm kernsec apply` | Render managed sysctl/modprobe files, update boot args, refresh the bootloader, apply mount rules, `sysctl -w` per key, unload managed modules. Flags: `--dry-run`, `--check`, `--no-refresh`, `--no-unload`, `--yes`, `--force-unsafe`. | Yes, unless `--dry-run` / `--check`. |
| `cfm kernsec disable` | Persist `tier = 0` and run apply with it. Flags: `--purge`, `--dry-run`, `--no-refresh`, `--no-unload`, `--force`, `--yes`, `--force-unsafe`. | Yes, unless `--dry-run`. |
| `cfm kernsec rollback` | Undo managed boot args and remove the managed sysctl drop-in. Flag: `--dry-run`. | Yes, unless `--dry-run`. |
| `cfm kernsec monitor enable` | Write and enable the drift-check timer. Flags: `--interval <OnCalendar>`, `--dry-run`. | Yes, unless `--dry-run`. |
| `cfm kernsec monitor disable` | Stop and disable the timer; keep unit files. | Yes. |
| `cfm kernsec monitor remove` | Stop, disable, remove unit files, daemon-reload. | Yes. |
| `cfm kernsec monitor status` | Timer status and recent service runs. | No. |
| `cfm kernsec modules audit` | List loaded modules with a signature-trust verdict. `--check` exits 1 if any is unsigned, signed-untrusted or unknown. | No. |
| `cfm kernsec secure-tmp --size <N>G` | Carve `/tmp` + `/var/tmp` into a hardened loop filesystem (reboot to activate). `--dry-run` shows the plan. | Yes, unless `--dry-run`. |

Flag notes:

- `--yes` skips the interactive safety preview and confirmation. Use it only
  for unattended runs whose preview was already reviewed.
- `--force-unsafe` acknowledges a `state = force` override on a rule the host
  profile would have skipped. Without it, `apply` and `disable` refuse.
- `disable --force` proceeds when the existing `kernsec.conf` is malformed or
  unreadable (its overrides are lost).
- `monitor enable` writes the path of the running `cfm` binary into the
  service's `ExecStart`.

The TUI can queue per-rule overrides; committing them writes `kernsec.conf`
and runs the same apply path (with the unload pass). The flash line carries
the unload summary, e.g. "applied 7 change(s) — 5 unloaded, 2 busy (will
clear at reboot)".

Check-mode exit codes (`status --check`, `apply --check`):

| Exit code | Meaning |
|---|---|
| `0` | Clean. |
| `1` | Drift or warnings found. |
| `2` | Indeterminate. The monitor service treats this as success. |

## Config

`/etc/cfm/kernsec.conf` is root-only (`0600`):

```ini
# /etc/cfm/kernsec.conf
tier = 1

[rule "KSEC-MOD-net.legacy-014"]
state = skip

[rule "KSEC-SCT-tier2.namespace-001"]
state = force
```

`tier` is the highest tier selected by default: `0` (audit only), `1`
(default), `2` (server-aggressive, opt-in) or `3` (aggressive, explicit
opt-in). Any other value is a parse error.

Per-rule `state`:

- `default` — follow tier and host-profile decisions.
- `skip` — never apply the rule.
- `force` — apply the rule regardless of tier and host-profile gate. A force
  over a host-profile skip needs `--force-unsafe`. A force can also take a
  sysctl key another cfm component owns; `apply` reports that conflict.

An override for an unknown rule ID is a warning (and makes `status --check`
fail), so typos surface.

## Files managed

| Path | Written by | Notes |
|---|---|---|
| `/etc/cfm/kernsec.conf` | `init`, `disable`, the TUI, operator | Primary config. |
| `/etc/sysctl.d/99-cfm-kernsec.conf` | `apply`, `disable`; removed by `rollback` and `--purge` | Unsupported kernel keys are written as commented skipped lines. |
| `/etc/modprobe.d/cfm-kernsec.conf` | `apply`, `disable`; removed by `--purge` | `blacklist <module>` plus `install <module> /bin/false`. |
| `/etc/default/grub` | GRUB backend | Only `GRUB_CMDLINE_LINUX` is written; `_DEFAULT` is read for audit/drift only. |
| `/etc/kernel/cmdline` | Proxmox backend | Followed by `proxmox-boot-tool refresh`. |
| BLS entries via `grubby` | BLS backend | `grubby --update-kernel`; rescue/debug kernels excluded. |
| `/etc/fstab`, systemd `tmp.mount` drop-in | `apply` / `disable` (mount rules), `secure-tmp` | See "fstab / mount rules". |
| `/etc/systemd/system/cfm-kernsec-check.service` | `monitor enable/remove` | Runs `cfm kernsec apply --check`. |
| `/etc/systemd/system/cfm-kernsec-check.timer` | `monitor enable/remove` | Drift-check timer. |
| `/var/lib/cfm/kernsec-{grub,proxmox,bls}-cmdline.cfm-kernsec.bak` | bootloader backends | Pre-apply snapshots of kernsec-managed boot args only. |
| `/run/lock/cfm-kernsec.lock` | mutating commands | Advisory lock against concurrent writers. |

Runtime sysctl apply: `apply` renders the drop-in (the persistent source for
boot), then, after file writes and the bootloader refresh succeed, runs
`sysctl -w key=value` for each active line. Failures do not stop later keys;
they are reported together with the drop-in line, key, value and kernel
error. Commented and malformed lines are not applied.

Backups:

- Managed sysctl and modprobe files get a one-shot `.cfm-kernsec.bak` before
  the first edit. If operator-edited lines are found, kernsec also keeps a
  timestamped backup and warns.
- GRUB and Proxmox keep managed-argument snapshots under `/var/lib/cfm/`.
  Legacy `.cfm-kernsec.bak` bootloader-file backups are fallback data for
  older rollback records only.
- The BLS snapshot comes from `grubby --info=ALL`, keyed by kernel image
  path, and holds only kernsec-managed args.
- Backups are never removed, `--purge` included.

## Cross-component sysctl ownership

`internal/managedsysctl` is the cfm-wide registry of which component owns
each managed sysctl key. It is ownership metadata, not a shared render
pipeline.

- `cfm-sysctl-tweaks` (`internal/sysctl`) registers its catalog there.
- kernsec consults the registry while resolving rules. A key another
  component owns resolves to `EXT`: kernsec audits the live value against its
  recommendation but never writes it to its drop-in or with `sysctl -w`.
- `state = force` is the explicit override. kernsec then writes the key too,
  and `apply` prints an ownership-conflict line ("last writer wins at
  runtime") instead of hiding it.
- If `cfm-sysctl-tweaks` is disabled in the main cfm config, the registry
  still treats its keys as externally owned.
- Each component keeps its own files and apply path; kernsec does not change
  how `cfm-sysctl-tweaks` writes.

## Rule tiers

| Tier | Meaning | Operator expectation |
|---|---|---|
| 0 | Audit only | Nothing selected unless forced; status still audits. |
| 1 | Default | Safe across typical hosting, KVM, cPanel, EL and Debian hosts. |
| 2 | Server-aggressive | Opt-in; can affect availability, diagnostics, containers or hosting panels. Host-profile gates skip known-risk hosts unless forced. |
| 3 | Aggressive | Explicit opt-in; measurable cost the operator signs up for. |

Per-rule decisions shown by `status`, `preview` and the TUI: `APPLY`,
`SKIP-CONF`, `SKIP-TIER`, `SKIP-HOST`, and `EXT` (sysctl owned by another cfm
component).

## Rule catalog

Rule IDs are stable: `KSEC-<class>-<group>-<NNN>`, class `SCT`, `BOOT`,
`MOD` or `FS`, plus the one-off `KSEC-LSM-bpf-001`. The registry
(`profile.go`, `modules.go`, `mounts.go`) is the source; `cfm kernsec
preview` lists every rule with its ID and decision on this host.

### Sysctl rules applied by kernsec

| Group | Tier | Settings | Operator impact |
|---|---:|---|---|
| `kspp.kernel` | 1 | `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=2` (accepts `1`), `kernel.randomize_va_space=2`, `kernel.perf_event_paranoid=3` (accepts `2` and `4`), `kernel.yama.ptrace_scope=2`, `vm.mmap_min_addr=65536` (accepts `131072`, `262144`) | Restricts unprivileged kernel visibility, BPF, perf and ptrace. See below for `ptrace_scope`. |
| `kspp.fs` | 1 | `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`, `fs.protected_fifos=2`, `fs.protected_regular=1` | `protected_regular` is 1, not 2: 2 also covers group-writable sticky dirs and breaks cPanel's DNS Zone Editor. A foreign `=2` is reconciled on apply (below). |
| `kspp.net` | 1 | `net.core.bpf_jit_harden=2` | Minor BPF JIT cost. |
| `sysctl.mem.exploit` | 1 | `vm.unprivileged_userfaultfd=0`, `vm.mmap_rnd_bits=32`, `vm.mmap_rnd_compat_bits=16`, `kernel.warn_limit=10`, `kernel.oops_limit=10`, `fs.suid_dumpable=0` | Removes common LPE primitives. Unsupported keys are skipped. |
| `sysctl.kernel.surface` | 1 | `dev.tty.ldisc_autoload=0`, `kernel.sysrq=0` | No TTY line-discipline autoload, no Magic SysRq. |
| `sysctl.kernel.kexec` | 1 | `kernel.kexec_load_disabled=1` | Blocks loading a replacement kernel post-boot (rootkit persistence). Sticky until reboot. Not a KernelCare / Ksplice or package-update conflict. Conflicts with kdump only, so it is gated on `HasKdump`. |
| `sysctl.net.harden` | 1 | `net.ipv4.icmp_echo_ignore_broadcasts=1`, `net.ipv4.conf.{all,default}.accept_source_route=0`, `net.ipv4.conf.all.log_martians=1`, `net.ipv4.tcp_rfc1337=1` | Static-IP servers unaffected. |
| `tier2.oops` | 2 | `kernel.panic_on_oops=1`, `kernel.panic=10` | Any oops becomes a reboot. |
| `tier2.namespace` | 2 | `user.max_user_namespaces=0`, `kernel.unprivileged_userns_clone=0` | Breaks rootless containers, bubblewrap, the Chromium sandbox and hosting isolation. |
| `sysctl.kernel.coredump` | 2 | `kernel.core_pattern=\|/bin/false` | Suppresses userspace core dumps globally. kdump is independent and does not gate it. |

`kernel.yama.ptrace_scope=2`: mode 1 is no longer accepted as green. Mode 2
closes the same-uid `pidfd_getfd()` exit-window race against setuid helpers
(the ssh-keysign / chage `/etc/shadow` disclosure chain, Linus commit
`31e62c2ebbfd`), which is a working exploit primitive under mode 1. A host
that needs same-uid debugging without sudo sets `state = skip` on
`KSEC-SCT-kspp.kernel-006`.

`kernel.unprivileged_bpf_disabled=2` pairs with the boot argument of the same
name: kernels built with `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y` (RHEL/Alma 9-10)
boot the knob at 1 and refuse runtime writes, so only the boot argument
lands 2.

### Sysctl rules audited as externally managed

Group `sysctl.net` is owned by `cfm-sysctl-tweaks` and renders as `EXT`:
`net.ipv4.conf.all.rp_filter=1`, `net.ipv4.conf.all.accept_redirects=0`,
`net.ipv4.conf.all.send_redirects=0`, `net.ipv4.tcp_syncookies=1`,
`net.ipv6.conf.all.accept_redirects=0`. To change those values, edit the
`SystemTweaks` fields in `cfm.conf`, not a kernsec override.

### Foreign drop-in reconcile

kernsec relies on `99-cfm-kernsec.conf` winning the `sysctl --system` order.
That order is lexical by basename, so a foreign file sorting after it — e.g.
the legacy `/etc/sysctl.d/99-kspp.conf` from the old `kspp.sh` — re-applies
its value on the next reboot, and kernsec's own drift check would not see it.

For an allowlist of keys where that revert brings back a known breakage,
`apply` reconciles foreign files:

- It scans `/etc/sysctl.d/*.conf` and `/etc/sysctl.conf`. An active line for
  an allowlisted key with a different value is commented out with a marker.
- Each edited file is backed up once to `<file>.cfm-kernsec.bak`; permissions
  are kept. A symlinked drop-in (Debian's `99-sysctl.conf -> ../sysctl.conf`)
  is edited at its target.
- Idempotent and best-effort: a failure on one file is reported, never
  aborts apply.
- A pending conflict counts as drift (`apply --check`, the monitor). The
  confirm prompt and `preview` name the files to be rewritten.
- Keys match in dotted form, so the slash form (`fs/protected_regular`) is
  caught too.
- Vendor directories (`/usr/lib/sysctl.d`, `/run/sysctl.d`) are neither
  scanned nor edited.
- `disable` does not run the reconcile.

The allowlist (`foreignReconcileKeys`, `internal/kernsec/foreign_sysctl.go`)
is one key, `fs.protected_regular`. It is not a licence to overwrite any
operator sysctl.

### Boot-argument rules

| Group | Tier | Args | Operator impact |
|---|---:|---|---|
| `kspp.boot` | 1 | `slab_nomerge`, `init_on_alloc=1`, `page_alloc.shuffle=1`, `randomize_kstack_offset=on`, `initcall_blacklist=algif_aead_init` | Memory-safety hardening; `init_on_alloc=1` costs a little on alloc-heavy loads. `initcall_blacklist` is the Copy Fail (CVE-2026-31431) mitigation for AEAD AF_ALG. |
| `boot.bug-detection` | 1 | `kfence.sample_interval=100` | Low-overhead KFENCE sampling. |
| `boot.sidechannel` | 1 | `tsx=off` | Removes Intel TSX side-channel surface. |
| `boot.bpf` | 1 | `unprivileged_bpf_disabled=2` | Pairs with the sysctl (see above). |
| `tier2.oops` | 2 | `oops=panic` | Pairs with the Tier 2 panic sysctls. |
| `tier3.mempaint` | 3 | `init_on_free=1` | With `init_on_alloc=1`, removes use-after-free read primitives. Brick-safe; combined cost ~3-8% worst case. |

kernsec owns only the keys in `ManagedBootArgKeys` (`profile.go`). It strips
stale instances of those keys, appends the desired set, and preserves every
other argument. `state = force` affects only rule IDs still in the registry;
it never resurrects a removed rule or key.

`KSEC-LSM-bpf-001` is not tied to a tier: it acts only with
`[rule "KSEC-LSM-bpf-001"] state = force`. It adds `bpf` to the existing
`lsm=` argument, keeping the other LSMs (`internal/kernsec/lsm_merge.go`).
If the cmdline has no `lsm=` argument, it changes nothing. A reboot applies
it. `status` shows it under `[LSM cmdline merge rule]`. `lsm` is not a
managed key, so `disable` and `rollback` do not remove `bpf` from it.

### Module blacklist rules

`apply` writes a `blacklist` line and an `install <module> /bin/false` line
per selected module, blocking both alias autoload and direct `modprobe`.

After writing, `apply` runs an unload pass: `modprobe -r` for every managed
module in `/proc/modules`, with a per-module status:

```
[Modules] unload pass (modprobe -r) over N managed-and-loaded module(s):
            UNLOADED   esp4
            BUSY       rxrpc            in use by another holder — will clear at reboot
            BUILTIN    sctp             compiled into the kernel — modprobe.d blacklist has no effect; needs kernel rebuild or cmdline change
```

This closes the running-kernel window (Fragnesia / Dirty Frag class) at
apply time. Host-profile-gated groups are filtered out first, so the pass
never touches a module the profile says is in use. `BUSY` never fails apply;
the blacklist keeps it out after reboot. `--no-unload` (on `apply` and
`disable`) skips the pass.

The initramfs is not rebuilt: no shipped module loads in the initramfs phase.
For a tidy initramfs, run `dracut --force` or `update-initramfs -u` by hand.

All module rules are Tier 1.

| Group | Modules | Skipped when |
|---|---|---|
| `modules.recent_cves` | `n_hdlc`, `vivid`, `watch_queue`, `binfmt_aout`, `nfc`, `nfcsim`, `pn533`, `pn533_usb`, `kcm`, `n_gsm`, `n_r3964` | — |
| `modules.recent_cves.ksmbd` | `ksmbd` | `HasKSMBDServer` |
| `modules.net.legacy` | `dccp`, `ax25`, `netrom`, `x25`, `rose`, `decnet`, `econet`, `ipx`, `appletalk`, `psnap`, `p8023`, `p8022`, `smc`, `smc_diag`, `slip`, `gtp`, `can`, `atm`, `irda`, `phonet`, `caif`, `caif_socket`, `hsr` | — (skip per rule if the host uses SMC) |
| `modules.net.legacy.llc` | `llc`, `llc2` | bridge in use: `UsesBridge`, containers, KVM host, libvirt, Proxmox |
| `modules.net.legacy.ppp` | `slhc` | L2TP or PPTP workload |
| `modules.net.legacy.sctp` | `sctp`, `sctp_diag` | `HasSCTPWorkload` |
| `modules.net.legacy.tipc` | `tipc` | `HasTIPCWorkload` |
| `modules.net.legacy.rxrpc` | `rxrpc` (CVE-2026-31635, DirtyDecrypt) | `HasAFS` |
| `modules.net.legacy.l2tp` | `l2tp_core`, `l2tp_ip`, `l2tp_ip6`, `l2tp_eth`, `l2tp_netlink`, `l2tp_ppp` | `HasL2TPWorkload` |
| `modules.net.legacy.pptp` | `pptp` | `HasPPTPWorkload` |
| `modules.net.legacy.rds` | `rds` | `HasRDSWorkload` |
| `modules.ipsec` | `esp4`, `esp6`, `ah4`, `ah6`, `ipcomp`, `ipcomp6`, `xfrm_interface`, `af_key` | `HasIPsec` |
| `modules.net.virt` | `vsock` | `IsKVMHost` |
| `modules.net.iot` | `ieee802154`, `mac802154`, `6lowpan` | — |
| `modules.fs.unused` | `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `qnx4`, `qnx6`, `omfs`, `befs`, `ufs`, `affs`, `sysv`, `nilfs2`, `gfs2`, `ocfs2`, `coda`, `reiserfs`, `adfs`, `hpfs`, `minix`, `bfs` | `HasMountedDeadFS` (the reason names the FS) |
| `modules.fs.container` | `erofs` | `HasContainers` |
| `modules.bus.bluetooth` | `bluetooth`, `btusb`, `bnep`, `hci_uart` | Bluetooth hardware |
| `modules.bus.firewire` | `firewire-core`, `firewire-ohci`, `firewire-net`, `firewire-sbp2` | FireWire hardware |
| `modules.bus.thunderbolt` | `thunderbolt` | Thunderbolt hardware |
| `modules.bus.misc` | `joydev`, `pcspkr`, `floppy` | — |
| `modules.mctp` | `mctp`, `mctp-i2c`, `mctp-serial` | `HasMCTPInBand` |
| `modules.input.userspace` | `uinput`, `uhid` | — |
| `modules.sidechannel` | `intel_rapl_common`, `intel_rapl_msr` | — |
| `modules.crypto_userapi` | `algif_hash`, `algif_skcipher`, `algif_rng`, `algif_akcipher`, `algif_aead` | — |

Why some groups exist:

- `modules.ipsec` answers the XFRM/ESP LPE class (CVE-2026-46300
  "Fragnesia" and "Dirty Frag"). AH and IPcomp ride the same XFRM path;
  `xfrm_interface` and `af_key` add XFRM surface with no hosting use.
- `llc` / `llc2` are dependencies of the `bridge` module (bridge → stp →
  llc), so any host with bridges keeps them.
- `slhc` is pulled in by `ppp_async`, `pptp` and `l2tp_ppp`.
- `modules.mctp` is in-band MCTP (OpenBMC, NVMe-MI, PCIe VDM). Classic
  Supermicro IPMI and Dell iDRAC use their own NIC and are not affected.
- `ksmbd` has had multiple LPE CVEs; some operators run it on purpose.

NFS, CIFS/SMB clients, `io_uring` and wifi modules are intentionally not
blacklisted: they have legitimate uses on some hosts.

### fstab / mount rules

| Rule ID | Mount point | Recommendation | Automated by `apply` |
|---|---|---|---|
| `KSEC-FS-mount.tmp-001` | `/tmp` | `nodev,nosuid,noexec` | Yes, persistence only (no live remount). |
| `KSEC-FS-mount.tmp-002` | `/var/tmp` | `nodev,nosuid,noexec` | Yes, persistence only. |
| `KSEC-FS-mount.tmp-003` | `/dev/shm` | `nodev,nosuid,noexec` | Yes, fstab edit plus live remount. |
| `KSEC-FS-mount.proc-001` | `/proc` | `hidepid=2` (recipe also sets `gid=`) | No — audit only (`CanEnable=false`). |

All four are Tier 1 with no host-profile gate, so a default `apply` edits
`/etc/fstab` for the three temp mounts. The direction follows the decision:
`APPLY` enables, `SKIP-TIER` / `SKIP-CONF` / `SKIP-HOST` reverts what kernsec
added. `disable` (tier 0) therefore reverts them. `noexec` on `/tmp` can break
composer, pip and hosting-panel workflows: preview first, or `state = skip`
the rule.

The audit renders `OK`, `PARTIAL` (the hint names only the missing options),
`MISSING`, `PEND` (written, waiting for reboot) or `SKIP` (not a separate
mount, or a symlink / bind sibling of another audited mount point). PARTIAL
and MISSING rows print the exact `mount -o remount,…` command and the
matching fstab or systemd `.mount` change.

`/tmp` and `/var/tmp` are persistence-only: kernsec writes an fstab edit, or a
systemd `tmp.mount` drop-in where systemd owns `/tmp`, and skips the live
remount. Every `PrivateTmp=yes` service (mysqld, named, php-fpm, nginx, exim,
…) holds bind mounts rooted in the current `/tmp`, and a live remount would
break them. The rows report `PEND` until reboot. Carve-outs:

- `/tmp` with neither an fstab line nor a `.mount` unit is refused, with a
  pointer to `cfm kernsec secure-tmp`.
- When `/var/tmp` is not a separate mount, Enable adds a
  `/tmp /var/tmp none bind` line. Existing `/var/tmp` content is shadowed,
  not deleted; use `secure-tmp` if it matters.
- On a cPanel securetmp host (`/usr/tmpDSK`), `/var/tmp` is left to
  securetmp. A bind line would create a systemd `var-tmp.mount` that races
  securetmp's own bind and can pin the old `/tmp` into a dead inode.

`/dev/shm` is tmpfs (no on-disk state; remount keeps contents; `noexec`
affects only new execs), so it is also remounted live. `size=` and `mode=` are
kept. An explicit operator `exec` / `suid` / `dev` aborts with an error instead
of being overwritten. Disable reverts only what kernsec added: systemd already
mounts `/dev/shm` `nosuid,nodev` (`MountRule.DefaultLiveOptions`), so the
revert is `mount -o remount,exec /dev/shm`. A line kernsec authored is removed
whole; on an operator line only kernsec's additions are stripped.

`/home` is not audited: panels with setuid helpers, NFS homes and CageFS
layouts vary too much for one recommendation.

#### `/proc hidepid=2,gid=<group>` — operator-applied process-table hiding

kernsec never automates this rule at any tier: every site has some
`ps`-scraping agent kernsec cannot know in advance.

Without `hidepid`, every vhost user can read other tenants'
`/proc/<pid>/{cmdline,status,environ,fd,maps}`: sshd command lines,
`mysql -p<password>` arguments, address-space layouts (a KASLR leak) and
admin sessions. `hidepid=2` hides other users' `/proc/<pid>` from non-root
users outside the escape group.

The audit checks the `hidepid` token only; `gid=` shows as a number in
`/proc/mounts`. `hidepid=invisible` (kernel 5.8+), `hidepid=4` and
`hidepid=ptraceable` also satisfy it.

Recipe:

1. Create the escape group:
   ```
   groupadd --system cfmprocreaders
   ```
2. Add the non-root monitoring users that read `/proc` (e.g. `netdata`,
   `munin`, `zabbix`, `nrpe`) and restart them:
   ```
   usermod -aG cfmprocreaders netdata
   usermod -aG cfmprocreaders zabbix
   systemctl restart netdata zabbix-agent
   ```
3. Set the options in `/etc/fstab` (append to an existing `proc` line, or
   add one):
   ```
   proc   /proc   proc   defaults,hidepid=2,gid=cfmprocreaders   0 0
   ```
4. Apply live:
   ```
   mount -o remount,hidepid=2,gid=cfmprocreaders /proc
   ```
5. Verify: a non-root, non-group user's `ps aux` shows only their own
   processes; root and group members see everything.

Unaffected (all run as root): cPanel/WHM Process Manager, DirectAdmin
daemons, lve-stats, cl-smart-advice, Imunify360, KernelCare. A cPanel user's
own Process Manager shows only that user's processes — the intended effect.
CageFS has its own `/proc` namespace. Needs the escape group: Munin `proc_*`
plugins, Netdata `apps.plugin`, Zabbix per-process discovery, New Relic /
Datadog process metrics.

#### `cfm kernsec secure-tmp` — operator-invoked /tmp + /var/tmp hardening

`cfm kernsec secure-tmp --size <N>G` (1G to 256G) puts `/tmp` and `/var/tmp`
on a dedicated hardened filesystem. It is a separate verb because activation
needs a reboot.

1. **Pre-flight.** Refuses if `/tmp` or `/var/tmp` is already a separate
   mount or has an fstab entry, if `/var/tmpDSK` exists, if `/var` has less
   than `<size> + 1G` free, or if `<size>` exceeds 50% of free space.
2. **Backing file.** `fallocate` `/var/tmpDSK` (mode `0600`), then
   `mkfs.ext4 -F -L cfm-securetmp`.
3. **Stage `/var/tmp`.** Mount at `/mnt/.cfm-newtmp`, `chmod 1777`, copy
   `/var/tmp`'s top-level entries except `systemd-private-*`. `/tmp` is not
   copied (it is wiped at boot anyway).
4. **Unmount** the scratch path and remove it.
5. **Append `/etc/fstab`**, backing it up once to
   `/etc/fstab.cfm-kernsec.bak`:
   ```
   /var/tmpDSK  /tmp      ext4  loop,nofail,nodev,nosuid,noexec,rw  0 0
   /tmp         /var/tmp  none  bind,nofail                          0 0
   ```
   `nofail` keeps a damaged or missing `/var/tmpDSK` from dropping the host
   into emergency mode at boot (fsck pass is 0). `/tmp` then falls back to an
   unhardened root directory, but the host stays reachable. Hosts that ran
   `secure-tmp` before `nofail` was added should add it to both lines by hand.
6. **Stop.** The operator reboots. The verb never unmounts the live `/tmp`:
   `PrivateTmp=yes` services pin it (`EBUSY`), and remounting under them
   risks stale descriptors.

`--dry-run` prints the plan (size, device, fstab lines, staged entry count).

Revert: `cp /etc/fstab.cfm-kernsec.bak /etc/fstab`, then
`umount /var/tmp /tmp` (or reboot), then `rm /var/tmpDSK`.

## Intentionally unsupported

`kernel.modules_disabled=1` is unsupported. It is one-way until reboot and
needs careful late-boot ordering so every required module loads first.

## Considered but not shipped

These three knobs (from the afflicted.sh "every kernel mitigation on
Resolute" writeup) were prototyped and held back because their auto-skip
probes are not reliable or cheap enough. `TestHeldBackRules_*`
(`profile_articleborrow_test.go`) keeps them out of the registry.

### `kernel.io_uring_disabled=2` — Tier 2

Removes io_uring as a kernel-spray substitute once BPF maps are blocked
(kernel 6.6+).

**Held back because:** the auto-skip probe walked `/proc/[0-9]*/fd/*` for
`anon_inode:[io_uring]` on every `DetectHostProfile()` call — every `status`,
`apply`, `preview` and TUI run. On a host with 10k+ pids that is hundreds of
thousands of `readlink()` calls.

**Re-land when:** host-profile probes can run on demand (only when the rule
is decided) or are cached with mtime invalidation.

### `vsyscall=none` — Tier 3

Removes the fixed-address legacy vsyscall page (a ROP target); the kernel
default `xonly` already blocks the worst uses.

**Held back because:** the legacy-binary probe scanned up to 4000 ELFs per
call and flagged every static binary (all Go binaries, `cfm` included). The
correct signal needs `Elf_Verneed` parsing for the highest bound glibc
version, and the binaries that would break on cPanel / CloudLinux / CageFS
live in customer chroots the probe never scanned.

**Re-land when:** the probe parses `Elf_Verneed`, covers panel chroots, and
has bounded cost.

### `debugfs=off` — Tier 3

Removes the whole `debugfs` surface (`tracefs` is a separate mount).

**Held back because:** putting `debugfs` in `ManagedBootArgKeys` would strip
an operator's own `debugfs=` on every apply, even below Tier 3, breaking the
"unmanaged args are preserved" contract. Its consumer probe had the same
per-call cost as io_uring's.

**Re-land when:** apply can strip a managed key only when its rule is being
applied, and the probe is on demand.

## Removed boot arguments

### `efi=disable_early_pci_dma` — removed 2026-07-19

Was Tier 1 (`KSEC-BOOT-dma-001`, group `boot.dma`), closing the pre-IOMMU DMA
window at `ExitBootServices`.

**Why removed:** it hung a production UEFI host at boot. The root `mdraid`
array sat behind a power-managed PCIe storage controller; with early PCI DMA
cut, the array never assembled. The kernel's `CONFIG_EFI_DISABLE_PCI_DMA`
help warns it "can cause failures to boot". For a hosting fleet the
availability risk outweighs the narrow benefit.

**Consequences:**

- kernsec writes it on no tier, and `efi` is not in `ManagedBootArgKeys`, so
  an operator's own `efi=` is never stripped.
- For the same reason, `apply` / `disable` / `rollback` do not remove an
  `efi=disable_early_pci_dma` an older kernsec wrote. Remove it by hand, e.g.
  on legacy-GRUB EL9:

  ```bash
  cp -a /etc/default/grub /root/grub.$(date +%F).bak
  sed -i 's/ *efi=disable_early_pci_dma//' /etc/default/grub
  grub2-mkconfig -o /boot/grub2/grub.cfg
  ```

- `TestHeldBackRules_NotInBootArgRegistry` keeps the arg, its ID and the key
  out of the registry.

## Host-profile gates

A host-profile gate skips a rule group where it would break a workload the
host evidently runs. A positive signal skips the group (`SKIP-HOST`, with the
reason); `state = force` plus `--force-unsafe` overrides it. The gates live
in `HostProfile.SkipReason` (`profile_probe.go`).

| Group | Skipped when |
|---|---|
| `tier2.namespace` | Processes in non-init user namespaces; containers; a hosting panel. |
| `tier2.oops` | KVM host; libvirt; Proxmox; containers; live patching (KernelCare / Ksplice / kpatch / kgraft); a hosting panel. |
| `sysctl.kernel.coredump` | A hosting panel; backup agents; monitoring / crash-diagnostic agents; KVM host or libvirt; containers. |
| `sysctl.kernel.kexec` | kdump: `crashkernel=` in `/proc/cmdline` or `kdump.service` installed. |
| `modules.*` | See the "Skipped when" column of the module table. |

"Hosting panel" means cPanel (`/usr/local/cpanel`), DirectAdmin
(`/usr/local/directadmin`), CloudLinux LVE (`/proc/lve` or a loaded
`lve`/`kmodlve`), CageFS (`/etc/cagefs` or `cagefsctl`) or Imunify360.

Signals:

| Signal | Detected from |
|---|---|
| Containers | Container daemons, shims, runtime sockets or nspawn machines (`runc`, `containerd`, `dockerd`, `crio`, `podman`, `kubelet`, LXC/LXD, Kata, gVisor). |
| `IsKVMHost` | A loaded `kvm_intel`/`kvm_amd` **and** hypervisor evidence: a `vhost*` module, libvirt, Proxmox, or a running QEMU. A bare-metal box where kvm merely auto-loaded is not a KVM host. |
| `UsesBridge` | Any `/sys/class/net/*/bridge`. |
| Proxmox | `/etc/pve`, Proxmox boot UUIDs, `proxmox-boot-tool`, or the Proxmox EFI path. |
| Live patching | `kcarectl` / KernelCare paths / `kcare.service`; `uptrack-upgrade` / Uptrack paths; loaded `kcare`, `kpatch*`, `kgraft`, `ksplice*`, `livepatch*` modules. |
| Backup workloads | Veeam, Acronis, JetBackup, Bareos, Bacula, UrBackup and backup-named services. |
| Monitoring workloads | node_exporter, Zabbix, Datadog, Elastic Agent, Telegraf, ABRT, Apport, systemd-coredump. |
| `HasIPsec` | Non-empty `/proc/net/xfrm_policy` or `/proc/net/pfkey`. |
| Bluetooth / Thunderbolt / FireWire | Non-empty `/sys/class/bluetooth`, `/sys/bus/thunderbolt/devices`, `/sys/bus/firewire/devices`. |
| `HasMCTPInBand` | Non-empty `/sys/bus/mctp/devices` or `/sys/class/mctp`, or a netdev of `type=290` (ARPHRD_MCTP). |
| `HasSCTPWorkload` | `sctp` loaded, `/proc/net/sctp`, `sctp_darn`, Nagios `check_sctp`, or a `*sctp*.service`. WebRTC's userspace usrsctp is not a signal. |
| `HasTIPCWorkload` | `tipc` loaded, `/proc/net/tipc`, `tipc-config`, or a `*tipc*.service`. The iproute2 `tipc` binary is not a signal. |
| `HasAFS` | `rxrpc` / `kafs` / `openafs` loaded, `/afs` mounted, or OpenAFS tooling. |
| `HasL2TPWorkload` | `l2tp_*` loaded, `/proc/net/l2tp*`, or xl2tpd / kl2tpd / accel-ppp. |
| `HasPPTPWorkload` | `pptp` loaded, `/etc/pptpd.conf`, or pptpd / accel-ppp. |
| `HasRDSWorkload` | `rds` loaded, `/proc/net/rds*`, or Oracle indicators (`/etc/oratab`, `lsnrctl`, `/u01/app/oracle`). |
| `HasMountedDeadFS` | A `modules.fs.unused` filesystem in `/proc/mounts` or `/etc/fstab`. |
| `HasKSMBDServer` | `ksmbd` loaded, `/sys/class/ksmbd` populated, `ksmbd.mountd` or `/etc/ksmbd`, or `ksmbd.service`. |

Informational only (no gate): DKMS / akmods / out-of-tree modules, ZFS and
NVIDIA (advisory below), NFS mounts, EFI boot.

### Advisories — soft warnings on Apply decisions

`HostProfile.Advisories(id, group)` adds notes to rules that still apply.
They print as `note:` lines in `preview`, `Note:` lines in the TUI detail
pane, and in the per-rule `advisories` field of `status --json`.

| Rule ID | Triggers when | Advisory |
|---|---|---|
| `KSEC-SCT-kspp.kernel-003` (`unprivileged_bpf_disabled=2`) | `HasDevTools` | Root tooling keeps working; unprivileged eBPF and non-root `bpftool` are blocked. |
| `KSEC-SCT-kspp.kernel-006` (`yama.ptrace_scope=2`) | `HasDevTools` | `gdb --attach`, `strace -p`, `py-spy`, `bpftrace -p` on your own processes need sudo. |
| `KSEC-SCT-kspp.kexec-001` (`kexec_load_disabled=1`) | live patching | Compatible, but adds nothing to live patching's protection. |
| `KSEC-BOOT-tier3.mempaint-001` (`init_on_free=1`) | `HasZFS` or `HasNVIDIA` | May add measurable alloc cost on those subsystems; benchmark first. |

### CloudLinux LVE vs. cgroup mode (status advisory)

On CloudLinux LVE / CageFS hosts, `status` prints
`[CloudLinux LVE / cgroup mode]` and WARNs when the host runs pure unified
cgroup v2. LVE needs the v1 controllers; under pure v2 per-tenant limits are
silently not enforced (`dmesg` fills with `os_resource_push … rc=-2`). Fix:
add `systemd.unified_cgroup_hierarchy=0` to the cmdline and reboot.

The argument is operator/distro-owned, not a managed key, so kernsec only
reports it. Detection: `/sys/fs/cgroup/cgroup.controllers` at the mount root
means pure v2 (`HostProfile.CgroupV2Unified`); v1 and hybrid do not warn.

## Bootloader backends

Detected in this order:

| Backend | Detection | Write and refresh |
|---|---|---|
| Proxmox / systemd-boot | `proxmox-boot-tool` in `PATH`, `/etc/kernel/cmdline`, and Proxmox evidence in `/proc/cmdline` or `proxmox-boot-tool status` | Writes `/etc/kernel/cmdline`, runs `proxmox-boot-tool refresh`. |
| BLS / grubby | `/boot/loader/entries` and `grubby`; GRUB config references `blscfg` or `GRUB_ENABLE_BLSCFG=true` (`=false` wins) | `grubby --update-kernel` per non-rescue, non-debug kernel from `grubby --info=ALL`; no separate refresh. |
| GRUB | fallback | Rewrites `GRUB_CMDLINE_LINUX`, regenerates `grub.cfg` (`update-grub` or grub-mkconfig). |

- Non-kernsec boot args are preserved; only managed keys change.
- `GRUB_CMDLINE_LINUX_DEFAULT` is read, never written; managed args found
  there are reported as drift. It is read leniently: EL/CloudLinux `tuned`
  puts shell expansions there (`${GRUB_CMDLINE_LINUX_DEFAULT:+…}\$tuned_params`),
  kept verbatim. `GRUB_CMDLINE_LINUX` keeps the strict decoder, so an
  unencodable expansion there is reported, not mangled.
- Rescue and debug BLS entries are excluded from snapshot, apply, drift and
  rollback, so a bad arg never removes the recovery path.
- If the refresh fails after a write, kernsec rolls the file back to a safe
  retry state and prints manual steps if that also fails.

## Rollback/disable/purge

`cfm kernsec rollback` undoes boot-argument changes without touching the
config:

- Strips kernsec-managed args, then restores the saved managed values when a
  backend snapshot exists, and refreshes the bootloader. It never replays a
  whole saved command line.
- GRUB rewrites `GRUB_CMDLINE_LINUX`; Proxmox rewrites `/etc/kernel/cmdline`;
  BLS strips managed args from every non-rescue, non-debug kernel and
  restores saved args for kernels whose image path matches the snapshot.
- A legacy whole-file `.cfm-kernsec.bak` restore is refused if the current
  file has operator changes since that backup.
- Removes `/etc/sysctl.d/99-cfm-kernsec.conf`, so the next boot uses kernel
  defaults. Live sysctl values stay until reboot.
- Leaves `kernsec.conf` alone: the next `apply` re-applies everything.

`cfm kernsec disable --yes` turns kernsec off persistently:

- Writes `tier = 0` to `/etc/cfm/kernsec.conf` and runs apply with it: strips
  managed boot args, writes empty managed sysctl and modprobe files, and
  reverts the automated mount options.
- Keeps per-rule overrides. A `state = force` rule is still applied at
  tier 0; remove force stanzas first for a full disable.
- Refuses a malformed or unreadable `kernsec.conf` unless `--force` or
  `--purge`.
- Live sysctl values stay until reboot.

`cfm kernsec disable --purge --yes` also removes `/etc/cfm/kernsec.conf`,
`/etc/sysctl.d/99-cfm-kernsec.conf`, `/etc/modprobe.d/cfm-kernsec.conf` and
the monitor units. A later `apply` creates a fresh `tier = 1` config.

Neither command removes backups or snapshots, nor `bpf` from `lsm=`. Use
`--dry-run` to inspect first; use `--no-refresh` only when the bootloader
refresh is handled separately.

## Monitor timer

`cfm kernsec monitor enable` installs a timer that runs
`cfm kernsec apply --check`. The default interval is `daily`; `--interval`
takes any systemd `OnCalendar` value (`hourly`, `weekly`,
`*-*-* 03:00:00`). The service has `SuccessExitStatus=2`, so an
indeterminate check retries on the next fire; drift fails the unit
(`systemctl is-failed`, the journal).

## Coexistence with cfm-lsm

kernsec (static kernel-surface reduction) and cfm-lsm (runtime BPF LSM
enforcement) are paired layers with no overlapping managed surface:

- kernsec manages **sysctls, boot args, modules, mounts**: less to pivot
  through after a userspace compromise.
- cfm-lsm manages **BPF LSM hooks at runtime**: it detects (or, in enforce
  mode, blocks) post-exploit patterns such as memfd exec and reverse-shell fd
  patterns that no sysctl can express.

Intentional non-overlaps:

- `kernel.yama.ptrace_scope=2` is kernsec's (Tier 1). The `CFML-OBS-001`
  ptrace-lockdown idea was dropped from cfm-lsm because kernsec covers it at
  a cheaper layer.
- `lsm=…,bpf` is managed by the opt-in `KSEC-LSM-bpf-001` (see "Boot-argument
  rules"). cfm-lsm's preflight still prints the remediation when `bpf` is
  missing from `/sys/kernel/security/lsm`.
- Module-load lockdown (and cfm-lsm's draft `CFML-SELF-002`) is excluded: it
  conflicts with KernelCare / Ksplice module reloads. kernsec hardens what can
  stay static; cfm-lsm watches what has to stay live.

kernsec state shows in `cfm kernsec status`, cfm-lsm state in
`cfm lsm status`; cfm-lsm events use the same notify pipeline as other
detectors. See [`docs/cfm-lsm.md`](./cfm-lsm.md).

## Compatibility notes

- Unsupported sysctl keys are commented out as skipped rather than failing
  apply; a later kernel picks up the same intent.
- `initcall_blacklist=algif_aead_init` and the `algif_*` blacklist can affect
  userspace AF_ALG consumers.

## Operator runbook

```sh
cfm kernsec status                         # 1. current state (--json for tooling)
sudo cfm kernsec init                      # 2. default tier = 1 config, if absent
sudo cfm kernsec preview --only-apply      # 3. what apply would do (mount rules edit /etc/fstab)
                                           # 4. review SKIP-HOST rows; override only with the host owner's OK
sudo cfm kernsec apply                     # 5. interactive; --yes only for reviewed unattended runs
                                           # 6. reboot for boot args and /tmp, then:
cfm kernsec status --check
sudo cfm kernsec monitor enable --interval=daily   # 7. drift monitoring
cfm kernsec monitor status
```

- Tier 2 or 3: set `tier` in `/etc/cfm/kernsec.conf`, then preview and apply
  again. Treat it as a per-host change request.
- Undo a boot-argument apply: `sudo cfm kernsec rollback --dry-run`, then
  without `--dry-run`.
- Turn kernsec off, keeping backups: `sudo cfm kernsec disable --yes`.
- Uninstall config and files, keeping backups:
  `sudo cfm kernsec disable --purge --yes`.
