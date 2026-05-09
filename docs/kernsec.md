# CFM kernsec — Kernel Attack Surface Reduction

## Status

Design phase. **`kspp.sh` is sunset** once kernsec lands — kernsec absorbs
everything that script does (KSPP sysctls + boot args + cross-bootloader
backends + status verification + Copy Fail mitigation), then extends it into a
first-class cfm component: module blacklists, additional sysctls, fstab audit,
drift detection, and rule-ID + group selectors so operators can opt rules in
or out at fleet scale. Single tool, single config, single audit surface.

Motivation: 2025-2026 saw multiple public kernel zero-day LPEs (Dirty Frag /
CVE-2026-31431 Copy Fail, ksmbd parade, watch_queue / Dirty Cred). Most of the
exploited code paths live in modules a typical hosting / KVM / cPanel / EL /
Debian server never uses. Disabling them is the highest-ROI defensive work
available right now and costs effectively nothing.

Out of scope: file integrity monitoring (AIDE / Samhain territory), runtime
exploit detection (LKRG — explicitly dropped, too fragile to ship by default),
generic CIS-benchmark compliance.

---

---

## What kernsec absorbs from `kspp.sh`

Everything `kspp.sh` does today must work identically in `cfm kernsec`. Nothing
regresses. Concretely:

**Bootloader backend abstraction.** Auto-detects and writes through the right
backend, no operator config needed:

- **Proxmox boot tool / systemd-boot** — `proxmox-boot-tool` present,
  `/etc/kernel/cmdline` exists, current boot uses `\EFI\proxmox\` initrd, or
  `proxmox-boot-tool status` reports configured ESPs. Edits
  `/etc/kernel/cmdline`, runs `proxmox-boot-tool refresh`.
- **BLS / grubby** — `/boot/loader/entries` populated, `grubby` present,
  `GRUB_ENABLE_BLSCFG` not explicitly false, and either `blscfg` referenced in
  `grub.cfg` or `GRUB_ENABLE_BLSCFG=true`. Uses `grubby --update-kernel=ALL`.
- **Legacy GRUB** — fallback. Edits `GRUB_CMDLINE_LINUX` in `/etc/default/grub`,
  regenerates with `update-grub` / `grub2-mkconfig` / `grub-mkconfig` against
  the right output path (`/boot/grub2/grub.cfg`, `/boot/grub/grub.cfg`, or
  EFI). Backs up `/etc/default/grub` before first edit.

**Managed-key boot-arg model.** kernsec owns a fixed set of arg keys
(`MANAGED_ARG_KEYS`); enable removes any stale instances of those keys and
writes the desired set; disable removes them entirely. Other operator-set args
on the cmdline are preserved untouched.

**Sysctl apply + verify.** Render `/etc/sysctl.d/99-cfm-kernsec.conf` skipping
keys absent from `/proc/sys/...` (with a `# skipped missing sysctl: …` line
and a warning), apply with `sysctl --load`, then verify each `/proc/sys/...`
matches expected.

**Status / audit checks ported wholesale:**

- `boot_backend_label` — display which backend is in use.
- Current `/proc/cmdline` vs configured next-boot cmdline diff per managed arg
  (`OK / DIFF / MISSING`).
- Kernel log scan for `Unknown kernel command line parameters | unknown
  parameter | invalid parameter | Malformed early option`, filtered to
  managed keys only — catches kernels that silently rejected an arg.
- AF_ALG AEAD bind probe (Python) — confirms `algif_aead_init` blacklist is
  actually preventing AEAD socket creation. kernsec extends this to probe
  `algif_hash`, `algif_skcipher`, `algif_rng`, `algif_akcipher` too.
- `/sys/module/page_alloc/parameters/shuffle` runtime read.
- `mem auto-init: … heap alloc:on` line in kernel log → confirms
  `init_on_alloc` actually active.
- Kernel config inspection from `/boot/config-$(uname -r)` or `/proc/config.gz`
  (via `zcat`) — verifies `CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET=y`,
  `CONFIG_RANDOMIZE_KSTACK_OFFSET=y`, and surfaces `CONFIG_SHUFFLE_PAGE_ALLOCATOR`,
  `CONFIG_INIT_ON_ALLOC`, `CONFIG_SLUB`, `CONFIG_BPF_JIT`,
  `CONFIG_CRYPTO_USER_API*`.

**Backups.** `kspp.sh` writes `/etc/default/grub.kspp.bak` and
`/etc/kernel/cmdline.kspp.bak` once, before first edit. kernsec keeps the
same one-shot backup pattern, renamed to `.cfm-kernsec.bak`. Disable does not
remove backups.

**Copy Fail / CVE-2026-31431 mitigation.** `initcall_blacklist=algif_aead_init`
in the boot args, with a clear in-doc comment that it's a temporary mitigation
to be removed once relevant kernels are patched. Stays exactly as-is, owned
by kernsec under rule `KSEC-BOOT-kspp-005`.

**Root + idempotency.** `EUID==0` check up front, every operation idempotent,
`set -Eeuo pipefail` discipline.

Anything `kspp.sh` does that isn't listed above is also in scope — the
acceptance bar for sunsetting it is "operator runs `cfm kernsec status` and
sees a strict superset of what `kspp.sh status` showed."

**"Port" means Go rewrite, not bash exec.** cfm is a Go binary; kernsec lives
in Go alongside the rest. Do not shell out to `kspp.sh`. The bash patterns are
the contract; the implementation is Go. Keep `scripts/kspp.sh` as a working
reference to diff behaviour against during development.

---

## Reconciliation with existing cfm internals

A scan of the repo before Phase 1 starts surfaced a few things that affect the
design. Pin them here so a later session doesn't re-discover them.

**`internal/sysctl/sys_tweaks.go` already exists** and writes
`/etc/sysctl.d/99-cfm.conf`. It manages: `nf_conntrack_max` (RAM-derived),
TCP timeouts, `rp_filter`, `accept_redirects`/`send_redirects` (v4 + v6),
`route_localnet`, `tcp_syncookies`, `nf_conntrack_tcp_loose`, plus a best-effort
conntrack hashsize tweak. This overlaps directly with the planned `KSEC-SCT-net.*`
audit group.

Resolution: kernsec **audits and defers** for any setting `sys_tweaks` already
owns — render as `EXT (managed by cfm sys_tweaks)` in `status`, never write a
duplicate. Phase 6 (shared sysctl library) merges both packages so there's one
audit/apply/drift loop with rule-IDs. Until then: no double-write, no fights
over `/etc/sysctl.d/`.

**CLI dispatch is a flat switch in `cmd/cfm/main.go`** (~1263 lines, no cobra).
Existing cases include `firewall`, `dnat`, `ssl`, `webtop`, `health`, `clam`,
`debug`. kernsec lands as `case "kernsec":` in the same style. Subcommand
parsing (`status`, `enable`, `disable`, `preview`, `audit`) follows the
pattern in the `firewall` and `dnat` handlers — read those before starting.

**`internal/config/`** holds the existing config conventions. Match its
format/loader for `/etc/cfm/kernsec.conf` rather than inventing a new one.
Verify before Phase 2.

**`packaging/`** is where deb/rpm bits live. Phase 3 needs:

- `/etc/modprobe.d/cfm-kernsec.conf` installed/removed on package upgrade.
- `/etc/sysctl.d/99-cfm-kernsec.conf` ditto.
- The late systemd unit for `kernel.modules_disabled=1` (Tier 2) packaged but
  not enabled by default.

**Internal packages worth using rather than reinventing**: `internal/logging`,
`internal/config`, `internal/diagnostics`. Don't roll a new logger.

**Test infrastructure for boot-arg paths does not exist.** Phase 3's acceptance
gate ("strict superset on Proxmox + EL + Debian") needs a `BootBackend` Go
interface from day one so unit tests can mock Proxmox/BLS/GRUB without real
bootloaders. Real-host verification stays a manual gate.

**Open external questions** (resolve before/during Phase 1):

- Are kdump or DKMS modules (zfs, nvidia) in use on cfm fleets? Affects
  whether `kernel.kexec_load_disabled=1` and `module.sig_enforce=1` are Tier 1
  or Tier 2 in practice.
- ssh access to a Proxmox + EL + Debian test host trio for the Phase 3
  acceptance gate.
- Confirm cfm packaging format(s) actually shipped (deb? rpm? both? install
  script?) so Phase 3 packaging work targets the right thing.

---

## Design principles

1. **Audit before mutate.** `cfm kernsec status` and `cfm kernsec preview` must
   work cleanly before `enable` is acceptable. Operators need to see the diff
   on one box before pulling the trigger on a hundred.
2. **Tier the controls.** Tier 1 is safe everywhere. Tier 2 has real
   tradeoffs and is opt-in per host role. No surprise breakage.
3. **Per-rule and per-group selectors.** Operators take Tier 1 except rule X,
   or just one group on its own. Rule IDs are stable and documented.
4. **Host profile detection.** Auto-skip rules that don't apply (don't
   blacklist IPsec on a host using `xfrm`, don't disable kexec on a kdump
   host). Skipped rules show up in status with the reason.
5. **Reuse cfm's sysctl machinery.** One audit/apply/drift-detect library,
   shared with cfm-firewall and any future component. Single source of truth
   per setting.
6. **Reversible.** Everything backed up, everything has `disable`. Boot-arg
   changes follow the same `MANAGED_*_KEYS` pattern `kspp.sh` already uses.

---

## Status state machine

Every rule reports two axes: configured (cfm wrote it) and runtime (kernel
confirms it). The `status` command renders this as a tri-state per rule:

| Configured | Runtime | Display | Meaning |
|---|---|---|---|
| yes | yes | `OK active` | Working as intended |
| yes | no | `PEND reboot` | Boot arg or module-unload pending |
| yes | n/a | `OK inert` | Module not present on this kernel — fine |
| yes | mismatch | `DRIFT` | Someone overrode it post-apply |
| no | — | `OFF` | Not enabled in cfm config |
| no | yes | `EXT` | Active by other means (distro default, another tool) |

`DRIFT` gets its own non-zero exit code so monitoring agents can alert on it.
Catches `sysctl -w` and stray `modprobe` after a fix.

---

## Rule ID scheme

```
KSEC-<class>-<group>-<NNN>
  class:  MOD | SCT | BOOT | FS
  group:  short dotted tag, see groups below
```

Examples:

- `KSEC-MOD-net.legacy-014`  — blacklist `dccp`
- `KSEC-SCT-mem.exploit-007` — `vm.unprivileged_userfaultfd=0`
- `KSEC-BOOT-kspp-002`       — `init_on_alloc=1`
- `KSEC-FS-mount.tmp-001`    — audit `nodev,nosuid,noexec` on `/tmp`

CLI selectors:

```
cfm kernsec status                                        # tri-state per rule
cfm kernsec preview enable --tier 1                       # diff, no writes
cfm kernsec enable  --tier 1
cfm kernsec enable  --tier 1 --skip KSEC-MOD-net.legacy-014
cfm kernsec enable  --group mem.exploit
cfm kernsec disable --id KSEC-SCT-net.icmp-003
cfm kernsec audit                                         # adds: loaded-but-blacklisted, fstab gaps, AF_ALG probe, userns probe
```

Selection persisted to `/etc/cfm/kernsec.conf` so `apply` is idempotent and
survives upgrades. Same backup/diff pattern `kspp.sh` already uses.

---

## Tiers

| Tier | Examples | Default |
|---|---|---|
| 1. Safe-everywhere | KSPP sysctls, blacklist of legacy network protocols, `dev.tty.ldisc_autoload=0`, `vm.unprivileged_userfaultfd=0`, `kernel.kexec_load_disabled=1` (gated on no-kdump) | enable |
| 2. Server-aggressive | `user.max_user_namespaces=0` (gated on no containers), `kernel.modules_disabled=1` post-boot, `oops=panic`, `lockdown=integrity`, `module.sig_enforce=1` (gated on no DKMS) | opt-in per role |

LKRG was considered and dropped: out-of-tree DKMS = breaks every kernel jump,
~3-5% perf hit, has had its own bugs. Not worth shipping in cfm.

---

## What we disable / harden — and why

### Module blacklists

Ship as `/etc/modprobe.d/cfm-kernsec.conf` with both `blacklist <mod>` and
`install <mod> /bin/false` lines. `blacklist` alone is bypassable by
alias-loaded names; `install … /bin/false` makes it stick.

**Group `modules.recent_cves`** — modules with documented LPE history.

| ID | Module | Why | Affects |
|---|---|---|---|
| KSEC-MOD-recent_cves-001 | `ksmbd` | Multiple in-kernel SMB server CVEs 2023-2025 | None on hosting (cfm uses NFS-over-VPN) |
| KSEC-MOD-recent_cves-002 | `n_hdlc` | TTY line discipline LPE class | None on servers |
| KSEC-MOD-recent_cves-003 | `vivid` | Virtual video driver, frequent CTF/CVE target | None |
| KSEC-MOD-recent_cves-004 | `watch_queue` | Dirty Cred vector | None |
| KSEC-MOD-recent_cves-005 | `nfc`, `nfcsim`, `pn533`, `pn533_usb` | Near-field comms stack, never present on servers | None |
| KSEC-MOD-recent_cves-006 | `binfmt_aout` | Dead format, occasional LPE vector | None |

**Group `modules.net.legacy`** — protocols a hosting box never speaks.

| ID | Module(s) | Why | Affects |
|---|---|---|---|
| KSEC-MOD-net.legacy-014 | `dccp` | Datagram Congestion Control, multiple LPE CVEs | None |
| KSEC-MOD-net.legacy-015 | `sctp` | Stream Control, telco-only protocol | Breaks lksctp if used (unlikely on hosting) |
| KSEC-MOD-net.legacy-016 | `tipc` | Cluster IPC, has had LPEs | None |
| KSEC-MOD-net.legacy-017 | `rds` | Reliable Datagram Sockets, Oracle-internal | None |
| KSEC-MOD-net.legacy-018 | `rxrpc` | AFS RPC, never on hosting | None |
| KSEC-MOD-net.legacy-019 | `ax25`, `netrom`, `x25`, `rose` | Ham radio / X.25 | None |
| KSEC-MOD-net.legacy-020 | `decnet`, `econet`, `ipx`, `appletalk` | Dead protocols | None |
| KSEC-MOD-net.legacy-021 | `psnap`, `p8023`, `p8022`, `llc`, `llc2` | LLC encapsulations | None |
| KSEC-MOD-net.legacy-022 | `pptp`, `gtp` | VPN protocols not in scope | Breaks PPTP/GTP if used |
| KSEC-MOD-net.legacy-023 | `can`, `can_raw`, `can_bcm`, `can_gw`, `vcan` | CAN bus, automotive | None on servers |
| KSEC-MOD-net.legacy-024 | `atm`, `br2684`, `clip`, `lec`, `mpoa`, `pppoatm` | ATM stack | None |
| KSEC-MOD-net.legacy-025 | `6pack`, `mkiss`, `baycom_*`, `hostap_*` | Ham radio + old wifi | None |
| KSEC-MOD-net.legacy-026 | `irda` | Dead, gone in newer kernels | None |

**Group `modules.net.conntrack_alg`** — niche conntrack ALGs with CVE history.
Don't blanket-blacklist; opt-in.

| ID | Module | Why | Affects |
|---|---|---|---|
| KSEC-MOD-net.conntrack_alg-001 | `nf_conntrack_pptp` | LPE history | Breaks PPTP NAT |
| KSEC-MOD-net.conntrack_alg-002 | `nf_conntrack_h323` | LPE history | Breaks H.323 / VoIP NAT |
| KSEC-MOD-net.conntrack_alg-003 | `nf_conntrack_sane`, `nf_conntrack_amanda` | Niche, occasional CVEs | Breaks SANE / Amanda |

**Group `modules.fs.unused`** — filesystems no hosting box mounts.

| ID | Module | Why | Affects |
|---|---|---|---|
| KSEC-MOD-fs.unused-001 | `cramfs`, `freevxfs`, `jffs2` | Embedded FS | None |
| KSEC-MOD-fs.unused-002 | `hfs`, `hfsplus` | macOS FS | None |
| KSEC-MOD-fs.unused-003 | `udf` | Optical media FS | None |
| KSEC-MOD-fs.unused-004 | `qnx4`, `qnx6`, `omfs`, `befs`, `ufs`, `efs`, `affs`, `sysv` | Dead FS | None |
| KSEC-MOD-fs.unused-005 | `nilfs2`, `gfs2`, `ocfs2`, `coda` | Cluster / niche FS | None on hosting |

NFS / cifs / io_uring left **strictly alone** — operator depends on them.

**Group `modules.bus`** — buses/devices that don't exist on KVM/dedis.

| ID | Module | Why | Affects |
|---|---|---|---|
| KSEC-MOD-bus-001 | `bluetooth`, `btusb`, `bnep`, `hci_uart`, `bluetooth_6lowpan` | No BT on servers | None (host probe skips if `/sys/class/bluetooth/*` exists) |
| KSEC-MOD-bus-002 | `firewire-core`, `firewire-ohci`, `firewire-net`, `firewire-sbp2` | DMA attack surface | None |
| KSEC-MOD-bus-003 | `cfg80211`, `mac80211` | Wifi stack | Skipped if wifi hardware present |
| KSEC-MOD-bus-004 | `thunderbolt` | DMA / KVM hosts | None on most |
| KSEC-MOD-bus-005 | `joydev`, `pcspkr`, `floppy` | Trivial surface, no use case | None |
| KSEC-MOD-bus-006 | DVB / `dvb-usb-*`, `media` | TV tuner stack | None |

**Group `modules.sidechannel`**

| ID | Module | Why | Affects |
|---|---|---|---|
| KSEC-MOD-sidechannel-001 | `intel_rapl_common`, `intel_rapl_msr` | Platypus / CVE-2020-8694 power side-channel | Loses RAPL power telemetry |

**Group `modules.ipsec`** (host probe: skip if `ip xfrm policy` non-empty)

| ID | Module | Why | Affects |
|---|---|---|---|
| KSEC-MOD-ipsec-001 | `esp4`, `esp6`, `ah4`, `ah6`, `xfrm_user`, `xfrm6_tunnel`, `xfrm4_tunnel` | IPsec stack surface | Breaks IPsec if used |

**Group `modules.crypto_userapi`** — extends the `algif_aead` blacklist already
in `kspp.sh`.

| ID | Module | Why | Affects |
|---|---|---|---|
| KSEC-MOD-crypto_userapi-001 | `algif_hash`, `algif_skcipher`, `algif_rng`, `algif_akcipher` | Userspace crypto API surface (Copy Fail family) | Userspace tools using AF_ALG |

### Sysctls

Shipped as `/etc/sysctl.d/99-cfm-kernsec.conf`. Existing `kspp.sh` settings
stay where they are (`/etc/sysctl.d/99-kspp.conf`); `kernsec` adds a separate
file so the components don't fight.

**Group `sysctl.mem.exploit`** — high signal, low breakage.

| ID | Setting | Why | Affects |
|---|---|---|---|
| KSEC-SCT-mem.exploit-001 | `vm.unprivileged_userfaultfd=0` | Kills a huge class of LPE heap-spray techniques | Userspace userfaultfd (rare) |
| KSEC-SCT-mem.exploit-002 | `vm.mmap_rnd_bits=32` | Strong ASLR (some distros ship 28) | None |
| KSEC-SCT-mem.exploit-003 | `vm.mmap_rnd_compat_bits=16` | ASLR for 32-bit compat | None |
| KSEC-SCT-mem.exploit-004 | `kernel.warn_limit=10` | Stops WARN-spray exploits | None |
| KSEC-SCT-mem.exploit-005 | `kernel.oops_limit=10` | Stops oops-spray exploits | None |
| KSEC-SCT-mem.exploit-006 | `kernel.panic_on_oops=1` + `kernel.panic=10` | Fail-closed posture | Reboot on kernel bug instead of continuing |
| KSEC-SCT-mem.exploit-007 | `fs.suid_dumpable=0` | No core dumps from suid binaries | Lose crash diagnostics from suid |

**Group `sysctl.kernel.surface`**

| ID | Setting | Why | Affects |
|---|---|---|---|
| KSEC-SCT-kernel.surface-001 | `dev.tty.ldisc_autoload=0` | Closes the n_hdlc class entirely | None |
| KSEC-SCT-kernel.surface-002 | `kernel.kexec_load_disabled=1` | Prevents unsigned kernel kexec | Skipped if kdump enabled |
| KSEC-SCT-kernel.surface-003 | `kernel.sysrq=0` (or 4 for SAK only) | Disables magic SysRq | Lose emergency-debug shortcuts |

**Group `sysctl.namespace`** (Tier 2, host-profile gated)

| ID | Setting | Why | Affects |
|---|---|---|---|
| KSEC-SCT-namespace-001 | `user.max_user_namespaces=0` | Hard kill of unprivileged userns LPE primitives | Breaks Chromium sandbox, bwrap, rootless podman, some cPanel jails. Skipped if containers detected. |
| KSEC-SCT-namespace-002 | `kernel.unprivileged_userns_clone=0` (Debian) | Reversible variant of above | Same surface, easier rollback |

**Group `sysctl.modules`** (Tier 2)

| ID | Setting | Why | Affects |
|---|---|---|---|
| KSEC-SCT-modules-001 | `kernel.modules_disabled=1` (late systemd unit) | No module load post-boot | Cannot load any module without reboot. Apply *after* observability stack is up. |

**Group `sysctl.net`** — almost certainly already owned by cfm-firewall. Audit
only here, mark `EXT (managed by cfm-firewall)` rather than fight for
ownership. Listed for completeness:

| ID | Setting | Why |
|---|---|---|
| KSEC-SCT-net.icmp-001 | `net.ipv4.icmp_echo_ignore_broadcasts=1` | Smurf |
| KSEC-SCT-net.icmp-002 | `net.ipv4.icmp_ignore_bogus_error_responses=1` | Bogus ICMP info leak |
| KSEC-SCT-net.spoof-001 | `net.ipv4.conf.all.rp_filter=1`, `default.rp_filter=1` | Reverse-path spoof guard |
| KSEC-SCT-net.spoof-002 | `net.ipv4.conf.all.accept_source_route=0` (+ v6) | Source-routed spoof |
| KSEC-SCT-net.redirect-001 | `accept_redirects=0`, `send_redirects=0` (v4 + v6) | ICMP redirect MitM |
| KSEC-SCT-net.tcp-001 | `net.ipv4.tcp_syncookies=1` | SYN flood |
| KSEC-SCT-net.tcp-002 | `net.ipv4.tcp_rfc1337=1` | TIME_WAIT assassination |
| KSEC-SCT-net.log-001 | `net.ipv4.conf.all.log_martians=1` | Visibility |
| KSEC-SCT-net.ipv6-001 | `net.ipv6.conf.all.accept_ra=0`, `default.accept_ra=0` | RA spoof |

### Boot args (extends `kspp.sh`)

`kspp.sh` already covers: `slab_nomerge`, `init_on_alloc=1`,
`page_alloc.shuffle=1`, `randomize_kstack_offset=on`,
`initcall_blacklist=algif_aead_init`. `kernsec` adds:

**Group `boot.lockdown`** (Tier 2, gated)

| ID | Arg | Why | Affects |
|---|---|---|---|
| KSEC-BOOT-lockdown-001 | `lockdown=integrity` | Kernel lockdown LSM, blocks unsigned modules / `/dev/mem` / unsigned kexec | Rarely breaks anything stock |
| KSEC-BOOT-lockdown-002 | `module.sig_enforce=1` | Only signed modules load | Breaks DKMS (zfs, nvidia). Skipped if DKMS modules detected. |

**Group `boot.bug-detection`**

| ID | Arg | Why | Affects |
|---|---|---|---|
| KSEC-BOOT-bug-detection-001 | `kfence.sample_interval=100` | KFENCE catches UAF / OOB at ~0% overhead | None measurable |
| KSEC-BOOT-bug-detection-002 | `oops=panic` | Pair with `panic_on_oops=1`; stops oops-spray | Aggressive: kernel bug = reboot |

**Group `boot.dma`** (KVM hosts with passthrough — auto-detect)

| ID | Arg | Why | Affects |
|---|---|---|---|
| KSEC-BOOT-dma-001 | `iommu=force iommu.strict=1 iommu.passthrough=0` | DMA attack surface containment | Mild perf cost on passthrough |
| KSEC-BOOT-dma-002 | `efi=disable_early_pci_dma` | Same family, EFI systems | None |

**Skipped permanently for hosting**: `init_on_free=1` (perf), `vsyscall=none`
(compat), `debugfs=off` (perf tools), `mitigations=*,nosmt` (kills capacity).

### fstab audit (report-only)

`/tmp`, `/var/tmp`, `/dev/shm`, `/home` — recommended `nodev,nosuid,noexec`.
Auto-applying breaks cPanel's `/tmp` and several composer/pip workflows, so
**report only**, never mutate. Operators decide.

| ID | Mount | Recommended |
|---|---|---|
| KSEC-FS-mount.tmp-001 | `/tmp` | `nodev,nosuid,noexec` |
| KSEC-FS-mount.tmp-002 | `/var/tmp` | `nodev,nosuid,noexec` |
| KSEC-FS-mount.tmp-003 | `/dev/shm` | `nodev,nosuid,noexec` |
| KSEC-FS-mount.home-001 | `/home` | `nodev,nosuid` (noexec breaks too much) |

---

## Host profile detection

Before applying any tier, probe the host for ~5 seconds:

| Probe | Effect |
|---|---|
| `kvm_intel` / `kvm_amd` loaded | KVM host — keep IOMMU rules |
| `runc`, `containerd`, `lxc` running | Containers — skip userns kill |
| `ip xfrm policy` non-empty | IPsec in use — skip ipsec module group |
| `cfg80211` loaded or wifi hw | Has wifi — skip wireless blacklist |
| `zfs` / `nvidia` loaded | DKMS in use — skip `module.sig_enforce` |
| kdump enabled | Skip `kexec_load_disabled` |
| `/sys/class/bluetooth/*` populated | BT hardware — flag, still allow blacklist |
| NFS mounts active | Don't touch NFS (already excluded by policy) |

Auto-skipped rules render as `SKIP (host profile: <reason>)` in `status`.
Operators override with `--force-id KSEC-...` if they really mean it.

---

## Reusing cfm's sysctl machinery

One library, three components (kernsec, firewall, future). The library:

1. Reads desired state from a rule file (id, group, key, value, runtime-check fn, doc string).
2. Renders `/etc/sysctl.d/9X-cfm-<component>.conf`.
3. Applies via `sysctl --load`.
4. Verifies `/proc/sys/...` matches.
5. Reports tri-state per rule.

Avoids the trap of three different "is this applied?" implementations drifting
apart. Also unifies backup, preview, and drift detection.

---

## Rollout plan

Each phase ships independently and has a working `status` before any `enable`
is offered.

### Phase 0 — kspp.sh as reference impl (DONE, sunset on Phase 3)

`kspp.sh` is the working proof-of-concept for the bootloader backends, sysctl
apply/verify loop, and status checks. Its logic is the contract kernsec has to
match. **Removed from the tree once Phase 3 lands** and `cfm kernsec status`
demonstrably covers everything `kspp.sh status` did. Until then it stays as
the reference behaviour.

### Phase 1 — `cfm kernsec status` (audit-only)

Read-only. Lists every rule, its tier, group, and tri-state runtime status.
Implements:

- Bootloader backend detection (Proxmox / BLS / GRUB) — ported from `kspp.sh`.
- Module presence + load detection (`/lib/modules/$(uname -r)`, `lsmod`).
- Sysctl current vs recommended (apply/verify loop ported from `kspp.sh`).
- Boot args: current `/proc/cmdline` vs configured next-boot per backend.
- Kernel-log scan for rejected/unknown managed args (ported).
- AF_ALG bind probes (extended beyond `kspp.sh`'s AEAD-only probe).
- `/sys/module/page_alloc/parameters/shuffle` + `mem auto-init` log check.
- Kernel `CONFIG_*` introspection.
- fstab audit.
- Host profile probe.

Ship this *first*. Operators run it across the fleet, see what's exposed,
build confidence in the rule set before any mutation lands.

### Phase 2 — Rule registry + selectors

Stable rule IDs, group tags, tier tags. Persistent config at
`/etc/cfm/kernsec.conf`. CLI selectors: `--tier`, `--group`, `--id`,
`--skip`, `--force-id`. `preview` subcommand prints diffs without writing.

### Phase 3 — Tier 1 enable / disable + sunset `kspp.sh`

- Module blacklist file generation (`/etc/modprobe.d/cfm-kernsec.conf`,
  both `blacklist` and `install … /bin/false` lines).
- Sysctl file generation (`/etc/sysctl.d/99-cfm-kernsec.conf`).
- Boot-arg backends ported in full from `kspp.sh` (Proxmox / BLS / GRUB),
  `MANAGED_ARG_KEYS` model preserved, backups renamed to `.cfm-kernsec.bak`.
- All KSPP-profile rules (`slab_nomerge`, `init_on_alloc=1`,
  `page_alloc.shuffle=1`, `randomize_kstack_offset=on`,
  `initcall_blacklist=algif_aead_init`) owned by kernsec under `KSEC-BOOT-kspp-*`.
- All backups, all reversible. Every rule has both directions.
- **Acceptance gate**: `cfm kernsec status` output is a strict superset of
  `kspp.sh status` output, verified on Proxmox + EL + Debian test hosts.
- `kspp.sh` removed from the repo once the gate passes.

### Phase 4 — Tier 2 (opt-in)

`user.max_user_namespaces=0`, `kernel.modules_disabled=1` (late systemd
unit), `lockdown=integrity`, `module.sig_enforce=1`, `oops=panic`. Each
gated on host profile detection.

### Phase 5 — Drift detection wiring

`cfm kernsec status --check` returns non-zero on any DRIFT, suitable for
monitoring agents. Optional periodic timer.

### Phase 6 — Shared sysctl library

Refactor: extract the audit/apply/drift loop into a cfm-internal library.
Migrate kernsec and cfm-firewall to use it. Single source of truth per
setting; `EXT (managed by cfm-firewall)` markers replaced with proper
cross-component awareness.

---

## Progress

### DONE

- `kspp.sh` server-safe profile shipping (sysctl + boot args + Proxmox/BLS/GRUB).
- `algif_aead_init` Copy Fail / CVE-2026-31431 mitigation in boot args.
- AF_ALG runtime probe in status.
- Cross-bootloader detection.
- Design doc (this file).
- `kspp.sh` committed to `scripts/kspp.sh` as the reference implementation
  (slated for removal in Phase 3 once acceptance gate passes).
- Reconciliation pass against existing cfm internals (`internal/sysctl/sys_tweaks.go`
  overlap, CLI dispatch pattern, config/packaging conventions) documented.

### TODO

- [ ] Phase 1: `cfm kernsec status` audit-only command (`case "kernsec":` in `cmd/cfm/main.go`).
- [ ] Phase 1: define `BootBackend` Go interface (Proxmox / BLS / GRUB) with mockable detection, so unit tests don't need real bootloaders.
- [ ] Phase 2: rule registry, ID/group/tier selectors, `/etc/cfm/kernsec.conf` (match `internal/config/` conventions).
- [ ] Phase 2: kernsec audits `KSEC-SCT-net.*` settings owned by `internal/sysctl/sys_tweaks.go` as `EXT (managed by cfm sys_tweaks)` — no double-write.
- [ ] Phase 2: host profile detection probes.
- [ ] Phase 3: module blacklist generator (`/etc/modprobe.d/cfm-kernsec.conf`).
- [ ] Phase 3: sysctl generator (`/etc/sysctl.d/99-cfm-kernsec.conf`).
- [ ] Phase 3: port `kspp.sh` bootloader backends (Proxmox / BLS / GRUB) into kernsec, with original `MANAGED_ARG_KEYS` model and backups.
- [ ] Phase 3: port `kspp.sh` sysctl apply/verify loop and status checks (AF_ALG probe, mem auto-init log, page_alloc.shuffle, kernel CONFIG introspection, unknown-arg dmesg scan).
- [ ] Phase 3: KSPP-profile rules registered under `KSEC-BOOT-kspp-*` (incl. Copy Fail mitigation).
- [ ] Phase 3: `preview enable` diff command.
- [ ] Phase 3: acceptance gate — `cfm kernsec status` ⊇ `kspp.sh status` on Proxmox + EL + Debian.
- [ ] Phase 3: **remove `kspp.sh` from the tree** once gate passes.
- [ ] Phase 4: Tier 2 rules with host-profile gating.
- [ ] Phase 4: late systemd unit for `kernel.modules_disabled=1`.
- [ ] Phase 5: `--check` drift exit code + monitoring hook.
- [ ] Phase 6: extract shared sysctl library, migrate `internal/sysctl/sys_tweaks.go` into it, kernsec consumes the same library.
- [ ] Document operator runbook for fleet rollout (preview-on-one,
      enable-on-canary, expand).
