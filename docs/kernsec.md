# CFM kernsec — Kernel Attack Surface Reduction

## Status

**Phase 1 shipped** (PR #766, branch `kernsec-1`). `cfm kernsec` is live as
an audit-only component with an interactive TermUI by default and a plain-
text mode for pipes / monitoring.

**Phase 3 shipped** (branch `kernsec-3`). Module blacklist generator
(`/etc/modprobe.d/cfm-kernsec.conf` with `blacklist X` + `install X /bin/false`
per applied rule), module rule wiring into apply / preview / disable / status
/ TUI. **`scripts/kspp.sh` stays in the tree** as a standalone hardening
script for hosts that don't run cfm; it also remains the reference
implementation for the cfm kernsec component. The historical "delete kspp.sh
once Phase 3 lands" plan is dropped — see "kspp.sh status" below for the
new policy.

**Phase 2 shipped** (PR #769 + #770, merged to main). Rule
registry with stable IDs (`KSEC-<class>-<group>-<NNN>`), tier and group
metadata, host-profile probe, declarative `/etc/cfm/kernsec.conf` with
per-rule overrides, and three new subcommands:

- `cfm kernsec init` — write default tier=1 conf if absent.
- `cfm kernsec preview` — read-only diff of what `apply` would do.
- `cfm kernsec apply` — write managed sysctl + boot-arg files atomically,
  run `sysctl --load`, refresh the bootloader. `--dry-run` and `--check`
  flags. First-run auto-creates the conf.
- `cfm kernsec disable` — friendly wrapper around `tier=0 + apply`.
  Strips managed boot args, empties managed sysctl file, persists
  `tier=0` to the conf. `--purge` removes the conf entirely
  (full uninstall). `--dry-run` and `--no-refresh` flags.

**Post-Phase-2 sweep complete.** Code review against the `kspp.sh`
contract surfaced two real bugs (silent read-failure paths in
`GRUBBackend.WriteCmdline` and `buildDesiredCmdline` that could have
caused apply to write a cmdline containing only managed args, dropping
`root=`, `ro`, `console=`, etc.) — both fixed and pinned by tests. See
"Sweep findings" below.

**Phase 4 shipped** (branch `kernsec-4`). Tier 2 server-aggressive
rules: `user.max_user_namespaces=0`,
`kernel.unprivileged_userns_clone=0`, `oops=panic`,
`lockdown=integrity`, `module.sig_enforce=1`. Each gated on the
existing host-profile probe (containers / DKMS / kdump). Operators
opt in by setting `tier = 2` in `/etc/cfm/kernsec.conf`.

**Phase 5 shipped** (branch `kernsec-5`). `cfm kernsec monitor`
manages a periodic drift-check systemd timer
(`cfm-kernsec-check.timer` / `.service`). Operators run
`cfm kernsec monitor enable` once and the timer fires `apply --check`
on the configured interval (default daily); drift exits non-zero so
`systemctl is-failed` and the journal surface it. `disable --purge`
auto-tears the timer down.

**`kernel.modules_disabled=1` is out of scope** for kernsec — see the
"Out of scope" section under the rollout plan. **Phase 6 (shared
sysctl library) shipped**: the new `internal/managedsysctl` package
mediates cross-component sysctl ownership; kernsec's `KSEC-SCT-net.*`
rule group resolves to `ManagedExternally` and renders as `EXT` in
status/TUI for keys owned by `cfm-sysctl-tweaks`. The Phase 1-6
rollout plan is now complete; remaining work items are
operator-facing polish (real-host smoke testing, follow-up audits).

**Post-Phase-6 audit sweep complete.** Eight new rules shipped on the
current branch:
- **`KSEC-BOOT-bug-detection-001`** (`kfence.sample_interval=100`) — Tier 1, no gate.
- **`KSEC-BOOT-dma-001`** (`efi=disable_early_pci_dma`) — Tier 1, EFI-boot gate (skipped on non-EFI/BIOS hosts).
- **`KSEC-BOOT-sidechannel-001`** (`tsx=off`) — Tier 1, no gate.
- **`KSEC-BOOT-ssbd-001`** (`spec_store_bypass_disable=seccomp`) — Tier 1, no gate.
- **`KSEC-SCT-kernel.coredump-001`** (`kernel.core_pattern=|/bin/false`) — Tier 1, kdump-gated.
- **`KSEC-SCT-net.harden-001` through `-007`** — 7 new kernsec-owned net hardening sysctls (icmp_echo_ignore_broadcasts, accept_source_route, log_martians, tcp_rfc1337, ipv6 accept_ra).
- **`cfm kernsec rollback`** — new subcommand that restores the pre-apply cmdline from `.cfm-kernsec.bak` and refreshes the bootloader. BLS backend now captures a pre-apply snapshot via `grubby --info=DEFAULT`.
- **`cfm kernsec status --json`** — machine-readable JSON output for fleet aggregation.
- **`kernel.unprivileged_bpf_disabled=1`** confirmed present as `KSEC-SCT-kspp.kernel-003` in `KSPPSysctls` (was documented in `kspp.sh` and correctly ported to the Go registry).

**`kspp.sh` status**: kept in the tree indefinitely. It started as the
reference implementation for the cfm kernsec component; with Phase 3
complete, kernsec absorbs everything kspp.sh does (KSPP sysctls + boot
args + cross-bootloader backends + status verification + Copy Fail
mitigation) and extends it (module blacklists, fstab audit, drift
detection, rule-ID + group selectors, declarative `kernsec.conf`).
**For cfm-managed hosts, use `cfm kernsec`.** kspp.sh remains useful
for the standalone case — hosts where shipping cfm is overkill or
not yet feasible. A future direction is for kspp.sh to delegate to
`cfm kernsec` when the binary is present, falling back to its
in-script bash logic otherwise; not implemented yet.

Motivation: 2025-2026 saw multiple public kernel zero-day LPEs (Dirty Frag /
CVE-2026-31431 Copy Fail, ksmbd parade, watch_queue / Dirty Cred). Most of the
exploited code paths live in modules a typical hosting / KVM / cPanel / EL /
Debian server never uses. Disabling them is the highest-ROI defensive work
available right now and costs effectively nothing.

Out of scope: file integrity monitoring (AIDE / Samhain territory), runtime
exploit detection (LKRG — explicitly dropped, too fragile to ship by default),
generic CIS-benchmark compliance.

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
acceptance bar for parity is "operator runs `cfm kernsec status` and
sees a strict superset of what `kspp.sh status` showed." With Phase 3
complete this is satisfied for the rule set; the operator-driven
acceptance gate verifies it on real hosts. kspp.sh stays in the tree
regardless — see "kspp.sh status" in the header.

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

Resolution as shipped (Phase 6): the new `internal/managedsysctl`
package owns a cross-component registry. `internal/sysctl/sys_tweaks.go`
registers a Catalog at init() time naming every key it owns;
`internal/kernsec/resolve.go::decideSysctl()` consults
`managedsysctl.Default().OwnerOf(key)` and resolves any rule whose
key falls in another component's catalog to the new
`ManagedExternally` decision (rendered as `StateEXT` / `EXT` in
`audit.go` + `status` + TUI). kernsec audits the runtime state but
never writes externally-owned keys.

Operator escape hatch: `[rule "KSEC-SCT-net.X"] state = force` in
`/etc/cfm/kernsec.conf` overrides the cross-component check —
kernsec writes its recommended value and the resulting cross-
component conflict is reported by `cfm kernsec apply` (top-of-
output `[!] cross-component sysctl ownership conflicts` block).

Edge case: when an operator sets `SYS_TWEAKS_ENABLE=0` in
`cfm.conf`, sys_tweaks's `ApplyTweaks` short-circuits and writes
nothing — but the catalog still claims those 21 keys, so kernsec
still resolves `KSEC-SCT-net.*` rules to `ManagedExternally`. The
live values surfaced in `EXT` rows will reflect whatever the
kernel/distro defaults are rather than sys_tweaks's intent. This
is intentional: the catalog must be compile-time-stable so
kernsec.Resolve can trust the cross-component view across init()
ordering. Operators who turn sys_tweaks off but want kernsec-
hardened net rules use `state = force` on each `KSEC-SCT-net.*`
rule.

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
- The Phase 5 `cfm-kernsec-check.service` / `.timer` units (operator-
  installed via `cfm kernsec monitor enable`) are not packaged —
  they're written by the binary at apply time so they reference the
  installed cfm path correctly.

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
| n/a | — | `EXT` | Owned by another cfm component (e.g. `cfm-sysctl-tweaks`) — kernsec audits the live state but never writes |

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

CLI surface as shipped:

```
cfm kernsec                                               # interactive TUI on a TTY; auto-falls back to text
cfm kernsec status                                        # plain-text per-rule audit (alias for `text`)
cfm kernsec status --check                                # exit 1 on any WARN — for monitoring
cfm kernsec status --json                                 # machine-readable JSON for fleet aggregation
cfm kernsec preview                                       # diff: what apply would select, no writes
cfm kernsec preview --tier 1 --only-apply                 # filter preview to tier 1, hide skipped
cfm kernsec preview --skip KSEC-MOD-net.legacy-014        # ad-hoc skip override (not persisted)
cfm kernsec preview --force-id KSEC-SCT-tier2.namespace-001  # ad-hoc force override (not persisted)
cfm kernsec init                                          # write default tier=1 /etc/cfm/kernsec.conf if absent
cfm kernsec apply                                         # render + write managed files; sysctl --load + bootloader refresh
cfm kernsec apply --check                                 # exit 0 (sync) / 1 (drift) / 2 (indeterminate)
cfm kernsec apply --dry-run                               # show what would change, no writes
cfm kernsec disable                                       # tier=0 + strip managed args; persistent
cfm kernsec disable --purge                               # also remove /etc/cfm/kernsec.conf and managed files
cfm kernsec disable --force                               # overwrite a malformed conf (loses overrides)
cfm kernsec rollback                                      # restore cmdline from .cfm-kernsec.bak and refresh bootloader
cfm kernsec rollback --dry-run                            # show what would be restored without writing
cfm kernsec monitor enable [--interval=daily]             # systemd timer that runs apply --check periodically
cfm kernsec monitor status                                # show timer + last service runs
```

Per-rule overrides are persisted in `/etc/cfm/kernsec.conf` via the
`[rule "ID"] state = skip|force` syntax (see Phase 2 design below).
`apply` is idempotent and survives upgrades.

---

## Tiers

| Tier | Examples | Default |
|---|---|---|
| 1. Safe-everywhere | KSPP sysctls, blacklist of legacy network protocols, `dev.tty.ldisc_autoload=0`, `vm.unprivileged_userfaultfd=0`, `kernel.kexec_load_disabled=1` (gated on no-kdump) | enable |
| 2. Server-aggressive | `user.max_user_namespaces=0` (gated on no containers), `oops=panic`, `lockdown=integrity`, `module.sig_enforce=1` (gated on no DKMS) | opt-in per role |

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
| KSEC-MOD-net.legacy-022 | `atm` | ATM stack | None |
| KSEC-MOD-net.legacy-023 | `irda` | Dead, gone in newer kernels | None |

The above is a summary of the design intent; for the canonical list of
shipped rules see `internal/kernsec/modules.go`. Rule IDs and sub-groups
in the source registry take precedence over this table when they
disagree.

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

**Group `modules.bus.*`** — buses/devices that don't exist on KVM/dedis.
The single `modules.bus` group was split in PR #780 into four sub-
groups so host-profile gating can target just the relevant subset
(skip Bluetooth without skipping Thunderbolt, etc.).

| Group | Modules | Host-profile gate |
|---|---|---|
| `modules.bus.bluetooth` | `bluetooth`, `btusb`, `bnep`, `hci_uart` | skipped if `/sys/class/bluetooth/*` non-empty |
| `modules.bus.firewire` | `firewire-core`, `firewire-ohci`, `firewire-net`, `firewire-sbp2` | none (rare hardware; operator overrides per-rule if needed) |
| `modules.bus.thunderbolt` | `thunderbolt` | skipped if `/sys/bus/thunderbolt/devices/*` non-empty |
| `modules.bus.misc` | `joydev`, `pcspkr`, `floppy` | none |

Wifi (`cfg80211` / `mac80211`) is **not** blacklisted today — the
shipped registry contains no wifi rules. The earlier "wireless
blacklist" plan was dropped: cfg80211 / mac80211 both have non-
hostable use cases (operator-managed servers can run wifi cards
intentionally), so kernsec leaves the decision to the operator. If
wifi rules are added later, they'll get their own group + host-
profile gate.
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

**Group `sysctl.kernel.coredump`** (Tier 1, kdump-gated)

| ID | Setting | Why | Affects |
|---|---|---|---|
| KSEC-SCT-kernel.coredump-001 | `kernel.core_pattern=\|/bin/false` | Pipes core dumps to `/bin/false` — prevents unprivileged processes exploiting CVE-2023-0386-class `core_pattern` injection (writing to a setuid-root process's namespace via a specially crafted core pattern). Skipped when kdump is enabled, because kdump relies on `core_pattern` to invoke its capture helper. | None on hosts without kdump. kdump hosts keep distro default. |

**Group `sysctl.namespace`** (Tier 2, host-profile gated)

| ID | Setting | Why | Affects |
|---|---|---|---|
| KSEC-SCT-namespace-001 | `user.max_user_namespaces=0` | Hard kill of unprivileged userns LPE primitives | Breaks Chromium sandbox, bwrap, rootless podman, some cPanel jails. Skipped if containers detected. |
| KSEC-SCT-namespace-002 | `kernel.unprivileged_userns_clone=0` (Debian) | Reversible variant of above | Same surface, easier rollback |

**Group `sysctl.modules`** (out of scope — see "Out of scope:
`kernel.modules_disabled=1`" under the rollout plan for the rationale)

**Group `sysctl.net`** — audit-only, owned by
`internal/sysctl/sys_tweaks.go` via the Phase 6 `managedsysctl`
cross-component registry. kernsec resolves every rule in this group
to `ManagedExternally`, prints `EXT` in status / TUI, and **never
writes the keys**. Operators tune the actual values via `cfm.conf`'s
`SystemTweaks` fields; kernsec's job here is the audit surface
(visibility into whether sys_tweaks's intent is live).

| ID | Setting | Owned by | Why |
|---|---|---|---|
| KSEC-SCT-net.spoof-001 | `net.ipv4.conf.all.rp_filter=1` | `cfm-sysctl-tweaks` | Reverse-path spoof guard |
| KSEC-SCT-net.redirect-001 | `net.ipv4.conf.all.accept_redirects=0` | `cfm-sysctl-tweaks` | ICMP-redirect MitM closure |
| KSEC-SCT-net.redirect-002 | `net.ipv4.conf.all.send_redirects=0` | `cfm-sysctl-tweaks` | Don't emit redirects (host isn't a router) |
| KSEC-SCT-net.tcp-001 | `net.ipv4.tcp_syncookies=1` | `cfm-sysctl-tweaks` | SYN flood survival |
| KSEC-SCT-net.ipv6-001 | `net.ipv6.conf.all.accept_redirects=0` | `cfm-sysctl-tweaks` | v6 redirect MitM closure |

**Group `sysctl.net.harden`** — kernsec-owned hardening settings not
covered by `cfm-sysctl-tweaks`. These keys are not in the
`managedsysctl` registry, so they resolve directly to `Apply` and are
written to `/etc/sysctl.d/99-cfm-kernsec.conf`.

| ID | Setting | Why | Affects |
|---|---|---|---|
| KSEC-SCT-net.harden-001 | `net.ipv4.icmp_echo_ignore_broadcasts=1` | Prevents smurf/broadcast amplification attacks | None |
| KSEC-SCT-net.harden-002 | `net.ipv4.conf.all.accept_source_route=0` | Source-routing bypass for firewalls | None |
| KSEC-SCT-net.harden-003 | `net.ipv4.conf.default.accept_source_route=0` | Same for newly-created interfaces | None |
| KSEC-SCT-net.harden-004 | `net.ipv4.conf.all.log_martians=1` | Logs spoofed / unroutable source addresses | Adds log volume; useful for anomaly detection |
| KSEC-SCT-net.harden-005 | `net.ipv4.tcp_rfc1337=1` | Drops RSTs in TIME_WAIT (RFC 1337 fix; prevents TCP hijack via RST in closing connections) | None |
| KSEC-SCT-net.harden-006 | `net.ipv6.conf.all.accept_ra=0` | Disables IPv6 Router Advertisement acceptance; prevents rogue-RA attacks | May interfere with SLAAC on hosts that need IPv6 auto-config via RA; operator overrides per-rule |
| KSEC-SCT-net.harden-007 | `net.ipv6.conf.default.accept_ra=0` | Same for newly-created interfaces | Same as above |

### Boot args (extends `kspp.sh`)

`kspp.sh` already covers: `slab_nomerge`, `init_on_alloc=1`,
`page_alloc.shuffle=1`, `randomize_kstack_offset=on`,
`initcall_blacklist=algif_aead_init`. `kernsec` adds:

**Group `boot.bug-detection`** (Tier 1, no gate)

| ID | Arg | Why | Affects |
|---|---|---|---|
| KSEC-BOOT-bug-detection-001 | `kfence.sample_interval=100` | **SHIPPED.** KFENCE heap safety net: one in 100 allocations is guarded — catches UAF/OOB in production at effectively zero overhead. | None measurable. |

**Group `boot.dma`** (Tier 1, EFI-boot gate)

| ID | Arg | Why | Affects |
|---|---|---|---|
| KSEC-BOOT-dma-001 | `efi=disable_early_pci_dma` | **SHIPPED.** Closes the pre-IOMMU DMA window on EFI systems. Skipped on non-EFI (BIOS/legacy) hosts — parameter is EFI-specific and a no-op there. | None on well-behaved hardware. |

**Group `boot.sidechannel`** (Tier 1, no gate)

| ID | Arg | Why | Affects |
|---|---|---|---|
| KSEC-BOOT-sidechannel-001 | `tsx=off` | **SHIPPED.** Disables Intel TSX — removes the hardware primitive exploited by TAA (CVE-2019-11135) and MDS variants. Unused by any hosting/KVM workload. | None. Non-Intel CPUs and already-patched Intel microcode ignore it. |

**Group `boot.ssbd`** (Tier 1, no gate)

| ID | Arg | Why | Affects |
|---|---|---|---|
| KSEC-BOOT-ssbd-001 | `spec_store_bypass_disable=seccomp` | **SHIPPED.** Spectre v4 / SSBD mitigation for seccomp-sandboxed processes. Distro default `prctl` is opt-in per-process; `seccomp` covers all threads under a seccomp policy (sandboxed web workloads) without the global hit of `on`. | ~1-5% syscall throughput on heavily syscall-bound seccomp workloads. |

**Group `boot.lockdown`** (Tier 2, gated)

| ID | Arg | Why | Affects |
|---|---|---|---|
| KSEC-BOOT-tier2.lockdown-001 | `lockdown=integrity` | Kernel lockdown LSM, blocks unsigned modules / `/dev/mem` / unsigned kexec | Rarely breaks anything stock |
| KSEC-BOOT-tier2.module-sig-enforce-001 | `module.sig_enforce=1` | Only signed modules load | Breaks DKMS (zfs, nvidia). Skipped if DKMS modules detected. |

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

Before applying any tier, probe the host for ~5 seconds. Probes are
intentionally over-broad: a false negative silently bricks (no
recovery without reboot once the boot arg / sysctl is loaded), a
false positive just means an operator runs `state = force` per-rule
to opt back in.

| Probe | Effect |
|---|---|
| `kvm_intel` / `kvm_amd` loaded | KVM host — keep IOMMU rules |
| Container daemon / shim / socket / nspawn machine | Containers in use — skip userns kill (full probe set: see `defaultContainerProbe()`) |
| `ip xfrm policy` non-empty | IPsec in use — skip ipsec module group |
| Out-of-tree module evidence (see below) | Skip `module.sig_enforce` and `lockdown=integrity` |
| kdump enabled (multi-distro detection) | Skip `kexec_load_disabled` AND `lockdown=integrity` (kexec primitives) AND `kernel.core_pattern` (kdump uses core_pattern for its capture helper) |
| `/sys/class/bluetooth/*` populated | BT hardware present — skip `modules.bus.bluetooth` group |
| `/sys/bus/thunderbolt/devices/*` populated | Thunderbolt hardware — skip `modules.bus.thunderbolt` group |
| NFS mounts active | Don't touch NFS (already excluded by policy) |
| `/sys/firmware/efi` present (`IsEFIBoot`) | EFI boot — `efi=disable_early_pci_dma` (`boot.dma` group) applies. On non-EFI/BIOS hosts this probe is absent and the rule is skipped as a no-op. |

Out-of-tree-module evidence (any single signal flips `HasDKMS` to
true, since any of these means `lockdown=integrity` /
`module.sig_enforce=1` would brick something the operator paid for):

- `zfs` / `nvidia` / `nvidia_drm` / `nvidia_modeset` loaded
- `/var/lib/dkms` non-empty (DKMS modules installed even if not loaded)
- `/usr/bin/akmods` or `/usr/sbin/akmods` present (akmod / ELRepo)
- KernelCare (TuxCare) — `kcarectl` binary, `/usr/lib/kernelcare`,
  `/var/cache/kcare`, `/etc/sysconfig/kcare`, or `kcare.service`
  unit file. Common on cPanel hosts; KernelCare loads vendor-signed
  patch modules that lockdown / sig_enforce would block, breaking
  CVE coverage.
- Ksplice (Oracle) — `uptrack-upgrade`, `/var/lib/uptrack`, `/etc/uptrack`
- `/usr/src/*-dkms*` source trees
- `/lib/modules/$(uname -r)/{extra,updates}` non-empty (out-of-tree
  module install dirs)

kdump multi-distro detection:

- `/sys/kernel/kexec_crash_loaded == 1` (kernel-side; only set after
  kdumpctl ran since last boot)
- `/etc/kdump.conf`, `/etc/sysconfig/kdump` (RHEL/Alma/Rocky/CentOS),
  `/etc/default/kdump-tools` (Debian/Ubuntu)
- `kdump.service` / `kdump-tools.service` unit-file presence in
  `/usr/lib/systemd/system/` or `/lib/systemd/system/`

Auto-skipped rules render as `SKIP (host profile: <reason>)` in `status`.
Operators override per-rule with `[rule "KSEC-..."] state = force` in
`/etc/cfm/kernsec.conf` (persisted), or with `preview --force-id KSEC-...`
for ad-hoc inspection.

### Pre-flight safety gate

Mutating `cfm kernsec apply` / `disable` invocations print a
"[!] About to apply:" preview at the top of output and require an
interactive `y` answer before any write happens. The preview lists:

- Every managed file path that will be mutated (sysctl drop-in,
  modprobe blacklist, /etc/default/grub etc.)
- Every boot-impacting risk in the apply set: `lockdown=*` with
  KernelCare / DKMS reminder, `module.sig_enforce=1`,
  `init_on_alloc/init_on_free` perf hint, force-overrides on
  externally-owned keys
- The backup file paths the operator can restore from manually

For unattended runs (cron, Ansible, shell-script wrappers), pass
`--yes` to skip the prompt. EOF on stdin (e.g. `echo "" | cfm
kernsec apply` without `--yes`) is treated as a decline so a piped
empty input cannot accidentally bypass the gate.

### Module deny-list (boot-critical drivers)

`apply` runs every module rule through `IsDangerousModule` before
writing `/etc/modprobe.d/cfm-kernsec.conf`. Any rule whose `Name`
matches a storage / filesystem / network / console driver pattern
(nvme*, ahci, ext4, btrfs, virtio_net, i915, drm, etc. — full list
in `internal/kernsec/safety_modules.go`) causes apply to abort
with the offending rule named.

Why a deny-list at all: dracut host-only mode (default on
RHEL/Alma/Rocky/CentOS) embeds `/etc/modprobe.d/*.conf` into the
initramfs at the next kernel package update. A blacklist on the
running root filesystem driver therefore becomes a brick at the
NEXT reboot after a kernel upgrade — a delayed, remote-install-
unfriendly failure mode. The deny-list is the belt-and-suspenders
companion to the curated rule data; `TestNoDangerousModulesInRegistry`
also runs the check at compile-time-test so the invariant can never
silently regress.

### BLS / grubby — rescue and debug kernels excluded

On BLS hosts, `WriteCmdline` enumerates kernels via
`grubby --info=ALL`, filters out any kernel image path containing
the token `rescue` or `debug` (case-insensitive, separator-aware),
and passes the remaining paths to
`grubby --update-kernel=PATH1,PATH2,...`. The rescue / debug
entries exist to recover from exactly the situation a bad managed
boot arg creates; modifying them with the same arg leaves the
operator with no recovery path.

### update-grub failure rollback

When the legacy GRUB backend's `Refresh()` (i.e. `update-grub`)
fails after `WriteCmdline` already modified `/etc/default/grub`,
applyWrites restores the file from `.cfm-kernsec.bak` before
returning the error. The operator sees the failure AND has a
clean `/etc/default/grub` to retry against. Without rollback the
NEXT legitimate `update-grub` run (kernel package install etc.)
would propagate the half-applied state into `grub.cfg` and the
bad cmdline would land at boot.

### GRUB_CMDLINE_LINUX_DEFAULT — read, don't write

`NextBootCmdline` returns the union of `GRUB_CMDLINE_LINUX +
GRUB_CMDLINE_LINUX_DEFAULT` so drift detection sees the full
cmdline GRUB will assemble at boot. kernsec WRITES only to
`GRUB_CMDLINE_LINUX`. Consequence: an operator who hand-edits a
managed kernsec arg into `_DEFAULT` will see drift flagged but
`cfm kernsec disable` cannot strip it (the disable code path only
modifies `_LINUX`). Documented undo gap.

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

## What Phase 1 actually shipped

Branch: `kernsec-1`. PR: #766.

**Package layout** (`internal/kernsec/`):

| File | Purpose |
|---|---|
| `cli.go` | Subcommand dispatch (`status`, `text`, `live`, `help`, default = TUI w/ TTY auto-fallback) |
| `profile.go` | KSPP rule data: 11 sysctls + 5 boot args, each with Description + Affects |
| `audit.go` | `BuildAuditRows()` — single source of truth feeding text + TUI |
| `backend.go` + `backend_{proxmox,bls,grub,detect}.go` | `BootBackend` interface + three impls + auto-detection (ports `kspp.sh`'s `is_proxmox_boot_tool` / `is_bls`) |
| `fs.go` | `FS` interface + `RealFS` so detection is unit-testable without real bootloaders |
| `cmdline.go` | `ParseCmdline`, `CheckBootArg` (OK/DIFF/MISSING), `RemoveManagedArgs` |
| `sysctl.go` | `ReadSysctl`, `CheckSysctl` (OK/Mismatch/Missing) |
| `probes.go` + `probes_{linux,other}.go` | Kernel CONFIG, page_alloc.shuffle, mem auto-init log, unknown-arg dmesg scan, AF_ALG bind probes (raw syscall, Linux build-tag split) |
| `status.go` | Plain-text audit output mirroring `kspp.sh status` sections |
| `tui.go` | TermUI (gizak/termui/v3) — Grid layout, ticker + PollEvents, no goroutines for fetch |
| `*_test.go` | 4 test files, table-driven, `fakeFS` for backend detection |

**Subcommands**:

```
cfm kernsec               # interactive TUI on TTY, auto-fallback to text
cfm kernsec live          # force the TUI
cfm kernsec text          # plain-text audit
cfm kernsec status        # alias for text (supports --check)
cfm kernsec status --check   # exit non-zero on any WARN (for monitoring)
cfm kernsec help          # subcommand help
```

**TUI shape**:

```
┌──────────────────────────────────────────────────────────────────┐
│ Header  cfm kernsec • boot mode: BLS / grubby • rules: 16        │
│         • warnings: 0 • updated: 19:49:29                        │
├──────────────────────────────────┬───────────────────────────────┤
│ Rules table (62%)                │ Detail panel (38%)            │
│  STATE   KIND    RULE            │  Selected: init_on_alloc=1    │
│  OK      sysctl  kernel.kptr_…=2 │  State:    OK                 │
│  OK      sysctl  fs.protected_…  │  Description: Zero pages on   │
│  OK      boot    slab_nomerge    │   allocation; kills uninit-   │
│  OK      boot    init_on_alloc=1 │   memory leaks across kernel. │
│  …                               │  Affects: ~0-5% perf cost on  │
│                                  │   alloc-heavy workloads.      │
│                                  │  Live state:                  │
│                                  │   /proc/cmdline:    present   │
│                                  │   next-boot config: present   │
├──────────────────────────────────┴───────────────────────────────┤
│ Footer  q quit • ↑/↓ nav • r refresh • t text • / filter         │
│         • ? help                                                 │
└──────────────────────────────────────────────────────────────────┘
```

Per-row state→color: `OK` green · `WARN`/`DIFF`/`MISSING` yellow · `DRIFT`
red · `SKIP` white. Cursor highlight via RowStyle bg swap.

Keybinds:

| Key | Action |
|---|---|
| `q`, `Ctrl-C` | Quit |
| `↑`/`↓` or `j`/`k` | Cursor |
| `Home`/`End` or `g`/`G` | First / last |
| `PgUp`/`PgDn` | Page |
| `r` | Re-run audit |
| `t` | Drop to text mode |
| `/` | Filter rows by substring (display, group, ID) |
| `c` | Clear active filter |
| `e` / `d` | Hint keys — flash a pointer to `cfm kernsec apply` / `disable` (TUI write-mode is intentionally not implemented; muscle-memory landing pad for shell commands) |
| `?` | Toggle help |

5-second refresh tick. No data goroutines. Non-TTY auto-falls back to
text via `golang.org/x/term IsTerminal`, matching `cfm health live`.

---

## Configuration model — `kernsec.conf` + `apply` (Phase 2 design)

The fleet workflow operators want is: ship a conf via `scp` / `git` /
Ansible, converge with one command, audit with another. cfm-firewall
already follows this shape; kernsec mirrors it.

**Three commands form the workflow**:

| Command | Writes? | Purpose |
|---|---|---|
| `cfm kernsec status` | no | Audit + show config-vs-reality (Phase 1, shipped) |
| `cfm kernsec preview` | no | Diff: "if I ran apply now, here's what would change" |
| `cfm kernsec apply` | yes | Idempotent converge: write managed files, refresh bootloader, verify |

**Config file**: `/etc/cfm/kernsec.conf` — INI-flavoured (matches the
`[rule "..."]` stanza style cfm uses elsewhere; final format gated on
checking `internal/config/` conventions before Phase 2 starts):

```ini
# /etc/cfm/kernsec.conf

# Tier selection. 1 = safe-everywhere, 2 = server-aggressive.
tier = 1

# Per-rule overrides. Default state for any rule in the selected tier
# is "applied"; these stanzas opt in or out by stable rule ID.
#
#   state = skip   -- configured but not applied (operator opt-out)
#   state = force  -- applied even if host-profile detection says skip

[rule "KSEC-MOD-net.legacy-014"]
state = skip          # we run DCCP somewhere weird

[rule "KSEC-SCT-namespace-001"]
state = force         # we know we don't run containers on this box
```

**Apply semantics**:

- Idempotent. Running `apply` twice is a no-op the second time.
- Atomic per file: write to `*.tmp`, `fsync`, `rename`. Backups taken
  once on first write (`.cfm-kernsec.bak`) and never overwritten.
- Marks every file: header `# Managed by cfm kernsec — do not edit.`.
- Targets in Phase 2 / 3:
  - `/etc/sysctl.d/99-cfm-kernsec.conf` (Phase 2).
  - Bootloader cmdline via `BootBackend` (Phase 2).
  - `/etc/modprobe.d/cfm-kernsec.conf` (Phase 3, modules).
- After writing, re-runs the audit and reports per-rule outcome.
- `apply --check` returns non-zero if config and reality disagree
  (CI / monitoring use case).
- **First-run safety**: `apply` against a host with no `kernsec.conf`
  refuses with a hint to run `cfm kernsec init` (writes a default
  `tier = 1` conf so the operator commits an explicit choice).

**Why this beats imperative `enable` / `disable`**:

- **Source of truth in one file.** `git` it, `scp` it, audit with
  `grep` / `vi` / `nano`. No "how was this box configured?" mystery.
- **Per-host overrides without forking the rule set.** A special-case
  box has one file that explains itself.
- **Drift detection becomes natural.** `apply` is idempotent → cron
  re-runs it; `status` already reports DRIFT when reality disagrees.
- **Rollback is `git revert` + `apply`**, not "flip these 14 keys".

**Open decisions (resolve at start of Phase 2)**:

1. Final conf format — INI / TOML / something else. Match
   `internal/config/` conventions.
2. Where the conf lives (`/etc/cfm/` vs `/etc/cfm.d/kernsec.conf` vs
   `/etc/cfm.conf` `[kernsec]` section) — match other cfm components.
3. Bootloader-cmdline rollback semantics: keep one backup or N
   generations? `kspp.sh` keeps one; that probably stays.
4. Whether `apply` should auto-trigger a `proxmox-boot-tool refresh`
   or `update-grub` (cost: a few seconds; benefit: idempotent
   converge). Default yes.

---

## Sweep findings (post-Phase-2)

A focused code review against the `kspp.sh` contract immediately after
Phase 2 merged. Surfaced two real bugs and a handful of robustness
gaps. All fixes landed on `kernsec-sweep` with regression tests.

### Bugs fixed

**SF-001 — `GRUBBackend.WriteCmdline` swallowed `NextBootCmdline`
errors.** The previous code used `current, _ := g.NextBootCmdline()`
which made a transient or permission read-failure indistinguishable
from "empty cmdline". `RemoveManagedArgs([])` then yields `[]`, and
appending the desired managed args produces a cmdline containing
**only kernsec-managed args** — `root=`, `ro`, `console=`,
`crashkernel=`, etc. would have been dropped. Fix: propagate the
error. Test: `TestBuildDesiredCmdline_ReadErrorPropagates`.

**SF-002 — `buildDesiredCmdline` had the same pattern**, used by
`preview` / `--dry-run` / `--check`. Same fix; test:
`TestComputeDrift_BootReadErrorSurfaced`. Apply now also refuses to
write if the read failed (`drift.BootReadErr != nil`).

### Robustness improvements

- **Drift report surfaces read errors.** `driftResult` gained
  `BootReadErr` and `SysctlReadErr` fields. Operators see the cause
  instead of a generic "DRIFT" line; `--check` exits non-zero on read
  failure so monitoring catches it.
- **`apply` refuses to write on cmdline read failure.** Closing the
  loop on SF-002.
- **`$tuned_params` literal token (Rocky 8 BLS hosts)** verified to
  pass through `rebuildManagedCmdline` unchanged. Test:
  `TestRebuildManagedCmdline_TunedParamsPassthrough` — captures the
  exact shape from the operator's real transcript.
- **Non-managed-token order preservation** verified. Test:
  `TestRebuildManagedCmdline_PreservesNonManagedOrder`.
- **Render determinism** verified — `RenderSysctlFile` produces
  byte-identical output across calls with the same input. Foundation
  for `apply --check` not false-positive after a clean apply. Test:
  `TestRenderSysctlFile_Idempotent`.
- **`tier = 0` documented semantics** verified. `tier = 0` + `apply`
  strips managed boot args from cmdline (good) and writes an empty
  managed sysctl file (good). **Limitation worth noting**: `sysctl
  --load` on a file with no key=value lines does NOT revert previously
  set live values to kernel defaults — those persist until reboot or
  until something else writes them. Operators expecting an immediate
  "back to baseline" need to reboot. Test:
  `TestResolve_Tier0NoApplyForAnything`.
- **Realistic rule IDs in conf stanzas** verified. Test:
  `TestParseSectionHeader_RealisticIDs`.
- **`state =` (empty value)** documented as alias for
  `state = default`. Test: `TestParseConf_StateEqualsEmpty`.

### Known limitations carried into Phase 3+

- **No advisory lock on `apply`.** Concurrent `cfm kernsec apply`
  invocations don't coordinate. Last writer wins on the cmdline file
  (atomic rename). With the same conf both runs produce the same
  content, so this is benign in practice — just hygiene worth
  closing later. (Phase 5 candidate.)
- **`cfm kernsec rollback` is now implemented** (`rollback.go`) and
  wired into the CLI. Backend-specific behaviour: GRUB restores
  `/etc/default/grub` from `.cfm-kernsec.bak` and re-runs
  `update-grub`; Proxmox restores `/etc/kernel/cmdline` and runs
  `proxmox-boot-tool refresh`; BLS replays the pre-apply args snapshot
  saved in `/var/lib/cfm/kernsec-bls-cmdline.cfm-kernsec.bak` (if
  present) or falls back to stripping all managed args. Operator
  recovery table updated — see Phase 2.5 section.
- **BLS pre-apply snapshot is best-effort.** `BLSBackend.WriteCmdline`
  now calls `grubby --info=DEFAULT` before any write and saves the
  pre-kernsec non-managed args to
  `/var/lib/cfm/kernsec-bls-cmdline.cfm-kernsec.bak` (one-shot;
  never overwritten). On hosts where apply was run before this version
  of cfm, no snapshot exists and `rollback` falls back to
  stripping managed args only.
- **`sysctl --load` on a file with no rules does not revert live
  values.** See tier=0 semantics above. Reboot-to-baseline is the
  contract.
- **No real-host integration test exists yet** for the three Refresh
  paths (`proxmox-boot-tool refresh`, `update-grub`, `grubby`). Phase
  3's acceptance gate (Proxmox + EL + Debian) covers this.

### Phase 3 readiness

Greenlight from this sweep. The Phase 2 surface is solid; the
remaining unknowns (real-host bootloader Refresh, module unload
semantics) are properly Phase 3 concerns covered by the existing
acceptance gate.

---

## Rollout plan

Each phase ships independently and has a working `status` before any `apply`
is offered.

### Phase 0 — kspp.sh as reference impl + standalone (DONE)

`kspp.sh` is the working proof-of-concept for the bootloader backends, sysctl
apply/verify loop, and status checks. Its logic is the contract kernsec
matched. **Stays in the tree** as a standalone hardening script for
non-cfm hosts. With Phase 3 complete, kernsec is the canonical
implementation for cfm-managed hosts; kspp.sh continues as the
in-script bash flow for everyone else.

### Phase 1 — `cfm kernsec status` + TUI (DONE — kernsec-1, PR #766)

Read-only audit-only. See "What Phase 1 actually shipped" above for the
package layout, subcommands, and TUI shape. Ports from `kspp.sh`:
bootloader-backend detection (Proxmox / BLS / GRUB), sysctl apply/verify
loop, boot-arg current-vs-next-boot diff, kernel-log scan for unknown
managed args, AF_ALG bind probes (extended), page_alloc.shuffle and
`mem auto-init` checks, kernel CONFIG introspection. Remaining audit
pieces (module presence checks, fstab audit, host-profile probe) move
to Phase 2 alongside the rule registry that needs them.

### Phase 2 — Rule registry + `kernsec.conf` + `preview` + `apply` (DONE — branch `kernsec-2`)

Shipped as two passes on the same branch. Phase 2a: registry + conf +
preview (no writes). Phase 2b: apply with writes.

**2a — registry, config, preview (no writes)**:

- Stable rule IDs (`KSEC-<class>-<group>-<NNN>`), group tags, tier tags
  attached to the existing `KSPPSysctls` and `KSPPBootArgs` data plus
  the new modules / namespace / fstab rule rows.
- `/etc/cfm/kernsec.conf` loader — match `internal/config/` conventions.
- `cfm kernsec init` — write a default `tier = 1` conf if absent.
- `cfm kernsec preview [enable|apply]` — diff against current managed
  files / cmdline. Read-only.
- CLI selectors: `--tier`, `--group`, `--id`, `--skip`, `--force-id`
  (override the conf for one-off invocations).
- TUI gains group + tier columns and a `/` filter.
- Module rule rows + fstab audit + host-profile probe land here so the
  registry has them on day one.
- kernsec audits `KSEC-SCT-net.*` settings owned by
  `internal/sysctl/sys_tweaks.go` via the new `managedsysctl`
  cross-component registry. Rules in this group resolve to
  `ManagedExternally` and render as `EXT` — no double-write,
  audit-only. (Phase 6.)

**2b — apply (writes)**:

- `cfm kernsec apply` — write `/etc/sysctl.d/99-cfm-kernsec.conf`,
  update bootloader cmdline through the existing `BootBackend`
  abstraction, run the post-apply verify pass.
- First-run safety: refuse if no conf, emit hint.
- `apply --check` for monitoring.
- Backups via `.cfm-kernsec.bak` (one-shot, never overwritten).
- Acceptance gate: `cfm kernsec status` after `apply` reports zero
  WARNs on a clean box.

### Phase 2.5 — `cfm kernsec disable` (DONE — branch `kernsec-disable`)

Friendly wrapper around `tier=0 + apply`. Same effect as editing the
conf to `tier = 0` and running `cfm kernsec apply`, packaged as one
command for ops who want a panic-button-flavoured disable.

```
cfm kernsec disable           # persistent: writes tier=0 to conf,
                              # strips managed boot args, empties
                              # managed sysctl, refreshes bootloader.
                              # Re-running `apply` is a no-op until
                              # the conf is edited back to tier=1.

cfm kernsec disable --purge   # full uninstall: same as above, but
                              # also removes /etc/cfm/kernsec.conf
                              # and /etc/sysctl.d/99-cfm-kernsec.conf.
                              # .cfm-kernsec.bak files are preserved.

cfm kernsec disable --dry-run     # show what would change
cfm kernsec disable --no-refresh  # skip post-write bootloader refresh
```

**What it does NOT do** (intentional, documented):
- Does not byte-restore `/etc/default/grub` or `/etc/kernel/cmdline`
  from `.cfm-kernsec.bak`. The .bak captures pre-kernsec state, not
  pre-most-recent-apply — restoring it could lose operator edits made
  between applies. Manual restore from the .bak is one `cp` away
  if needed.
- Does not revert live `/proc/sys/...` values to kernel defaults.
  `sysctl --load` of an empty file does not reset values; reboot is
  the contract.
- Does not `rmmod` blacklisted modules (Phase 3 concern). Reboot or
  manual `modprobe -r`.

When operators reach for what:

| Situation | Right command |
|---|---|
| Back kernsec off, may re-enable later | `cfm kernsec disable` |
| Uninstall kernsec configuration entirely | `cfm kernsec disable --purge` |
| Restore cmdline to pre-kernsec state | `cfm kernsec rollback` (reads `.cfm-kernsec.bak`, rewrites cmdline, refreshes bootloader) |
| Preview rollback without writing | `cfm kernsec rollback --dry-run` |
| System won't boot after apply | Edit cmdline at GRUB / systemd-boot rescue, or `proxmox-boot-tool kernel pin <old>` |
| Restore exact pre-kernsec /etc/default/grub manually | `cp /etc/default/grub.cfm-kernsec.bak /etc/default/grub && update-grub` |
| Fully clean state | `cfm kernsec disable --purge` + reboot |

Implementation: `applyCore` was extracted from `RunApply` to make
this clean — `RunApply` loads the conf from disk and calls
`applyCore`; `RunDisable` constructs an in-memory tier=0 conf
(preserving any existing per-rule overrides for transparency in
output) and calls the same helper. `WriteConf` was added for the
persistence step. Backup files are never touched by purge.

### Phase 3 — Modules (DONE — branch `kernsec-3`)

**Module blacklist** is now wired through the same apply / preview /
disable / status / TUI pipes as sysctls and boot args. Single rule set
(67 Tier-1 modules), three views (preview decisions, apply drift +
write, status audit), one source of truth.

**File format** (`/etc/modprobe.d/cfm-kernsec.conf`):

```
# Managed by cfm kernsec — do not edit by hand.
# Generated from /etc/cfm/kernsec.conf.

# Group: modules.recent_cves
blacklist ksmbd
install ksmbd /bin/false
blacklist n_hdlc
install n_hdlc /bin/false
…

# Group: modules.net.legacy
blacklist dccp
install dccp /bin/false
…
```

`blacklist` stops alias-loaded auto-loads; `install … /bin/false` stops
direct `modprobe X` calls — defense in depth, matches the original
design doc.

**Audit states** for module rules (new `LOADED` state):

| State | Meaning |
|---|---|
| `OK` | Module is in our managed file AND not loaded (or kernel doesn't ship it). |
| `LOADED` | Module is blacklisted in our file BUT currently loaded. **Reboot or `rmmod`** for the blacklist to take effect. |
| `MISSING` | Module is present on this kernel but not in our managed file. `cfm kernsec apply` will fix. |
| `SKIP` | Module not present under `/lib/modules/$(uname -r)`. Irrelevant on this host. |

**Apply behaviour** for modules:

- Atomic write of `/etc/modprobe.d/cfm-kernsec.conf` with one-shot
  `.cfm-kernsec.bak` of the previous content (if any).
- No `modprobe -r` / `rmmod` — operators reboot or unload manually.
  Loaded-but-blacklisted modules surface clearly in status output and
  in the apply post-write verify pass.
- `apply --check` extends to module-file byte equality.
- `disable` empties the file (tier=0 → no rules → empty managed
  content); `disable --purge` removes it entirely. Backups preserved.

**Acceptance gate (operator-driven)**:

Run `cfm kernsec status` on:
- A Proxmox host (validates ProxmoxBackend + proxmox-boot-tool refresh).
- A RHEL/Alma/Rocky host (validates BLSBackend + grubby).
- A Debian/Ubuntu host (validates GRUBBackend + update-grub).

Compare the output to `bash scripts/kspp.sh status` on the same hosts.
The kernsec output should be a strict superset (every label, every
KSPP rule check, every probe). When all three pass, kernsec parity
with kspp.sh is verified for the cfm-managed surface.

**`scripts/kspp.sh` is NOT deleted on gate pass.** It stays in the
tree as a standalone hardening script for hosts that don't run cfm.
The earlier "delete on Phase 3" plan was dropped — see "kspp.sh
status" in the document header. Future direction: have kspp.sh
delegate to `cfm kernsec` when the binary is present, fall back to
its in-script bash flow otherwise.

**Limitation carried over**: kernsec does not autoload modules, so
this is purely defensive — it ensures specific modules **cannot** be
loaded after the next reboot. Modules already loaded require
operator action (reboot, `rmmod`).

### Phase 4 — Tier 2 (opt-in) — DONE — branch `kernsec-4`

Tier 2 rules ship behind explicit `tier = 2` opt-in in kernsec.conf,
host-profile gated where they would clearly break things.

**Sysctls** (`tier2.namespace` group):

- `user.max_user_namespaces=0` (`KSEC-SCT-tier2.namespace-001`).
  Disables unprivileged user namespace creation. Skipped when
  containers (runc / containerd / lxc / podman) are detected.
- `kernel.unprivileged_userns_clone=0` (`KSEC-SCT-tier2.namespace-002`).
  Debian-flavoured alternative for the same surface. Same gating;
  also skipped (via `sysctlExists` in render) on kernels that don't
  expose the key.

**Boot args** (one rule per group for explicit per-rule overrides):

- `oops=panic` (`KSEC-BOOT-tier2.oops-001`). Pair with
  `kernel.panic_on_oops=1` to stop oops-spray exploit techniques.
  No host-profile gating — aggressive by design.
- `lockdown=integrity` (`KSEC-BOOT-tier2.lockdown-001`). Kernel
  lockdown LSM. Skipped when DKMS modules (zfs / nvidia) are
  detected — lockdown=integrity blocks unsigned module load.
- `module.sig_enforce=1` (`KSEC-BOOT-tier2.module-sig-enforce-001`).
  Belt-and-suspenders alongside lockdown. Same DKMS gating.

`ManagedBootArgKeys` extended to include `oops`, `lockdown`, and
`module.sig_enforce` so `disable` and `apply --remove` strip them
cleanly across both tiers.

**Operator workflow**:

```
# audit Tier 2 effect without committing
cfm kernsec preview --tier 2

# audit one rule specifically
cfm kernsec preview --tier 2 --id KSEC-SCT-tier2.namespace-001

# commit: edit /etc/cfm/kernsec.conf
tier = 2
[rule "KSEC-BOOT-tier2.lockdown-001"]
state = skip      # this box has zfs DKMS

cfm kernsec apply
```

**Status output**: `cfm kernsec status` now reads the conf and
filters its expected-rule list to `tier <= conf.Tier`. A tier=1
host doesn't see Tier 2 rules reported as MISSING; a tier=2 host
sees the full set audited.

**Deferred / out of scope**:

- `kernel.modules_disabled=1` — out of scope (see the dedicated
  "Out of scope" section under the rollout plan; cfm's own runtime
  triggers `request_module()` long after boot, so a late-systemd
  heuristic can't bracket it safely).
- `iommu=force` — deferred; requires broad hardware compatibility
  testing across vendor BIOS/UEFI.
- `kfence.sample_interval=100`, `efi=disable_early_pci_dma`, `tsx=off`,
  `spec_store_bypass_disable=seccomp` — **now shipped** as Tier 1 in
  `Tier1BootArgsExt` (see Boot args section above).

### Phase 5 — Drift detection wiring (DONE — branch `kernsec-5`)

`cfm kernsec apply --check` and `cfm kernsec status --check` shipped
in Phase 2b — they return non-zero on any DRIFT, suitable for
monitoring agents. Phase 5 makes the periodic check turnkey via a
systemd timer:

```
cfm kernsec monitor enable [--interval=daily]   # install + start
cfm kernsec monitor disable                     # stop + disable
cfm kernsec monitor remove                      # stop + disable + delete unit files
cfm kernsec monitor status                      # systemctl + last 5 service runs
```

What gets installed:

- `/etc/systemd/system/cfm-kernsec-check.service` — `Type=oneshot`,
  `ExecStart=<resolved cfm path> kernsec apply --check`. Drift exits
  the service non-zero, which `systemctl is-failed` reports.
- `/etc/systemd/system/cfm-kernsec-check.timer` —
  `OnCalendar=<interval>` (default daily), `Persistent=true`,
  `RandomizedDelaySec=1h` to spread fleet load.

Apply path / verification:

- Both unit files are written with `AtomicWriteFile`. No `.bak` —
  these are wholly kernsec-owned (no operator content to preserve).
- `enable` runs `systemctl daemon-reload` + `systemctl enable --now`.
- `remove` reverses: `systemctl disable --now`, deletes both files,
  `systemctl daemon-reload`. Idempotent on uninstalled hosts.
- `status` shows file presence + `systemctl status` + last 5 lines
  from `journalctl -u cfm-kernsec-check.service`.
- `disable --purge` (Phase 2.5) auto-runs `monitor remove` first if
  the timer is installed, so a single command tears everything down.

Operator runbook:

```
cfm kernsec monitor enable        # most fleets: daily check is enough
journalctl -u cfm-kernsec-check.service -n 50
                                  # see history
systemctl is-failed cfm-kernsec-check.service
                                  # exits 0 if clean, 1 if drift seen
```

### Phase 6 — Shared sysctl library (DONE)

New `internal/managedsysctl` package owns a cross-component registry
of (Owner, Key) tuples. Each cfm component that writes sysctls
registers a `Catalog` at package-init() time naming the keys it
owns. `kernsec.Resolve` consults `managedsysctl.Default().OwnerOf(key)`
when deciding what to do with a sysctl rule:

- Key owned by another component → `ManagedExternally` decision,
  rendered as `EXT` in `status` / TUI / preview. kernsec audits the
  live state but never writes the key.
- Operator escape hatch: `[rule "X"] state = force` overrides the
  cross-component check; kernsec writes its recommended value and
  the resulting conflict is surfaced via
  `managedsysctl.Default().Conflicts()`.

Shipped scope:

- `internal/managedsysctl` package: Registry, Catalog interface,
  Owner enum (kernsec / cfm-sysctl-tweaks / cfm-firewall),
  conflict detection, reusable primitives (`ApplyKeys` per-key
  apply with continue-on-error, `ParseFileToPairs` for
  /etc/sysctl.d-style files).
- `internal/sysctl/catalog.go`: `ManagedKeys()` + Catalog impl
  registers `cfm-sysctl-tweaks` ownership at init() for every
  sysctl `sys_tweaks.go` may write.
- `internal/kernsec`: new `NetSysctls` rule group
  (`KSEC-SCT-net.*`); `decideSysctl` consults the registry; new
  `ManagedExternally` Decision and `StateEXT` audit state;
  `status.go` / `tui.go` / `preview.go` render EXT rows; force-
  override escape hatch wired explicitly.

Out of scope for this Phase 6 PR (deferred):

- Migrating sys_tweaks.go's apply path to use
  `managedsysctl.ApplyKeys` (currently it loops over its own map
  and stderr-prints failures). The Catalog registration alone is
  enough to satisfy the cross-component awareness contract;
  routing through `ApplyKeys` is a future polish.
- Migrating cfm-firewall to register a Catalog. Reserved
  `OwnerFirewall` constant exists for the future migration.
- Expanding `KSEC-SCT-net.*` beyond the keys sys_tweaks actually
  owns today — **now shipped** as the new `sysctl.net.harden` group
  (`KSEC-SCT-net.harden-001` through `-007`): `icmp_echo_ignore_broadcasts`,
  `accept_source_route=0` (all + default), `log_martians=1`,
  `tcp_rfc1337=1`, `ipv6 accept_ra=0` (all + default). These keys are
  not in the `managedsysctl` registry, so kernsec owns and writes them
  directly (resolves to `Apply`, not `ManagedExternally`).

---

### Out of scope: `kernel.modules_disabled=1`

Originally queued for Phase 6 alongside a late-systemd-unit
abstraction, then dropped after a code review of cfm's own runtime.

`modules_disabled=1` is a one-way switch — once set, the kernel
refuses every subsequent module load until reboot. cfm has several
runtime triggers that autoload kernel modules:

- `internal/firewall/nftlib/backend.go` — `nftables.New(AsLasting())`
  at daemon startup autoloads `nf_tables`, `nfnetlink`. Per-operation
  `AddTable` / `Flush` / `SetAddElements` autoload family-specific
  `nft_*` submodules on demand throughout the daemon's lifetime.
- `internal/nflog/smtp_snoop.go` and `internal/outbound/collector.go`
  — `nflog.Open(...)` triggers `nfnetlink_log` autoload **only when
  the operator enables SMTP block / outbound tracking** in cfm.conf.
  Could be enabled weeks after first boot.
- `internal/firewall/nftlib/challenge.go` — DNAT / challenge flow
  autoloads `nf_nat`, `nft_nat`, `nft_redir` the first time challenge
  fires in production traffic.
- `internal/sysctl/sys_tweaks.go::trySetHashsize` writes to
  `/sys/module/nf_conntrack/parameters/hashsize` (silently fails if
  `nf_conntrack` isn't loaded at write time).

A "fire after `multi-user.target`" heuristic cannot bracket all of
these — operator-driven feature toggles would still trigger
`request_module()` weeks later. The protection added is also small
relative to the existing Phase 3 module-blacklist set (67 modules);
an attacker with `CAP_SYS_MODULE` typically already has another path
to root.

**Operator workaround for hosts that genuinely want
`modules_disabled=1`**:

- Pre-load every kernel module the environment needs via
  `/etc/modules-load.d/` or initramfs (the cfm modules listed above,
  plus any DKMS, plus distro-specific helpers).
- Apply `modules_disabled=1` themselves outside kernsec, accepting
  that any cfm feature toggled later that wants a new module will
  fail.

The late-systemd-unit infrastructure that would have shipped this
rule isn't built — it would exist solely for `modules_disabled=1`.
If a future Tier 2 candidate genuinely needs post-`multi-user.target`
execution **and** is compatible with cfm's runtime, this decision
can be revisited.

---

## Progress

### DONE

**Phase 5 — Drift detection wiring** (branch `kernsec-5`)
- New `cfm kernsec monitor <action>` subcommand wired into cli.go +
  top-level usage banner. Actions: `enable | disable | remove | status`.
- `RenderMonitorService(cfmBinary)` produces a `Type=oneshot`
  service with `ExecStart=<binary> kernsec apply --check`; the path
  is resolved via `os.Executable()` at apply time so the service
  references whatever cfm binary is actually running.
- `RenderMonitorTimer(interval)` produces an `OnCalendar=<interval>`
  timer with `Persistent=true` + `RandomizedDelaySec=1h` for
  fleet-load smoothing. Default interval `daily`.
- `monitor enable`: `AtomicWriteFile` for both unit files,
  `systemctl daemon-reload`, `systemctl enable --now <timer>`.
- `monitor disable`: `systemctl disable --now <timer>` (idempotent
  on hosts where the unit was never installed).
- `monitor remove`: stop + disable + remove both files +
  daemon-reload. Idempotent on missing files.
- `monitor status`: file-presence check + `systemctl status` +
  last 5 lines from `journalctl -u <service> --no-pager`.
- `disable --purge` (Phase 2.5) extended: if `MonitorInstalled()`
  returns true, runs `monitor remove` first so a single command
  tears the whole stack down.
- `MonitorServicePath` and `MonitorTimerPath` declared as `var`
  for tests to redirect to `t.TempDir()`. `MonitorInstalled()`
  helper for the disable-purge hook.
- 11 new tests covering: render content (binary path, interval,
  stable shape, idempotency), `MonitorInstalled` truth table,
  dry-run produces no writes, unknown / empty action returns
  exit 2, dry-run remove on uninstalled host succeeds.

**Phase 4 — Tier 2 (opt-in)** (branch `kernsec-4`)
- `Tier2Sysctls`: `user.max_user_namespaces=0`,
  `kernel.unprivileged_userns_clone=0`. Group `tier2.namespace`,
  host-profile gated on `HasContainers`.
- `Tier2BootArgs`: `oops=panic` (no gating), `lockdown=integrity`
  + `module.sig_enforce=1` (both gated on `HasDKMS`). Each in its
  own group for granular per-rule overrides.
- `ManagedBootArgKeys` extended for the new boot args so disable /
  apply-remove strip them cleanly.
- `AllSysctls()` / `AllBootArgs()` now concatenate Tier 1 + Tier 2
  in stable order (Tier 1 first). `Resolve`, `BuildAuditRows`,
  `ApplySysctls`, `ApplyBootArgs` all iterate the All* helpers, so
  Phase 4 rules are first-class across preview / apply / status / TUI.
- `HostProfile.SkipReason` extended for the new groups
  (`tier2.namespace`, `tier2.lockdown`, `tier2.module-sig-enforce`).
- `RunStatus` now best-effort loads the conf and filters its
  expected-rule iteration to `rule.Tier <= conf.Tier` — tier=1
  hosts don't see Tier 2 reported as MISSING.
- `--tier N` preview flag overrides conf tier in either direction
  (was clamp-down only); operators preview Tier 2 effect from a
  tier=1 host without committing.
- `StatusResult` gains `Tier` for callers / monitoring.
- 2 new resolve tests: tier=2-applies-all + host-profile gates;
  profile sanity test extends to Tier 2 (every rule has ID, Tier,
  Description, Affects; no duplicate IDs across tiers).

**Phase 3 — Modules** (branch `kernsec-3`)
- `RenderModprobeFile` produces `/etc/modprobe.d/cfm-kernsec.conf`
  with `blacklist X` + `install X /bin/false` lines per applied rule,
  grouped by `modules.<group>` for human readability.
- `WriteModprobeFile` atomic write + one-shot `.cfm-kernsec.bak`
  backup. `ModprobePath` declared as var so tests can redirect.
- `ParseManagedBlacklist` reads our managed file back to compute the
  current "what's blacklisted" set for audit / drift.
- `ModulePresentOnKernel` walks `/lib/modules/$(uname -r)` for `.ko`
  / `.ko.xz` / `.ko.zst` / `.ko.gz` to drive SKIP-on-missing-on-kernel
  semantics.
- `LoadedModules` reads `/proc/modules` once per audit pass.
- `BuildAuditRows` extended with `KindModule` rows + new `StateLOADED`
  for blacklisted-but-still-loaded modules.
- `ResolvedSet.ApplyModules()` filters the resolved set down to the
  Tier1Modules whose Decision == Apply.
- `applyCore`: writes module file, drift-compares, surfaces
  loaded-and-managed modules with reboot/rmmod hint, post-write
  verify counts module states.
- `disable.purgeManagedFiles` extends to remove `ModprobePath`;
  `disable --purge --dry-run` lists it in would-remove output.
- TUI detail panel: module-specific live state (blacklisted-in-file,
  loaded, present-on-kernel) + "blacklist active but module loaded"
  warning when `StateLOADED`.
- Plain-text status: new `[Module blacklist]` section with managed-
  file presence + per-state counts.
- Preview: module rows under `[Modules]` section (was Phase-3-stub).
- 11 new tests: render golden + idempotency, ParseManagedBlacklist
  (incl. install-line-not-leaking + comment-immune), moduleRowState
  truth table, atomic write + one-shot backup, modprobeDriftCheck
  for absent / matching / different cases, loadedAndManaged on
  fake module names.
- Doc: Phase 3 status flipped to "shipped"; acceptance gate procedure
  documented for operators (Proxmox + EL + Debian); `scripts/kspp.sh`
  kept as a standalone hardening script for non-cfm hosts (the
  earlier "delete on Phase 3" plan dropped — see header).

**Phase 2.5 — `cfm kernsec disable`** (branch `kernsec-disable`)
- New subcommand. `cfm kernsec disable` persists tier=0 + applies;
  `--purge` removes conf + managed sysctl file entirely.
- `applyCore` extracted from `RunApply` so the same orchestration
  drives apply (loads conf from disk) and disable (in-memory tier=0
  conf with existing overrides preserved for transparency).
- `WriteConf` added — atomic-write any `*Conf` to `ConfPath`.
- ConfPath / SysctlPath demoted from `const` to `var` so tests can
  redirect to `t.TempDir()`. No production-code behaviour change.
- 7 new tests: WriteConf round-trip + nil-refused + tier-0
  persistence; purgeManagedFiles removes both files and preserves
  .cfm-kernsec.bak; idempotent on missing files; loadConfForDisable
  returns tier=0 placeholder when no conf, preserves overrides when
  conf exists.
- Doc: when-to-use table operators can scan; explicit "what disable
  does NOT do" list (no byte-restore from .bak, no live-sysctl
  revert, no `rmmod`).

**Post-Phase-2 sweep** (branch `kernsec-sweep`)
- Code review of `apply.go`, `backend_*.go`, `sysctl_apply.go`,
  `conf.go` against the `kspp.sh` contract.
- Bug fix SF-001: `GRUBBackend.WriteCmdline` propagates
  `NextBootCmdline` errors instead of silently treating them as empty
  cmdline (would have nuked `root=` / `ro` / `console=` on read failure).
- Bug fix SF-002: `buildDesiredCmdline` propagates the same error;
  `RunApply` refuses to write on cmdline read failure.
- `driftResult` carries `BootReadErr` + `SysctlReadErr` so operators
  see the cause, not just "DRIFT".
- 8 new edge-case tests pinning the fixes plus `$tuned_params`
  passthrough, non-managed-order preservation, render determinism,
  tier=0 zero-rules, realistic rule-ID parsing, `state =` empty alias.
- All known limitations enumerated for Phase 3+.

**Phase 0 (reference impl)**
- `kspp.sh` server-safe profile shipping (sysctl + boot args + Proxmox/BLS/GRUB).
- `algif_aead_init` Copy Fail / CVE-2026-31431 mitigation in boot args.
- AF_ALG runtime probe in status.
- Cross-bootloader detection.
- `kspp.sh` committed to `scripts/kspp.sh` as the reference implementation
  (slated for removal in Phase 3 once acceptance gate passes).

**Design / docs**
- Design doc (this file), kept current after every kernsec PR.
- Reconciliation pass against existing cfm internals (`internal/sysctl/sys_tweaks.go`
  overlap, CLI dispatch pattern, config/packaging conventions) documented.
- Configuration model (`kernsec.conf` + `apply`) designed.

**Phase 2 — registry + conf + preview + apply** (branch `kernsec-2`)
- Stable rule IDs across 16 KSPP rules + 67 module rules + 4 mount-audit rules.
- `/etc/cfm/kernsec.conf` INI-flavoured with `[rule "..."] state =` overrides; round-trip safe parser + canonical Render with deterministic ordering.
- `cfm kernsec init` (idempotent default conf), `cfm kernsec preview`
  (filterable read-only diff with apply/skip-conf/skip-tier/skip-host
  decisions and reasons), `cfm kernsec apply` (atomic sysctl + boot-arg
  writes, sysctl --load, bootloader refresh, post-write verify).
- `BootBackend` interface extended with `WriteCmdline` + `Refresh`;
  Proxmox / BLS / GRUB implementations port `kspp.sh apply_boot_args_*`
  including managed-keys workflow (strip stale, add desired, preserve
  everything else).
- Atomic-write helpers (`AtomicWriteFile`, `BackupOnce`) with
  `.cfm-kernsec.bak` one-shot backups for `/etc/kernel/cmdline` and
  `/etc/default/grub`.
- Host-profile probe (KVM, containers, IPsec, wifi, DKMS, kdump,
  Bluetooth hardware, NFS) with per-group skip reasons.
- TUI rules table grew TIER + GROUP columns and a `/` substring filter;
  `c` clears the filter.
- 50 new test functions (conf parser edge cases, override resolution,
  host-profile decision tree, sysctl render with skipped-key handling,
  cmdline rebuild, GRUB file rewrite, atomic write + backup helpers).

**Phase 1 — `cfm kernsec` audit-only + TUI** (PR #766, branch `kernsec-1`)
- `case "kernsec":` wired in `cmd/cfm/main.go`. Top-level `cfm` usage banner
  lists the four subcommands (`/`, `live`, `text`, `status`).
- `BootBackend` Go interface + Proxmox / BLS / GRUB implementations with
  mockable `FS` interface; unit tests run without real bootloaders.
- Bootloader detection logic ported from `kspp.sh` (`is_proxmox_boot_tool`,
  `is_bls`, fallback-to-GRUB).
- KSPP profile (11 sysctls + 5 boot args) lifted into Go data with
  Description + Affects fields per rule.
- `BuildAuditRows()` — single source of truth feeding both text and TUI.
- Plain-text `RunStatus` mirrors `kspp.sh status` sections.
- Interactive TermUI (gizak/termui/v3) with rules table + detail panel,
  state→colour mapping, cursor, refresh tick, `t` to drop to text mode,
  `/` filter, `e`/`d` hint keys pointing to `cfm kernsec apply` /
  `disable` (TUI write-mode intentionally not implemented), `?` help
  overlay.
- Auto-fallback from TUI to text on non-TTY (`golang.org/x/term IsTerminal`).
- All probes ported: kernel CONFIG introspection (`/boot/config-$(uname -r)`
  → `/proc/config.gz`), page_alloc.shuffle, mem auto-init log scan,
  unknown-arg dmesg scan, AF_ALG bind probes (extended beyond `kspp.sh`'s
  AEAD-only set to `{aead, hash, skcipher, rng, akcipher}`).
- `--check` exit-code mode for monitoring (text/status path).
- 4 test files, table-driven, 100% of pure-logic paths covered. `go vet`,
  `go test`, `go build` clean.

### TODO

**Phase 2 — registry + `kernsec.conf` + `preview` + `apply`** (DONE — branch `kernsec-2`)
- [x] Stable rule IDs (`KSEC-<class>-<group>-<NNN>`) on every rule.
- [x] Tier and Group fields on `SysctlRule`, `BootArg`, `ModuleRule`,
      `MountRule`; KSPP rules + 67 modules + 4 mount audits populated.
- [x] `/etc/cfm/kernsec.conf` INI-flavoured loader/writer with
      `[rule "KSEC-..."] state = skip|force|default` stanzas.
- [x] `cfm kernsec init` — write default tier=1 conf if absent.
- [x] `cfm kernsec preview` — diff against current managed files / cmdline.
- [x] CLI selectors: `--tier`, `--group`, `--id`, `--skip`, `--force-id`,
      `--only-apply`.
- [x] TUI: group + tier columns; `/` filter (substring over Display + Group + ID).
- [x] Host-profile probe (KVM, containers, IPsec, wifi, DKMS, kdump,
      Bluetooth hardware, NFS) with per-group skip semantics; `--force-id`
      override.
- [x] `cfm kernsec apply` for sysctls + boot args (modules deferred to
      Phase 3 per design). Atomic writes, one-shot `.cfm-kernsec.bak`,
      `sysctl --load`, bootloader refresh.
- [x] First-run safety: `apply` auto-creates `kernsec.conf` with tier=1
      and proceeds (per the locked first-run UX choice).
- [x] `apply --check` for monitoring (compares desired vs current; exit 1
      on drift; no writes).
- [x] `apply --dry-run` and `apply --no-refresh` flags.
- [x] Module rule rows, fstab audit, host-profile probe (data + audit).
- [x] Audit `KSEC-SCT-net.*` settings owned by
      `internal/sysctl/sys_tweaks.go` — shipped in Phase 6 via the
      `managedsysctl` cross-component registry; rules resolve to
      `ManagedExternally` and render as `EXT` in status/TUI.
      kernsec audits but never writes them.

**Phase 3 — modules** (DONE — branch `kernsec-3`)
- [x] Module blacklist generator (`/etc/modprobe.d/cfm-kernsec.conf`,
      `blacklist` + `install … /bin/false` lines).
- [x] Module rules wired into `apply`, `preview`, `disable`, `status`,
      and TUI.
- [x] KSPP-profile rules registered under `KSEC-BOOT-kspp-*`.
- [ ] Acceptance gate — `cfm kernsec status` ⊇ `kspp.sh status` on
      Proxmox + EL + Debian (operator-driven; can't be done from
      this sandbox). Verifies parity; **does not** trigger kspp.sh
      removal — the script is kept as a standalone hardening flow
      for non-cfm hosts.

**`kspp.sh` future direction** (optional, no timeline)
- [ ] Have `kspp.sh` detect a `cfm` binary and delegate to
      `cfm kernsec apply` / `status` / `disable` when present, fall
      back to its in-script bash flow otherwise. Single user-facing
      command across both managed and standalone hosts.

**Phase 4 — Tier 2 (opt-in)** (DONE — branch `kernsec-4`)
- [x] Tier 2 rules with host-profile gating
      (`user.max_user_namespaces=0`,
      `kernel.unprivileged_userns_clone=0`,
      `lockdown=integrity`, `module.sig_enforce=1`, `oops=panic`).
- ~~Late systemd unit for `kernel.modules_disabled=1`~~ — dropped;
      see "Out of scope: `kernel.modules_disabled=1`" under the
      rollout plan. cfm's own runtime triggers `request_module()`
      throughout the daemon's lifetime, so no late-systemd heuristic
      can bracket it safely.

**Phase 5 — drift wiring** (DONE — branch `kernsec-5`)
- [x] `cfm kernsec apply --check` exit-code (shipped in Phase 2b).
- [x] `cfm kernsec monitor` subcommand: enable / disable / remove /
      status of the periodic systemd timer.
- [x] `disable --purge` auto-removes monitor units when present.

**Phase 6 — shared sysctl library** (DONE)
- [x] New `internal/managedsysctl` package — Owner enum, Catalog
      interface, default Registry singleton with conflict detection.
- [x] `internal/sysctl/catalog.go` — sys_tweaks publishes its
      `ManagedKeys()` via Catalog; init() registers
      `cfm-sysctl-tweaks` ownership.
- [x] `internal/kernsec`: `NetSysctls` rule group;
      `ManagedExternally` Decision; `StateEXT` audit state;
      `decideSysctl` consults registry; status / TUI / preview /
      verifyAfterApply render EXT rows; `state = force` escape
      hatch wired.
- [ ] Migrate sys_tweaks.go's apply path to
      `managedsysctl.ApplyKeys` (currently registers Catalog only;
      apply path unchanged). Future polish.
- [ ] cfm-firewall Catalog registration (reserved
      `OwnerFirewall` constant). Future polish.

**Out of scope** (decision recorded in the rollout-plan section
above — not a TODO, not coming back unless a future rule needs the
abstraction)
- ~~Late-systemd-unit infrastructure~~
- ~~`kernel.modules_disabled=1`~~

**Operator-facing**
- [ ] Document operator runbook for fleet rollout
      (preview-on-one → apply-on-canary → expand).
