// Package kernsec implements the cfm kernel attack-surface reduction
// component. See docs/kernsec.md for the full design.
//
// This file defines the KSPP server-safe profile (sysctls + boot args)
// that kernsec inherits from scripts/kspp.sh and the Tier 1 extensions
// (modules + fstab) added in Phase 2. Stable rule IDs follow the
// `KSEC-<class>-<group>-<NNN>` scheme from docs/kernsec.md.
package kernsec

// Tier classifies a rule by safety / blast radius.
//
//	Tier1: safe-everywhere on hosting / KVM / cPanel / EL / Debian.
//	Tier2: server-aggressive — opt-in per host role, host-profile gated.
type Tier int

const (
	Tier1 Tier = 1
	Tier2 Tier = 2
)

// SysctlRule is one expected sysctl key/value pair plus the human-readable
// blurbs the TUI surfaces and the registry metadata used by selectors.
type SysctlRule struct {
	ID          string // stable, e.g. KSEC-SCT-kspp.kernel-001
	Group       string // dotted tag, e.g. kspp.kernel
	Tier        Tier
	Key         string // dotted form, e.g. kernel.kptr_restrict
	Value       string // expected value as string
	Description string // one-line "what this does"
	Affects     string // one-line "what enabling this breaks"
}

// BootArg is one expected kernel boot argument.
//
// A bare token like "slab_nomerge" has Key=="slab_nomerge", Value=="".
// A "k=v" arg like "init_on_alloc=1" has Key=="init_on_alloc", Value=="1".
type BootArg struct {
	ID          string
	Group       string
	Tier        Tier
	Key         string
	Value       string
	Description string
	Affects     string
}

// ModuleRule is one kernel module that should be blacklisted.
// Phase 2 carries the data; the actual /etc/modprobe.d generator lives
// in Phase 3.
type ModuleRule struct {
	ID          string
	Group       string
	Tier        Tier
	Name        string // module name as used by lsmod / modprobe
	Description string
	Affects     string
}

// MountRule is one fstab audit entry. Phase 2 audit is report-only;
// kernsec never auto-mutates /etc/fstab.
type MountRule struct {
	ID          string
	Group       string
	Tier        Tier
	MountPoint  string // e.g. "/tmp"
	Recommended string // e.g. "nodev,nosuid,noexec"
	Description string
	Affects     string
}

// KSPPSysctls is the server-safe sysctl profile from kspp.sh.
// Keep in sync with scripts/kspp.sh KSPP_SYSCTL until kspp.sh is removed.
var KSPPSysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-kspp.kernel-001", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.kptr_restrict", Value: "2",
		Description: "Hide kernel pointers from userspace (/proc/kallsyms, dmesg, /proc/<pid>/stack).",
		Affects:     "Nothing on production. Symbol resolution still works for root.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-002", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.dmesg_restrict", Value: "1",
		Description: "Restrict dmesg / kernel log reads to root.",
		Affects:     "Regular users can no longer read the kernel log.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-003", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.unprivileged_bpf_disabled", Value: "1",
		Description: "Block unprivileged BPF program loading.",
		Affects:     "Kills a major LPE primitive class. Root BPF (cilium etc.) unchanged.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-004", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.randomize_va_space", Value: "2",
		Description: "Full ASLR for stack, heap, mmap, VDSO.",
		Affects:     "Nothing. Distro default already.",
	},
	{
		ID: "KSEC-SCT-kspp.fs-001", Group: "kspp.fs", Tier: Tier1,
		Key: "fs.protected_hardlinks", Value: "1",
		Description: "Prevent hardlink-based privilege escalation in shared directories.",
		Affects:     "Nothing in normal use.",
	},
	{
		ID: "KSEC-SCT-kspp.fs-002", Group: "kspp.fs", Tier: Tier1,
		Key: "fs.protected_symlinks", Value: "1",
		Description: "Restrict symlink-following in sticky-bit directories like /tmp.",
		Affects:     "Nothing in normal use.",
	},
	{
		ID: "KSEC-SCT-kspp.fs-003", Group: "kspp.fs", Tier: Tier1,
		Key: "fs.protected_fifos", Value: "2",
		Description: "Block unsafe FIFO usage in world-writable directories.",
		Affects:     "Nothing in normal use.",
	},
	{
		ID: "KSEC-SCT-kspp.fs-004", Group: "kspp.fs", Tier: Tier1,
		Key: "fs.protected_regular", Value: "2",
		Description: "Same protection family applied to regular files.",
		Affects:     "Nothing in normal use.",
	},
	{
		ID: "KSEC-SCT-kspp.net-001", Group: "kspp.net", Tier: Tier1,
		Key: "net.core.bpf_jit_harden", Value: "2",
		Description: "Constant blinding in the BPF JIT to defeat JIT-spray exploits.",
		Affects:     "Minor JIT performance cost. Negligible in practice.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-005", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.perf_event_paranoid", Value: "3",
		Description: "Restrict perf_event_open() to root.",
		Affects:     "Developer profiling tools (perf, flamegraph) need sudo.",
	},
	{
		ID: "KSEC-SCT-kspp.kernel-006", Group: "kspp.kernel", Tier: Tier1,
		Key: "kernel.yama.ptrace_scope", Value: "1",
		Description: "Limit ptrace() to direct children.",
		Affects:     "gdb attaching to an existing PID needs CAP_SYS_PTRACE / sudo.",
	},
}

// KSPPBootArgs is the server-safe boot-arg profile from kspp.sh.
// Keep in sync with scripts/kspp.sh KSPP_ARGS until kspp.sh is removed.
//
// initcall_blacklist=algif_aead_init is the temporary mitigation for
// CVE-2026-31431 (Copy Fail). Remove later once all relevant kernels
// are patched.
var KSPPBootArgs = []BootArg{
	{
		ID: "KSEC-BOOT-kspp-001", Group: "kspp.boot", Tier: Tier1,
		Key:         "slab_nomerge",
		Description: "Don't merge slab caches that have similar size. Hardens against type-confusion UAF exploits.",
		Affects:     "Small RAM overhead.",
	},
	{
		ID: "KSEC-BOOT-kspp-002", Group: "kspp.boot", Tier: Tier1,
		Key: "init_on_alloc", Value: "1",
		Description: "Zero pages on allocation. Kills uninitialized-memory leaks across the whole kernel.",
		Affects:     "~0-5% performance cost on alloc-heavy workloads.",
	},
	{
		ID: "KSEC-BOOT-kspp-003", Group: "kspp.boot", Tier: Tier1,
		Key: "page_alloc.shuffle", Value: "1",
		Description: "Randomize buddy-allocator freelists. Mild ASLR boost for kernel allocations.",
		Affects:     "Nothing measurable.",
	},
	{
		ID: "KSEC-BOOT-kspp-004", Group: "kspp.boot", Tier: Tier1,
		Key: "randomize_kstack_offset", Value: "on",
		Description: "Per-syscall kernel-stack randomization. Makes ROP / stack-spray exploits harder.",
		Affects:     "Nothing.",
	},
	{
		ID: "KSEC-BOOT-kspp-005", Group: "kspp.boot", Tier: Tier1,
		Key: "initcall_blacklist", Value: "algif_aead_init",
		Description: "TEMPORARY: blocks algif_aead init at boot — mitigation for Copy Fail / CVE-2026-31431.",
		Affects:     "AEAD operations via AF_ALG userspace API. Remove once kernels are patched.",
	},
}

// Tier2Sysctls is the server-aggressive sysctl profile (Phase 4).
// Each rule is opt-in — operator must set tier=2 in kernsec.conf — and
// host-profile gated where it would break common workloads.
//
// kernel.modules_disabled=1 is intentionally NOT here. It needs a late
// systemd unit (post multi-user.target) so cfm itself can finish
// loading kernel modules before the lockout fires; that's a follow-up
// PR, not Phase 4.
var Tier2Sysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-tier2.namespace-001", Group: "tier2.namespace", Tier: Tier2,
		Key: "user.max_user_namespaces", Value: "0",
		Description: "Disable unprivileged user namespace creation — kills a major LPE primitive class.",
		Affects:     "Breaks rootless podman, bwrap, Chromium sandbox, cPanel jails, CloudLinux/CageFS isolation. Skipped if containers or hosting panels detected.",
	},
	{
		ID: "KSEC-SCT-tier2.namespace-002", Group: "tier2.namespace", Tier: Tier2,
		Key: "kernel.unprivileged_userns_clone", Value: "0",
		Description: "Debian-flavoured alternative for blocking unprivileged userns. Reversible without breaking root use.",
		Affects:     "Same surface as user.max_user_namespaces=0. Skipped if containers or hosting panels detected. Skipped if kernel doesn't expose the key (non-Debian).",
	},
}

// Tier2BootArgs is the server-aggressive boot-arg profile (Phase 4).
//
// Each adds an entry to ManagedBootArgKeys so disable / apply --remove
// strip it cleanly.
var Tier2BootArgs = []BootArg{
	{
		ID: "KSEC-BOOT-tier2.oops-001", Group: "tier2.oops", Tier: Tier2,
		Key: "oops", Value: "panic",
		Description: "Pair with kernel.panic_on_oops=1 to stop oops-spray exploit techniques cold.",
		Affects:     "Aggressive: any kernel oops becomes a reboot. Trade reliability for exploit mitigation.",
	},
	{
		ID: "KSEC-BOOT-tier2.lockdown-001", Group: "tier2.lockdown", Tier: Tier2,
		Key: "lockdown", Value: "integrity",
		Description: "Kernel lockdown LSM — blocks unsigned module load, /dev/mem write, unsigned kexec.",
		Affects:     "Breaks DKMS/vendor modules (CloudLinux LVE/CageFS, live patching, ZFS, NVIDIA). Skipped when evidence is detected.",
	},
	{
		ID: "KSEC-BOOT-tier2.module-sig-enforce-001", Group: "tier2.module-sig-enforce", Tier: Tier2,
		Key: "module.sig_enforce", Value: "1",
		Description: "Require kernel-signed modules. Belt-and-suspenders alongside lockdown=integrity.",
		Affects:     "Breaks DKMS/vendor modules (CloudLinux LVE/CageFS, live patching, ZFS, NVIDIA). Skipped when evidence is detected.",
	},
}

// Tier1BootArgsExt are boot args beyond the KSPP baseline.
// Safe entries are Tier 1; compatibility-sensitive entries remain here for
// stable ordering but carry Tier 2 and host-profile gates (see profile_probe.go).
var Tier1BootArgsExt = []BootArg{
	// --- boot.bug-detection ------------------------------------------
	{
		ID: "KSEC-BOOT-bug-detection-001", Group: "boot.bug-detection", Tier: Tier1,
		Key: "kfence.sample_interval", Value: "100",
		Description: "Enable KFENCE heap safety net: one in 100 allocations gets a guarded page, catching use-after-free and out-of-bounds bugs in production at effectively zero overhead.",
		Affects:     "None measurable. The guarded fraction adds <0.1% allocation latency on benchmarks; field experience shows negligible impact on hosting workloads.",
	},
	// --- boot.dma: pre-IOMMU DMA window hardening (EFI only) ---------
	{
		ID: "KSEC-BOOT-dma-001", Group: "boot.dma", Tier: Tier1,
		Key: "efi", Value: "disable_early_pci_dma",
		Description: "Disable DMA from PCI devices before the IOMMU is initialised — closes the pre-IOMMU window that a malicious peripheral (e.g. a Thunderbolt device) could use to read/write kernel memory before protections are active.",
		Affects:     "None on well-behaved hardware. Skipped on non-EFI systems (parameter is EFI-specific and a no-op on BIOS/legacy-boot).",
	},
	// --- boot.sidechannel: TSX side-channel mitigation ---------------
	{
		ID: "KSEC-BOOT-sidechannel-001", Group: "boot.sidechannel", Tier: Tier1,
		Key: "tsx", Value: "off",
		Description: "Disable Intel Transactional Synchronization Extensions — removes the hardware primitives exploited by TAA (CVE-2019-11135) and related MDS variants. TSX is unused by any standard hosting or KVM workload.",
		Affects:     "None on hosting / KVM servers; TSX is not used by MySQL, nginx, PHP, Python, etc. Non-Intel CPUs and Intel CPUs with the TSX deprecation microcode already applied ignore the parameter.",
	},
	// --- boot.ssbd: Spectre v4 mitigation for seccomp workloads ------
	{
		ID: "KSEC-BOOT-ssbd-001", Group: "tier2.ssbd", Tier: Tier2,
		Key: "spec_store_bypass_disable", Value: "seccomp",
		Description: "Enable Speculative Store Bypass Disable (SSBD / Spectre v4 mitigation) for all threads running under a seccomp policy. Covers sandboxed web workloads without the global perf hit of 'on'. Distro default 'prctl' means mitigation is off unless each process opts in explicitly.",
		Affects:     "Tier 2: can impose a measurable syscall-throughput cost on seccomp-heavy container, backup, monitoring, and hosting-panel workloads; skipped when those workloads are detected.",
	},
}

// MemExploitSysctls is the memory/exploit-mitigation sysctl group.
// The safe-everywhere entries reduce common LPE primitives without
// changing normal server behaviour. The oops/panic pair intentionally
// lives in Tier 2 because it trades availability for fail-closed exploit
// mitigation: any kernel oops can reboot the host.
var MemExploitSysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-mem.exploit-001", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "vm.unprivileged_userfaultfd", Value: "0",
		Description: "Disable unprivileged userfaultfd — removes a frequently-abused heap-spray / race primitive from unprivileged attackers.",
		Affects:     "Rare userspace checkpointing / post-copy migration tools need privileges or a per-host override.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-002", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "vm.mmap_rnd_bits", Value: "32",
		Description: "Maximise mmap ASLR entropy on 64-bit kernels that expose this knob.",
		Affects:     "None on normal hosting workloads; skipped automatically on kernels that do not expose the key.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-003", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "vm.mmap_rnd_compat_bits", Value: "16",
		Description: "Maximise mmap ASLR entropy for 32-bit compatibility processes where supported.",
		Affects:     "None; skipped automatically on kernels without 32-bit compat ASLR support.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-004", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "kernel.warn_limit", Value: "10",
		Description: "Rate-limit WARN splats so warning-spray exploit techniques cannot loop indefinitely.",
		Affects:     "None for production use; very noisy kernel debugging sessions may need an override.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-005", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "kernel.oops_limit", Value: "10",
		Description: "Rate-limit kernel oops handling to blunt oops-spray exploit techniques.",
		Affects:     "None in normal operation; repeated kernel bugs stop producing unlimited oops reports.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-006", Group: "tier2.oops", Tier: Tier2,
		Key: "kernel.panic_on_oops", Value: "1",
		Description: "Fail closed on a kernel oops instead of continuing after possible kernel memory corruption.",
		Affects:     "Aggressive: any kernel oops can reboot the host. Tier 2 only; pair with oops=panic and kernel.panic=10.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-007", Group: "sysctl.mem.exploit", Tier: Tier1,
		Key: "fs.suid_dumpable", Value: "0",
		Description: "Disable core dumps from setuid/setgid binaries so privileged memory is not written to attacker-readable paths.",
		Affects:     "Crash diagnostics for setuid helpers require a deliberate per-host override.",
	},
	{
		ID: "KSEC-SCT-mem.exploit-008", Group: "tier2.oops", Tier: Tier2,
		Key: "kernel.panic", Value: "10",
		Description: "Reboot ten seconds after a panic so Tier 2 oops=panic hosts recover automatically after fail-closed crashes.",
		Affects:     "Aggressive: panic reboots may reduce forensic time on the console. Tier 2 only.",
	},
}

// KernelSurface is the kernel attack-surface hardening sysctl group.
// Rules that share a gate (e.g. kdump) use a sub-group so the
// host-profile skip can target them without gating the whole surface
// set.
var KernelSurface = []SysctlRule{
	// --- sysctl.kernel.surface: generic kernel surface reductions -----
	{
		ID: "KSEC-SCT-kernel.surface-001", Group: "sysctl.kernel.surface", Tier: Tier1,
		Key: "dev.tty.ldisc_autoload", Value: "0",
		Description: "Disable automatic TTY line-discipline module loading — closes n_hdlc-style autoload attack paths from unprivileged TTY users.",
		Affects:     "None on servers; unusual TTY line disciplines must be loaded explicitly by root before use.",
	},
	{
		ID: "KSEC-SCT-kernel.surface-002", Group: "sysctl.kernel.kexec", Tier: Tier2,
		Key: "kernel.kexec_load_disabled", Value: "1",
		Description: "Disable future kexec_load() calls after boot — prevents replacing the running kernel without a firmware/bootloader transition.",
		Affects:     "Tier 2: skipped when kdump/Proxmox/live-patching evidence is detected. Once set, this knob cannot be re-enabled until reboot.",
	},
	{
		ID: "KSEC-SCT-kernel.surface-003", Group: "sysctl.kernel.surface", Tier: Tier1,
		Key: "kernel.sysrq", Value: "0",
		Description: "Disable Magic SysRq actions from keyboard/proc triggers to reduce emergency-control primitives exposed to compromised privileged processes.",
		Affects:     "Loses Magic SysRq emergency debugging shortcuts unless overridden (for example to SAK-only mode).",
	},

	// --- sysctl.kernel.coredump: core_pattern (Tier 2, gated) -----
	{
		ID: "KSEC-SCT-kernel.coredump-001", Group: "sysctl.kernel.coredump", Tier: Tier2,
		Key: "kernel.core_pattern", Value: "|/bin/false",
		Description: "Redirect coredumps to /bin/false — prevents exploit-writable core-dump paths used by OverlayFS-class privilege escalations (CVE-2023-0386 and similar). On a shared hosting server where tenants can trigger process crashes you do not want coredumps landing anywhere.",
		Affects:     "Tier 2: coredumps are suppressed for all processes, which can break support diagnostics, backup/monitoring crash capture, and hosting-panel/vendor troubleshooting. Skipped when those risks are detected.",
	},
}

// NetHardenSysctls is the network hardening sysctl group owned
// directly by kernsec. These keys are NOT owned by cfm-sysctl-tweaks
// (compare NetSysctls which is audit-only / EXT for sys_tweaks keys).
// kernsec writes these values itself via the normal apply pipeline.
var NetHardenSysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-net.harden-001", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.icmp_echo_ignore_broadcasts", Value: "1",
		Description: "Ignore ICMP echo requests sent to broadcast addresses — prevents Smurf amplification attacks that can overwhelm bandwidth.",
		Affects:     "None. Broadcast ping is unused in any legitimate hosting workflow.",
	},
	{
		ID: "KSEC-SCT-net.harden-002", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.conf.all.accept_source_route", Value: "0",
		Description: "Reject IPv4 source-routed packets — source routing can bypass firewall rules and enable traffic redirection attacks.",
		Affects:     "None. Source routing is deprecated and unused on modern networks.",
	},
	{
		ID: "KSEC-SCT-net.harden-003", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.conf.default.accept_source_route", Value: "0",
		Description: "Same source-route rejection policy for newly-created interfaces (ensures the secure default propagates).",
		Affects:     "None.",
	},
	{
		ID: "KSEC-SCT-net.harden-004", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.conf.all.log_martians", Value: "1",
		Description: "Log packets with impossible (martian) source addresses — surfaces IP spoofing, route injection, and misconfigured upstream routers.",
		Affects:     "Minor log volume on misconfigured network segments. Expected to produce no log lines on a well-configured host.",
	},
	{
		ID: "KSEC-SCT-net.harden-005", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv4.tcp_rfc1337", Value: "1",
		Description: "RFC 1337 TIME_WAIT assassination fix — prevents RST packets from prematurely killing connections in TIME_WAIT, closing a timing-based connection-hijack vector.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-SCT-net.harden-006", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv6.conf.all.accept_ra", Value: "0",
		Description: "Reject IPv6 Router Advertisements — prevents rogue RA attacks that redirect the default route or hand out an attacker-controlled DNS server. Critical on shared hosting where tenants share a broadcast domain.",
		Affects:     "Breaks SLAAC (stateless address auto-configuration) if the host relies on RA for IPv6 address assignment. Static-IP hosting setups are unaffected. Use `state = skip` if SLAAC is required on this host.",
	},
	{
		ID: "KSEC-SCT-net.harden-007", Group: "sysctl.net.harden", Tier: Tier1,
		Key: "net.ipv6.conf.default.accept_ra", Value: "0",
		Description: "Same RA rejection for newly-created interfaces — ensures the secure default propagates to any interface added after boot.",
		Affects:     "Same as accept_ra=0 on all; new interfaces inherit the deny-RA policy.",
	},
}

// ManagedBootArgKeys is the set of cmdline keys kernsec owns.
// Mirrors kspp.sh MANAGED_ARG_KEYS. enable removes any stale instance
// of these keys before adding the desired set; disable removes them
// entirely. Operator-set args on the cmdline outside this set are
// preserved untouched.
var ManagedBootArgKeys = []string{
	// Tier 1 (KSPP)
	"slab_nomerge",
	"init_on_alloc",
	"page_alloc.shuffle",
	"randomize_kstack_offset",
	"initcall_blacklist",
	// Tier 1 extensions
	"kfence.sample_interval",
	"efi",
	"tsx",
	// Tier 2
	"spec_store_bypass_disable",
	"oops",
	"lockdown",
	"module.sig_enforce",
}

// String returns the cmdline form of a boot arg ("key" or "key=value").
func (a BootArg) String() string {
	if a.Value == "" {
		return a.Key
	}
	return a.Key + "=" + a.Value
}

// AllSysctls returns the full sysctl rule set across tiers (Tier 1 KSPP +
// Tier 1 surface/net extensions + Tier 2 server-aggressive + EXT audit).
// Order: Tier 1 first, then Tier 2, EXT last — keeps the rendered file
// deterministic and Tier-1-first-readable.
func AllSysctls() []SysctlRule {
	out := make([]SysctlRule, 0,
		len(KSPPSysctls)+len(MemExploitSysctls)+len(KernelSurface)+len(NetHardenSysctls)+
			len(Tier2Sysctls)+len(NetSysctls))
	out = append(out, KSPPSysctls...)
	out = append(out, MemExploitSysctls...)
	out = append(out, KernelSurface...)
	out = append(out, NetHardenSysctls...)
	out = append(out, Tier2Sysctls...)
	out = append(out, NetSysctls...)
	return out
}

// NetSysctls is the network-hardening sysctl audit set. Every key
// here is owned by `internal/sysctl/sys_tweaks.go` (the cfm daemon's
// imperative TCP/conntrack/spoof-guard tuning) per the
// managedsysctl cross-component registry. kernsec ships these as
// Tier 1 audit-only rules: the resolver consults
// managedsysctl.Default().OwnerOf(), sees sys_tweaks owns the key,
// and resolves every rule in this group to ManagedExternally —
// kernsec NEVER writes these values, only audits whether the live
// state matches what sys_tweaks intended.
//
// This realises the "single source of truth per setting" goal of
// Phase 6 without merging the imperative sys_tweaks logic into
// kernsec rule data: sys_tweaks keeps owning runtime computation
// (RAM-derived nf_conntrack_max, config-driven rp_filter strict-
// vs-loose, etc.), kernsec keeps owning the audit / status / TUI
// surface, and the managedsysctl registry mediates.
//
// Scope intentionally limited to keys sys_tweaks's ManagedKeys()
// actually claims. Additional network-hardening rules (icmp_echo
// broadcast drop, accept_source_route=0, log_martians, etc.) are
// design-table candidates but not shipped here — they'd require
// either expanding sys_tweaks's surface or having kernsec own them
// directly. Future PR.
//
// Operators who disagree with sys_tweaks's chosen values edit
// cfm.conf's SystemTweaks fields rather than via kernsec overrides;
// kernsec.Resolve respects `state = force` though, in which case
// kernsec WILL write its recommended value and the conflict surfaces
// in the daemon log.
var NetSysctls = []SysctlRule{
	{
		ID: "KSEC-SCT-net.spoof-001", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv4.conf.all.rp_filter", Value: "1",
		Description: "Reverse-path filter — drops packets whose source can't route back the same way.",
		Affects:     "Asymmetric-routing setups (rare on hosting). Owned by cfm-sysctl-tweaks; tunable via SystemTweaks.RPFilter.",
	},
	{
		ID: "KSEC-SCT-net.redirect-001", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv4.conf.all.accept_redirects", Value: "0",
		Description: "Refuse ICMP redirects — closes the routing-table-MitM primitive.",
		Affects:     "None — modern routing tables don't depend on ICMP redirects. Owned by cfm-sysctl-tweaks; tunable via SystemTweaks.AcceptRedirects.",
	},
	{
		ID: "KSEC-SCT-net.redirect-002", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv4.conf.all.send_redirects", Value: "0",
		Description: "Don't emit ICMP redirects — host isn't a router.",
		Affects:     "None on hosting. Owned by cfm-sysctl-tweaks; tunable via SystemTweaks.SendRedirects.",
	},
	{
		ID: "KSEC-SCT-net.tcp-001", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv4.tcp_syncookies", Value: "1",
		Description: "TCP SYN cookies — survive SYN floods without resource exhaustion.",
		Affects:     "None. Owned by cfm-sysctl-tweaks (hard-coded =1 when SystemTweaks.Enable).",
	},
	{
		ID: "KSEC-SCT-net.ipv6-001", Group: "sysctl.net", Tier: Tier1,
		Key: "net.ipv6.conf.all.accept_redirects", Value: "0",
		Description: "v6 ICMP-redirect refusal — same MitM closure for IPv6.",
		Affects:     "None. Owned by cfm-sysctl-tweaks (hard-coded =0 when SystemTweaks.Enable).",
	},
}

// AllBootArgs returns the full boot-arg rule set across tiers.
// Order: Tier 1 KSPP baseline, Tier 1 extensions, Tier 2 opt-in.
func AllBootArgs() []BootArg {
	out := make([]BootArg, 0, len(KSPPBootArgs)+len(Tier1BootArgsExt)+len(Tier2BootArgs))
	out = append(out, KSPPBootArgs...)
	out = append(out, Tier1BootArgsExt...)
	out = append(out, Tier2BootArgs...)
	return out
}

// AllModules returns the full module-blacklist rule set.
// Phase 2 carries the data; apply lands in Phase 3.
func AllModules() []ModuleRule {
	out := make([]ModuleRule, 0, len(Tier1Modules)+len(Tier2Modules))
	out = append(out, Tier1Modules...)
	out = append(out, Tier2Modules...)
	return out
}

// AllMounts returns the full fstab audit rule set.
func AllMounts() []MountRule {
	return append([]MountRule(nil), Tier1Mounts...)
}
