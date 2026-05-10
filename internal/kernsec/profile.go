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
		Key: "slab_nomerge",
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
		Affects:     "Breaks rootless podman, bwrap, Chromium sandbox, some cPanel jail variants. Skipped if containers detected.",
	},
	{
		ID: "KSEC-SCT-tier2.namespace-002", Group: "tier2.namespace", Tier: Tier2,
		Key: "kernel.unprivileged_userns_clone", Value: "0",
		Description: "Debian-flavoured alternative for blocking unprivileged userns. Reversible without breaking root use.",
		Affects:     "Same surface as user.max_user_namespaces=0. Skipped if containers detected. Skipped if kernel doesn't expose the key (non-Debian).",
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
		Affects:     "Breaks DKMS modules (zfs, nvidia). Skipped if DKMS detected on host.",
	},
	{
		ID: "KSEC-BOOT-tier2.module-sig-enforce-001", Group: "tier2.module-sig-enforce", Tier: Tier2,
		Key: "module.sig_enforce", Value: "1",
		Description: "Require kernel-signed modules. Belt-and-suspenders alongside lockdown=integrity.",
		Affects:     "Breaks DKMS modules. Skipped if DKMS detected on host.",
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
	// Tier 2
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
// Tier 2 server-aggressive). Order: Tier 1 first, then Tier 2 — keeps the
// rendered file deterministic and Tier-1-first-readable.
func AllSysctls() []SysctlRule {
	out := make([]SysctlRule, 0, len(KSPPSysctls)+len(Tier2Sysctls)+len(NetSysctls))
	out = append(out, KSPPSysctls...)
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
func AllBootArgs() []BootArg {
	out := make([]BootArg, 0, len(KSPPBootArgs)+len(Tier2BootArgs))
	out = append(out, KSPPBootArgs...)
	out = append(out, Tier2BootArgs...)
	return out
}

// AllModules returns the full module-blacklist rule set.
// Phase 2 carries the data; apply lands in Phase 3.
func AllModules() []ModuleRule {
	return append([]ModuleRule(nil), Tier1Modules...)
}

// AllMounts returns the full fstab audit rule set.
func AllMounts() []MountRule {
	return append([]MountRule(nil), Tier1Mounts...)
}
