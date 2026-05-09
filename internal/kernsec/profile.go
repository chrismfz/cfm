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

// ManagedBootArgKeys is the set of cmdline keys kernsec owns.
// Mirrors kspp.sh MANAGED_ARG_KEYS. enable removes any stale instance
// of these keys before adding the desired set; disable removes them
// entirely. Operator-set args on the cmdline outside this set are
// preserved untouched.
var ManagedBootArgKeys = []string{
	"slab_nomerge",
	"init_on_alloc",
	"page_alloc.shuffle",
	"randomize_kstack_offset",
	"initcall_blacklist",
}

// String returns the cmdline form of a boot arg ("key" or "key=value").
func (a BootArg) String() string {
	if a.Value == "" {
		return a.Key
	}
	return a.Key + "=" + a.Value
}

// AllSysctls returns the full sysctl rule set across tiers.
// Phase 2 only ships KSPP rules; Tier 2 sysctls land in Phase 4.
func AllSysctls() []SysctlRule {
	return append([]SysctlRule(nil), KSPPSysctls...)
}

// AllBootArgs returns the full boot-arg rule set across tiers.
func AllBootArgs() []BootArg {
	return append([]BootArg(nil), KSPPBootArgs...)
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
