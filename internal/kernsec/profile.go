// Package kernsec implements the cfm kernel attack-surface reduction
// component. See docs/kernsec.md for the full design.
//
// This file defines the KSPP server-safe profile (sysctls + boot args)
// that kernsec inherits from scripts/kspp.sh. Stable rule IDs and the
// full registry come in Phase 2; for now the profile is a flat list
// matching kspp.sh exactly so we can demonstrate "cfm kernsec status"
// is a strict superset of "kspp.sh status".
package kernsec

// SysctlRule is one expected sysctl key/value pair plus the human-readable
// blurbs the TUI surfaces for it.
type SysctlRule struct {
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
	Key         string
	Value       string
	Description string // one-line "what this does"
	Affects     string // one-line "what enabling this breaks"
}

// KSPPSysctls is the server-safe sysctl profile from kspp.sh.
// Keep in sync with scripts/kspp.sh KSPP_SYSCTL until kspp.sh is removed.
var KSPPSysctls = []SysctlRule{
	{
		Key: "kernel.kptr_restrict", Value: "2",
		Description: "Hide kernel pointers from userspace (/proc/kallsyms, dmesg, /proc/<pid>/stack).",
		Affects:     "Nothing on production. Symbol resolution still works for root.",
	},
	{
		Key: "kernel.dmesg_restrict", Value: "1",
		Description: "Restrict dmesg / kernel log reads to root.",
		Affects:     "Regular users can no longer read the kernel log.",
	},
	{
		Key: "kernel.unprivileged_bpf_disabled", Value: "1",
		Description: "Block unprivileged BPF program loading.",
		Affects:     "Kills a major LPE primitive class. Root BPF (cilium etc.) unchanged.",
	},
	{
		Key: "kernel.randomize_va_space", Value: "2",
		Description: "Full ASLR for stack, heap, mmap, VDSO.",
		Affects:     "Nothing. Distro default already.",
	},
	{
		Key: "fs.protected_hardlinks", Value: "1",
		Description: "Prevent hardlink-based privilege escalation in shared directories.",
		Affects:     "Nothing in normal use.",
	},
	{
		Key: "fs.protected_symlinks", Value: "1",
		Description: "Restrict symlink-following in sticky-bit directories like /tmp.",
		Affects:     "Nothing in normal use.",
	},
	{
		Key: "fs.protected_fifos", Value: "2",
		Description: "Block unsafe FIFO usage in world-writable directories.",
		Affects:     "Nothing in normal use.",
	},
	{
		Key: "fs.protected_regular", Value: "2",
		Description: "Same protection family applied to regular files.",
		Affects:     "Nothing in normal use.",
	},
	{
		Key: "net.core.bpf_jit_harden", Value: "2",
		Description: "Constant blinding in the BPF JIT to defeat JIT-spray exploits.",
		Affects:     "Minor JIT performance cost. Negligible in practice.",
	},
	{
		Key: "kernel.perf_event_paranoid", Value: "3",
		Description: "Restrict perf_event_open() to root.",
		Affects:     "Developer profiling tools (perf, flamegraph) need sudo.",
	},
	{
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
		Key: "slab_nomerge",
		Description: "Don't merge slab caches that have similar size. Hardens against type-confusion UAF exploits.",
		Affects:     "Small RAM overhead.",
	},
	{
		Key: "init_on_alloc", Value: "1",
		Description: "Zero pages on allocation. Kills uninitialized-memory leaks across the whole kernel.",
		Affects:     "~0-5% performance cost on alloc-heavy workloads.",
	},
	{
		Key: "page_alloc.shuffle", Value: "1",
		Description: "Randomize buddy-allocator freelists. Mild ASLR boost for kernel allocations.",
		Affects:     "Nothing measurable.",
	},
	{
		Key: "randomize_kstack_offset", Value: "on",
		Description: "Per-syscall kernel-stack randomization. Makes ROP / stack-spray exploits harder.",
		Affects:     "Nothing.",
	},
	{
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
