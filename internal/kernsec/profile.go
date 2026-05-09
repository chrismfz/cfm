// Package kernsec implements the cfm kernel attack-surface reduction
// component. See docs/kernsec.md for the full design.
//
// This file defines the KSPP server-safe profile (sysctls + boot args)
// that kernsec inherits from scripts/kspp.sh. Stable rule IDs and the
// full registry come in Phase 2; for now the profile is a flat list
// matching kspp.sh exactly so we can demonstrate "cfm kernsec status"
// is a strict superset of "kspp.sh status".
package kernsec

// SysctlRule is one expected sysctl key/value pair.
type SysctlRule struct {
	Key   string // dotted form, e.g. kernel.kptr_restrict
	Value string // expected value as string
}

// BootArg is one expected kernel boot argument.
//
// A bare token like "slab_nomerge" has Key=="slab_nomerge", Value=="".
// A "k=v" arg like "init_on_alloc=1" has Key=="init_on_alloc", Value=="1".
type BootArg struct {
	Key   string
	Value string
}

// KSPPSysctls is the server-safe sysctl profile from kspp.sh.
// Keep in sync with scripts/kspp.sh KSPP_SYSCTL until kspp.sh is removed.
var KSPPSysctls = []SysctlRule{
	{Key: "kernel.kptr_restrict", Value: "2"},
	{Key: "kernel.dmesg_restrict", Value: "1"},
	{Key: "kernel.unprivileged_bpf_disabled", Value: "1"},
	{Key: "kernel.randomize_va_space", Value: "2"},

	{Key: "fs.protected_hardlinks", Value: "1"},
	{Key: "fs.protected_symlinks", Value: "1"},
	{Key: "fs.protected_fifos", Value: "2"},
	{Key: "fs.protected_regular", Value: "2"},

	{Key: "net.core.bpf_jit_harden", Value: "2"},

	{Key: "kernel.perf_event_paranoid", Value: "3"},
	{Key: "kernel.yama.ptrace_scope", Value: "1"},
}

// KSPPBootArgs is the server-safe boot-arg profile from kspp.sh.
// Keep in sync with scripts/kspp.sh KSPP_ARGS until kspp.sh is removed.
//
// initcall_blacklist=algif_aead_init is the temporary mitigation for
// CVE-2026-31431 (Copy Fail). Remove later once all relevant kernels
// are patched.
var KSPPBootArgs = []BootArg{
	{Key: "slab_nomerge"},
	{Key: "init_on_alloc", Value: "1"},
	{Key: "page_alloc.shuffle", Value: "1"},
	{Key: "randomize_kstack_offset", Value: "on"},
	{Key: "initcall_blacklist", Value: "algif_aead_init"},
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
