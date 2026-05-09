package kernsec

import "testing"

func TestSysctlProcPath(t *testing.T) {
	tests := []struct {
		key, want string
	}{
		{"kernel.kptr_restrict", "/proc/sys/kernel/kptr_restrict"},
		{"net.core.bpf_jit_harden", "/proc/sys/net/core/bpf_jit_harden"},
		{"kernel.yama.ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope"},
	}
	for _, tc := range tests {
		if got := SysctlProcPath(tc.key); got != tc.want {
			t.Errorf("SysctlProcPath(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestKSPPProfileSanity(t *testing.T) {
	if len(KSPPSysctls) == 0 {
		t.Fatal("KSPPSysctls is empty")
	}
	if len(KSPPBootArgs) == 0 {
		t.Fatal("KSPPBootArgs is empty")
	}
	if len(ManagedBootArgKeys) == 0 {
		t.Fatal("ManagedBootArgKeys is empty")
	}
	// Every BootArg key must be in ManagedBootArgKeys, otherwise enable
	// would add args that disable couldn't remove.
	for _, a := range AllBootArgs() {
		if !IsManagedKey(a.Key) {
			t.Errorf("boot arg key %q not in ManagedBootArgKeys", a.Key)
		}
		if a.Description == "" {
			t.Errorf("%q has empty Description", a.Key)
		}
		if a.Affects == "" {
			t.Errorf("%q has empty Affects", a.Key)
		}
		if a.ID == "" {
			t.Errorf("%q has empty ID", a.Key)
		}
		if a.Tier != Tier1 && a.Tier != Tier2 {
			t.Errorf("%q has invalid Tier %d", a.Key, a.Tier)
		}
	}
	// Every sysctl rule must have a non-empty key, value, description, affects.
	for _, r := range AllSysctls() {
		if r.Key == "" || r.Value == "" {
			t.Errorf("sysctl has empty key/value: %+v", r)
		}
		if r.Description == "" {
			t.Errorf("sysctl %q has empty Description", r.Key)
		}
		if r.Affects == "" {
			t.Errorf("sysctl %q has empty Affects", r.Key)
		}
		if r.ID == "" {
			t.Errorf("sysctl %q has empty ID", r.Key)
		}
		if r.Tier != Tier1 && r.Tier != Tier2 {
			t.Errorf("sysctl %q has invalid Tier %d", r.Key, r.Tier)
		}
	}
	// Tier 2 rules must exist (Phase 4 invariant).
	if len(Tier2Sysctls) == 0 {
		t.Error("Tier2Sysctls is empty")
	}
	if len(Tier2BootArgs) == 0 {
		t.Error("Tier2BootArgs is empty")
	}
	// Rule IDs must be unique across both tiers.
	ids := map[string]struct{}{}
	for _, r := range AllSysctls() {
		if _, dup := ids[r.ID]; dup {
			t.Errorf("duplicate sysctl ID: %q", r.ID)
		}
		ids[r.ID] = struct{}{}
	}
	for _, a := range AllBootArgs() {
		if _, dup := ids[a.ID]; dup {
			t.Errorf("duplicate boot arg ID: %q", a.ID)
		}
		ids[a.ID] = struct{}{}
	}
}
