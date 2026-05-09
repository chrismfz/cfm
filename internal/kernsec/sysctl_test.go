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
	for _, a := range KSPPBootArgs {
		if !IsManagedKey(a.Key) {
			t.Errorf("KSPPBootArgs key %q not in ManagedBootArgKeys", a.Key)
		}
	}
	// Every sysctl rule must have a non-empty key and value.
	for _, r := range KSPPSysctls {
		if r.Key == "" || r.Value == "" {
			t.Errorf("KSPPSysctls has empty key/value: %+v", r)
		}
	}
}
