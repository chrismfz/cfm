package kernsec

import (
	"strings"
	"testing"
)

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
		if a.Tier != Tier1 && a.Tier != Tier2 && a.Tier != Tier3 {
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
		if r.Tier != Tier1 && r.Tier != Tier2 && r.Tier != Tier3 {
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

func TestCheckSysctl_AcceptValuesTreatedAsOK(t *testing.T) {
	// kernel.unprivileged_bpf_disabled rule: target =2, accepts =1.
	// On CONFIG_BPF_UNPRIV_DEFAULT_OFF=y kernels the live value is 1
	// and runtime upgrade is locked — flagging this as WARN would
	// pollute the audit's green signal forever.
	var rule SysctlRule
	for _, r := range KSPPSysctls {
		if r.Key == "kernel.unprivileged_bpf_disabled" {
			rule = r
			break
		}
	}
	if rule.Key == "" {
		t.Fatal("kernel.unprivileged_bpf_disabled rule missing from KSPPSysctls")
	}
	if len(rule.AcceptValues) == 0 {
		t.Fatal("kernel.unprivileged_bpf_disabled rule must list =1 in AcceptValues")
	}
	found := false
	for _, v := range rule.AcceptValues {
		if v == "1" {
			found = true
		}
	}
	if !found {
		t.Errorf("AcceptValues=%v should contain \"1\"", rule.AcceptValues)
	}
}

func TestCheckSysctl_PtraceScopeRequiresMode2(t *testing.T) {
	// kernel.yama.ptrace_scope rule: target =2, no AcceptValues. Mode 1
	// used to be accepted as also-green, but it leaves the same-uid
	// pidfd_getfd() exit-window race against setuid helpers open — the
	// ssh-keysign / chage fd-leak chain (Linus commit 31e62c2ebbfd) is
	// a working /etc/shadow disclosure primitive. Operators who need
	// same-uid debuggability must `state = skip` this rule in
	// kernsec.conf instead of relying on a permissive AcceptValues.
	var rule SysctlRule
	for _, r := range KSPPSysctls {
		if r.Key == "kernel.yama.ptrace_scope" {
			rule = r
			break
		}
	}
	if rule.Key == "" {
		t.Fatal("kernel.yama.ptrace_scope rule missing from KSPPSysctls")
	}
	if rule.Value != "2" {
		t.Errorf("kernel.yama.ptrace_scope rule Value=%q, want \"2\"", rule.Value)
	}
	if len(rule.AcceptValues) != 0 {
		t.Errorf("kernel.yama.ptrace_scope rule must not list AcceptValues "+
			"(got %v) — =1 leaves the setuid-helper fd-leak race open and "+
			"is no longer audit-green; operators wanting =1 must `state = skip`",
			rule.AcceptValues)
	}
}

func TestRemovedSysctlRulesAbsentFromRegistry(t *testing.T) {
	removedIDs := []string{
		strings.Join([]string{"KSEC-SCT-net", "harden-006"}, "."),
		strings.Join([]string{"KSEC-SCT-net", "harden-007"}, "."),
	}
	removedKeys := []string{
		"net.ipv6.conf.all." + "accept" + "_ra",
		"kernel." + "kexec" + "_load_disabled",
		"kernel." + "lock" + "down",
		"module." + "sig" + "_enforce",
	}

	for _, r := range AllSysctls() {
		for _, id := range removedIDs {
			if r.ID == id {
				t.Fatalf("removed sysctl rule ID %q is still registered", id)
			}
		}
		for _, key := range removedKeys {
			if r.Key == key {
				t.Fatalf("removed sysctl key %q is still registered as %s", key, r.ID)
			}
		}
	}
}
