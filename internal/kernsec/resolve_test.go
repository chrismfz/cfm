package kernsec

import (
	"bytes"
	"strings"
	"testing"
)

func TestResolve_Tier0SkipsEverything(t *testing.T) {
	rs := Resolve(&Conf{Tier: 0}, HostProfile{})
	for _, r := range rs.Sysctls {
		if r.Decision != SkipByTier {
			t.Errorf("sysctl %q at tier 0: decision %v, want SkipByTier", r.ID, r.Decision)
		}
	}
	for _, r := range rs.BootArgs {
		if r.Decision != SkipByTier {
			t.Errorf("boot %q at tier 0: decision %v, want SkipByTier", r.ID, r.Decision)
		}
	}
}

func TestResolveForceDoesNotResurrectRemovedRules(t *testing.T) {
	removedIDs := []string{
		strings.Join([]string{"KSEC-SCT-net", "harden-006"}, "."),
		strings.Join([]string{"KSEC-SCT-net", "harden-007"}, "."),
	}
	conf := &Conf{Tier: Tier2, Overrides: map[string]RuleOverride{}}
	for _, id := range removedIDs {
		conf.Overrides[id] = OverrideForce
	}

	rs := Resolve(conf, HostProfile{IsEFIBoot: true})
	for _, r := range append(append(rs.Sysctls, rs.BootArgs...), rs.Modules...) {
		for _, id := range removedIDs {
			if r.ID == id {
				t.Fatalf("removed rule %q resolved despite force override: %+v", id, r)
			}
		}
	}
}

func TestResolve_Tier1AppliesKSPP(t *testing.T) {
	// IsEFIBoot: true ensures boot.dma (efi=disable_early_pci_dma) is not
	// host-profile skipped in this test — the rule is EFI-specific but we
	// want to verify the resolver lets it through on an EFI host.
	rs := Resolve(&Conf{Tier: Tier1}, HostProfile{IsEFIBoot: true})
	// Tier 1 rules should Apply; Tier 2 rules should SkipByTier.
	// Exception: sysctl.net group is owned by cfm-sysctl-tweaks per
	// managedsysctl, so those Tier 1 rules resolve to ManagedExternally
	// (audit-only).
	for _, r := range rs.Sysctls {
		want := Apply
		if r.Group == "sysctl.net" {
			want = ManagedExternally
		}
		if r.Tier == Tier1 && r.Decision != want {
			t.Errorf("Tier 1 sysctl %q (group %q) at tier 1: decision %v reason=%q, want %v",
				r.ID, r.Group, r.Decision, r.Reason, want)
		}
		if (r.Tier == Tier2 || r.Tier == Tier3) && r.Decision != SkipByTier {
			t.Errorf("Tier %d sysctl %q at tier 1: decision %v, want SkipByTier", r.Tier, r.ID, r.Decision)
		}
	}
	for _, r := range rs.BootArgs {
		if r.Tier == Tier1 && r.Decision != Apply {
			t.Errorf("Tier 1 boot %q at tier 1: decision %v reason=%q, want Apply", r.ID, r.Decision, r.Reason)
		}
		if (r.Tier == Tier2 || r.Tier == Tier3) && r.Decision != SkipByTier {
			t.Errorf("Tier %d boot %q at tier 1: decision %v, want SkipByTier", r.Tier, r.ID, r.Decision)
		}
	}
}

func TestResolve_Tier2AppliesAll(t *testing.T) {
	// IsEFIBoot: true so boot.dma rules apply (they're skipped on non-EFI hosts).
	rs := Resolve(&Conf{Tier: Tier2}, HostProfile{IsEFIBoot: true})
	// At tier=2 with an EFI host profile, every Tier 1 + Tier 2 rule
	// should Apply EXCEPT KSEC-SCT-net.* (ManagedExternally — owned
	// by cfm-sysctl-tweaks). Tier 3 rules remain SkipByTier — that's
	// the explicit opt-in semantic and is exercised separately by
	// TestResolve_Tier3AppliesAll.
	for _, r := range rs.Sysctls {
		if r.Tier == Tier3 {
			if r.Decision != SkipByTier {
				t.Errorf("Tier 3 sysctl %q at tier 2: decision %v, want SkipByTier", r.ID, r.Decision)
			}
			continue
		}
		want := Apply
		if r.Group == "sysctl.net" {
			want = ManagedExternally
		}
		if r.Decision != want {
			t.Errorf("sysctl %q (group %q) at tier 2: decision %v reason=%q, want %v",
				r.ID, r.Group, r.Decision, r.Reason, want)
		}
	}
	for _, r := range rs.BootArgs {
		if r.Tier == Tier3 {
			if r.Decision != SkipByTier {
				t.Errorf("Tier 3 boot %q at tier 2: decision %v, want SkipByTier", r.ID, r.Decision)
			}
			continue
		}
		if r.Decision != Apply {
			t.Errorf("boot %q at tier 2: decision %v reason=%q, want Apply", r.ID, r.Decision, r.Reason)
		}
	}
}

func TestResolve_Tier3AppliesAll(t *testing.T) {
	// At tier=3 with an empty host profile, every rule across all
	// tiers should Apply (modulo ManagedExternally for sys_tweaks-owned
	// keys). This is the operator-opt-in semantic: raise conf.Tier to
	// 3 and the article-borrow Tier 3 boot args (init_on_free,
	// vsyscall=none, debugfs=off) land. Host-profile probes that
	// auto-skip individual entries (HasLegacyBinaries → vsyscall;
	// HasDebugfsConsumers → debugfs) are exercised separately by
	// TestResolve_Tier3HostProfileGates.
	rs := Resolve(&Conf{Tier: Tier3}, HostProfile{IsEFIBoot: true})
	for _, r := range rs.Sysctls {
		want := Apply
		if r.Group == "sysctl.net" {
			want = ManagedExternally
		}
		if r.Decision != want {
			t.Errorf("sysctl %q (group %q) at tier 3: decision %v reason=%q, want %v",
				r.ID, r.Group, r.Decision, r.Reason, want)
		}
	}
	for _, r := range rs.BootArgs {
		if r.Decision != Apply {
			t.Errorf("boot %q at tier 3: decision %v reason=%q, want Apply", r.ID, r.Decision, r.Reason)
		}
	}
}

func TestResolve_Tier2HostProfileGates(t *testing.T) {
	// HasContainers → tier2.namespace skipped.
	conf := &Conf{Tier: Tier2}
	profile := HostProfile{HasContainers: true}
	rs := Resolve(conf, profile)

	wantSkip := map[string]bool{
		"KSEC-SCT-tier2.namespace-001": true,
		"KSEC-SCT-tier2.namespace-002": true,
	}
	for id := range wantSkip {
		var got *ResolvedRule
		for i := range rs.Sysctls {
			if rs.Sysctls[i].ID == id {
				got = &rs.Sysctls[i]
				break
			}
		}
		if got == nil {
			for i := range rs.BootArgs {
				if rs.BootArgs[i].ID == id {
					got = &rs.BootArgs[i]
					break
				}
			}
		}
		if got == nil {
			t.Errorf("rule %q not in resolved set", id)
			continue
		}
		if got.Decision != SkipByHostProfile {
			t.Errorf("rule %q under host profile: got %v, want SkipByHostProfile (reason=%q)",
				id, got.Decision, got.Reason)
		}
	}
}

func TestResolve_OverrideSkip(t *testing.T) {
	conf := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-SCT-kspp.kernel-001": OverrideSkip,
		},
	}
	rs := Resolve(conf, HostProfile{})
	var found *ResolvedRule
	for i := range rs.Sysctls {
		if rs.Sysctls[i].ID == "KSEC-SCT-kspp.kernel-001" {
			found = &rs.Sysctls[i]
			break
		}
	}
	if found == nil {
		t.Fatal("rule not in resolved set")
	}
	if found.Decision != SkipByConf {
		t.Errorf("got %v, want SkipByConf", found.Decision)
	}
}

func TestResolve_OverrideForceBeatsHostProfile(t *testing.T) {
	// Host has IPsec policies → modules.ipsec normally skipped.
	// But operator forces a specific rule → Apply wins.
	hostHasIPsec := HostProfile{HasIPsec: true}

	// Use a synthetic rule ID forced by conf to exercise the path
	// without coupling the test to a specific shipped rule. The
	// effective behaviour we care about: OverrideForce returns Apply
	// even when a SkipReason would otherwise fire.
	conf := &Conf{
		Tier:      Tier1,
		Overrides: map[string]RuleOverride{"FAKE": OverrideForce},
	}
	d, _, _ := decide("FAKE", Tier1, "modules.ipsec", conf, hostHasIPsec)
	if d != Apply {
		t.Errorf("force override under hostprofile block: got %v, want Apply", d)
	}
}

func TestResolve_ForceUnderGatePopulatesWouldSkipReason(t *testing.T) {
	// llc forced on a Docker host: decision is Apply (force wins),
	// but WouldSkipReason carries the gate's "you'd break the bridge
	// module" warning so apply can refuse without --force-unsafe.
	conf := &Conf{
		Tier:      Tier1,
		Overrides: map[string]RuleOverride{"KSEC-MOD-net.legacy-017": OverrideForce},
	}
	rs := Resolve(conf, HostProfile{HasContainers: true})
	var got *ResolvedRule
	for i := range rs.Modules {
		if rs.Modules[i].ID == "KSEC-MOD-net.legacy-017" {
			got = &rs.Modules[i]
			break
		}
	}
	if got == nil {
		t.Fatal("llc rule not in resolved set")
	}
	if got.Decision != Apply {
		t.Errorf("decision = %v, want Apply", got.Decision)
	}
	if got.WouldSkipReason == "" {
		t.Error("WouldSkipReason is empty; expected gate reason for HasContainers + llc")
	}
}

func TestResolve_ForceWithoutGateLeavesWouldSkipReasonEmpty(t *testing.T) {
	// Forcing a rule on a host where the gate does NOT fire must
	// leave WouldSkipReason empty (i.e. apply will not refuse).
	conf := &Conf{
		Tier:      Tier1,
		Overrides: map[string]RuleOverride{"KSEC-MOD-net.legacy-017": OverrideForce},
	}
	rs := Resolve(conf, HostProfile{})
	for _, r := range rs.Modules {
		if r.ID == "KSEC-MOD-net.legacy-017" {
			if r.WouldSkipReason != "" {
				t.Errorf("WouldSkipReason = %q on clean host, want empty", r.WouldSkipReason)
			}
			return
		}
	}
	t.Fatal("llc rule not in resolved set")
}

func TestReportUnsafeForces_NamesRuleAndGateReason(t *testing.T) {
	var w bytes.Buffer
	unsafe := []ResolvedRule{
		{
			ID:              "KSEC-MOD-net.legacy-017",
			Display:         "llc",
			WouldSkipReason: "in-kernel bridge interface present",
		},
	}
	reportUnsafeForces(&w, unsafe)
	out := w.String()
	if !strings.Contains(out, "UNSAFE FORCE detected") {
		t.Errorf("output missing UNSAFE FORCE banner: %s", out)
	}
	if !strings.Contains(out, "KSEC-MOD-net.legacy-017") {
		t.Errorf("output missing rule ID: %s", out)
	}
	if !strings.Contains(out, "in-kernel bridge interface present") {
		t.Errorf("output missing gate reason: %s", out)
	}
}

func TestUnsafeForcedRules(t *testing.T) {
	// One forced-on-bridge-host rule, one normally-applied rule:
	// only the first one shows up as unsafe.
	conf := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-MOD-net.legacy-017": OverrideForce,
		},
	}
	rs := Resolve(conf, HostProfile{UsesBridge: true})
	unsafe := unsafeForcedRules(rs)
	if len(unsafe) == 0 {
		t.Fatal("unsafeForcedRules returned no entries; expected llc on UsesBridge host")
	}
	found := false
	for _, r := range unsafe {
		if r.ID == "KSEC-MOD-net.legacy-017" {
			found = true
			if r.WouldSkipReason == "" {
				t.Error("unsafe entry has empty WouldSkipReason")
			}
		}
	}
	if !found {
		t.Errorf("expected KSEC-MOD-net.legacy-017 in unsafe list; got %+v", unsafe)
	}

	// Clean host: same conf produces no unsafe entries.
	rsClean := Resolve(conf, HostProfile{})
	if got := unsafeForcedRules(rsClean); len(got) != 0 {
		t.Errorf("unsafeForcedRules on clean host = %d entries, want 0; got %+v", len(got), got)
	}
}

func TestResolve_NilConfTreatsEverythingAsSkipByTier(t *testing.T) {
	rs := Resolve(nil, HostProfile{})
	for _, r := range rs.Sysctls {
		if r.Decision != SkipByTier {
			t.Errorf("nil conf: %q decision %v, want SkipByTier", r.ID, r.Decision)
		}
	}
}

func TestResolvedSet_ApplySysctlsAndBootArgs(t *testing.T) {
	conf := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-SCT-kspp.kernel-001": OverrideSkip,
			"KSEC-BOOT-kspp-005":       OverrideSkip,
		},
	}
	// IsEFIBoot:true so efi=disable_early_pci_dma (boot.dma) applies.
	rs := Resolve(conf, HostProfile{IsEFIBoot: true})

	// Expected applying sysctls at tier=1:
	//   KSPPSysctls (11) - 1 skipped     = 10
	//   MemExploitSysctls (8) - Tier2 (2) = 6
	//   KernelSurface  (3) - Tier2 (1)    = 2
	//   NetHardenSysctls (5)              = 5
	//   Tier2Sysctls: SkipByTier        = 0
	//   NetSysctls (5): ManagedExternally = 0
	// Total = 23
	wantSysctls := len(KSPPSysctls) - 1 + (len(MemExploitSysctls) - 2) + (len(KernelSurface) - 1) + len(NetHardenSysctls)
	scts := rs.ApplySysctls()
	if len(scts) != wantSysctls {
		t.Errorf("ApplySysctls len = %d, want %d", len(scts), wantSysctls)
	}
	for _, s := range scts {
		if s.ID == "KSEC-SCT-kspp.kernel-001" {
			t.Error("skipped rule still in ApplySysctls")
		}
	}

	// Expected applying boot args at tier=1 with IsEFIBoot:
	//   KSPPBootArgs (5) - 1 skipped = 4
	//   Tier1BootArgsExt (3)        = 3
	//   Tier2BootArgs: SkipByTier   = 0
	// Total = 7
	wantBootArgs := len(KSPPBootArgs) - 1 + len(Tier1BootArgsExt)
	args := rs.ApplyBootArgs()
	if len(args) != wantBootArgs {
		t.Errorf("ApplyBootArgs len = %d, want %d", len(args), wantBootArgs)
	}
	for _, a := range args {
		if a.ID == "KSEC-BOOT-kspp-005" {
			t.Error("skipped rule still in ApplyBootArgs")
		}
	}
}

func TestReconciledDocsOnlySysctlsAreRegistered(t *testing.T) {
	want := map[string]struct {
		id    string
		value string
		tier  Tier
	}{
		"vm.unprivileged_userfaultfd": {"KSEC-SCT-mem.exploit-001", "0", Tier1},
		"vm.mmap_rnd_bits":            {"KSEC-SCT-mem.exploit-002", "32", Tier1},
		"vm.mmap_rnd_compat_bits":     {"KSEC-SCT-mem.exploit-003", "16", Tier1},
		"kernel.warn_limit":           {"KSEC-SCT-mem.exploit-004", "10", Tier1},
		"kernel.oops_limit":           {"KSEC-SCT-mem.exploit-005", "10", Tier1},
		"kernel.panic_on_oops":        {"KSEC-SCT-mem.exploit-006", "1", Tier2},
		"fs.suid_dumpable":            {"KSEC-SCT-mem.exploit-007", "0", Tier1},
		"kernel.panic":                {"KSEC-SCT-mem.exploit-008", "10", Tier2},
		"dev.tty.ldisc_autoload":      {"KSEC-SCT-kernel.surface-001", "0", Tier1},
		"kernel.sysrq":                {"KSEC-SCT-kernel.surface-003", "0", Tier1},
	}

	seen := map[string]SysctlRule{}
	for _, r := range AllSysctls() {
		seen[r.Key] = r
	}
	for key, w := range want {
		r, ok := seen[key]
		if !ok {
			t.Fatalf("%s missing from AllSysctls", key)
		}
		if r.ID != w.id || r.Value != w.value || r.Tier != w.tier {
			t.Errorf("%s registered as id=%q value=%q tier=%v, want id=%q value=%q tier=%v",
				key, r.ID, r.Value, r.Tier, w.id, w.value, w.tier)
		}
	}
}

func TestResolve_ReconciledSysctlTiersAndKdumpGate(t *testing.T) {
	tier1 := Resolve(&Conf{Tier: Tier1}, HostProfile{})
	decisions := map[string]Decision{}
	for _, r := range tier1.Sysctls {
		decisions[r.Display] = r.Decision
	}
	for _, display := range []string{
		"vm.unprivileged_userfaultfd=0",
		"vm.mmap_rnd_bits=32",
		"vm.mmap_rnd_compat_bits=16",
		"kernel.warn_limit=10",
		"kernel.oops_limit=10",
		"fs.suid_dumpable=0",
		"dev.tty.ldisc_autoload=0",
		"kernel.sysrq=0",
	} {
		if decisions[display] != Apply {
			t.Errorf("tier1 decision for %s = %v, want Apply", display, decisions[display])
		}
	}
	for _, display := range []string{"kernel.core_pattern=|/bin/false", "kernel.panic_on_oops=1", "kernel.panic=10"} {
		if decisions[display] != SkipByTier {
			t.Errorf("tier1 decision for %s = %v, want SkipByTier", display, decisions[display])
		}
	}

	tier2 := Resolve(&Conf{Tier: Tier2}, HostProfile{})
	for _, r := range tier2.Sysctls {
		if (r.Display == "kernel.panic_on_oops=1" || r.Display == "kernel.panic=10") && r.Decision != Apply {
			t.Errorf("tier2 decision for %s = %v, want Apply", r.Display, r.Decision)
		}
	}
}

func TestDecisionString(t *testing.T) {
	for _, tc := range []struct {
		d    Decision
		want string
	}{
		{Apply, "APPLY"},
		{SkipByConf, "SKIP-CONF"},
		{SkipByTier, "SKIP-TIER"},
		{SkipByHostProfile, "SKIP-HOST"},
	} {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("%v.String() = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestResolve_ForceOverrideShowsForcedAgainstHostingPanelGate(t *testing.T) {
	conf := &Conf{
		Tier: Tier2,
		Overrides: map[string]RuleOverride{
			"KSEC-SCT-tier2.namespace-001": OverrideForce,
		},
	}
	rs := Resolve(conf, HostProfile{IsCPanel: true, HasHostingPanelWorkload: true})
	for _, r := range rs.Sysctls {
		if r.ID != "KSEC-SCT-tier2.namespace-001" {
			continue
		}
		if r.Decision != Apply || r.Reason != "forced by conf" {
			t.Fatalf("forced namespace rule = decision %v reason %q, want Apply/forced by conf", r.Decision, r.Reason)
		}
		return
	}
	t.Fatal("namespace rule not found")
}

func TestReviewedRulesTierAndHostProfileDecisions(t *testing.T) {
	tests := []struct {
		name    string
		tier    Tier
		profile HostProfile
		id      string
		want    Decision
	}{
		{
			name: "core_pattern suppression is tier2", tier: Tier1, id: "KSEC-SCT-kernel.coredump-001", want: SkipByTier,
		},
		{
			name: "core_pattern applies on clean tier2 host", tier: Tier2, id: "KSEC-SCT-kernel.coredump-001", want: Apply,
		},
		{
			name: "core_pattern skips hosting panels", tier: Tier2, profile: HostProfile{IsCPanel: true, HasHostingPanelWorkload: true}, id: "KSEC-SCT-kernel.coredump-001", want: SkipByHostProfile,
		},
		{
			name: "core_pattern skips backup workloads", tier: Tier2, profile: HostProfile{HasBackupWorkload: true}, id: "KSEC-SCT-kernel.coredump-001", want: SkipByHostProfile,
		},
		{
			name: "core_pattern skips KVM host", tier: Tier2, profile: HostProfile{IsKVMHost: true}, id: "KSEC-SCT-kernel.coredump-001", want: SkipByHostProfile,
		},
		{
			name: "core_pattern skips container host", tier: Tier2, profile: HostProfile{HasContainers: true}, id: "KSEC-SCT-kernel.coredump-001", want: SkipByHostProfile,
		},
		{
			name: "llc applies on clean host", tier: Tier1, id: "KSEC-MOD-net.legacy-017", want: Apply,
		},
		{
			name: "llc skipped when bridges in use", tier: Tier1, profile: HostProfile{UsesBridge: true}, id: "KSEC-MOD-net.legacy-017", want: SkipByHostProfile,
		},
		{
			name: "llc2 skipped on Docker host", tier: Tier1, profile: HostProfile{HasContainers: true}, id: "KSEC-MOD-net.legacy-018", want: SkipByHostProfile,
		},
		{
			name: "llc skipped on KVM host", tier: Tier1, profile: HostProfile{IsKVMHost: true}, id: "KSEC-MOD-net.legacy-017", want: SkipByHostProfile,
		},
		{
			name: "llc skipped on Proxmox host", tier: Tier1, profile: HostProfile{IsProxmox: true}, id: "KSEC-MOD-net.legacy-017", want: SkipByHostProfile,
		},
		{
			name: "panic_on_oops skipped on KVM host", tier: Tier2, profile: HostProfile{IsKVMHost: true}, id: "KSEC-SCT-mem.exploit-006", want: SkipByHostProfile,
		},
		{
			name: "oops=panic bootarg skipped on container host", tier: Tier2, profile: HostProfile{HasContainers: true}, id: "KSEC-BOOT-tier2.oops-001", want: SkipByHostProfile,
		},
		{
			name: "panic=10 skipped on Proxmox host", tier: Tier2, profile: HostProfile{IsProxmox: true}, id: "KSEC-SCT-mem.exploit-008", want: SkipByHostProfile,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rs := Resolve(&Conf{Tier: tc.tier}, tc.profile)
			for _, r := range append(append(rs.Sysctls, rs.BootArgs...), rs.Modules...) {
				if r.ID == tc.id {
					if r.Decision != tc.want {
						t.Fatalf("%s decision = %v reason=%q, want %v", tc.id, r.Decision, r.Reason, tc.want)
					}
					return
				}
			}
			t.Fatalf("rule %s not found", tc.id)
		})
	}
}
