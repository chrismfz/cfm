package kernsec

import "testing"

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
		if r.Tier == Tier2 && r.Decision != SkipByTier {
			t.Errorf("Tier 2 sysctl %q at tier 1: decision %v, want SkipByTier", r.ID, r.Decision)
		}
	}
	for _, r := range rs.BootArgs {
		if r.Tier == Tier1 && r.Decision != Apply {
			t.Errorf("Tier 1 boot %q at tier 1: decision %v reason=%q, want Apply", r.ID, r.Decision, r.Reason)
		}
		if r.Tier == Tier2 && r.Decision != SkipByTier {
			t.Errorf("Tier 2 boot %q at tier 1: decision %v, want SkipByTier", r.ID, r.Decision)
		}
	}
}

func TestResolve_Tier2AppliesAll(t *testing.T) {
	// IsEFIBoot: true so boot.dma rules apply (they're skipped on non-EFI hosts).
	rs := Resolve(&Conf{Tier: Tier2}, HostProfile{IsEFIBoot: true})
	// At tier=2 with an EFI host profile, every rule should Apply
	// EXCEPT KSEC-SCT-net.* which the managedsysctl registry marks
	// as ManagedExternally (owned by cfm-sysctl-tweaks). That's the
	// Phase 6 cross-component contract: kernsec audits but doesn't
	// write keys another cfm component owns.
	for _, r := range rs.Sysctls {
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
		if r.Decision != Apply {
			t.Errorf("boot %q at tier 2: decision %v reason=%q, want Apply", r.ID, r.Decision, r.Reason)
		}
	}
}

func TestResolve_Tier2HostProfileGates(t *testing.T) {
	// HasContainers → tier2.namespace skipped.
	// HasDKMS       → tier2.lockdown + tier2.module-sig-enforce skipped.
	conf := &Conf{Tier: Tier2}
	profile := HostProfile{HasContainers: true, HasDKMS: true}
	rs := Resolve(conf, profile)

	wantSkip := map[string]bool{
		"KSEC-SCT-tier2.namespace-001":           true,
		"KSEC-SCT-tier2.namespace-002":           true,
		"KSEC-BOOT-tier2.lockdown-001":           true,
		"KSEC-BOOT-tier2.module-sig-enforce-001": true,
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

	// We don't ship modules.ipsec rules until later phases; use a
	// synthetic rule ID forced by conf to exercise the path. The
	// effective behaviour we care about: OverrideForce returns Apply
	// even when a SkipReason would otherwise fire.
	conf := &Conf{
		Tier:      Tier1,
		Overrides: map[string]RuleOverride{"FAKE": OverrideForce},
	}
	d, _ := decide("FAKE", Tier1, "modules.ipsec", conf, hostHasIPsec)
	if d != Apply {
		t.Errorf("force override under hostprofile block: got %v, want Apply", d)
	}
}

func TestResolve_HostProfileSkipsKexec(t *testing.T) {
	conf := &Conf{Tier: Tier1}
	profile := HostProfile{HasKdump: true}
	d, reason := decide("KSEC-FAKE", Tier1, "boot.kexec", conf, profile)
	if d != SkipByHostProfile {
		t.Errorf("kdump host: got %v, want SkipByHostProfile", d)
	}
	if reason == "" {
		t.Error("expected non-empty reason")
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
	//   KernelSurface  (4) - Tier2 (2)    = 2
	//   NetHardenSysctls (7)              = 7
	//   Tier2Sysctls: SkipByTier        = 0
	//   NetSysctls (5): ManagedExternally = 0
	// Total = 27
	wantSysctls := len(KSPPSysctls) - 1 + (len(MemExploitSysctls) - 2) + (len(KernelSurface) - 2) + len(NetHardenSysctls)
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
	//   KSPPBootArgs (5) - 1 skipped       = 4
	//   Tier1BootArgsExt (4) - Tier2 SSBD = 3
	//   Tier2BootArgs: SkipByTier          = 0
	// Total = 7
	wantBootArgs := len(KSPPBootArgs) - 1 + (len(Tier1BootArgsExt) - 1)
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
		"kernel.kexec_load_disabled":  {"KSEC-SCT-kernel.surface-002", "1", Tier2},
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
	for _, display := range []string{"kernel.kexec_load_disabled=1", "kernel.core_pattern=|/bin/false", "kernel.panic_on_oops=1", "kernel.panic=10"} {
		if decisions[display] != SkipByTier {
			t.Errorf("tier1 decision for %s = %v, want SkipByTier", display, decisions[display])
		}
	}

	kdump := Resolve(&Conf{Tier: Tier2}, HostProfile{HasKdump: true})
	for _, r := range kdump.Sysctls {
		if r.Display == "kernel.kexec_load_disabled=1" && r.Decision != SkipByHostProfile {
			t.Errorf("kdump host decision for kernel.kexec_load_disabled = %v, want SkipByHostProfile", r.Decision)
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
			name: "kexec disabled is tier2", tier: Tier1, id: "KSEC-SCT-kernel.surface-002", want: SkipByTier,
		},
		{
			name: "kexec disabled applies on clean tier2 host", tier: Tier2, id: "KSEC-SCT-kernel.surface-002", want: Apply,
		},
		{
			name: "kexec disabled skips kdump", tier: Tier2, profile: HostProfile{HasKdump: true}, id: "KSEC-SCT-kernel.surface-002", want: SkipByHostProfile,
		},
		{
			name: "kexec disabled skips proxmox", tier: Tier2, profile: HostProfile{IsProxmox: true}, id: "KSEC-SCT-kernel.surface-002", want: SkipByHostProfile,
		},
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
			name: "ssbd seccomp is tier2", tier: Tier1, id: "KSEC-BOOT-ssbd-001", want: SkipByTier,
		},
		{
			name: "ssbd applies on clean tier2 host", tier: Tier2, profile: HostProfile{IsEFIBoot: true}, id: "KSEC-BOOT-ssbd-001", want: Apply,
		},
		{
			name: "ssbd skips containers", tier: Tier2, profile: HostProfile{IsEFIBoot: true, HasContainers: true}, id: "KSEC-BOOT-ssbd-001", want: SkipByHostProfile,
		},
		{
			name: "sctp blacklist is tier2", tier: Tier1, id: "KSEC-MOD-net.legacy-002", want: SkipByTier,
		},
		{
			name: "sctp blacklist applies on clean tier2 host", tier: Tier2, id: "KSEC-MOD-net.legacy-002", want: Apply,
		},
		{
			name: "sctp blacklist skips sctp workloads", tier: Tier2, profile: HostProfile{HasSCTPWorkload: true}, id: "KSEC-MOD-net.legacy-002", want: SkipByHostProfile,
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
