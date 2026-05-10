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
		"KSEC-SCT-tier2.namespace-001":            true,
		"KSEC-SCT-tier2.namespace-002":            true,
		"KSEC-BOOT-tier2.lockdown-001":            true,
		"KSEC-BOOT-tier2.module-sig-enforce-001":  true,
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
	//   KSPPSysctls (11) - 1 skipped   = 10
	//   KernelSurface  (1)              = 1
	//   NetHardenSysctls (7)            = 7
	//   Tier2Sysctls: SkipByTier        = 0
	//   NetSysctls (5): ManagedExternally = 0
	// Total = 18
	wantSysctls := len(KSPPSysctls) - 1 + len(KernelSurface) + len(NetHardenSysctls)
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
	//   Tier1BootArgsExt (4): all apply on EFI host = 4
	//   Tier2BootArgs: SkipByTier          = 0
	// Total = 8
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
