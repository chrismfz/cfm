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
	rs := Resolve(&Conf{Tier: Tier1}, HostProfile{})
	for _, r := range rs.Sysctls {
		if r.Decision != Apply {
			t.Errorf("sysctl %q at tier 1: decision %v reason=%q, want Apply", r.ID, r.Decision, r.Reason)
		}
	}
	for _, r := range rs.BootArgs {
		if r.Decision != Apply {
			t.Errorf("boot %q at tier 1: decision %v reason=%q, want Apply", r.ID, r.Decision, r.Reason)
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
	rs := Resolve(conf, HostProfile{})

	scts := rs.ApplySysctls()
	if len(scts) != len(KSPPSysctls)-1 {
		t.Errorf("ApplySysctls len = %d, want %d", len(scts), len(KSPPSysctls)-1)
	}
	for _, s := range scts {
		if s.ID == "KSEC-SCT-kspp.kernel-001" {
			t.Error("skipped rule still in ApplySysctls")
		}
	}

	args := rs.ApplyBootArgs()
	if len(args) != len(KSPPBootArgs)-1 {
		t.Errorf("ApplyBootArgs len = %d, want %d", len(args), len(KSPPBootArgs)-1)
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
