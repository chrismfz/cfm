package kernsec

import (
	"testing"
)

func TestDecisionForBootArg_FallsBackToApplyForUnknown(t *testing.T) {
	// Empty resolved set → Apply (so hard-coded RunStatus follow-up
	// checks for kernel-feature health probes still run even when
	// they're not registered as kernsec rules).
	got := decisionForBootArg(ResolvedSet{}, "no_such_key", "")
	if got != Apply {
		t.Errorf("unknown rule should fall back to Apply, got %v", got)
	}
}

func TestDecisionForBootArg_FindsManagedRule(t *testing.T) {
	// algif_aead_init mitigation is KSEC-BOOT-kspp-005 — an actual
	// kernsec-managed boot arg. The cross-reference must find it by
	// display string ("key=value") so the hard-coded mitigation check
	// in RunStatus respects the operator's conf decision.
	conf := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-BOOT-kspp-005": OverrideSkip,
		},
	}
	resolved := Resolve(conf, HostProfile{})
	got := decisionForBootArg(resolved, "initcall_blacklist", "algif_aead_init")
	if got != SkipByConf {
		t.Errorf("operator-skipped algif rule should resolve to SkipByConf, got %v", got)
	}
}

func TestDecisionForBootArg_TierZeroProducesSkipByTier(t *testing.T) {
	conf := &Conf{Tier: 0, Overrides: map[string]RuleOverride{}}
	resolved := Resolve(conf, HostProfile{})
	got := decisionForBootArg(resolved, "initcall_blacklist", "algif_aead_init")
	if got != SkipByTier {
		t.Errorf("tier=0 should produce SkipByTier for algif rule, got %v", got)
	}
}

func TestDecisionForBootArg_Tier1AppliesAlgifMitigation(t *testing.T) {
	conf := &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	resolved := Resolve(conf, HostProfile{})
	got := decisionForBootArg(resolved, "initcall_blacklist", "algif_aead_init")
	if got != Apply {
		t.Errorf("tier=1 with no override should Apply algif mitigation, got %v", got)
	}
}
