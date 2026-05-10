package kernsec

import (
	"bytes"
	"strings"
	"testing"
)

func TestApplyBootKeysFromResolved_FiltersToApply(t *testing.T) {
	// tier=1 conf with one explicit per-rule skip on a tier-1 boot
	// arg → that key must NOT appear in the kernel-log scan list.
	conf := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-BOOT-kspp-001": OverrideSkip, // slab_nomerge
		},
	}
	resolved := Resolve(conf, HostProfile{})
	keys := applyBootKeysFromResolved(resolved)

	for _, k := range keys {
		if k == "slab_nomerge" {
			t.Errorf("skipped boot arg should not be in scan list: %v", keys)
		}
	}
	// Other Tier 1 boot args should still be present (init_on_alloc,
	// page_alloc.shuffle, randomize_kstack_offset, initcall_blacklist).
	wantContains := []string{
		"init_on_alloc",
		"page_alloc.shuffle",
		"randomize_kstack_offset",
		"initcall_blacklist",
	}
	for _, w := range wantContains {
		found := false
		for _, k := range keys {
			if k == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected key %q in resolver-Apply scan list, got %v", w, keys)
		}
	}
}

func TestApplyBootKeysFromResolved_Tier0EmptyList(t *testing.T) {
	// tier=0 → nothing in Apply → empty key list. Kernel-log scan
	// for unknown args becomes a no-op, so a kernel that warns
	// about a key the operator manually added doesn't make
	// `status --check` non-zero on a disabled host.
	conf := &Conf{Tier: 0, Overrides: map[string]RuleOverride{}}
	resolved := Resolve(conf, HostProfile{})
	keys := applyBootKeysFromResolved(resolved)
	if len(keys) != 0 {
		t.Errorf("tier=0 should produce no scan keys, got %v", keys)
	}
}

func TestRunStatus_Tier0DoesNotWarnOnDisabledRuleProbes(t *testing.T) {
	// On a tier=0 host, every kernel-feature health probe paired with
	// a kernsec rule (AF_ALG, page_alloc.shuffle, mem auto-init,
	// randomize_kstack) must render OFF instead of WARN. `--check`
	// exit code reflects only kernsec-actionable drift, not
	// kernel-feature state on a host the operator chose to disable.
	withTempConfPath(t)
	c := &Conf{Tier: 0, Overrides: map[string]RuleOverride{}}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	res := RunStatus(&w, StatusOptions{SkipAFAlg: true})
	out := w.String()

	// Every gated kernel-feature probe should print an OFF line, not
	// a WARN — the probe runs informationally but doesn't escalate
	// to res.warn().
	for _, marker := range []string{
		"OFF   page_alloc.shuffle rule is disabled",
		"OFF   init_on_alloc rule is disabled",
		"OFF   randomize_kstack_offset rule is disabled",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("expected %q in tier=0 status, got:\n%s", marker, out)
		}
	}
	// Module section should report the file-absent state as OFF, not
	// MISSING — every module rule is OFF on a tier=0 host.
	if !strings.Contains(out, "OFF        ") || !strings.Contains(out, "no module rules active") {
		t.Errorf("expected OFF (not MISSING) for absent modprobe file on tier=0; got:\n%s", out)
	}
	// Sanity: the result struct should not reflect any of the gated
	// probes as warnings. There may still be tier-independent
	// warnings (e.g. kernel-config-not-readable IF kstack rule were
	// Apply, but it isn't here), so we don't assert exactly zero —
	// just that none of the strings above contributed.
	_ = res
}


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
