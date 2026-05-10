package kernsec

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunPreview_TierOverrideZeroResolvesAsTierZero(t *testing.T) {
	// Operator passes `--tier 0` (TierOverride=true, Tier=0) — every
	// rule must render as OFF (decision SkipByTier). Previously the
	// guard `if opts.Tier != 0` treated 0 as "no override" so the
	// operator couldn't preview "what would `disable` look like?".
	withTempConfPath(t)
	// Write a tier=2 conf so opts.Tier=0 is genuinely overriding.
	c := &Conf{Tier: Tier2, Overrides: map[string]RuleOverride{}}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	rc := RunPreview(&w, PreviewOptions{TierOverride: true, Tier: 0})
	if rc != 0 {
		t.Fatalf("expected rc=0 from preview, got %d. Output:\n%s", rc, w.String())
	}
	out := w.String()
	// Banner shows tier=0 (the override).
	if !strings.Contains(out, "Tier:     0") {
		t.Errorf("expected banner to show overridden tier=0, got:\n%s", out)
	}
	// And every rule renders as a SKIP-TIER decision.
	if !strings.Contains(out, "SKIP-TIER") {
		t.Errorf("expected SKIP-TIER decisions on every rule, got:\n%s", out)
	}
	// Critically: no Apply rows when the override is tier=0.
	if strings.Contains(out, " APPLY  ") {
		t.Errorf("tier=0 override should produce zero Apply rows, got:\n%s", out)
	}
}

func TestRunPreview_NoTierOverrideHonorsConf(t *testing.T) {
	// Without TierOverride, conf.Tier (set to Tier1 here) is honored.
	// Tier 1 rules should still resolve to Apply.
	withTempConfPath(t)
	c := &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	rc := RunPreview(&w, PreviewOptions{}) // TierOverride=false, Tier=0
	if rc != 0 {
		t.Fatalf("rc=%d: %s", rc, w.String())
	}
	out := w.String()
	if !strings.Contains(out, "Tier:     1") {
		t.Errorf("expected banner to show conf tier=1 (no override), got:\n%s", out)
	}
	// At least some rule should resolve to APPLY at tier=1.
	if !strings.Contains(out, "APPLY") {
		t.Errorf("tier=1 should produce Apply rows, got:\n%s", out)
	}
}
