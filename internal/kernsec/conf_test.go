package kernsec

import (
	"strings"
	"testing"
)

func TestParseConf_Defaults(t *testing.T) {
	c, err := ParseConf(strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Tier != 0 {
		t.Errorf("default Tier = %d, want 0", c.Tier)
	}
	if len(c.Overrides) != 0 {
		t.Errorf("default Overrides = %v, want empty", c.Overrides)
	}
}

func TestParseConf_Tier(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Tier
	}{
		{"tier = 0\n", 0},
		{"tier = 1\n", Tier1},
		{"tier = 2\n", Tier2},
		{"  tier=1\n", Tier1},
		{"# comment\ntier = 1 # inline comment\n", Tier1},
	} {
		c, err := ParseConf(strings.NewReader(tc.in))
		if err != nil {
			t.Fatalf("parse %q: %v", tc.in, err)
		}
		if c.Tier != tc.want {
			t.Errorf("parse %q: Tier = %d, want %d", tc.in, c.Tier, tc.want)
		}
	}
}

func TestParseConf_TierInvalid(t *testing.T) {
	for _, in := range []string{
		"tier = 3\n",
		"tier = -1\n",
		"tier = banana\n",
	} {
		if _, err := ParseConf(strings.NewReader(in)); err == nil {
			t.Errorf("parse %q: expected error, got nil", in)
		}
	}
}

func TestParseConf_RuleOverrides(t *testing.T) {
	in := `
tier = 1

[rule "KSEC-MOD-net.legacy-001"]
state = skip

[rule "KSEC-SCT-kspp.kernel-005"]
state = force

# below should land as default
[rule "KSEC-BOOT-kspp-001"]
state = default
`
	c, err := ParseConf(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Tier != Tier1 {
		t.Errorf("Tier = %d, want 1", c.Tier)
	}
	wantOverrides := map[string]RuleOverride{
		"KSEC-MOD-net.legacy-001":   OverrideSkip,
		"KSEC-SCT-kspp.kernel-005":  OverrideForce,
		"KSEC-BOOT-kspp-001":        OverrideDefault,
	}
	if len(c.Overrides) != len(wantOverrides) {
		t.Fatalf("got %d overrides, want %d: %v", len(c.Overrides), len(wantOverrides), c.Overrides)
	}
	for id, want := range wantOverrides {
		if got := c.Overrides[id]; got != want {
			t.Errorf("override %q = %v, want %v", id, got, want)
		}
	}
}

func TestParseConf_BadHeader(t *testing.T) {
	for _, in := range []string{
		`[banana "x"]` + "\n",
		`[rule]` + "\n",
		`[rule x]` + "\n",
	} {
		if _, err := ParseConf(strings.NewReader(in)); err == nil {
			t.Errorf("parse %q: expected error, got nil", in)
		}
	}
}

func TestParseConf_BadRuleKey(t *testing.T) {
	in := `[rule "KSEC-MOD-net.legacy-001"]
banana = skip
`
	if _, err := ParseConf(strings.NewReader(in)); err == nil {
		t.Error("expected error for unknown rule key")
	}
}

func TestParseConf_BadStateValue(t *testing.T) {
	in := `[rule "KSEC-MOD-net.legacy-001"]
state = banana
`
	if _, err := ParseConf(strings.NewReader(in)); err == nil {
		t.Error("expected error for bad state value")
	}
}

func TestParseConf_BadTopLevelKey(t *testing.T) {
	if _, err := ParseConf(strings.NewReader("banana = 1\n")); err == nil {
		t.Error("expected error for unknown top-level key")
	}
}

func TestRenderRoundtrip(t *testing.T) {
	c := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-MOD-net.legacy-001":  OverrideSkip,
			"KSEC-SCT-kspp.kernel-005": OverrideForce,
		},
	}
	out := c.Render()
	c2, err := ParseConf(strings.NewReader(out))
	if err != nil {
		t.Fatalf("parse rendered: %v\n%s", err, out)
	}
	if c2.Tier != c.Tier {
		t.Errorf("roundtrip Tier = %d, want %d", c2.Tier, c.Tier)
	}
	for id, want := range c.Overrides {
		if got := c2.Overrides[id]; got != want {
			t.Errorf("roundtrip override %q = %v, want %v", id, got, want)
		}
	}
}

func TestRenderStableOrder(t *testing.T) {
	// Same Conf twice → identical render.
	c := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-Z": OverrideSkip,
			"KSEC-A": OverrideForce,
			"KSEC-M": OverrideSkip,
		},
	}
	a := c.Render()
	b := c.Render()
	if a != b {
		t.Errorf("render not deterministic:\nA:\n%s\nB:\n%s", a, b)
	}
	// Stanzas should be alphabetised.
	idx := func(s string) int { return strings.Index(a, s) }
	if !(idx("KSEC-A") < idx("KSEC-M") && idx("KSEC-M") < idx("KSEC-Z")) {
		t.Errorf("stanzas not alphabetised:\n%s", a)
	}
}

func TestStripComment(t *testing.T) {
	tests := []struct{ in, want string }{
		{"foo", "foo"},
		{"foo # comment", "foo "},
		{"# whole-line", ""},
		{"key = value # tail", "key = value "},
	}
	for _, tc := range tests {
		if got := stripComment(tc.in); got != tc.want {
			t.Errorf("stripComment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRuleOverrideString(t *testing.T) {
	tests := []struct {
		in   RuleOverride
		want string
	}{
		{OverrideDefault, "default"},
		{OverrideSkip, "skip"},
		{OverrideForce, "force"},
	}
	for _, tc := range tests {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("%v.String() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseConf_RejectsDuplicateTopLevelKey(t *testing.T) {
	// A merge artifact or hand-edit can produce two `tier = N` lines.
	// Previously the second silently overwrote the first; now it's a
	// parse error naming both lines so the operator can resolve the
	// conflict explicitly.
	conf := `# header
tier = 1
tier = 2
`
	_, err := ParseConf(strings.NewReader(conf))
	if err == nil {
		t.Fatal("expected duplicate top-level key error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "duplicate top-level key") {
		t.Errorf("error should mention duplicate top-level: %v", err)
	}
	if !strings.Contains(msg, "tier") {
		t.Errorf("error should name the duplicated key: %v", err)
	}
	if !strings.Contains(msg, "first at line 2") {
		t.Errorf("error should reference the first occurrence line: %v", err)
	}
}

func TestParseConf_RejectsDuplicateRuleSection(t *testing.T) {
	// A merge artifact or hand-edit can produce two `[rule "X"]`
	// stanzas for the same ID. Previously the second silently
	// overwrote the first; now it's a parse error naming both lines.
	conf := `tier = 1

[rule "KSEC-MOD-net.legacy-001"]
state = skip

[rule "KSEC-MOD-net.legacy-001"]
state = force
`
	_, err := ParseConf(strings.NewReader(conf))
	if err == nil {
		t.Fatal("expected duplicate-section error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "duplicate rule section") {
		t.Errorf("error should mention duplicate-section: %v", err)
	}
	if !strings.Contains(msg, "KSEC-MOD-net.legacy-001") {
		t.Errorf("error should name the rule ID: %v", err)
	}
	if !strings.Contains(msg, "first at line") {
		t.Errorf("error should reference the first occurrence line: %v", err)
	}
}

func TestAllRuleIDs_CoversEveryRegistry(t *testing.T) {
	ids := AllRuleIDs()
	// Spot-check at least one ID from each registry is present.
	for _, want := range []string{
		"KSEC-SCT-kspp.kernel-001",     // sysctl
		"KSEC-BOOT-kspp-001",           // boot arg
		"KSEC-MOD-net.legacy-001",      // module
		"KSEC-FS-mount.tmp-001",        // mount
		LSMBPFRuleID,                   // one-off cmdline mutator, not in any registry
	} {
		if _, ok := ids[want]; !ok {
			t.Errorf("AllRuleIDs missing %q", want)
		}
	}
	// No duplicates / empty entries.
	if _, ok := ids[""]; ok {
		t.Error("AllRuleIDs contains empty string key")
	}
}

func TestValidateConfOverrideIDs_NilAndEmpty(t *testing.T) {
	if got := ValidateConfOverrideIDs(nil); got != nil {
		t.Errorf("nil conf: got %v, want nil", got)
	}
	if got := ValidateConfOverrideIDs(&Conf{}); got != nil {
		t.Errorf("conf with no overrides: got %v, want nil", got)
	}
}

func TestValidateConfOverrideIDs_KnownIDsHaveNoWarning(t *testing.T) {
	c := &Conf{
		Overrides: map[string]RuleOverride{
			"KSEC-SCT-kspp.kernel-001":  OverrideSkip,
			"KSEC-MOD-net.legacy-001":   OverrideForce,
			"KSEC-FS-mount.tmp-001":     OverrideSkip,
			// KSEC-LSM-bpf-001 is the documented activation override
			// for the BPF LSM cmdline merger. Must not warn when set.
			LSMBPFRuleID:                OverrideForce,
		},
	}
	if got := ValidateConfOverrideIDs(c); got != nil {
		t.Errorf("known IDs should produce no warnings, got %v", got)
	}
}

func TestValidateConfOverrideIDs_TypoSurfacesWarning(t *testing.T) {
	c := &Conf{
		Overrides: map[string]RuleOverride{
			"KSEC-MOD-net.legacy-099":  OverrideSkip, // typo: only the curated range exists
			"KSEC-SCT-typo-999":        OverrideForce, // wholly fake
			"KSEC-MOD-net.legacy-001":  OverrideSkip, // real, must NOT warn
		},
	}
	got := ValidateConfOverrideIDs(c)
	if len(got) != 2 {
		t.Fatalf("expected 2 warnings (one per typo), got %d: %v", len(got), got)
	}
	// Warnings are sorted by ID for stable output. KSEC-MOD-net.legacy-099
	// comes before KSEC-SCT-typo-999 alphabetically.
	if !strings.Contains(got[0], "KSEC-MOD-net.legacy-099") {
		t.Errorf("first warning should mention the typo'd module ID: %v", got[0])
	}
	if !strings.Contains(got[1], "KSEC-SCT-typo-999") {
		t.Errorf("second warning should mention the fake sysctl ID: %v", got[1])
	}
}
