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
