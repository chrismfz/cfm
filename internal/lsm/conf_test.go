package lsm

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConf_Empty(t *testing.T) {
	c, err := ParseConf(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseConf(empty): %v", err)
	}
	if c.Enabled {
		t.Fatal("empty conf should have enabled=false")
	}
	// Every known policy should be present with its DefaultMode.
	for _, p := range AllPolicies() {
		if got := c.Modes[p.ID]; got != p.DefaultMode {
			t.Errorf("policy %s: got mode %v, want default %v", p.ID, got, p.DefaultMode)
		}
	}
}

func TestParseConf_Full(t *testing.T) {
	body := `
# top-level
enabled = true

[policy "CFML-EXEC-001"]
mode = enforce

[policy "CFML-EXEC-003"]
mode = monitor

[policy "CFML-FS-005"]
mode = monitor
origin_tracking = monitor
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	if !c.Enabled {
		t.Fatal("enabled=true was not parsed")
	}
	if got := c.Modes[PolicyMemfdExec]; got != ModeEnforce {
		t.Errorf("memfd mode: got %v, want enforce", got)
	}
	if got := c.Modes[PolicyReverseShell]; got != ModeMonitor {
		t.Errorf("revshell mode: got %v, want monitor", got)
	}
	if !c.FS005WebOriginMonitor {
		t.Fatal("origin_tracking=monitor was not parsed")
	}
}

func TestParseConf_BoolAliases(t *testing.T) {
	cases := map[string]bool{
		"enabled = true":  true,
		"enabled = false": false,
		"enabled = 1":     true,
		"enabled = 0":     false,
		"enabled = on":    true,
		"enabled = off":   false,
		"enabled = YES":   true,
		"enabled = No":    false,
	}
	for body, want := range cases {
		c, err := ParseConf(strings.NewReader(body))
		if err != nil {
			t.Errorf("ParseConf(%q): %v", body, err)
			continue
		}
		if c.Enabled != want {
			t.Errorf("ParseConf(%q): got Enabled=%t, want %t", body, c.Enabled, want)
		}
	}
}

func TestParseConf_ModeAliases(t *testing.T) {
	cases := map[string]Mode{
		"disabled": ModeDisabled,
		"off":      ModeDisabled,
		"monitor":  ModeMonitor,
		"observe":  ModeMonitor,
		"enforce":  ModeEnforce,
		"block":    ModeEnforce,
	}
	for in, want := range cases {
		body := "[policy \"CFML-EXEC-001\"]\nmode = " + in + "\n"
		c, err := ParseConf(strings.NewReader(body))
		if err != nil {
			t.Errorf("ParseConf(mode=%q): %v", in, err)
			continue
		}
		if got := c.Modes[PolicyMemfdExec]; got != want {
			t.Errorf("ParseConf(mode=%q): got %v, want %v", in, got, want)
		}
	}
}

func TestParseConf_Errors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown top-level key",
			body: "tier = 1\n",
			want: "unknown top-level key",
		},
		{
			name: "unknown policy id",
			body: `[policy "CFML-BOGUS-999"]` + "\nmode = monitor\n",
			want: "unknown policy ID",
		},
		{
			name: "duplicate top-level key",
			body: "enabled = true\nenabled = false\n",
			want: "duplicate top-level key",
		},
		{
			name: "duplicate policy section",
			body: "[policy \"CFML-EXEC-001\"]\nmode = monitor\n\n[policy \"CFML-EXEC-001\"]\nmode = enforce\n",
			want: "duplicate policy section",
		},
		{
			name: "invalid mode",
			body: "[policy \"CFML-EXEC-001\"]\nmode = warpspeed\n",
			want: "invalid mode",
		},
		{
			name: "unknown policy key",
			body: "[policy \"CFML-EXEC-001\"]\nhook = bprm_check_security\n",
			want: "unknown policy key",
		},
		{
			name: "origin tracking on wrong policy",
			body: "[policy \"CFML-EXEC-001\"]\norigin_tracking = monitor\n",
			want: "origin_tracking is only valid",
		},
		{
			name: "invalid origin tracking",
			body: "[policy \"CFML-FS-005\"]\norigin_tracking = enforce\n",
			want: "invalid origin_tracking",
		},
		{
			name: "malformed line",
			body: "enabled\n",
			want: "malformed",
		},
		{
			name: "invalid bool",
			body: "enabled = maybe\n",
			want: "enabled must be",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConf(strings.NewReader(tc.body))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseConf_CommentsAndBlankLines(t *testing.T) {
	body := `
# this is a comment
# another comment

enabled = true   # trailing comment

# policy section follows
[policy "CFML-EXEC-001"]
mode = monitor   # inline comment after value
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	if !c.Enabled {
		t.Fatal("trailing comments should not break enabled parsing")
	}
	if got := c.Modes[PolicyMemfdExec]; got != ModeMonitor {
		t.Errorf("inline-comment line: got mode %v, want monitor", got)
	}
}

func TestFormatConf_RoundTrip(t *testing.T) {
	original := DefaultConf()
	original.Enabled = true
	original.Modes[PolicyMemfdExec] = ModeEnforce
	original.Modes[PolicyReverseShell] = ModeMonitor
	original.FS005WebOriginMonitor = true

	rendered := FormatConf(original)
	roundtrip, err := ParseConf(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("ParseConf(FormatConf): %v\n--- rendered ---\n%s", err, rendered)
	}
	if roundtrip.Enabled != original.Enabled {
		t.Errorf("enabled: got %t, want %t", roundtrip.Enabled, original.Enabled)
	}
	for _, p := range AllPolicies() {
		if a, b := original.Modes[p.ID], roundtrip.Modes[p.ID]; a != b {
			t.Errorf("policy %s: original %v, roundtrip %v", p.ID, a, b)
		}
	}
	if roundtrip.FS005WebOriginMonitor != original.FS005WebOriginMonitor {
		t.Errorf("origin tracking: got %t, want %t", roundtrip.FS005WebOriginMonitor, original.FS005WebOriginMonitor)
	}
}

func TestWriteDefaultConf(t *testing.T) {
	tmp := t.TempDir()
	prev := ConfPath
	ConfPath = filepath.Join(tmp, "lsm.conf")
	t.Cleanup(func() { ConfPath = prev })

	created, err := WriteDefaultConf()
	if err != nil {
		t.Fatalf("WriteDefaultConf: %v", err)
	}
	if !created {
		t.Fatal("first call should have created the file")
	}

	// Idempotent: second call must not overwrite.
	created2, err := WriteDefaultConf()
	if err != nil {
		t.Fatalf("WriteDefaultConf (2nd): %v", err)
	}
	if created2 {
		t.Fatal("second call should have reported created=false")
	}

	// Loaded conf must be parseable and contain every known policy.
	c, err := LoadConf(false)
	if err != nil {
		t.Fatalf("LoadConf: %v", err)
	}
	if c.Enabled {
		t.Fatal("default conf must have enabled=false")
	}
	for _, p := range AllPolicies() {
		if _, ok := c.Modes[p.ID]; !ok {
			t.Errorf("default conf missing policy %s", p.ID)
		}
	}
}

func TestModeFor_DefaultsWhenSilent(t *testing.T) {
	c := &Conf{
		Enabled: true,
		Modes:   map[PolicyID]Mode{}, // empty — every policy should fall back to DefaultMode
	}
	for _, p := range AllPolicies() {
		if got := c.ModeFor(p.ID); got != p.DefaultMode {
			t.Errorf("policy %s: got %v, want default %v", p.ID, got, p.DefaultMode)
		}
	}
	// Unknown ID returns disabled.
	if got := c.ModeFor("CFML-BOGUS-999"); got != ModeDisabled {
		t.Errorf("unknown ID: got %v, want disabled", got)
	}
	// Nil receiver returns disabled.
	var nilC *Conf
	if got := nilC.ModeFor(PolicyMemfdExec); got != ModeDisabled {
		t.Errorf("nil receiver: got %v, want disabled", got)
	}
}

func TestParseConf_KmsgSection(t *testing.T) {
	body := `
enabled = true

[kmsg]
state_transitions   = true
detect_events       = false
detect_rate_per_min = 25
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	if !c.Kmsg.StateTransitions {
		t.Error("state_transitions=true was not parsed")
	}
	if c.Kmsg.DetectEvents {
		t.Error("detect_events=false was not parsed")
	}
	if c.Kmsg.DetectRatePerMin != 25 {
		t.Errorf("detect_rate_per_min: got %d, want 25", c.Kmsg.DetectRatePerMin)
	}
}

func TestParseConf_KmsgSection_Defaults(t *testing.T) {
	// No [kmsg] section at all → DefaultKmsgConf() applies.
	body := `enabled = true`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseConf: %v", err)
	}
	def := DefaultKmsgConf()
	if c.Kmsg != def {
		t.Errorf("kmsg defaults not applied: got %+v, want %+v", c.Kmsg, def)
	}
}

func TestParseConf_KmsgSection_Errors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown kmsg key",
			body: "[kmsg]\nturbo = true\n",
			want: "unknown kmsg key",
		},
		{
			name: "non-bool state_transitions",
			body: "[kmsg]\nstate_transitions = sometimes\n",
			want: "state_transitions must be",
		},
		{
			name: "negative rate",
			body: "[kmsg]\ndetect_rate_per_min = -1\n",
			want: "detect_rate_per_min must be",
		},
		{
			name: "non-numeric rate",
			body: "[kmsg]\ndetect_rate_per_min = many\n",
			want: "detect_rate_per_min must be",
		},
		{
			name: "duplicate [kmsg] section",
			body: "[kmsg]\nstate_transitions = true\n\n[kmsg]\ndetect_events = false\n",
			want: "duplicate [kmsg] section",
		},
		{
			name: "duplicate key inside kmsg",
			body: "[kmsg]\nstate_transitions = true\nstate_transitions = false\n",
			want: "duplicate kmsg key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConf(strings.NewReader(tc.body))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestFormatConf_KmsgRoundTrip(t *testing.T) {
	original := DefaultConf()
	original.Enabled = true
	original.Kmsg.StateTransitions = true
	original.Kmsg.DetectEvents = false
	original.Kmsg.DetectRatePerMin = 7

	rendered := FormatConf(original)
	roundtrip, err := ParseConf(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("ParseConf(FormatConf): %v\n--- rendered ---\n%s", err, rendered)
	}
	if roundtrip.Kmsg != original.Kmsg {
		t.Errorf("kmsg round-trip drift: got %+v, want %+v", roundtrip.Kmsg, original.Kmsg)
	}
}
