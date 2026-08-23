package detconf

import (
	"testing"
	"time"
)

// ParseCfgDuration is the single duration grammar for detectors.conf scalars
// (kvDur fields AND BLOCK). The runtime and the API-server save-time
// validation MUST agree on it — see TestValidateDetectorDraftBlockAcceptsDays.
func TestParseCfgDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"30m", 30 * time.Minute, true},
		{"1h30m", 90 * time.Minute, true},
		{"7d", 7 * 24 * time.Hour, true},
		{"1d12h", 36 * time.Hour, true},
		{"1.5d", 36 * time.Hour, true},
		{"2w", 0, false}, // weeks are not a unit
		{"7x", 0, false},
		{"d7", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, err := ParseCfgDuration(c.in)
		if c.ok && err != nil {
			t.Errorf("ParseCfgDuration(%q) unexpected error: %v", c.in, err)
			continue
		}
		if !c.ok {
			if err == nil {
				t.Errorf("ParseCfgDuration(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("ParseCfgDuration(%q) = %v want %v", c.in, got, c.want)
		}
	}
}
