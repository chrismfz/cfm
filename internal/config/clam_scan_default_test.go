package config

import (
	"strings"
	"testing"
)

// CLAM_SCAN_DEFAULT is a "default true" bool: the async notify-only scanner has
// run fleet-wide for months, so an absent key must preserve scanning (not
// silently stop it on upgrade). ParseCFMConf seeds true before the parse loop
// and only an explicit key flips it. These pin all three cases so a future
// refactor of the defaulting can't regress the upgrade behaviour.
func TestParseCFMConf_ClamScanDefault(t *testing.T) {
	cases := []struct {
		name string
		conf string
		want bool
	}{
		{"absent key defaults ON", "", true},
		{"explicit 0 disables", "CLAM_SCAN_DEFAULT = 0\n", false},
		{"explicit 1 enables", "CLAM_SCAN_DEFAULT = 1\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseCFMConf(strings.NewReader(tc.conf))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cfg.Clam.ScanDefault != tc.want {
				t.Fatalf("ScanDefault = %v, want %v", cfg.Clam.ScanDefault, tc.want)
			}
		})
	}
}
