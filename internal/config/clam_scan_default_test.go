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

// CLAM_SCAN_SCOPE defaults to archives (a deliberate, announced coverage
// change); only the two known values are accepted, anything else keeps the
// default rather than silently disabling the gate.
func TestParseCFMConf_ClamScanScope(t *testing.T) {
	cases := []struct {
		name string
		conf string
		want string
	}{
		{"absent key defaults archives", "", "archives"},
		{"explicit all", "CLAM_SCAN_SCOPE = all\n", "all"},
		{"explicit archives", "CLAM_SCAN_SCOPE = archives\n", "archives"},
		{"case/space normalized", "CLAM_SCAN_SCOPE =  ALL \n", "all"},
		{"unknown value keeps default", "CLAM_SCAN_SCOPE = everything\n", "archives"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseCFMConf(strings.NewReader(tc.conf))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cfg.Clam.ScanScope != tc.want {
				t.Fatalf("ScanScope = %q, want %q", cfg.Clam.ScanScope, tc.want)
			}
		})
	}
}

// CLAM_SIG_IGNORE defaults to the hunting-grade pattern; a present key
// replaces the default entirely, and an explicit empty value clears it
// (act on every verdict).
func TestParseCFMConf_ClamSigIgnore(t *testing.T) {
	cases := []struct {
		name string
		conf string
		want []string
	}{
		{"absent key defaults hunting", "", []string{"*_Hunting.UNOFFICIAL"}},
		{"explicit empty clears", "CLAM_SIG_IGNORE =\n", []string{}},
		{"single pattern", "CLAM_SIG_IGNORE = Foo.Bar-*\n", []string{"Foo.Bar-*"}},
		{"comma list trims + drops empties", "CLAM_SIG_IGNORE = a*, ,b.c\n", []string{"a*", "b.c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseCFMConf(strings.NewReader(tc.conf))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(cfg.Clam.SigIgnore) != len(tc.want) {
				t.Fatalf("SigIgnore = %v, want %v", cfg.Clam.SigIgnore, tc.want)
			}
			for i := range tc.want {
				if cfg.Clam.SigIgnore[i] != tc.want[i] {
					t.Fatalf("SigIgnore = %v, want %v", cfg.Clam.SigIgnore, tc.want)
				}
			}
		})
	}
}
