package config

import (
	"strings"
	"testing"
	"time"
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

// CLAM_SCAN_MODE defaults async and only the two known values are accepted —
// inline blocking must never arm via a typo or corrupt value.
func TestParseCFMConf_ClamScanMode(t *testing.T) {
	cases := []struct {
		name string
		conf string
		want string
	}{
		{"absent defaults async", "", "async"},
		{"explicit inline", "CLAM_SCAN_MODE = inline\n", "inline"},
		{"explicit async", "CLAM_SCAN_MODE = async\n", "async"},
		{"unknown keeps async", "CLAM_SCAN_MODE = blocking\n", "async"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseCFMConf(strings.NewReader(tc.conf))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cfg.Clam.ScanMode != tc.want {
				t.Fatalf("ScanMode = %q, want %q", cfg.Clam.ScanMode, tc.want)
			}
		})
	}
	cfg, err := ParseCFMConf(strings.NewReader("CLAM_INLINE_TIMEOUT = 5s\nCLAM_INLINE_DRY_RUN = 1\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Clam.InlineTimeout != 5*time.Second || !cfg.Clam.InlineDryRun {
		t.Fatalf("inline knobs wrong: timeout=%s dryrun=%v", cfg.Clam.InlineTimeout, cfg.Clam.InlineDryRun)
	}
	// Default timeout when absent.
	cfg, _ = ParseCFMConf(strings.NewReader(""))
	if cfg.Clam.InlineTimeout != 3*time.Second {
		t.Fatalf("default InlineTimeout = %s, want 3s", cfg.Clam.InlineTimeout)
	}
}
