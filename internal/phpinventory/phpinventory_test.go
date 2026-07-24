package phpinventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseModules(t *testing.T) {
	out := `[PHP Modules]
Core
snuffleupagus
curl
json

[Zend Modules]
Zend OPcache
`
	sp, pro, n := parseModules(out)
	if !sp {
		t.Error("expected snuffleupagus detected")
	}
	if pro {
		t.Error("did not expect a proactive/imunify module")
	}
	if n != 5 { // Core, snuffleupagus, curl, json, Zend OPcache — headers/blank skipped
		t.Errorf("module count = %d, want 5", n)
	}
}

func TestParseModules_ProactiveHint(t *testing.T) {
	// Imunify's PHP module ships as i360 (i360.so/i360.ini) on real
	// cPanel+CloudLinux hosts — that's the primary signal.
	if _, pro, _ := parseModules("Core\ni360\ncurl\n"); !pro {
		t.Error("expected i360 (Imunify) module to be flagged")
	}
	// Broader hints still work as a backstop.
	if _, pro, _ := parseModules("Core\nimunify_proactive\ncurl\n"); !pro {
		t.Error("expected a proactive/imunify module to be flagged")
	}
}

func TestProbeBuild_VersionAndZTS(t *testing.T) {
	run := func(bin string, args ...string) (string, error) {
		switch args[0] {
		case "-v":
			return "PHP 8.2.18 (cli) (built: Mar  5 2024 12:00:00) (ZTS)\nCopyright (c) The PHP Group\n", nil
		case "-m":
			return "[PHP Modules]\nsnuffleupagus\ncurl\n", nil
		}
		return "", nil
	}
	b := probeBuild(run, "/opt/cpanel/ea-php82/root/usr/bin/php", "ea4")
	if b.Version != "8.2.18" {
		t.Errorf("version = %q, want 8.2.18", b.Version)
	}
	if !b.ZTS {
		t.Error("expected ZTS build")
	}
	if !b.HasSP {
		t.Error("expected SP detected")
	}
	if b.Err != "" {
		t.Errorf("unexpected err: %s", b.Err)
	}
}

// Full scan over a temp root with fake binaries, asserting flavour inference,
// dedup, and the SP+proactive conflict warning.
func TestScan_DiscoveryAndConflictWarning(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ea82 := mk("opt/cpanel/ea-php82/root/usr/bin/php")
	sys := mk("usr/bin/php")

	run := func(bin string, args ...string) (string, error) {
		if args[0] == "-v" {
			return "PHP 8.2.18 (cli) (built: x) (NTS)\n", nil
		}
		// ea82 has BOTH sp and an imunify module (conflict); system has neither.
		if bin == ea82 {
			return "[PHP Modules]\nsnuffleupagus\nimunify\ncurl\n", nil
		}
		return "[PHP Modules]\ncurl\njson\n", nil
	}

	rep := (&Scanner{Root: root, Run: run}).Scan()
	if len(rep.Builds) != 2 {
		t.Fatalf("builds = %d, want 2 (%+v)", len(rep.Builds), rep.Builds)
	}

	byPath := map[string]Build{}
	for _, b := range rep.Builds {
		byPath[b.Path] = b
	}
	if byPath[ea82].Flavor != "ea4" {
		t.Errorf("ea82 flavor = %q, want ea4", byPath[ea82].Flavor)
	}
	if byPath[sys].Flavor != "system" {
		t.Errorf("system flavor = %q, want system", byPath[sys].Flavor)
	}
	if !byPath[ea82].HasSP || !byPath[ea82].HasProactive {
		t.Errorf("ea82 should have both SP and proactive: %+v", byPath[ea82])
	}
	if byPath[sys].HasSP || byPath[sys].HasProactive {
		t.Errorf("system build should have neither: %+v", byPath[sys])
	}

	var gotConflict bool
	for _, w := range rep.Warnings {
		if strings.Contains(w, "conflict") && strings.Contains(w, ea82) {
			gotConflict = true
		}
	}
	if !gotConflict {
		t.Errorf("expected a conflict warning for %s, warnings=%v", ea82, rep.Warnings)
	}
}

// TestDefaultScannerRootIsAbsolute guards the production glob path: with an
// empty Root, filepath.Join("", "opt/…") yields a CWD-RELATIVE glob, so
// `cfm php-inventory` would silently find nothing off a real host unless run
// from "/". DefaultScanner must root at "/" and rootOrSlash("") must resolve
// to "/", so every probe glob is absolute.
func TestDefaultScannerRootIsAbsolute(t *testing.T) {
	if got := DefaultScanner().Root; got != "/" {
		t.Fatalf("DefaultScanner().Root = %q, want \"/\"", got)
	}
	if got := rootOrSlash(""); got != "/" {
		t.Fatalf("rootOrSlash(\"\") = %q, want \"/\"", got)
	}
	// The joined probe globs must be absolute (the actual bug: they were not).
	for _, p := range defaultProbes {
		g := filepath.Join(rootOrSlash(""), p.glob)
		if !filepath.IsAbs(g) {
			t.Errorf("probe glob %q joined to %q is not absolute", p.glob, g)
		}
	}
}

func TestScan_NoBuilds(t *testing.T) {
	rep := (&Scanner{Root: t.TempDir(), Run: func(string, ...string) (string, error) { return "", nil }}).Scan()
	if len(rep.Builds) != 0 || len(rep.Warnings) != 0 {
		t.Fatalf("expected empty report, got %+v", rep)
	}
}
