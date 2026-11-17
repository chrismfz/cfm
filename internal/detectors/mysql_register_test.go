package detectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// applyGovernorSection mirrors what maybeReload does with one read of
// detectors.conf for the governor: syncPendingGovernorFromSections on the
// read sections, then the factory for ENABLED sections only (the manager's
// loop skips a disabled section, which is why the sync exists).
func applyGovernorSection(t *testing.T, conf string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "detectors.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	secs, err := ReadSectionsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	syncPendingGovernorFromSections(secs.ByName)
	f, ok := getFactory("mysql_governor")
	if !ok {
		t.Fatal("mysql_governor factory not registered")
	}
	for name, kv := range secs.ByName {
		if typ, _ := splitTypeInstance(name); typ != "mysql_governor" || !kvBool(kv, "ENABLED", true) {
			continue
		}
		if _, err := f(name, kv, secs.Global); err != nil {
			t.Fatal(err)
		}
	}
}

// ENABLED = 0 must reach the governor lifecycle as Enabled=false (do not
// start), a removed section as "no section" (built-in defaults), and a
// re-enabled section as its full config — through the path the daemon takes,
// not by calling the factory with ENABLED = 0 (the manager never does).
func TestMySQLGovernorPendingConfigFollowsDetectorsConf(t *testing.T) {
	oCfg, oOK := GetPendingGovernorConfig()
	t.Cleanup(func() { setPendingGovernorConfig(oCfg, oOK) })

	applyGovernorSection(t, "[mysql_governor]\nENABLED = 1\nMODE = enforce\n")
	if cfg, ok := GetPendingGovernorConfig(); !ok || !cfg.Enabled || cfg.Mode != "enforce" {
		t.Fatalf("enabled: ok=%v cfg=%+v", ok, cfg)
	}

	// The operator turns it off: the stale enforce config must not survive.
	applyGovernorSection(t, "[mysql_governor]\nENABLED = 0\nMODE = enforce\n")
	if cfg, ok := GetPendingGovernorConfig(); !ok || cfg.Enabled {
		t.Fatalf("ENABLED = 0: ok=%v Enabled=%v, want ok=true Enabled=false", ok, cfg.Enabled)
	}

	// Section removed: built-in defaults, not the last config.
	applyGovernorSection(t, "[global]\nDEFAULT_EVERY = 2s\n")
	if cfg, ok := GetPendingGovernorConfig(); ok {
		t.Fatalf("no section: ok=true cfg=%+v, want ok=false", cfg)
	}

	// Re-enabled after a disable.
	applyGovernorSection(t, "[mysql_governor]\nENABLED = 0\n")
	applyGovernorSection(t, "[mysql_governor]\nENABLED = 1\nMODE = monitor\n")
	if cfg, ok := GetPendingGovernorConfig(); !ok || !cfg.Enabled || cfg.Mode != "monitor" {
		t.Fatalf("re-enabled: ok=%v cfg=%+v", ok, cfg)
	}
}

// The test above stands in for maybeReload; this pins that maybeReload really
// calls the sync, and only for a config that was read (a failed read must not
// turn a disabled governor back on).
func TestManagerSyncsGovernorConfigOnSuccessfulRead(t *testing.T) {
	src, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	call := strings.Index(s, "syncPendingGovernorFromSections(secs.ByName)")
	guard := strings.LastIndex(s[:max(call, 0)], "if err == nil {")
	if call < 0 || guard < 0 || strings.Contains(s[guard:call], "}") {
		t.Fatal("maybeReload must call syncPendingGovernorFromSections(secs.ByName) inside its `if err == nil {` block")
	}
}
