package detectors

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"cfm/internal/detectors/mysql"
)

// sweepGovernor mirrors one maybeReload sweep for the governor:
// syncPendingGovernor on the read sections, then the factory for ENABLED
// sections only (the manager's loop skips a disabled section, which is why the
// sync exists).
func sweepGovernor(t *testing.T, conf string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "detectors.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	secs, err := ReadSectionsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	syncPendingGovernor(secs.ByName, nil, false)
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

func keepPendingGovernor(t *testing.T) {
	t.Helper()
	oCfg, oOK := GetPendingGovernorConfig()
	t.Cleanup(func() { setPendingGovernorConfig(oCfg, oOK) })
}

// ENABLED = 0 must reach the governor lifecycle as Enabled=false (do not
// start), a removed section as "no section" (built-in defaults), and a
// re-enabled section as its full config — through the path the daemon takes,
// not by calling the factory with ENABLED = 0 (the manager never does).
func TestMySQLGovernorPendingConfigFollowsDetectorsConf(t *testing.T) {
	keepPendingGovernor(t)

	sweepGovernor(t, "[mysql_governor]\nENABLED = 1\nMODE = enforce\n")
	if cfg, ok := GetPendingGovernorConfig(); !ok || !cfg.Enabled || cfg.Mode != "enforce" {
		t.Fatalf("enabled: ok=%v cfg=%+v", ok, cfg)
	}

	// The operator turns it off: the stale enforce config must not survive.
	sweepGovernor(t, "[mysql_governor]\nENABLED = 0\nMODE = enforce\n")
	if cfg, ok := GetPendingGovernorConfig(); !ok || cfg.Enabled {
		t.Fatalf("ENABLED = 0: ok=%v Enabled=%v, want ok=true Enabled=false", ok, cfg.Enabled)
	}

	// Section removed: built-in defaults, not the last config.
	sweepGovernor(t, "[global]\nDEFAULT_EVERY = 2s\n")
	if cfg, ok := GetPendingGovernorConfig(); ok {
		t.Fatalf("no section: ok=true cfg=%+v, want ok=false", cfg)
	}

	// Re-enabled after a disable.
	sweepGovernor(t, "[mysql_governor]\nENABLED = 0\n")
	sweepGovernor(t, "[mysql_governor]\nENABLED = 1\nMODE = monitor\n")
	if cfg, ok := GetPendingGovernorConfig(); !ok || !cfg.Enabled || cfg.Mode != "monitor" {
		t.Fatalf("re-enabled: ok=%v cfg=%+v", ok, cfg)
	}
}

// With several instances the sync must leave an enabled config alone when any
// instance is enabled, whatever the map order: it runs before the factories,
// and on a sweep where the enabled factory sets the same config this would be
// invisible, so the sync is checked on its own (a first-match sync fails here
// on about half the map orders).
func TestMySQLGovernorPendingConfigInstances(t *testing.T) {
	keepPendingGovernor(t)
	byName := map[string]KV{
		"global":                {},
		"mysql_governor":        {"ENABLED": "1", "MODE": "enforce"},
		"mysql_governor:spare":  {"ENABLED": "0"},
		"mysql_governor:spare2": {"ENABLED": "0"},
	}
	for i := 0; i < 50; i++ { // map iteration order varies
		setPendingGovernorConfig(mysql.GovernorConfig{Enabled: true, Mode: "enforce"}, true)
		syncPendingGovernor(byName, nil, false)
		if cfg, ok := GetPendingGovernorConfig(); !ok || !cfg.Enabled || cfg.Mode != "enforce" {
			t.Fatalf("enabled + disabled instances: the sync replaced the enabled config: ok=%v cfg=%+v", ok, cfg)
		}
	}
	sweepGovernor(t, "[mysql_governor:a]\nENABLED = 0\n\n[mysql_governor:b]\nENABLED = 0\n")
	if cfg, ok := GetPendingGovernorConfig(); !ok || cfg.Enabled {
		t.Fatalf("all instances disabled: ok=%v cfg=%+v", ok, cfg)
	}
}

// A failed read never turns a disabled governor back on: an unreadable first
// load holds it, a missing file at first load keeps "no config = defaults",
// and anything else leaves the config alone.
func TestMySQLGovernorPendingConfigOnReadErrors(t *testing.T) {
	keepPendingGovernor(t)
	byName := map[string]KV{"global": {}}

	setPendingGovernorConfig(mysql.GovernorConfig{}, false)
	syncPendingGovernor(byName, errors.New("permission denied"), true)
	if cfg, ok := GetPendingGovernorConfig(); !ok || cfg.Enabled || cfg.HoldReason == "" {
		t.Fatalf("unreadable first load: ok=%v cfg=%+v, want held", ok, cfg)
	}

	setPendingGovernorConfig(mysql.GovernorConfig{}, false)
	syncPendingGovernor(byName, &fs.PathError{Op: "open", Path: "detectors.conf", Err: fs.ErrNotExist}, true)
	if _, ok := GetPendingGovernorConfig(); ok {
		t.Fatal("missing file at first load: want built-in defaults (ok=false)")
	}

	setPendingGovernorConfig(mysql.GovernorConfig{Enabled: false}, true)
	syncPendingGovernor(byName, &fs.PathError{Op: "open", Path: "detectors.conf", Err: fs.ErrNotExist}, false)
	if cfg, ok := GetPendingGovernorConfig(); !ok || cfg.Enabled {
		t.Fatalf("file removed while running: ok=%v cfg=%+v, want the disabled config kept", ok, cfg)
	}
}

// The tests above stand in for maybeReload; this pins how maybeReload calls
// the sync: with the read error captured straight from the read (err is
// reused later in the function), and in the same sweep as the factories —
// after the unchanged-config early return, right before the section loop —
// so the sync never runs on a tick whose factories do not.
func TestManagerSyncsGovernorConfigInTheFactorySweep(t *testing.T) {
	src, err := os.ReadFile("manager.go")
	if err != nil {
		t.Fatal(err)
	}
	// The body of maybeReload, without comments.
	s := string(src)
	start := strings.Index(s, "func (m *manager) maybeReload(")
	if start < 0 {
		t.Fatal("maybeReload not found")
	}
	body := s[start:]
	if end := strings.Index(body[1:], "\nfunc "); end > 0 {
		body = body[:end+1]
	}
	body = regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(body, "")

	read := strings.Index(body, "m.readForReload(path)") // readSectionsForReload behind the stamp
	capture := regexp.MustCompile(`readErr, firstLoad := err, !m\.running`).FindStringIndex(body)
	earlyReturn := strings.Index(body, "sig == m.lastSig")
	call := strings.Index(body, "syncPendingGovernor(secs.ByName, readErr, firstLoad)")
	loop := strings.LastIndex(body, "for secName, kv := range secs.ByName {")
	switch {
	case read < 0 || capture == nil || earlyReturn < 0 || call < 0 || loop < 0:
		t.Fatalf("maybeReload is missing a piece: read=%d capture=%v early-return=%d sync=%d loop=%d",
			read, capture, earlyReturn, call, loop)
	case !(read < capture[0] && strings.Count(body[read:capture[0]], "\n") <= 1):
		t.Fatal("readErr/firstLoad must be captured on the line right after the read (readForReload)")
	case !(earlyReturn < call && call < loop):
		t.Fatal("syncPendingGovernor must run after the unchanged-config early return and before the section loop")
	}
}
