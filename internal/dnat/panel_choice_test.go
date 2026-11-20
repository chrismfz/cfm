package dnat

import (
	"os"
	"path/filepath"
	"testing"
)

func isolatePanelChoice(t *testing.T, savedMode, savedPrio string) {
	t.Helper()
	dir := t.TempDir()
	om, op := panelDNATModePath, panelDNATPriorityPath
	panelDNATModePath = filepath.Join(dir, "dnat_panel_mode")
	panelDNATPriorityPath = filepath.Join(dir, "dnat_panel_priority")
	t.Cleanup(func() { panelDNATModePath, panelDNATPriorityPath = om, op })
	if savedMode != "" {
		if err := os.WriteFile(panelDNATModePath, []byte(savedMode+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if savedPrio != "" {
		if err := os.WriteFile(panelDNATPriorityPath, []byte(savedPrio+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A bare `on` re-uses what panel DNAT was last turned on with; an explicit
// --mode takes its own default priority; --priority always wins.
func TestResolvePanelChoice(t *testing.T) {
	cases := []struct {
		name                 string
		savedMode, savedPrio string
		sub, mode            string
		prio                 int
		modeSet, prioSet     bool
		want                 panelChoice
	}{
		{"nothing saved: today's defaults", "", "", "on", "auto", -101, false, false,
			panelChoice{mode: "auto", priority: -101}},
		{"bare on re-uses fallback/-99", "fallback", "-99", "on", "auto", -101, false, false,
			panelChoice{mode: "fallback", priority: -99, modeFromSaved: true, prioFromSaved: true}},
		{"bare on re-uses an explicit priority", "direct-cpsrvd", "-120", "on", "auto", -101, false, false,
			panelChoice{mode: "direct-cpsrvd", priority: -120, modeFromSaved: true, prioFromSaved: true}},
		{"bare on keeps a saved priority under a saved fallback", "fallback", "-120", "on", "auto", -101, false, false,
			panelChoice{mode: "fallback", priority: -120, modeFromSaved: true, prioFromSaved: true}},
		{"saved priority without a saved mode (older cfm)", "", "-99", "on", "auto", -101, false, false,
			panelChoice{mode: "auto", priority: -99, prioFromSaved: true}},
		{"explicit mode takes its own default", "fallback", "-99", "on", "direct-cpsrvd", -101, true, false,
			panelChoice{mode: "direct-cpsrvd", priority: -101}},
		{"explicit fallback without saved state", "", "", "on", "fallback", -101, true, false,
			panelChoice{mode: "fallback", priority: -99}},
		{"explicit priority wins", "fallback", "-99", "on", "auto", -110, false, true,
			panelChoice{mode: "auto", priority: -110}},
		{"fallback with explicit priority keeps it", "", "", "on", "fallback", -101, true, true,
			panelChoice{mode: "fallback", priority: -101}},
		{"status re-uses the mode only", "fallback", "-99", "status", "auto", -101, false, false,
			panelChoice{mode: "fallback", priority: -99, modeFromSaved: true}},
		{"an unknown saved mode is ignored", "bogus", "", "on", "auto", -101, false, false,
			panelChoice{mode: "auto", priority: -101}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			isolatePanelChoice(t, c.savedMode, c.savedPrio)
			if got := resolvePanelChoice(c.sub, c.mode, c.prio, c.modeSet, c.prioSet); got != c.want {
				t.Fatalf("got %+v want %+v", got, c.want)
			}
		})
	}
}

func TestPersistPanelModeRoundTrip(t *testing.T) {
	isolatePanelChoice(t, "", "")
	if _, ok := LoadPanelMode(); ok {
		t.Fatal("no file must read as not saved")
	}
	if err := PersistPanelMode("chain-imunify"); err != nil {
		t.Fatal(err)
	}
	if m, ok := LoadPanelMode(); !ok || m != "chain-imunify" {
		t.Fatalf("got %q %v", m, ok)
	}
}
