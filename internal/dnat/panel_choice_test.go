package dnat

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

var errWant = errors.New("an error")

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
		{"saved -99 without a saved mode (older cfm) is fallback", "", "-99", "on", "auto", -101, false, false,
			panelChoice{mode: "fallback", priority: -99, modeFromSaved: true, prioFromSaved: true}},
		{"saved priority without a saved mode (older cfm)", "", "-110", "on", "auto", -101, false, false,
			panelChoice{mode: "auto", priority: -110, prioFromSaved: true}},
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
		{"status --priority still shows the saved mode", "fallback", "-99", "status", "auto", -110, false, true,
			panelChoice{mode: "fallback", priority: -110, modeFromSaved: true}},
		{"status --mode shows the flag's mode", "fallback", "-99", "status", "direct-cpsrvd", -101, true, false,
			panelChoice{mode: "direct-cpsrvd", priority: -101}},
		{"an unknown saved mode refuses a bare on", "bogus", "", "on", "auto", -101, false, false,
			panelChoice{mode: "auto", priority: -101, err: errWant}},
		{"an unparsable saved priority refuses a bare on", "", "garbage", "on", "auto", -101, false, false,
			panelChoice{mode: "auto", priority: -101, err: errWant}},
		{"a broken saved file does not block explicit flags", "", "garbage", "on", "fallback", -101, true, false,
			panelChoice{mode: "fallback", priority: -99}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			isolatePanelChoice(t, c.savedMode, c.savedPrio)
			got := resolvePanelChoice(c.sub, c.mode, c.prio, c.modeSet, c.prioSet)
			if (got.err != nil) != (c.want.err != nil) {
				t.Fatalf("err=%v want an error: %v", got.err, c.want.err != nil)
			}
			got.err, c.want.err = nil, nil
			if got != c.want {
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

// A typo'd --mode is refused before anything runs; it used to go on at -101.
func TestPanelOnRefusesAnUnknownMode(t *testing.T) {
	stubNoEdgeDetected(t)
	stubNoExternalTools(t)
	isolatePanelChoice(t, "fallback", "-99")
	b := &redirectBackend{}
	var rc int
	_, errOut := captureStreams(t, func() { rc = RunCLI([]string{"cpanel", "on", "--mode", "fallbak"}, b) })
	if rc != 2 || !strings.Contains(errOut, `unknown --mode "fallbak"`) || !strings.Contains(errOut, "nothing changed") {
		t.Fatalf("rc=%d stderr=%q", rc, errOut)
	}
	if m, _ := LoadPanelMode(); m != "fallback" {
		t.Fatalf("the saved mode changed: %q", m)
	}
	if p, _ := LoadPanelPriority(); p != -99 {
		t.Fatalf("the saved priority changed: %d", p)
	}
}

// With nothing saved, a bare `on` takes the daemon's default: the
// NFT_PANEL_DNAT_PRIORITY override when set (it used to save -101 over it).
func TestResolvePanelChoiceNothingSavedUsesTheDaemonDefault(t *testing.T) {
	isolatePanelChoice(t, "", "")
	t.Setenv("NFT_PANEL_DNAT_PRIORITY", "-105")
	if got := resolvePanelChoice("on", "auto", -101, false, false); got.priority != -105 || got.err != nil {
		t.Fatalf("got %+v", got)
	}
	// An explicit mode keeps its own default.
	if got := resolvePanelChoice("on", "direct-cpsrvd", -101, true, false); got.priority != -101 {
		t.Fatalf("explicit mode: got %+v", got)
	}
}

func TestPanelChoiceReusedText(t *testing.T) {
	for pc, want := range map[panelChoice]string{
		{mode: "fallback", priority: -99, modeFromSaved: true, prioFromSaved: true}: "mode fallback and priority -99",
		{mode: "auto", priority: -110, prioFromSaved: true}:                         "priority -110",
		{mode: "fallback", priority: -99, modeFromSaved: true}:                      "mode fallback",
	} {
		if got := pc.reused(); got != want {
			t.Errorf("%+v: %q want %q", pc, got, want)
		}
	}
}
