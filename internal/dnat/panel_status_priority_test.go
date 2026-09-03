package dnat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/firewall"
)

// panelStatusStub satisfies firewall.Backend via embedding and only implements
// the two methods `cfm dnat cpanel status` reaches: PanelDNATStatus (on/off +
// rules) and PanelDNATAcceptState (scoped-accept probe).
type panelStatusStub struct {
	firewall.Backend
	on    bool
	rules string
}

func (b panelStatusStub) PanelDNATStatus() (bool, string, error) { return b.on, b.rules, nil }
func (b panelStatusStub) PanelDNATAcceptState() map[int]string    { return nil }

// TestPanelStatusReportsInstalledPriority pins the #4 fix: when panel DNAT is
// enabled at a priority other than the flag default (-101) — here -99, persisted
// by a prior `panel on` — `status` must report that installed value, not the
// -101 flag default it used to print regardless. It is read from the persisted
// operator choice (PanelStartupPriority), which is correct on both firewall
// backends (the nftlib backend's synthesized rule text is not).
func TestPanelStatusReportsInstalledPriority(t *testing.T) {
	dir := t.TempDir()
	origPath := panelDNATPriorityPath
	panelDNATPriorityPath = filepath.Join(dir, "dnat_panel_priority")
	t.Cleanup(func() { panelDNATPriorityPath = origPath })
	if err := os.WriteFile(panelDNATPriorityPath, []byte("-99\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	be := panelStatusStub{on: true, rules: "table inet cfm_panel_redirect {\n  chain prerouting {\n    type nat hook prerouting priority dstnat + 1; policy accept;\n  }\n}\n"}

	out, _ := captureStreams(t, func() {
		if code := runPanelCLI([]string{"status"}, be); code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
	})

	if !strings.Contains(out, "Installed priority: -99") {
		t.Fatalf("expected installed priority -99 from the persisted operator choice, got:\n%s", out)
	}
	if strings.Contains(out, "priority: -101") {
		t.Fatalf("status must not report the -101 flag default as the installed priority:\n%s", out)
	}
}
