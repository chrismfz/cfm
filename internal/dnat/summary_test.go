package dnat

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/firewall"
	"cfm/internal/systemdunit"
)

type summaryBackend struct {
	firewall.Backend
	webOn    bool
	webErr   error
	show     string
	panelOn  bool
	panelErr error
}

func (b summaryBackend) DNATStatus(string, string) (bool, error) { return b.webOn, b.webErr }
func (b summaryBackend) DNATShow(string, string) (string, error) { return b.show, nil }
func (b summaryBackend) PanelDNATStatus() (bool, string, error) {
	return b.panelOn, "", b.panelErr
}

// isolateSummaryFiles points every file CollectSummary reads at a temp dir.
func isolateSummaryFiles(t *testing.T) string {
	t.Helper()
	stubNoEdgeDetected(t)
	dir := t.TempDir()
	saved := []*string{&webDNATIntentPath, &panelChallengeEnabledStatePath, &panelDNATPriorityPath,
		&firewall.DNATBypassWebPath, &firewall.DNATBypassCpanelPath}
	orig := make([]string, len(saved))
	for i, p := range saved {
		orig[i] = *p
	}
	webDNATIntentPath = filepath.Join(dir, "dnat_enabled")
	panelChallengeEnabledStatePath = filepath.Join(dir, "panel_challenge_enabled")
	panelDNATPriorityPath = filepath.Join(dir, "dnat_panel_priority")
	firewall.DNATBypassWebPath = filepath.Join(dir, "cfm.dnat_bypass")
	firewall.DNATBypassCpanelPath = filepath.Join(dir, "cfm.dnat_cpanel_bypass")
	t.Cleanup(func() {
		for i, p := range saved {
			*p = orig[i]
		}
	})
	return dir
}

func TestCollectSummaryReadsTheLiveRedirect(t *testing.T) {
	isolateSummaryFiles(t)
	if err := os.WriteFile(firewall.DNATBypassWebPath, []byte("192.0.2.1\n198.51.100.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(panelDNATPriorityPath, []byte("-99\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := PersistIntent(ScopeWeb, true); err != nil {
		t.Fatal(err)
	}
	show := "table inet cfm_redirect {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat - 1; policy accept;\n" +
		"\t\ttcp dport 80 dnat to :19080\n\t\ttcp dport 443 dnat to :19043\n\t\tudp dport 443 dnat to :19043\n\t}\n}\n"
	s := CollectSummary(summaryBackend{webOn: true, show: show, panelOn: true})

	if !s.WebOn || s.WebErr != nil || s.WebPriority != -101 || s.HTTPPort != 19080 || s.HTTPSPort != 19043 {
		t.Fatalf("web: %+v", s)
	}
	if s.WebIntent != "on" || s.WebBypass != 2 {
		t.Fatalf("web intent/bypass: %q %d", s.WebIntent, s.WebBypass)
	}
	if !s.PanelOn || s.PanelPriority != -99 || s.PanelBypass != 0 || s.PanelIntent != "" {
		t.Fatalf("panel: %+v", s)
	}
	if s.ActiveEdge != "" || s.Ambiguous {
		t.Fatalf("engine: %q ambiguous=%v", s.ActiveEdge, s.Ambiguous)
	}
}

func TestCollectSummaryKeepsErrorsAsUnknown(t *testing.T) {
	isolateSummaryFiles(t)
	s := CollectSummary(summaryBackend{webErr: errors.New("nft: boom"), panelErr: errors.New("nft: bang")})
	if s.WebErr == nil || s.PanelErr == nil || s.WebOn || s.PanelOn || s.WebPriority != 0 || s.PanelPriority != 0 {
		t.Fatalf("an error must stay an error, never read as off with values: %+v", s)
	}
	if got := CollectSummary(nil); got.WebErr == nil || got.PanelErr == nil {
		t.Fatalf("nil backend: %+v", got)
	}
}

func TestCollectSummaryUnreadableBypassIsUnknown(t *testing.T) {
	dir := isolateSummaryFiles(t)
	firewall.DNATBypassWebPath = dir // a directory: the read fails
	if s := CollectSummary(summaryBackend{}); s.WebBypass != -1 {
		t.Fatalf("unreadable bypass list must read -1, got %d", s.WebBypass)
	}
}

// A flag before the subcommand used to be taken by the wrong flag set (the
// panel went on at its default priority) or the word after it was dropped
// (the report printed instead). Both are refused now, before anything runs.
func TestFlagsBeforeTheSubcommandAreRefused(t *testing.T) {
	isolateSummaryFiles(t)
	stubNoExternalTools(t)
	b := &redirectBackend{}
	for _, args := range [][]string{
		{"cpanel", "--priority", "-99", "on"},
		{"panel", "--mode", "fallback", "off"},
		{"--priority", "-99", "on"},
		{"--http-port", "9080", "off"},
	} {
		var rc int
		_, errOut := captureStreams(t, func() { rc = RunCLI(args, b) })
		if rc != 2 || !strings.Contains(errOut, "flags go after the subcommand") {
			t.Errorf("%v: rc=%d stderr=%q", args, rc, errOut)
		}
	}
	if b.onCalls != 0 || b.offCalls != 0 {
		t.Fatalf("a refused command changed DNAT: on=%d off=%d", b.onCalls, b.offCalls)
	}
}

// The resolver names the one ENABLED engine when none is active (a crashed
// edge); the summary must say it does not run, not call it active.
func TestCollectSummaryEnabledButStoppedEngine(t *testing.T) {
	isolateSummaryFiles(t)
	panelSystemdUnitProbe = func(unit string) (systemdunit.Status, bool) {
		return systemdunit.Status{Enabled: strings.HasPrefix(unit, "angie")}, true
	}
	s := CollectSummary(summaryBackend{webOn: true})
	if s.ActiveEdge != "angie" || s.EdgeRunning || s.Ambiguous {
		t.Fatalf("got edge=%q running=%v ambiguous=%v", s.ActiveEdge, s.EdgeRunning, s.Ambiguous)
	}
	panelSystemdUnitProbe = func(unit string) (systemdunit.Status, bool) {
		return systemdunit.Status{Enabled: true, Active: strings.HasPrefix(unit, "cfm-edge")}, true
	}
	if s := CollectSummary(summaryBackend{}); s.ActiveEdge != "cfm-edge" || !s.EdgeRunning {
		t.Fatalf("got edge=%q running=%v", s.ActiveEdge, s.EdgeRunning)
	}
}
