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
	showErr  error
	panelOn  bool
	rules    string
	panelErr error
}

func (b summaryBackend) DNATStatus(string, string) (bool, error) { return b.webOn, b.webErr }
func (b summaryBackend) DNATShow(string, string) (string, error) { return b.show, b.showErr }
func (b summaryBackend) PanelDNATStatus() (bool, string, error) {
	return b.panelOn, b.rules, b.panelErr
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
	if !s.PanelOn || s.PanelPriority != -99 || !s.PanelFromSaved || s.PanelBypass != 0 || s.PanelIntent != "" {
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

// systemd's answer wins: a `tail -f …/openresty/…/error.log` that the loose
// process match takes for the edge must not make a stopped unit "running".
func TestEdgeRunningTrustsSystemdOverTheProcessMatch(t *testing.T) {
	isolateSummaryFiles(t)
	panelSystemdUnitProbe = func(unit string) (systemdunit.Status, bool) {
		return systemdunit.Status{Enabled: strings.HasPrefix(unit, "openresty")}, true
	}
	panelListenerProcessDetector = func() string { return "openresty" } // e.g. tail -f its log
	if s := CollectSummary(summaryBackend{webOn: true}); s.ActiveEdge != "openresty" || s.EdgeRunning {
		t.Fatalf("got edge=%q running=%v", s.ActiveEdge, s.EdgeRunning)
	}
	// Without systemd the process is all there is.
	panelSystemdUnitProbe = func(string) (systemdunit.Status, bool) { return systemdunit.Status{}, false }
	if s := CollectSummary(summaryBackend{}); s.ActiveEdge != "openresty" || !s.EdgeRunning {
		t.Fatalf("no systemd: got edge=%q running=%v", s.ActiveEdge, s.EdgeRunning)
	}
}

func TestCollectSummaryUnparsedChainIsFromConfig(t *testing.T) {
	isolateSummaryFiles(t)
	if s := CollectSummary(summaryBackend{webOn: true, show: "garbage"}); !s.WebFromConfig {
		t.Fatalf("an unparsed chain must be flagged: %+v", s)
	}
	show := "table inet cfm_redirect {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat - 1; policy accept;\n" +
		"\t\ttcp dport 80 dnat to :9080\n\t\ttcp dport 443 dnat to :9043\n\t}\n}\n"
	if s := CollectSummary(summaryBackend{webOn: true, show: show}); s.WebFromConfig {
		t.Fatalf("a parsed chain flagged as configured: %+v", s)
	}
}

func TestStrayWordsAndDeprecatedChallenge(t *testing.T) {
	isolateSummaryFiles(t)
	stubNoExternalTools(t)
	b := &redirectBackend{}
	for args, want := range map[string]string{
		"on extra":              `dnat on: unexpected argument "extra"`,
		"cpanel off now":        `dnat cpanel off: unexpected argument "now"`,
		"foo bar":               "unknown subcommand",
		"cpanel --challenge on": "",
	} {
		var rc int
		_, errOut := captureStreams(t, func() { rc = RunCLI(strings.Fields(args), b) })
		if want == "" {
			continue
		}
		if rc != 2 || !strings.Contains(errOut, want) {
			t.Errorf("%q: rc=%d stderr=%q, want %q", args, rc, errOut, want)
		}
	}
	// `--challenge on`: "on" is the subcommand, not the deprecated flag's value.
	got, err := normalizePanelArgs([]string{"--challenge", "on"})
	if err != nil || strings.Join(got, " ") != "on" {
		t.Fatalf("got %v %v", got, err)
	}
	if b.onCalls != 0 || b.offCalls != 0 {
		t.Fatalf("a refused command changed web DNAT: on=%d off=%d", b.onCalls, b.offCalls)
	}
}

// The exec backend's DNATStatus says "off" for any failure to list the table:
// the summary must tell "no table" (off) from "could not ask" (unknown).
func TestCollectSummaryUnreadableWebTableIsUnknown(t *testing.T) {
	isolateSummaryFiles(t)
	s := CollectSummary(summaryBackend{showErr: errors.New("exit status 1: Error: Operation not permitted")})
	if s.WebErr == nil || s.WebOn {
		t.Fatalf("an unreadable table read as off: %+v", s)
	}
	for _, absent := range []string{"Error: No such file or directory", "table inet cfm_redirect does not exist"} {
		if s := CollectSummary(summaryBackend{showErr: errors.New(absent)}); s.WebErr != nil || s.WebOn {
			t.Fatalf("%q: a missing table must read as off: %+v", absent, s)
		}
	}
	if s := CollectSummary(summaryBackend{}); s.WebErr != nil {
		t.Fatalf("an empty listing (nftlib, no chain) must read as off: %+v", s)
	}
}

// The panel priority is the live chain's; the saved one only when the rules
// do not parse, and then it says so.
func TestCollectSummaryPanelPriorityIsLive(t *testing.T) {
	isolateSummaryFiles(t)
	if err := os.WriteFile(panelDNATPriorityPath, []byte("-101\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rules := "table inet cfm_panel_redirect {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat + 1; policy accept;\n\t}\n}\n"
	if s := CollectSummary(summaryBackend{panelOn: true, rules: rules}); s.PanelPriority != -99 || s.PanelFromSaved {
		t.Fatalf("live: %+v", s)
	}
	if s := CollectSummary(summaryBackend{panelOn: true, rules: "garbage"}); s.PanelPriority != -101 || !s.PanelFromSaved {
		t.Fatalf("saved fallback: %+v", s)
	}
}
