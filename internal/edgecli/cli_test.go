package edgecli

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"cfm/internal/dnat"
)

type recorder struct {
	dnatArgs    [][]string
	realipArgs  [][]string
	edgeInFront []bool
}

func testDeps(r *recorder, s dnat.Summary, v6 []string, v6err error) (deps, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	return deps{
		out:     &out,
		errOut:  &errOut,
		summary: func() dnat.Summary { return s },
		dnat:    func(a []string) int { r.dnatArgs = append(r.dnatArgs, a); return 7 },
		realip:  func(a []string) int { r.realipArgs = append(r.realipArgs, a); return 5 },
		verdict: func(front bool) (bool, string) {
			r.edgeInFront = append(r.edgeInFront, front)
			return true, "Origin real-IP: cpanel/apache trusts the edge"
		},
		ipv6: func() ([]string, error) { return v6, v6err },
	}, &out, &errOut
}

// The subcommands are the existing ones: each routes to the same code with
// the same arguments, and its exit code comes back unchanged.
func TestRouting(t *testing.T) {
	cases := []struct {
		args       []string
		wantDNAT   []string
		wantRealIP []string
		wantRC     int
	}{
		{args: []string{"on"}, wantDNAT: []string{"on"}, wantRC: 7},
		{args: []string{"on", "--priority", "-101"}, wantDNAT: []string{"on", "--priority", "-101"}, wantRC: 7},
		{args: []string{"off"}, wantDNAT: []string{"off"}, wantRC: 7},
		{args: []string{"bypass", "add", "192.0.2.1"}, wantDNAT: []string{"bypass", "add", "192.0.2.1"}, wantRC: 7},
		{args: []string{"web"}, wantDNAT: nil, wantRC: 7},
		{args: []string{"panel"}, wantDNAT: []string{"cpanel"}, wantRC: 7},
		{args: []string{"panel", "on", "--mode", "fallback"}, wantDNAT: []string{"cpanel", "on", "--mode", "fallback"}, wantRC: 7},
		{args: []string{"cpanel", "off"}, wantDNAT: []string{"cpanel", "off"}, wantRC: 7},
		{args: []string{"panel", "bypass", "list"}, wantDNAT: []string{"cpanel", "bypass", "list"}, wantRC: 7},
		{args: []string{"realip"}, wantRealIP: []string{}, wantRC: 5},
		{args: []string{"realip", "fix", "--dry-run"}, wantRealIP: []string{"fix", "--dry-run"}, wantRC: 5},
	}
	for _, c := range cases {
		r := &recorder{}
		d, _, _ := testDeps(r, dnat.Summary{}, nil, nil)
		if rc := run(c.args, d); rc != c.wantRC {
			t.Errorf("%v: rc=%d want %d", c.args, rc, c.wantRC)
		}
		if c.wantRealIP != nil {
			if len(r.realipArgs) != 1 || !reflect.DeepEqual(r.realipArgs[0], c.wantRealIP) || len(r.dnatArgs) != 0 {
				t.Errorf("%v: realip got %v, dnat %v", c.args, r.realipArgs, r.dnatArgs)
			}
			continue
		}
		if len(r.dnatArgs) != 1 || len(r.realipArgs) != 0 {
			t.Fatalf("%v: dnat calls %v realip %v", c.args, r.dnatArgs, r.realipArgs)
		}
		got := r.dnatArgs[0]
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.wantDNAT) {
			t.Errorf("%v: dnat got %v want %v", c.args, got, c.wantDNAT)
		}
	}
}

// Nothing reachable from the summary or from a bad argument changes state.
func TestSummaryAndRefusalsNeverCallTheWriters(t *testing.T) {
	for _, args := range [][]string{nil, {"status"}, {"help"}, {"ipv6"}, {"ipv6", "status"},
		{"ipv6", "on"}, {"ipv6", "off"}, {"bogus"}, {"status", "on"}, {"web", "on"}} {
		r := &recorder{}
		d, _, _ := testDeps(r, dnat.Summary{}, []string{"cfm-edge: IPv4 only"}, nil)
		rc := run(args, d)
		if len(r.dnatArgs) != 0 || len(r.realipArgs) != 0 {
			t.Errorf("%v reached a writer: dnat %v realip %v", args, r.dnatArgs, r.realipArgs)
		}
		refused := len(args) > 0 && (args[0] == "bogus" || len(args) > 1 && args[1] != "status")
		if refused && rc != 2 {
			t.Errorf("%v: rc=%d want 2", args, rc)
		}
	}
}

func TestSummaryOutput(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 32, 0, 0, time.UTC)
	s := dnat.Summary{
		ActiveEdge: "cfm-edge", EdgeRunning: true, WebOn: true, WebPriority: -101, HTTPPort: 9080, HTTPSPort: 9043, WebBypass: 2,
		LastProbe: dnat.ProbeResult{At: at, OK: true},
		PanelOn:   true, PanelPriority: -101,
	}
	d, out, _ := testDeps(&recorder{}, s, []string{"cfm-edge: listening on IPv6 too (ready)", "Angie: IPv4 only"}, nil)
	if rc := run(nil, d); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	for _, want := range []string{
		"Engine:      cfm-edge (running)",
		"Web DNAT:    ON   priority -101, tcp/80 -> :9080, tcp+udp/443 -> :9043; 2 bypass source(s)",
		"last health probe ok at 2026-11-20T12:32:00Z",
		"Panel DNAT:  ON   priority -101\n",
		"IPv6 listen: cfm-edge: listening on IPv6 too (ready)\n",
		"Origin:      OK   cpanel/apache trusts the edge",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "Angie: IPv4 only") {
		t.Errorf("the summary showed an inactive engine's IPv6 line:\n%s", out.String())
	}
	if strings.Contains(out.String(), "! ") {
		t.Errorf("a healthy edge printed a warning:\n%s", out.String())
	}
}

func TestSummaryFlagsWhatNeedsALook(t *testing.T) {
	cases := []struct {
		name string
		s    dnat.Summary
		v6   error
		want []string
		rc   int
	}{
		{"redirect to nothing", dnat.Summary{WebOn: true, WebPriority: -99, HTTPPort: 9080, HTTPSPort: 9043},
			nil, []string{"Engine:      none active", "web DNAT is ON but no edge engine runs"}, 0},
		{"enabled but crashed", dnat.Summary{ActiveEdge: "angie", WebOn: true, PanelOn: true},
			nil, []string{"Engine:      angie (enabled, NOT running)", "web DNAT is ON but no edge engine runs", "panel DNAT is ON but no edge engine runs"}, 0},
		{"ambiguous", dnat.Summary{Ambiguous: true}, nil, []string{"WARNING: more than one of"}, 0},
		{"ipv6 unknown alone", dnat.Summary{ActiveEdge: "angie", EdgeRunning: true}, errors.New("script missing"),
			[]string{"IPv6 listen: UNKNOWN (script missing)"}, 1},
		{"intent on, dnat off", dnat.Summary{ActiveEdge: "angie", EdgeRunning: true, WebIntent: "on", PanelIntent: "on"},
			nil, []string{"Web DNAT:    OFF", "saved intent is ON: the daemon's failsafe", "panel DNAT is OFF but its saved intent is ON"}, 0},
		{"unknown state", dnat.Summary{WebErr: errors.New("nft: boom"), PanelErr: errors.New("nft: bang")},
			errors.New("script missing"), []string{"Web DNAT:    UNKNOWN (nft: boom)", "Panel DNAT:  UNKNOWN (nft: bang)", "IPv6 listen: UNKNOWN (script missing)"}, 1},
		{"failed probe", dnat.Summary{ActiveEdge: "angie", EdgeRunning: true, WebOn: true, LastProbe: dnat.ProbeResult{At: time.Unix(1, 0), Reason: "timeout"}},
			nil, []string{"last health probe FAILED", "timeout"}, 0},
		{"unreadable bypass", dnat.Summary{ActiveEdge: "angie", EdgeRunning: true, WebBypass: -1}, nil, []string{"bypass list unreadable"}, 1},
		{"panel priority from the saved file", dnat.Summary{ActiveEdge: "angie", EdgeRunning: true, PanelOn: true, PanelPriority: -101, PanelFromSaved: true},
			nil, []string{"priority -101 (saved value: the live chain could not be parsed)"}, 0},
	}
	for _, c := range cases {
		d, out, _ := testDeps(&recorder{}, c.s, nil, c.v6)
		if rc := run(nil, d); rc != c.rc {
			t.Errorf("%s: rc=%d want %d", c.name, rc, c.rc)
		}
		for _, w := range c.want {
			if !strings.Contains(out.String(), w) {
				t.Errorf("%s: missing %q in:\n%s", c.name, w, out.String())
			}
		}
		if c.rc == 0 && c.name != "redirect to nothing" && c.name != "enabled but crashed" && strings.Contains(out.String(), "no edge engine runs") {
			t.Errorf("%s: a running engine was reported as not running:\n%s", c.name, out.String())
		}
		if c.name == "unknown state" && strings.Contains(out.String(), "OFF") {
			t.Errorf("%s: an unknown state read as OFF:\n%s", c.name, out.String())
		}
	}
}

func TestActiveEngineLines(t *testing.T) {
	all := []string{"OpenResty: IPv4 only", "Angie: ready", "cfm-edge: listening", `WARNING: EDGE_LISTEN_V6 = "x" is not a value; treating it as off`}
	for active, want := range map[string][]string{
		"cfm-edge":  {"cfm-edge: listening", all[3]},
		"openresty": {"OpenResty: IPv4 only", all[3]},
		"":          all,
		"unknown":   all,
	} {
		if got := activeEngineLines(all, active); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %q want %q", active, got, want)
		}
	}
	// `cfm edge ipv6` prints every engine, whichever runs.
	d, out, _ := testDeps(&recorder{}, dnat.Summary{ActiveEdge: "cfm-edge"}, all, nil)
	if rc := run([]string{"ipv6"}, d); rc != 0 || strings.Count(out.String(), "\n") != 4 {
		t.Fatalf("rc=%d out=%q", rc, out.String())
	}
}

func TestIPv6Lines(t *testing.T) {
	got := ipv6Lines("CFM edge IPv6 listen: cfm-edge: IPv4 only (off)\n\nCFM edge IPv6 listen: Angie: listening\nother line\n")
	want := []string{"cfm-edge: IPv4 only (off)", "Angie: listening", "other line"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

// With DNAT pointing at a stopped edge, the origin verdict must not say "no
// edge in front": traffic is sent to an edge either way.
func TestOriginVerdictSeesTheRedirectNotJustTheProcess(t *testing.T) {
	for _, c := range []struct {
		s    dnat.Summary
		want bool
	}{
		{dnat.Summary{ActiveEdge: "angie", WebOn: true}, true},
		{dnat.Summary{PanelOn: true}, true},
		{dnat.Summary{ActiveEdge: "angie", EdgeRunning: true}, true},
		{dnat.Summary{ActiveEdge: "angie"}, false},
		{dnat.Summary{WebErr: errors.New("x")}, true},
		{dnat.Summary{PanelErr: errors.New("x")}, true},
		{dnat.Summary{Ambiguous: true}, true},
	} {
		r := &recorder{}
		d, _, _ := testDeps(r, c.s, nil, nil)
		run(nil, d)
		if len(r.edgeInFront) != 1 || r.edgeInFront[0] != c.want {
			t.Errorf("%+v: edgeInFront=%v want %v", c.s, r.edgeInFront, c.want)
		}
	}
}

func TestSummaryMarksConfiguredValues(t *testing.T) {
	s := dnat.Summary{ActiveEdge: "angie", EdgeRunning: true, WebOn: true, WebPriority: -99, HTTPPort: 9080, HTTPSPort: 9043, WebFromConfig: true}
	d, out, _ := testDeps(&recorder{}, s, nil, nil)
	run(nil, d)
	if !strings.Contains(out.String(), "configured values: the live chain could not be read") {
		t.Fatalf("configured values printed as live:\n%s", out.String())
	}
}
