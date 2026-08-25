package srcreportcli

import (
	"strings"
	"testing"
)

func TestDaemonCell(t *testing.T) {
	cases := []struct {
		name string
		in   covType
		want string
	}{
		{"unknown type", covType{}, "—"},
		{"event-driven", covType{Type: "waf_security", DaemonAware: false}, "—"},
		{"active unit wins", covType{Type: "ssh_auth", DaemonAware: true, Units: []covUnit{
			{Unit: "sshd", Found: true}, {Unit: "ssh", Found: true, Active: true}}}, "ssh (active)"},
		{"found but stopped", covType{Type: "exim_security", DaemonAware: true, Units: []covUnit{
			{Unit: "exim", Found: true}}}, "exim (stopped)"},
		{"nothing found", covType{Type: "postfix_relays", DaemonAware: true, Units: []covUnit{
			{Unit: "postfix"}}}, "absent"},
	}
	for _, tc := range cases {
		if got := daemonCell(tc.in); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestCoverageExtras(t *testing.T) {
	rows := []row{{Section: "ssh_auth", Type: "ssh_auth"}, {Section: "ftpd", Type: "ftpd"}}
	types := []covType{
		{Type: "ssh_auth", Verdict: "ok"},          // has a row → no extra
		{Type: "ftpd", Verdict: "gap"},             // has a row → no extra (DAEMON column carries it)
		{Type: "proxmox_auth", Verdict: "gap"},     // the forgotten-daemon case → extra
		{Type: "dovecot_auth", Verdict: "dormant"}, // watched, daemon absent, no row → extra
		{Type: "modsec", Verdict: "absent"},        // informational → no extra
		{Type: "cfm_endpoints", Verdict: "na"},     // event-driven → no extra
		{Type: "postfix_security", Verdict: "ok"},  // healthy unconfigured?? (ok implies enabled) → no extra
	}
	got := coverageExtras(rows, types)
	if len(got) != 2 || got[0].Type != "dovecot_auth" || got[1].Type != "proxmox_auth" {
		t.Fatalf("extras: got %+v", got)
	}
}

func TestClipRuneSafe(t *testing.T) {
	s := strings.Repeat("α", 100) // 2-byte runes
	out := clip(s, 10)
	if got := len([]rune(out)); got != 10 {
		t.Fatalf("clip length: %d runes", got)
	}
	if !strings.HasSuffix(out, "…") || strings.Contains(out, "�") {
		t.Fatalf("clip mangled runes: %q", out)
	}
}
