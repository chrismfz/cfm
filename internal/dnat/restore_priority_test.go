package dnat

import (
	"cfm/internal/firewall"
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// priorityBackend is a web DNAT chain the previous daemon run left installed
// (DNATStatus true) at `installed`, with cfm.conf asking for `want`.
type priorityBackend struct {
	firewall.Backend
	installed  string // the nft priority expression, as `nft list` prints it
	want       int
	fromConfig bool
	onErr      error
	statusOn   bool
	onCalls    []string
}

func (b *priorityBackend) DNATStatus(string, string) (bool, error) { return b.statusOn, nil }
func (b *priorityBackend) DNATShow(string, string) (string, error) {
	return "table inet cfm_redirect {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority " + b.installed +
		"; policy accept;\n\t\tiif \"lo\" accept\n\t\ttcp dport 80 dnat to :9180\n\t\ttcp dport 443 dnat to :9143\n\t\tudp dport 443 dnat to :9143\n\t}\n}\n", nil
}
func (b *priorityBackend) DNATOn(fam, tbl string, hp, hsp int) error {
	b.onCalls = append(b.onCalls, fam+" "+tbl+" "+strconv.Itoa(hp)+" "+strconv.Itoa(hsp))
	if b.onErr != nil {
		b.statusOn = false
		return b.onErr
	}
	return nil
}
func (b *priorityBackend) ConfiguredDNATPriority() (int, bool) { return b.want, b.fromConfig }

// noReporterBackend is the same chain on a backend that can't report its
// configured priority.
type noReporterBackend struct {
	firewall.Backend
	onCalls int
}

func (b *noReporterBackend) DNATStatus(string, string) (bool, error) { return true, nil }
func (b *noReporterBackend) DNATShow(string, string) (string, error) {
	return "table inet cfm_redirect {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat + 1; policy accept;\n\t}\n}\n", nil
}
func (b *noReporterBackend) DNATOn(string, string, int, int) error { b.onCalls++; return nil }

func withWebIntentOn(t *testing.T) {
	t.Helper()
	orig := webDNATIntentPath
	webDNATIntentPath = filepath.Join(t.TempDir(), "dnat_enabled")
	t.Cleanup(func() { webDNATIntentPath = orig })
	if err := PersistIntent(ScopeWeb, true); err != nil {
		t.Fatalf("persist ON: %v", err)
	}
	transitionMu.Lock()
	transitions = map[DNATScope]LastTransition{}
	transitionMu.Unlock()
}

// A restart after NFT_DNAT_PRIORITY changed must re-install the chain the
// previous run left, at the new priority and on the SAME ports; and leave it
// alone whenever it can't be sure what the operator wants.
func TestRestoreOnStartup_ReappliesChangedWebDNATPriority(t *testing.T) {
	cases := []struct {
		name       string
		installed  string
		want       int
		fromConfig bool
		onErr      error
		wantOn     int
		wantState  string
		wantReason string
	}{
		{name: "-99 installed, cfm.conf says -101", installed: "dstnat + 1", want: -101, fromConfig: true,
			wantOn: 1, wantState: "ON", wantReason: "re-applied: NFT_DNAT_PRIORITY -101 (was -99)"},
		{name: "-101 installed, cfm.conf says -99", installed: "dstnat - 1", want: -99, fromConfig: true,
			wantOn: 1, wantState: "ON", wantReason: "re-applied: NFT_DNAT_PRIORITY -99 (was -101)"},
		{name: "plain integer priority", installed: "-120", want: -101, fromConfig: true,
			wantOn: 1, wantState: "ON", wantReason: "(was -120)"},
		{name: "already at the configured priority", installed: "dstnat - 1", want: -101, fromConfig: true},
		{name: "no applied cfm.conf: -99 is only the fallback", installed: "dstnat - 1", want: -99, fromConfig: false},
		{name: "unreadable installed priority", installed: "bogus", want: -101, fromConfig: true},
		{name: "re-apply fails and leaves DNAT off", installed: "dstnat + 1", want: -101, fromConfig: true,
			onErr: errors.New("nft: boom"), wantOn: 1, wantState: "OFF", wantReason: "failed: nft: boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withWebIntentOn(t)
			be := &priorityBackend{installed: tc.installed, want: tc.want, fromConfig: tc.fromConfig, onErr: tc.onErr, statusOn: true}
			RestoreOnStartup(context.Background(), ScopeWeb, be)
			if len(be.onCalls) != tc.wantOn {
				t.Fatalf("DNATOn calls = %v, want %d", be.onCalls, tc.wantOn)
			}
			lt := GetLastTransition(ScopeWeb)
			if tc.wantOn == 0 {
				if lt.Action != "" {
					t.Fatalf("unexpected transition %+v", lt)
				}
				return
			}
			if be.onCalls[0] != "inet cfm_redirect 9180 9143" {
				t.Fatalf("DNATOn(%s): must keep the chain's current ports 9180/9143", be.onCalls[0])
			}
			if lt.State != tc.wantState || lt.Action != "startup" || !strings.Contains(lt.Reason, tc.wantReason) {
				t.Fatalf("transition = %+v, want state %s action startup reason containing %q", lt, tc.wantState, tc.wantReason)
			}
		})
	}
}

func TestRestoreOnStartup_PriorityReapplySkips(t *testing.T) {
	t.Run("backend without a priority reporter", func(t *testing.T) {
		withWebIntentOn(t)
		be := &noReporterBackend{}
		RestoreOnStartup(context.Background(), ScopeWeb, be)
		if be.onCalls != 0 {
			t.Fatalf("DNATOn called %d times", be.onCalls)
		}
	})
	t.Run("web intent off", func(t *testing.T) {
		withWebIntentOn(t)
		if err := PersistIntent(ScopeWeb, false); err != nil {
			t.Fatal(err)
		}
		be := &priorityBackend{installed: "dstnat + 1", want: -101, fromConfig: true, statusOn: true}
		RestoreOnStartup(context.Background(), ScopeWeb, be)
		if len(be.onCalls) != 0 {
			t.Fatalf("DNATOn called with intent off: %v", be.onCalls)
		}
	})
}

// `cfm dnat on --priority X` with X != cfm.conf warns that a restart, reboot or
// failsafe recovery will put cfm.conf's value back.
func TestPriorityOverrideWarning(t *testing.T) {
	if w := priorityOverrideWarning(-101, -101); w != "" {
		t.Fatalf("same as cfm.conf: want no warning, got %q", w)
	}
	w := priorityOverrideWarning(-101, -99)
	for _, want := range []string{"-101", "(-99)", "restarts", "reboots", "failsafe", "NFT_DNAT_PRIORITY = -101"} {
		if !strings.Contains(w, want) {
			t.Fatalf("warning %q lacks %q", w, want)
		}
	}
}
