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
		{name: "-199 is a valid nat priority", installed: "dstnat + 1", want: -199, fromConfig: true,
			wantOn: 1, wantState: "ON", wantReason: "re-applied: NFT_DNAT_PRIORITY -199 (was -99)"},
		{name: "cfm.conf priority nft rejects for nat (-200): keep the chain", installed: "dstnat + 1", want: -200, fromConfig: true,
			wantOn: 0, wantState: "ON", wantReason: "not a valid nat priority"},
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
			if tc.wantOn == 0 && tc.wantReason != "" {
				if lt.State != tc.wantState || !strings.Contains(lt.Reason, tc.wantReason) {
					t.Fatalf("transition = %+v, want state %s reason containing %q", lt, tc.wantState, tc.wantReason)
				}
				return
			}
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
	if w := priorityOverrideWarning(-101, -101, true); w != "" {
		t.Fatalf("same as cfm.conf: want no warning, got %q", w)
	}
	cases := []struct {
		name                string
		applied, configured int
		read                bool
		want, notWant       []string
	}{
		{"differs", -101, -99, true, []string{"-101", "(-99)", "restarts", "reboots", "failsafe", "NFT_DNAT_PRIORITY = -101"}, nil},
		// The -99 fallback of an unreadable cfm.conf is not "cfm.conf's value".
		{"cfm.conf unreadable", -101, -99, false, []string{"could not be read", "NFT_DNAT_PRIORITY = -101"}, []string{"(-99)", "differs"}},
		// cfm.conf reads 0 as the -99 default: never advise writing 0 there.
		{"zero", 0, -99, true, []string{"can't be kept", "-1 or 1"}, []string{"NFT_DNAT_PRIORITY = 0"}},
	}
	for _, tc := range cases {
		w := priorityOverrideWarning(tc.applied, tc.configured, tc.read)
		for _, want := range tc.want {
			if !strings.Contains(w, want) {
				t.Errorf("%s: warning %q lacks %q", tc.name, w, want)
			}
		}
		for _, nw := range tc.notWant {
			if strings.Contains(w, nw) {
				t.Errorf("%s: warning %q must not say %q", tc.name, w, nw)
			}
		}
	}
}

// `cfm dnat on --priority` at -200 or below is refused before the backend is
// touched: nft rejects the chain, and the nft backend deletes the live table
// before adding, which would leave web DNAT off.
func TestDNATOnRefusesPriorityNFTRejects(t *testing.T) {
	withWebIntentOn(t)
	for _, p := range []string{"-200", "-250", "-300"} {
		be := &priorityBackend{installed: "dstnat - 1", want: -101, fromConfig: true, statusOn: true}
		if rc := RunCLI([]string{"on", "--priority", p}, be); rc != 2 {
			t.Fatalf("--priority %s: rc=%d, want 2", p, rc)
		}
		if len(be.onCalls) != 0 {
			t.Fatalf("--priority %s: DNATOn called %v", p, be.onCalls)
		}
	}
}

// DNAT that came up while the restore was still waiting (the operator's
// `cfm dnat on --priority X`, or the failsafe) is left as it is: only a chain
// the previous run left in place is re-applied.
func TestRestoreOnStartup_NoReapplyForChainInstalledWhileWaiting(t *testing.T) {
	withWebIntentOn(t)
	t.Setenv("CFM_DNAT_STARTUP_WAIT_MS", "3000")
	t.Setenv("CFM_DNAT_STARTUP_STEP_MS", "20")
	t.Setenv("HTTP_PORT", "1") // the edge probe fails: keep waiting
	t.Setenv("HTTPS_PORT", "1")
	be := &laterOnBackend{priorityBackend: priorityBackend{installed: "-120", want: -101, fromConfig: true}}
	RestoreOnStartup(context.Background(), ScopeWeb, be)
	if len(be.onCalls) != 0 {
		t.Fatalf("re-applied a chain installed while waiting: %v", be.onCalls)
	}
}

// laterOnBackend: web DNAT off at the first check, on from the second.
type laterOnBackend struct {
	priorityBackend
	checks int
}

func (b *laterOnBackend) DNATStatus(string, string) (bool, error) {
	b.checks++
	return b.checks > 1, nil
}
