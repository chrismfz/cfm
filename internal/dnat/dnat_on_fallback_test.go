package dnat

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"cfm/internal/firewall"
)

// redirectBackend answers the reads dropRedirectToOtherPorts makes after a
// failed `cfm dnat on` and records DNATOff calls.
type redirectBackend struct {
	firewall.Backend
	statusOn  bool
	statusErr error
	httpPort  int
	httpsPort int
	showErr   error
	offErr    error
	offCalls  int
}

func (b *redirectBackend) DNATStatus(string, string) (bool, error) { return b.statusOn, b.statusErr }
func (b *redirectBackend) DNATShow(string, string) (string, error) {
	if b.showErr != nil {
		return "", b.showErr
	}
	return "table inet cfm_redirect {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat - 1; policy accept;\n\t\tiif \"lo\" accept\n" +
		"\t\ttcp dport 80 dnat to :" + strconv.Itoa(b.httpPort) + "\n\t\ttcp dport 443 dnat to :" + strconv.Itoa(b.httpsPort) +
		"\n\t\tudp dport 443 dnat to :" + strconv.Itoa(b.httpsPort) + "\n\t}\n}\n", nil
}
func (b *redirectBackend) DNATOff(string, string) error { b.offCalls++; return b.offErr }
func (b *redirectBackend) DNATOn(string, string, int, int) error {
	return errors.New("nft: Could not process rule")
}

func lastWebTransition() LastTransition {
	transitionMu.Lock()
	defer transitionMu.Unlock()
	return transitions[ScopeWeb]
}

func resetWebTransition(t *testing.T) {
	t.Helper()
	transitionMu.Lock()
	prev, had := transitions[ScopeWeb]
	delete(transitions, ScopeWeb)
	transitionMu.Unlock()
	t.Cleanup(func() {
		transitionMu.Lock()
		defer transitionMu.Unlock()
		if had {
			transitions[ScopeWeb] = prev
		} else {
			delete(transitions, ScopeWeb)
		}
	})
}

// The failed `on` was moving to other listener ports and the old redirect is
// still there: it points at ports the edge may no longer serve, so it goes
// (the outcome the old delete-then-create always had), recorded as OFF.
func TestDropRedirectToOtherPorts_RemovesARedirectToOtherPorts(t *testing.T) {
	resetWebTransition(t)
	be := &redirectBackend{statusOn: true, httpPort: 9080, httpsPort: 9043}
	dropRedirectToOtherPorts(be, DefaultFamily, DefaultTable, 9081, 9044)
	if be.offCalls != 1 {
		t.Fatalf("DNATOff calls = %d, want 1", be.offCalls)
	}
	tr := lastWebTransition()
	if tr.State != "OFF" || !strings.Contains(tr.Reason, "old ports 9080/9043") {
		t.Fatalf("transition = %+v", tr)
	}
}

// The same ports (a priority or bypass change failed), or the kernel committed
// the new ports despite the error: the redirect in force is right, kept.
func TestDropRedirectToOtherPorts_KeepsARedirectToTheRequestedPorts(t *testing.T) {
	resetWebTransition(t)
	be := &redirectBackend{statusOn: true, httpPort: 9081, httpsPort: 9044}
	dropRedirectToOtherPorts(be, DefaultFamily, DefaultTable, 9081, 9044)
	if be.offCalls != 0 || lastWebTransition().State != "" {
		t.Fatalf("removed a redirect to the requested ports: off=%d transition=%+v", be.offCalls, lastWebTransition())
	}
}

// No redirect, or one that can't be read: nothing is removed on a guess.
func TestDropRedirectToOtherPorts_NeverGuesses(t *testing.T) {
	for name, be := range map[string]*redirectBackend{
		"absent":        {statusOn: false},
		"status error":  {statusErr: errors.New("busy")},
		"show error":    {statusOn: true, showErr: errors.New("busy")},
		"no dnat rules": {statusOn: true}, // ports 0: unparseable
	} {
		resetWebTransition(t)
		dropRedirectToOtherPorts(be, DefaultFamily, DefaultTable, 9081, 9044)
		if be.offCalls != 0 {
			t.Errorf("%s: DNATOff called", name)
		}
	}
}

// A removal that fails is not recorded as OFF (the redirect is still there).
func TestDropRedirectToOtherPorts_FailedRemovalIsNotAnOFF(t *testing.T) {
	resetWebTransition(t)
	be := &redirectBackend{statusOn: true, httpPort: 9080, httpsPort: 9043, offErr: errors.New("busy")}
	dropRedirectToOtherPorts(be, DefaultFamily, DefaultTable, 9081, 9044)
	if be.offCalls != 1 || lastWebTransition().State != "" {
		t.Fatalf("off=%d transition=%+v", be.offCalls, lastWebTransition())
	}
}

// `cfm dnat on` to new ports that fails runs the fallback: the redirect to
// the old ports goes, and the intent is not changed by the failed command.
func TestDNATOnFailureToNewPortsRemovesTheOldRedirect(t *testing.T) {
	withWebIntentOn(t)
	t.Setenv("NFT_DNAT_PRIORITY", "")
	be := &redirectBackend{statusOn: true, httpPort: 9080, httpsPort: 9043}
	if rc := RunCLI([]string{"on", "--http-port", "9081", "--https-port", "9044"}, be); rc != 1 {
		t.Fatalf("rc=%d, want 1", rc)
	}
	if be.offCalls != 1 {
		t.Fatalf("DNATOff calls = %d, want 1", be.offCalls)
	}
	if enabled, present := LoadIntent(ScopeWeb); !present || !enabled {
		t.Fatalf("intent changed by a failed on: enabled=%v present=%v", enabled, present)
	}
}
