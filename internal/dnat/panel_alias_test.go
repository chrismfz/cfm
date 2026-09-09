package dnat

import (
	"testing"

	"cfm/internal/firewall"
)

// panelRouteStub counts PanelDNATStatus calls so a test can prove a CLI
// invocation reached runPanelCLI's status path *without* capturing output.
//
// We deliberately avoid the captureStreams helper here: it swaps the process
// globals os.Stdout/os.Stderr, which data-races with any unrelated background
// goroutine that logs concurrently (e.g. a `startDNATFailSafe` runner leaked by
// another test in this package that cancels its context but does not join the
// goroutine before returning). Asserting on a backend side effect keeps this
// test race-clean regardless of test ordering.
type panelRouteStub struct {
	firewall.Backend
	statusCalls int
}

func (b *panelRouteStub) PanelDNATStatus() (bool, string, error) {
	b.statusCalls++
	return false, "", nil
}
func (b *panelRouteStub) PanelDNATAcceptState() map[int]string { return nil }

// TestPanelAliasRoutesToPanelCLI pins that `cfm dnat panel …` is accepted as the
// panel-neutral alias of `cfm dnat cpanel …`: `panel status` must reach
// runPanelCLI's status path (proven by the backend's PanelDNATStatus being hit).
func TestPanelAliasRoutesToPanelCLI(t *testing.T) {
	be := &panelRouteStub{}
	if code := RunCLI([]string{"panel", "status"}, be); code != 0 {
		t.Fatalf("`dnat panel status` expected code 0, got %d", code)
	}
	if be.statusCalls == 0 {
		t.Fatalf("`dnat panel status` did not route to runPanelCLI (PanelDNATStatus never called)")
	}
}

// TestPanelAndCpanelRouteEquivalently pins that the alias is a true synonym for a
// state-reaching subcommand (status), not a partial alias — both spellings must
// reach the same runPanelCLI status path identically.
func TestPanelAndCpanelRouteEquivalently(t *testing.T) {
	pb := &panelRouteStub{}
	if code := RunCLI([]string{"panel", "status"}, pb); code != 0 {
		t.Fatalf("`dnat panel status` expected code 0, got %d", code)
	}
	cb := &panelRouteStub{}
	if code := RunCLI([]string{"cpanel", "status"}, cb); code != 0 {
		t.Fatalf("`dnat cpanel status` expected code 0, got %d", code)
	}
	if pb.statusCalls == 0 {
		t.Fatalf("`dnat panel status` did not route to runPanelCLI")
	}
	if cb.statusCalls != pb.statusCalls {
		t.Fatalf("panel/cpanel status routing diverged: panel=%d cpanel=%d", pb.statusCalls, cb.statusCalls)
	}
}
