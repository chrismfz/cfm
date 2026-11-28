//go:build linux

package nftlib

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/nftables"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// fakeNFTHungInput puts an `nft` first in PATH whose `-a list chain inet cfm
// input` never answers (EL8's 4-12 s listing, past any deadline a test can
// wait for); every other run succeeds.
func fakeNFTHungInput(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
echo "ARGS $*" >> %q
if [ "$1" = "-f" ]; then cat >/dev/null; exit 0; fi
if [ "$*" = "-a list chain inet cfm input" ]; then exec sleep 30; fi
exit 0
`, filepath.Join(dir, "nft.log"))
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// DNATOn's accepts read is an nft CLI run of up to InputAcceptsNFTTimeout
// (30 s), and b.mu serialises every ban and set write: held across it, a hung
// EL8 listing stalled all of them behind DNATOn. installDNATRules holds b.mu
// for its netlink read and rebuild only, so while the accepts read hangs
// another writer gets the lock at once.
func TestInstallDNATRules_AcceptsReadRunsOutsideTheLock(t *testing.T) {
	old := firewall.InputAcceptsNFTTimeout
	firewall.InputAcceptsNFTTimeout = 1500 * time.Millisecond
	t.Cleanup(func() { firewall.InputAcceptsNFTTimeout = old })
	fakeNFTHungInput(t)
	hermeticBypass(t)

	var batches [][]int
	b := dnatPrioBackend(t, firewall.DNATDefaultTable, -99, nil, &batches)
	wanted := dnatUnscopedWantedSpecs(nftables.TableFamilyINet, 9080, 9043)
	done := make(chan error, 1)
	go func() {
		done <- b.installDNATRules("inet", firewall.DNATDefaultTable, wanted, dnatRuleNamespaceEdge, true)
	}()

	time.Sleep(300 * time.Millisecond) // past the netlink read, into the hung accepts read
	got := false
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if b.mu.TryLock() {
			b.mu.Unlock()
			got = true
			break
		}
	}
	select {
	case err := <-done:
		t.Fatalf("installDNATRules returned before the hung read timed out (%v): the test did not catch it in the read", err)
	default:
	}
	if !got {
		t.Error("b.mu stayed held while the accepts read hung: every ban and set write waits on DNATOn")
	}
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("installDNATRules: %v, want the accepts read's timeout", err)
	}
	if len(batches) != 0 {
		t.Errorf("rebuilt the redirect after the accepts read failed: %v", batches)
	}
}

// Every DNAT accepts read of the input chain (web ensure and cleanup, panel
// ensure) is bounded by firewall.InputAcceptsNFTTimeout, not by
// ListChainText's 5 s diagnostic deadline, which EL8's 4-12 s listing ran past
// (`cfm edge on` failed on virgo, 2026-11-28). With the budget shortened and
// the listing hung, each returns well before 5 s: a read still on the 5 s
// deadline fails the test. TestInputAcceptsNFTTimeout_FitsEL8 pins the budget.
func TestInputAcceptsRead_UsesItsBudget(t *testing.T) {
	if firewall.InputAcceptsNFTTimeout < firewall.BaseInputReadTimeout {
		t.Fatalf("InputAcceptsNFTTimeout = %v, below EnsureBase's %v", firewall.InputAcceptsNFTTimeout, firewall.BaseInputReadTimeout)
	}
	old := firewall.InputAcceptsNFTTimeout
	firewall.InputAcceptsNFTTimeout = 300 * time.Millisecond
	t.Cleanup(func() { firewall.InputAcceptsNFTTimeout = old })

	fakeNFTHungInput(t)

	b := &Backend{}
	spec := []dnatRuleSpec{{proto: 6, dport: 80, toPort: 9080}}
	for _, c := range []struct {
		name    string
		run     func() error
		wantErr bool
	}{
		{"ListInput", func() error { _, err := b.inputAcceptOps().ListInput(); return err }, true},
		{"web ensure", func() error { return b.ensureScopedDNATAccepts(dnatAcceptNamespaceEdge, spec, true) }, true},
		{"web cleanup", func() error { return b.cleanupScopedDNATAccepts(dnatAcceptNamespaceEdge) }, false},
		{"panel ensure", func() error { _, err := b.EnsurePanelDNATAccepts(); return err }, true},
	} {
		start := time.Now()
		err := c.run()
		took := time.Since(start)
		if c.wantErr && err == nil {
			t.Errorf("%s: a hung listing read as success", c.name)
		}
		if c.wantErr && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: error %v does not mark the timeout (EnsureInputAccepts would read again)", c.name, err)
		}
		// One read each: a timed-out web ensure no longer declares the chain
		// and waits out a second read.
		if took >= 2*time.Second {
			t.Errorf("%s took %v with a 300ms budget: the read is not bounded by InputAcceptsNFTTimeout", c.name, took)
		}
	}
}
