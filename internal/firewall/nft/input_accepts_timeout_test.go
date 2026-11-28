//go:build linux

package nft

import (
	"context"
	"errors"
	"testing"
	"time"

	"cfm/internal/firewall"
)

func withInputAcceptsTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := firewall.InputAcceptsNFTTimeout
	firewall.InputAcceptsNFTTimeout = d
	t.Cleanup(func() { firewall.InputAcceptsNFTTimeout = old })
}

// Every DNAT accepts read of the input chain (web ensure and cleanup, panel
// ensure and state) is bounded by firewall.InputAcceptsNFTTimeout, not by
// ListChainText's 5 s diagnostic deadline, which EL8's 4-12 s listing ran past
// (`cfm edge on` failed on virgo, 2026-11-28). With the budget shortened and
// the listing hung, each returns well before 5 s: a read still on the 5 s
// deadline fails the test. TestInputAcceptsNFTTimeout_FitsEL8 pins the budget.
func TestInputAcceptsRead_UsesItsBudget(t *testing.T) {
	if firewall.InputAcceptsNFTTimeout < firewall.BaseInputReadTimeout {
		t.Fatalf("InputAcceptsNFTTimeout = %v, below EnsureBase's %v", firewall.InputAcceptsNFTTimeout, firewall.BaseInputReadTimeout)
	}
	withInputAcceptsTimeout(t, 300*time.Millisecond)
	fakeNFTOpts(t, fakeOpts{chains: "ok", inputHang: true})
	b := New()
	for _, c := range []struct {
		name    string
		run     func() error
		wantErr bool
	}{
		{"ListInput", func() error { _, err := b.inputAcceptOps().ListInput(); return err }, true},
		{"web ensure", func() error { return b.ensureScopedDNATAccepts(9080, 9043, true) }, true},
		{"web cleanup", b.cleanupScopedDNATAccepts, false}, // best effort: an unread chain is no error
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
