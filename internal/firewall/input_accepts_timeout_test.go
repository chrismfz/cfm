package firewall

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// The DNAT accepts' read of the input chain (both engines' NFTTextOps.
// ListInput) gets EnsureBase's budget: at 5 s, EL8's 4-12 s `list chain`
// failed `cfm edge on` during an upgrade on virgo (2026-11-28), and the web
// DNAT stayed off until a retry. The engines' wiring is pinned by
// TestInputAcceptsRead_UsesItsBudget in nft/ and nftlib/.
func TestInputAcceptsNFTTimeout_FitsEL8(t *testing.T) {
	if InputAcceptsNFTTimeout < BaseInputReadTimeout {
		t.Errorf("InputAcceptsNFTTimeout = %v, below EnsureBase's %v: EL8's 4-12 s `list chain` plus the slot wait",
			InputAcceptsNFTTimeout, BaseInputReadTimeout)
	}
}

// A read that ran out of time is not a missing chain: EnsureInputAccepts
// fails at once, with no table/chain declaration and no second read (a
// second 30 s wait before `cfm edge on` failed). Any other listing error is
// still taken for a missing chain: declared, then read again.
func TestEnsureInputAccepts_TimeoutIsNotAMissingChain(t *testing.T) {
	for _, c := range []struct {
		name      string
		err       error
		wantReads int
		wantRuns  int
	}{
		{"timed out", fmt.Errorf("nft list chain inet cfm input: %w: signal: killed", context.DeadlineExceeded), 1, 0},
		{"no such chain", errors.New("nft list chain inet cfm input: exit status 1: Error: No such file or directory"), 2, 2},
	} {
		reads, runs := 0, 0
		ops := NFTTextOps{
			ListInput: func() (string, error) { reads++; return "", c.err },
			Run:       func(string) error { runs++; return nil },
		}
		_, err := EnsureInputAccepts(ops, webWant, IsWebDNATAccept, true)
		if err == nil {
			t.Fatalf("%s: want an error", c.name)
		}
		if reads != c.wantReads || runs != c.wantRuns {
			t.Errorf("%s: %d reads, %d runs; want %d, %d", c.name, reads, runs, c.wantReads, c.wantRuns)
		}
		if c.wantReads == 1 && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: error %v no longer marks the timeout", c.name, err)
		}
	}
}
