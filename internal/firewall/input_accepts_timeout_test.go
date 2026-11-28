package firewall

import "testing"

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
