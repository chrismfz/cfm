package main

import (
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
	"cfm/internal/logging"
)

// edgeBanReconcileEvery paces the edge ban store's narrowing to nft (an
// unblock from the CLI, a flush, an expiry). Unbans inside the daemon are
// immediate; this is the backstop.
const edgeBanReconcileEvery = time.Minute

// edgeBanFailClear is how many failed reads in a row empty the store.
const edgeBanFailClear = 3

// runEdgeBanReconcile narrows the edge ban store to the block sets nft still
// holds, minus the allow sets, now and every edgeBanReconcileEvery. A read
// error leaves the store as it is (it stays not ready until a read works:
// nothing is blocked at the edge on a store never checked against nft);
// edgeBanFailClear reads failing in a row (the table gone after `cfm
// disable`, a broken backend) empty it: the edge must not keep enforcing
// bans nft may no longer hold.
func runEdgeBanReconcile(s *edgeban.Store, be firewall.Backend) {
	t := time.NewTicker(edgeBanReconcileEvery)
	defer t.Stop()
	fails := 0
	for {
		blocks, err := be.ListBlocks()
		if err == nil {
			var allows []firewall.BlockedEntry
			allows, err = be.ListAllows()
			if err == nil {
				s.Reconcile(blocks, allows)
			}
		}
		if err != nil {
			fails++
			logging.Logf("[edgeban] reconcile skipped (%d in a row): %v", fails, err)
			if fails == edgeBanFailClear && s.Ready() {
				s.Reconcile(nil, nil)
				logging.Logf("[edgeban] %d failed reads: store emptied (fail toward not blocking)", fails)
			}
		} else {
			fails = 0
		}
		<-t.C
	}
}
