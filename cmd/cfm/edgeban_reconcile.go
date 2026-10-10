package main

import (
	"fmt"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
	"cfm/internal/logging"
)

// edgeBanReconcileEvery paces the edge ban store's narrowing to nft (an
// unblock from the CLI, a flush, an expiry, a new allow). Unbans inside the
// daemon are immediate; this is the backstop.
const edgeBanReconcileEvery = time.Minute

// edgeBanFailClear is how many failed reads in a row empty the store.
const edgeBanFailClear = 3

// The sets a reconcile reads: the host block sets, and every allow set nft
// accepts before its block drops (inet cfm input).
var (
	edgeBanBlockSets = []string{"block_v4", "block_v6"}
	edgeBanAllowSets = []string{
		"allow_v4", "allow_v6", "allow_dyn_v4", "allow_dyn_v6",
		"allow_ext_v4_hosts", "allow_ext_v6_hosts", "allow_ext_v4_nets", "allow_ext_v6_nets",
		"allow_v4_nets", "allow_v6_nets",
	}
)

// readEdgeBanSnapshot reads every set, or fails: a partial read (one set
// missing or erroring) must not reconcile, it would drop real bans.
func readEdgeBanSnapshot(be firewall.Backend) (edgeban.Snapshot, error) {
	snap := edgeban.Snapshot{ReadAt: time.Now()}
	for _, set := range edgeBanBlockSets {
		elems, err := be.ListSetElementsTimed(set)
		if err != nil {
			return snap, fmt.Errorf("%s: %w", set, err)
		}
		snap.Blocks = append(snap.Blocks, elems...)
	}
	for _, set := range edgeBanAllowSets {
		elems, err := be.ListSetElementsTimed(set)
		if err != nil {
			return snap, fmt.Errorf("%s: %w", set, err)
		}
		for _, e := range elems {
			snap.Allows = append(snap.Allows, e.Elem)
		}
	}
	return snap, nil
}

// runEdgeBanReconcile narrows the edge ban store to what nft holds, now and
// every edgeBanReconcileEvery. A failed read leaves the store as it is (it
// stays not ready until a read works: nothing is blocked at the edge on a
// store never checked against nft); edgeBanFailClear failed reads in a row
// (the table gone after `cfm disable`, a broken backend) empty it: the edge
// must not keep enforcing bans nft may no longer hold.
func runEdgeBanReconcile(s *edgeban.Store, be firewall.Backend) {
	t := time.NewTicker(edgeBanReconcileEvery)
	defer t.Stop()
	fails := 0
	for {
		snap, err := readEdgeBanSnapshot(be)
		if err == nil {
			s.Reconcile(snap)
			fails = 0
		} else {
			fails++
			logging.Logf("[edgeban] reconcile skipped (%d in a row): %v", fails, err)
			if fails == edgeBanFailClear {
				s.Clear()
				logging.Logf("[edgeban] %d failed reads: store emptied (fail toward not blocking)", fails)
			}
		}
		<-t.C
	}
}
