package main

import (
	"fmt"
	"os"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
	"cfm/internal/logging"
)

// edgeBanReconcileEvery paces the edge ban store's narrowing to nft (an
// unblock from the CLI, a flush, a new allow entry). Unbans and allows inside
// the daemon, `cfm unblock` and `cfm allow` are immediate and expiry is
// checked at lookup; this is the backstop. Each run lists 14 sets — on the
// exec backend 14 nft processes, each loading the ruleset — hence not every
// minute.
const edgeBanReconcileEvery = 2 * time.Minute

// edgeBanFailClear is how many failed reads in a row stop the store (and
// the edge) answering bans until a read works again.
const edgeBanFailClear = 3

// edgeBanFailRemind repeats the "answers no ban" warning while reads keep
// failing (every hour at the two-minute pace), so it is not one line lost in
// the log.
const edgeBanFailRemind = 30

// The sets a reconcile reads: the host block sets, and every set nft accepts
// in `inet cfm input` before its block drops (self, allow, dyndns, the fleet
// whitelist, allow nets). TestEdgeBanSetsMatchTheInputChain pins both lists
// to both backends' EnsureBase: a set missing here leaves an allow unseen, a
// set that no longer exists fails every read and turns the edge ban off.
var (
	edgeBanBlockSets = []string{"block_v4", "block_v6"}
	edgeBanAllowSets = []string{
		"self_v4", "self_v6",
		"allow_v4", "allow_v6", "allow_dyn_v4", "allow_dyn_v6",
		"allow_ext_v4_hosts", "allow_ext_v6_hosts", "allow_ext_v4_nets", "allow_ext_v6_nets",
		"allow_v4_nets", "allow_v6_nets",
	}
)

// The trusted proxies' own ranges, as the edge includes them (the live copy
// first, then the packaged reference). A var so tests point it elsewhere.
var edgeBanTrustedProxyFiles = []string{
	"/usr/local/openresty/nginx/conf/trusted_proxies.conf",
	"/etc/angie/trusted_proxies.conf",
	"/usr/share/cfm/configs/trusted_proxies.conf",
}

// loadEdgeBanTrustedProxies hands the first readable trusted_proxies.conf to
// the store (an address in it is never edge-banned).
func loadEdgeBanTrustedProxies() {
	for _, p := range edgeBanTrustedProxyFiles {
		raw, err := os.ReadFile(p) // #nosec G304 -- fixed system paths
		if err != nil {
			continue
		}
		if nets := edgeban.ParseTrustedProxies(string(raw)); len(nets) > 0 {
			edgeban.SetTrustedProxies(nets)
			return
		}
	}
	logging.Logf("[edgeban] no trusted_proxies.conf found: proxy addresses are not guarded")
}

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

// edgeBanReconcileOnce runs one reconcile and returns the failed reads in a
// row. A failed read leaves the store as it is (a store never checked against
// nft answers nothing); edgeBanFailClear in a row (the table gone after `cfm
// disable`, a broken backend) Clear it: it answers nothing until a
// read works again. Logged on the transitions only.
func edgeBanReconcileOnce(s *edgeban.Store, be firewall.Backend, fails int) int {
	snap, err := readEdgeBanSnapshot(be)
	if err == nil {
		if fails >= edgeBanFailClear {
			logging.Logf("[edgeban] nft readable again after %d failed reads", fails)
		}
		s.Reconcile(snap)
		return 0
	}
	fails++
	switch {
	case fails < edgeBanFailClear:
		logging.Logf("[edgeban] reconcile skipped (%d in a row): %v", fails, err)
	case fails == edgeBanFailClear:
		s.Clear()
		logging.Logf("[edgeban] %d failed reads: the edge answers no ban until nft is readable: %v", fails, err)
	case fails%edgeBanFailRemind == 0:
		logging.Logf("[edgeban] still unreadable after %d reads, the edge answers no ban: %v", fails, err)
	}
	return fails
}

// runEdgeBanReconcile reconciles now and every edgeBanReconcileEvery.
func runEdgeBanReconcile(s *edgeban.Store, be firewall.Backend) {
	loadEdgeBanTrustedProxies()
	t := time.NewTicker(edgeBanReconcileEvery)
	defer t.Stop()
	fails := 0
	for {
		fails = edgeBanReconcileOnce(s, be, fails)
		<-t.C
	}
}
