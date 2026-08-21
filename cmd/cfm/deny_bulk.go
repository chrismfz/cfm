package main

import (
	"fmt"
	"net"
	"os"

	"cfm/internal/allowlist"
)

// manualBulkBlocker is the narrow backend capability the cfm.deny fast-path
// needs: reconcile a batch of permanent host blocks in bulk nft transactions and
// return the IPs that could not be applied. Backends that don't implement it
// (e.g. the fork-free nftlib backend) simply don't take the fast path.
type manualBulkBlocker interface {
	AddManualBlocksBulk([]net.IP) ([]net.IP, error)
}

// denyBulkMinBatch is the number of new permanent host entries below which the
// per-IP path is cheaper than a full block-set read, so small incremental
// reloads skip the bulk path entirely.
const denyBulkMinBatch = 64

// bulkPreapplyDenyHosts applies the permanent, non-CIDR host entries of a block
// list in bulk (the expensive-at-scale part of cfm.deny), marking each applied
// IP seen so the per-IP caller then skips it and handles only the remainder
// (CIDRs, TTL'd entries, and any that failed to bulk-apply). It mutates
// seenBlock. Entries with a nil IP are left to the per-IP path, which surfaces
// the parse error rather than swallowing it here.
//
// Duplicate-spec safety: the per-IP loop still runs over every entry in file
// order and skips only an exact (key, spec) repeat, so pre-marking a bulk IP as
// "perm" only skips a redundant permanent duplicate; a later TTL/until line for
// the same IP has a different spec and is still applied — the final state stays
// the spec of the last matching line, exactly as before.
func bulkPreapplyDenyHosts(entries []allowlist.Entry, seenBlock map[string]string, be manualBulkBlocker) {
	var bulk []net.IP
	inBulk := map[string]struct{}{}
	for _, e := range entries {
		// Only permanent, literal-IP host entries take the bulk path. Keying on
		// KindIP explicitly (rather than "not CIDR") keeps a future
		// hostname-resolving block file from ever sweeping resolved IPs in here.
		if e.Kind != allowlist.KindIP || e.Until != nil || e.TTL != nil || e.IP == nil {
			continue
		}
		k := "ip|" + e.IP.String()
		if _, seen := seenBlock[k]; seen {
			continue
		}
		if _, dup := inBulk[k]; dup { // dedupe within this file so the threshold counts distinct IPs
			continue
		}
		inBulk[k] = struct{}{}
		bulk = append(bulk, e.IP)
	}
	if len(bulk) < denyBulkMinBatch {
		return
	}

	failed, err := be.AddManualBlocksBulk(bulk)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bulk block apply (per-IP fallback for the rest):", err)
		if len(failed) == 0 {
			// Error but no specific failures reported: don't assume anything
			// landed — leave every entry unseen so the per-IP loop re-applies
			// them all, rather than silently marking them done.
			return
		}
	}
	skip := make(map[string]struct{}, len(failed))
	for _, ip := range failed {
		skip["ip|"+ip.String()] = struct{}{}
	}
	// Mark succeeded entries seen; failed ones stay unseen so the per-IP loop
	// re-applies only the remainder.
	for _, ip := range bulk {
		k := "ip|" + ip.String()
		if _, bad := skip[k]; !bad {
			seenBlock[k] = "perm"
		}
	}
}
