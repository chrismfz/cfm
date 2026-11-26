package webdetector

import "cfm/internal/proxyipfilter"

// isProxiedIPFilterBlock403 reports whether rec is the edge's 403 for a
// client the proxied IP filter refuses (internal/proxyipfilter, enforce
// mode): a client behind a trusted proxy that is on a fleet feed or a local
// block set. The 403 counters (403_flood, 40x_combo, the per-IP 4xx
// challenge counters) skip it, as they skip a traffic rule's block: the edge
// already refuses every decided request of that client, and counting the
// refusals turned a fleet-list entry into this node's own nft + edge ban
// (/64 for IPv6), which clearing the entry in cfm-web does not lift: a shared
// mobile / CGNAT address on the list can reach IP403_COUNT (150) refusals in
// minutes, every one of them a 403.
//
// The edge logs this refusal as plain "cfm_block" (cfm.lua Step 3), like an
// IP / vhost block or a WAF block, so the predicate asks the filter itself:
// a client the filter enforces on is refused at the decision whatever else
// matched. A direct client on those lists never reaches the edge (nft drops
// it), so a hit here is a proxied one. Asked only for a 403 cfm_block, an
// in-memory lookup.
func isProxiedIPFilterBlock403(rec LogRec) bool {
	return rec.Status == 403 && rec.UpstreamName == "cfm_block" && proxyipfilter.Check(rec.IP).Enforce
}
