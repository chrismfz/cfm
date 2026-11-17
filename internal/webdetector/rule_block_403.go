package webdetector

// upstreamRuleBlock is the $cfm_upstream cfm.lua sets when it refuses a
// request because a TRAFFIC RULE's action is block (and neither the IP nor
// the vhost decision is): log-cfm.lua column 13. Every other edge refusal
// (IP / vhost block, WAF, edge ban, fingerprint deny) stays "cfm_block".
const upstreamRuleBlock = "cfm_block_rule"

// isRuleBlock403 reports whether rec is the edge's 403 for a traffic rule's
// block. The 403 counters (403_flood and 40x_combo) skip it: the operator's
// rule already refuses that request at the edge, and counting the refusals
// turned the rule into a node-wide nft ban the operator never chose. On
// 2026-11-17 a gokids.gr shopper (from a Google Ads click) shared a product
// on WhatsApp; the rule that blocks WhatsApp's fetcher on that site refused
// its link-preview retries ~400 times in two minutes from the shopper's own
// home IP, 403_flood banned it for an hour (rigel). A client that keeps
// hammering a rule's block costs the edge one Lua decision per request, the
// same as before the rule existed; a scanner among them still reaches the
// WAF, malicious-path and rate counters, which this does not touch. The
// request still counts in the IP's total, so it dilutes the 403 share.
//
// An edge on older Lua writes "cfm_block" for a rule block too, so there the
// refusal keeps counting until the edge is upgraded.
func isRuleBlock403(rec LogRec) bool {
	return rec.Status == 403 && rec.UpstreamName == upstreamRuleBlock
}
