package firewall

// The base layer of the `inet cfm input` chain, written by both backends'
// EnsureBase (nft/nft.go, nftlib/lifecycle.go): ONE list, so the two engines
// can't drift in what they write or in what they deduplicate.
//
// Each backend inserts BaseEarlyRules at position 0 in reverse (so the first
// ends on top), then appends BaseLateRules in order, then BaseFloodJump; a
// rule that reads present (ChainRules.Present, the queued ones included) is
// not written again.

// ICMPFloodJumps send echo-requests through the flood chain when ICMP rate
// limiting is on.
var ICMPFloodJumps = []string{
	`ip protocol icmp icmp type echo-request jump flood`,
	`ip6 nexthdr ipv6-icmp icmpv6 type echo-request jump flood`,
}

// BaseFloodJump ends the base layer: TCP/UDP through the flood chain, before
// the ports policy's rules.
const BaseFloodJump = `jump flood`

// BaseEstablishedAccept is also the ports policy's ruleEstablished, which it
// positions itself (PortsPolicyScript): never deduplicated by EnsureBase.
const BaseEstablishedAccept = `ct state established,related accept`

// BaseEarlyRules is the top of the input chain, top-down: loopback, self,
// every allow set, every unconditional block set, then (ICMP rate limiting
// on) the ICMP jumps to flood. A fresh slice on every call.
func BaseEarlyRules(icmpJumps bool) []string {
	early := []string{
		// 1) loopback
		`iif lo accept`,

		// 2) self IPs
		`ip saddr @self_v4 accept`,
		`ip6 saddr @self_v6 accept`,

		// 3) ALLOW sets (manual + dyn + external + nets)
		`ip saddr @allow_v4 accept`,
		`ip6 saddr @allow_v6 accept`,
		`ip saddr @allow_dyn_v4 accept`,
		`ip6 saddr @allow_dyn_v6 accept`,
		`ip saddr @allow_ext_v4_hosts accept`,
		`ip6 saddr @allow_ext_v6_hosts accept`,
		`ip saddr @allow_ext_v4_nets accept`,
		`ip6 saddr @allow_ext_v6_nets accept`,
		`ip saddr @allow_v4_nets accept`,
		`ip6 saddr @allow_v6_nets accept`,

		// 4) UNCONDITIONAL BLOCKS (must be above ICMP/conntrack/ports)
		`ip saddr @block_v4 drop`,
		`ip6 saddr @block_v6 drop`,
		`ip saddr @block_ext_v4_hosts drop`,
		`ip6 saddr @block_ext_v6_hosts drop`,
		`ip saddr @block_ext_v4_nets drop`,
		`ip6 saddr @block_ext_v6_nets drop`,
		`ip saddr @block_v4_nets drop`,
		`ip6 saddr @block_v6_nets drop`,
		`ip6 saddr @block_v6_clients drop`,
	}
	// 5) ICMP → flood (below unconditional drops)
	if icmpJumps {
		early = append(early, ICMPFloodJumps...)
	}
	return early
}

// BaseLateRules are appended after the early group, in this order (a rule
// the early group already holds reads present and is not added again). A
// fresh slice on every call.
func BaseLateRules() []string {
	return []string{
		// Established/related from IPs already in a block set
		`ct state established,related ip saddr @block_v4 drop`,
		`ct state established,related ip6 saddr @block_v6 drop`,
		// External feeds — hosts & nets
		`ct state established,related ip saddr @block_ext_v4_hosts drop`,
		`ct state established,related ip saddr @block_ext_v4_nets drop`,
		`ct state established,related ip6 saddr @block_ext_v6_hosts drop`,
		`ct state established,related ip6 saddr @block_ext_v6_nets drop`,
		// Manual/aggregate nets
		`ct state established,related ip saddr @block_v4_nets drop`,
		`ct state established,related ip6 saddr @block_v6_nets drop`,
		`ct state established,related ip6 saddr @block_v6_clients drop`,
		// The general established/related accept, after the drops
		BaseEstablishedAccept,
		// 1) manual allow
		`ip saddr @allow_v4 accept`,
		`ip6 saddr @allow_v6 accept`,
		// 2) dyn allow
		`ip saddr @allow_dyn_v4 accept`,
		`ip6 saddr @allow_dyn_v6 accept`,
		// 3) external allow (hosts, then nets)
		`ip saddr @allow_ext_v4_hosts accept`,
		`ip6 saddr @allow_ext_v6_hosts accept`,
		`ip saddr @allow_ext_v4_nets accept`,
		`ip6 saddr @allow_ext_v6_nets accept`,
		// 4) manual block
		`ip saddr @block_v4 drop`,
		`ip6 saddr @block_v6 drop`,
		// 5) external block (hosts, then nets)
		`ip saddr @block_ext_v4_hosts drop`,
		`ip6 saddr @block_ext_v6_hosts drop`,
		`ip saddr @block_ext_v4_nets drop`,
		`ip6 saddr @block_ext_v6_nets drop`,
		// manual block nets
		`ip saddr @block_v4_nets drop`,
		`ip6 saddr @block_v6_nets drop`,
	}
}

// BaseDedupeExprs is every base rule EnsureBase writes, each once, but the
// established accept: the ICMP jumps always (a copy left from when ICMP rate
// limiting was on is still a copy) and the flood jump. Both backends delete
// every extra copy of each (ChainRules.DuplicateHandles), keeping the
// top-most, in one transaction: an old exec-backend bug added the whole base
// layer again whenever its read of the input chain failed (141–268 copies of
// each rule on the EL8 nodes, 2026-11-22), and every copy of `jump flood`
// counts a packet in the flood meters once more.
func BaseDedupeExprs() []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range [][]string{BaseEarlyRules(true), BaseLateRules(), {BaseFloodJump}} {
		for _, e := range group {
			if e == BaseEstablishedAccept || seen[e] {
				continue
			}
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}
