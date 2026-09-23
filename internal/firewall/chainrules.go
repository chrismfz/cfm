package firewall

import "strings"

// ChainRules answers EnsureBase's "is this base rule already in the chain?"
// from one `nft -a list chain` listing, on both backends.
//
// A rule counts as present when a listed rule contains it (the check the base
// rules have always used, so an established/related copy of a block rule
// counts), compared as nft prints rules: quotes dropped (`iif lo` is printed
// `iif "lo"`) and an ICMP type match without the protocol match that implies
// it (nft 1.0.9 prints the ICMP jumps as written; older versions may not). A
// bare verdict (`jump flood`) must be a whole rule: as a substring it is found
// inside every `… jump flood` rule, and with ICMP rate limiting on, the plain
// `jump flood` that sends TCP/UDP through the flood chain was never added.
type ChainRules struct {
	rules []chainRule // listing order, then rules queued with Add
}

type chainRule struct {
	key    string // ruleKey of the rule's text
	handle string // "# handle N" in the listing; "" for a queued rule
}

// ParseChainRules reads the rules of an `nft [-a] list chain` listing.
func ParseChainRules(listing string) *ChainRules {
	c := &ChainRules{}
	for _, line := range strings.Split(listing, "\n") {
		text, handle := line, ""
		if i := strings.LastIndex(text, "# handle "); i >= 0 {
			handle = strings.TrimSpace(text[i+len("# handle "):])
			text = text[:i]
		}
		text = strings.TrimSpace(text)
		// The table and chain lines open a block, the hook line ends in ";".
		if text == "" || text == "}" || strings.HasSuffix(text, "{") || strings.HasSuffix(text, ";") {
			continue
		}
		c.rules = append(c.rules, chainRule{key: ruleKey(text), handle: handle})
	}
	return c
}

// Has reports whether expr is present (see ChainRules).
func (c *ChainRules) Has(expr string) bool {
	k := ruleKey(expr)
	whole := isBareVerdict(k)
	for _, r := range c.rules {
		if r.key == k || (!whole && strings.Contains(" "+r.key+" ", " "+k+" ")) {
			return true
		}
	}
	return false
}

// Add records expr as present, for a rule about to be written.
func (c *ChainRules) Add(expr string) {
	c.rules = append(c.rules, chainRule{key: ruleKey(expr)})
}

// DuplicateHandles returns the handles of the listed rules that repeat one of
// exprs exactly, all but the first (top-most) of each. A rule the old presence
// check didn't recognise was added again on every EnsureBase — `iif lo accept`
// on the nft backend, seen; an ICMP jump, should an nft version print it
// differently from how it is written — so a long-running chain can hold many
// copies.
func (c *ChainRules) DuplicateHandles(exprs ...string) []string {
	var out []string
	for _, e := range exprs {
		k, seen := ruleKey(e), false
		for _, r := range c.rules {
			if r.handle == "" || r.key != k {
				continue
			}
			if seen {
				out = append(out, r.handle)
			}
			seen = true
		}
	}
	return out
}

// ruleKey is a rule's text as nft prints it, reduced to what identifies it.
func ruleKey(s string) string {
	s = " " + strings.Join(strings.Fields(strings.ReplaceAll(s, `"`, "")), " ") + " "
	for _, p := range []struct{ from, to string }{
		{" ip protocol icmp icmp type ", " icmp type "},
		{" meta l4proto icmp icmp type ", " icmp type "},
		{" ip6 nexthdr ipv6-icmp icmpv6 type ", " icmpv6 type "},
		{" meta l4proto ipv6-icmp icmpv6 type ", " icmpv6 type "},
	} {
		s = strings.ReplaceAll(s, p.from, p.to)
	}
	return strings.TrimSpace(s)
}

func isBareVerdict(key string) bool {
	f := strings.Fields(key)
	switch len(f) {
	case 1:
		return f[0] == "accept" || f[0] == "drop" || f[0] == "return" || f[0] == "continue"
	case 2:
		return f[0] == "jump" || f[0] == "goto"
	}
	return false
}
