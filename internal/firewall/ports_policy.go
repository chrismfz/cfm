package firewall

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"cfm/internal/config"
)

// Sets and rules the ports policy owns (port sets: type inet_service, flags interval).
const (
	setTCPIn         = "tcp_in_ports"
	setUDPIn         = "udp_in_ports"
	setTCPOut        = "tcp_out_ports"
	setUDPOut        = "udp_out_ports"
	setPSTrackTCP    = "ps_track_tcp_ports"
	setPSTrackUDP    = "ps_track_udp_ports"
	setPSPairsV4     = "ps_pairs_v4"
	setPSPairsV6     = "ps_pairs_v6"
	setPSPairsUDPV4  = "ps_pairs_udp_v4"
	setPSPairsUDPV6  = "ps_pairs_udp_v6"
	setDebugAPIV4    = "debug_api_v4"
	setDebugAPIV6    = "debug_api_v6"
	portSetDecl      = "{ type inet_service; flags interval; }"
	outputChainDecl  = "{ type filter hook output priority 0; policy accept; }"
	ruleEstablished  = "ct state established,related accept"
	ruleInvalidDrop  = "ct state invalid drop"
	ruleNewTCPDrop   = "ct state new tcp dport 0-65535 drop"
	ruleNewUDPDrop   = "ct state new udp dport 0-65535 drop"
	ruleBareTCPDrop  = "tcp dport 0-65535 drop"
	ruleBareUDPDrop  = "udp dport 0-65535 drop"
	defaultPSTimeout = 60
)

// PortsPolicy is what ApplyPortsPolicy writes, on either engine.
type PortsPolicy struct {
	Family, Table string

	// TCPIn has the debug ports already removed (they are opened per source
	// by the DebugPorts rules instead).
	TCPIn, UDPIn, TCPOut, UDPOut []config.PortRange

	// DebugPorts are the debug HTTP/TLS listener ports, accepted only from
	// self and the debug_api_* sets. The engine creates those sets.
	DebugPorts []int

	// Portscan is nil when portscan tracking is off. The engine creates the
	// ps_pairs_* sets.
	Portscan *PortscanTracking
}

// PortscanTracking is the portscan part of the ports policy.
type PortscanTracking struct {
	TrackTCP, TrackUDP bool
	Interval           int                // seconds; <= 0 means 60
	Service            []config.PortRange // PS_ONLY_PORTS + PS_PORTS; empty = track ports NOT in TCP_IN/UDP_IN
}

// PortsPolicyScript returns ONE nft script (`nft -f`, a single kernel
// transaction) that brings the port sets and the ports rules of the input and
// output chains to p, given each chain's `nft -a list chain` listing. The
// caller must not pass an unread listing.
//
// The port sets are always reloaded (flush + elements, inside the transaction,
// so no packet ever sees a set empty or half-filled).
//
// Rules: when the chains already hold the policy, the script writes no rule.
// Otherwise it deletes the policy's accepts and catch-all drops (and their
// pre-ct-state "bare" forms) and re-adds them at the tail, accepts first,
// with any missing rule of the policy in its place, so the drops end up
// last, below the rules other features insert above them. Rules the policy
// adds only when missing (established/invalid, portscan tracking, the debug
// ports) keep their place when present. Output additionally gets
// OutputLoopbackAccept as its first rule.
//
// This replaces a sequence of separate nft runs that deleted the live accepts
// and drops by substring and re-added them one process at a time: on every
// apply the input chain had moments with no default drop or no TCP_IN accept,
// and an error between a delete and its re-add left it that way.
func PortsPolicyScript(p PortsPolicy, inputListing, outputListing string) string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	sets := []struct {
		name   string
		ranges []config.PortRange
	}{
		{setTCPIn, p.TCPIn}, {setUDPIn, p.UDPIn}, {setTCPOut, p.TCPOut}, {setUDPOut, p.UDPOut},
	}
	ps := p.Portscan
	if ps != nil && len(ps.Service) > 0 {
		sets = append(sets, struct {
			name   string
			ranges []config.PortRange
		}{setPSTrackTCP, ps.Service})
		if ps.TrackUDP {
			sets = append(sets, struct {
				name   string
				ranges []config.PortRange
			}{setPSTrackUDP, ps.Service})
		}
	}
	for _, s := range sets {
		add("add set %s %s %s %s", p.Family, p.Table, s.name, portSetDecl)
		add("flush set %s %s %s", p.Family, p.Table, s.name)
		if el := portElements(s.ranges); el != "" {
			add("add element %s %s %s { %s }", p.Family, p.Table, s.name, el)
		}
	}
	add("add chain %s %s output %s", p.Family, p.Table, outputChainDecl)

	in := chainSpec{
		before:  append(portscanServiceRules(ps), ruleEstablished),
		accepts: []string{"ct state new tcp dport @" + setTCPIn + " accept", "ct state new udp dport @" + setUDPIn + " accept"},
		middle:  append(debugPortRules(p.DebugPorts), portscanUnlistedRules(ps)...),
		drops:   []string{ruleNewTCPDrop, ruleNewUDPDrop},
		after:   []string{ruleInvalidDrop},
		legacy: append([]string{"tcp dport @" + setTCPIn + " accept", "udp dport @" + setUDPIn + " accept",
			"tcp dport @" + setTCPIn + " ct state new accept", "udp dport @" + setUDPIn + " ct state new accept"},
			legacyDrops...),
		stale: isStalePortsRule,
	}
	outc := chainSpec{
		head:    OutputLoopbackAccept,
		before:  []string{ruleEstablished, ruleInvalidDrop},
		accepts: []string{"ct state new tcp dport @" + setTCPOut + " accept", "ct state new udp dport @" + setUDPOut + " accept"},
		drops:   []string{ruleNewTCPDrop, ruleNewUDPDrop},
		legacy: append([]string{"tcp dport @" + setTCPOut + " ct state new accept", "udp dport @" + setUDPOut + " ct state new accept"},
			legacyDrops...),
	}
	out = append(out, in.plan(p.Family, p.Table, "input", inputListing)...)
	out = append(out, outc.plan(p.Family, p.Table, "output", outputListing)...)
	return strings.Join(out, "\n")
}

// legacyDrops are older forms of the catch-all drops: without the ct state,
// and in the order IsInputDefaultDropLine also accepts. Left in the chain, one
// would sit above the re-added accepts and drop every new connection.
var legacyDrops = []string{
	ruleBareTCPDrop, ruleBareUDPDrop,
	"tcp dport 0-65535 ct state new drop", "udp dport 0-65535 ct state new drop",
}

// isStalePortsRule matches the rules only the ports policy writes whose
// content follows the config: portscan tracking (its TTL and mode) and the
// debug-port accepts. One that is not in the current policy is left from an
// earlier config (or, for a TTL of 60s or more, from the old duplicate-adding
// presence check) and is deleted.
func isStalePortsRule(key string) bool {
	if strings.Contains(key, " add @ps_pairs_") {
		return true
	}
	return debugRuleRE.MatchString(key)
}

var debugRuleRE = regexp.MustCompile(`^ct state new tcp dport \d+ ip6? saddr @(self_v4|self_v6|` + setDebugAPIV4 + `|` + setDebugAPIV6 + `) accept$`)

// chainSpec is the ports policy's share of one chain, in the order written.
type chainSpec struct {
	head    string   // exactly one copy, as the chain's first rule ("" = none)
	before  []string // added when missing, before the accepts
	accepts []string // owned: exactly once, before the drops
	middle  []string // added when missing, between the accepts and the drops
	drops   []string // owned: exactly once, in this order, below every other rule but `after`
	after   []string // added when missing, after the drops; may sit anywhere
	legacy  []string // older forms of owned rules: deleted
	// stale matches rules the policy owns by shape; one not in before/middle,
	// and every copy after the first of one that is, is deleted.
	stale func(key string) bool
}

func (c chainSpec) plan(family, table, chain, listing string) []string {
	rules := ParseChainRules(listing).rules
	var out []string

	if c.head != "" {
		hk := ruleKey(c.head)
		atHead := len(rules) > 0 && rules[0].key == hk
		if !atHead {
			out = append(out, fmt.Sprintf("insert rule %s %s %s %s", family, table, chain, c.head))
		}
		for i, r := range rules {
			if r.key == hk && r.handle != "" && !(atHead && i == 0) {
				out = append(out, fmt.Sprintf("delete rule %s %s %s handle %s", family, table, chain, r.handle))
			}
		}
	}

	owned := map[string]bool{}
	for _, s := range append(append(append([]string{}, c.accepts...), c.drops...), c.legacy...) {
		owned[ruleKey(s)] = true
	}
	has := map[string]bool{}
	for _, r := range rules {
		has[r.key] = true
	}
	missing := func(list []string) []string {
		var m []string
		for _, s := range list {
			if !has[ruleKey(s)] {
				m = append(m, s)
			}
		}
		return m
	}
	mb, mm, ma := missing(c.before), missing(c.middle), missing(c.after)

	if c.stale != nil {
		want := map[string]bool{}
		for _, s := range append(append([]string{}, c.before...), c.middle...) {
			want[ruleKey(s)] = true
		}
		seen := map[string]bool{}
		for _, r := range rules {
			if r.handle == "" || owned[r.key] || !c.stale(r.key) {
				continue
			}
			if want[r.key] && !seen[r.key] {
				seen[r.key] = true
				continue
			}
			out = append(out, fmt.Sprintf("delete rule %s %s %s handle %s", family, table, chain, r.handle))
		}
	}

	if len(mb) == 0 && len(mm) == 0 && len(ma) == 0 && c.converged(rules) {
		return out
	}
	for _, r := range rules {
		if owned[r.key] && r.handle != "" {
			out = append(out, fmt.Sprintf("delete rule %s %s %s handle %s", family, table, chain, r.handle))
		}
	}
	for _, list := range [][]string{mb, c.accepts, mm, c.drops, ma} {
		for _, s := range list {
			out = append(out, fmt.Sprintf("add rule %s %s %s %s", family, table, chain, s))
		}
	}
	return out
}

// converged: every accept and drop exactly once, no legacy form, the accepts
// above the drops, the drops in order, and below the first drop nothing but
// the other drops and `after` rules.
func (c chainSpec) converged(rules []chainRule) bool {
	pos := map[string][]int{}
	for i, r := range rules {
		pos[r.key] = append(pos[r.key], i)
	}
	for _, s := range c.legacy {
		if len(pos[ruleKey(s)]) > 0 {
			return false
		}
	}
	for _, s := range append(append([]string{}, c.accepts...), c.drops...) {
		if len(pos[ruleKey(s)]) != 1 {
			return false
		}
	}
	firstDrop := pos[ruleKey(c.drops[0])][0]
	for _, s := range c.accepts {
		if pos[ruleKey(s)][0] > firstDrop {
			return false
		}
	}
	prev := firstDrop
	for _, s := range c.drops[1:] {
		i := pos[ruleKey(s)][0]
		if i < prev {
			return false
		}
		prev = i
	}
	tail := map[string]bool{}
	for _, s := range append(append([]string{}, c.drops...), c.after...) {
		tail[ruleKey(s)] = true
	}
	for _, r := range rules[firstDrop:] {
		if !tail[r.key] {
			return false
		}
	}
	return true
}

func debugPortRules(ports []int) []string {
	var out []string
	for _, port := range ports {
		out = append(out,
			fmt.Sprintf("ct state new tcp dport %d ip saddr @self_v4 accept", port),
			fmt.Sprintf("ct state new tcp dport %d ip6 saddr @self_v6 accept", port),
			fmt.Sprintf("ct state new tcp dport %d ip saddr @%s accept", port, setDebugAPIV4),
			fmt.Sprintf("ct state new tcp dport %d ip6 saddr @%s accept", port, setDebugAPIV6),
		)
	}
	return out
}

// portscanServiceRules track hits on the service ports (PS_ONLY_PORTS /
// PS_PORTS); they must see the packet before an accept ends evaluation.
func portscanServiceRules(ps *PortscanTracking) []string {
	if ps == nil || len(ps.Service) == 0 {
		return nil
	}
	return portscanRules(ps, "@"+setPSTrackTCP, "@"+setPSTrackUDP)
}

// portscanUnlistedRules track hits on ports NOT in TCP_IN/UDP_IN, when no
// service filter is set.
func portscanUnlistedRules(ps *PortscanTracking) []string {
	if ps == nil || len(ps.Service) > 0 {
		return nil
	}
	return portscanRules(ps, "!= @"+setTCPIn, "!= @"+setUDPIn)
}

func portscanRules(ps *PortscanTracking, tcpMatch, udpMatch string) []string {
	ttl := NFTDuration(ps.Interval)
	var out []string
	if ps.TrackTCP {
		out = append(out,
			fmt.Sprintf("tcp dport %s add @%s { ip saddr . tcp dport timeout %s }", tcpMatch, setPSPairsV4, ttl),
			fmt.Sprintf("ip6 nexthdr tcp tcp dport %s add @%s { ip6 saddr . tcp dport timeout %s }", tcpMatch, setPSPairsV6, ttl),
		)
	}
	if ps.TrackUDP {
		out = append(out,
			fmt.Sprintf("udp dport %s add @%s { ip saddr . udp dport timeout %s }", udpMatch, setPSPairsUDPV4, ttl),
			fmt.Sprintf("ip6 nexthdr udp udp dport %s add @%s { ip6 saddr . udp dport timeout %s }", udpMatch, setPSPairsUDPV6, ttl),
		)
	}
	return out
}

// NFTDuration renders seconds the way `nft list` prints a timeout (90 →
// "1m30s", 3600 → "1h"), so a rule written with it is found again by its
// printed text. Written as "%ds", a timeout of 60s or more read back as
// missing, and the rule was added again on every apply. <= 0 means 60s.
func NFTDuration(sec int) string {
	if sec <= 0 {
		sec = defaultPSTimeout
	}
	var b strings.Builder
	for _, u := range []struct {
		n    int
		unit string
	}{{86400, "d"}, {3600, "h"}, {60, "m"}, {1, "s"}} {
		if sec >= u.n {
			fmt.Fprintf(&b, "%d%s", sec/u.n, u.unit)
			sec %= u.n
		}
	}
	return b.String()
}

// NormalizePortRanges clamps ranges to 0-65535, merges overlapping and
// adjacent ones, and sorts them: nft refuses overlapping interval elements.
func NormalizePortRanges(prs []config.PortRange) []config.PortRange {
	rs := make([]config.PortRange, 0, len(prs))
	for _, r := range prs {
		if r.From < 0 {
			r.From = 0
		}
		if r.To > 65535 {
			r.To = 65535
		}
		if r.From > r.To {
			continue
		}
		rs = append(rs, r)
	}
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].From == rs[j].From {
			return rs[i].To < rs[j].To
		}
		return rs[i].From < rs[j].From
	})
	out := []config.PortRange{rs[0]}
	for _, r := range rs[1:] {
		cur := &out[len(out)-1]
		if r.From <= cur.To+1 {
			if r.To > cur.To {
				cur.To = r.To
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func portElements(prs []config.PortRange) string {
	var el []string
	for _, r := range NormalizePortRanges(prs) {
		if r.From == r.To {
			el = append(el, fmt.Sprint(r.From))
		} else {
			el = append(el, fmt.Sprintf("%d-%d", r.From, r.To))
		}
	}
	return strings.Join(el, ", ")
}

// SubtractPort removes port p from prs, splitting the range that holds it.
func SubtractPort(prs []config.PortRange, p int) []config.PortRange {
	if p <= 0 || p > 65535 {
		return prs
	}
	out := make([]config.PortRange, 0, len(prs)+1)
	for _, r := range prs {
		if p < r.From || p > r.To {
			out = append(out, r)
			continue
		}
		if r.From < p {
			out = append(out, config.PortRange{From: r.From, To: p - 1})
		}
		if p < r.To {
			out = append(out, config.PortRange{From: p + 1, To: r.To})
		}
	}
	return out
}

// ListChainFunc returns a chain's `nft -a list chain` listing. exists is false
// (with a nil error) only when the chain is absent; any other failure is err.
type ListChainFunc func(chain string) (listing string, exists bool, err error)

// ApplyPortsPolicyScript reads the input and output chains, plans with
// PortsPolicyScript and runs the result as one nft transaction. A failed
// transaction changes nothing (the kernel rolls the whole batch back), so it is
// planned again from a fresh read and retried once: another writer (a DNAT
// re-assert, a CLI one-shot) may have moved a handle in between.
func ApplyPortsPolicyScript(p PortsPolicy, list ListChainFunc, exec func(script string) error) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		var in, out string
		var exists bool
		if in, exists, err = list("input"); err != nil {
			return fmt.Errorf("ports policy: reading the input chain: %w", err)
		}
		if !exists {
			return fmt.Errorf("ports policy: inet %s input chain missing (EnsureBase has not run)", p.Table)
		}
		if out, _, err = list("output"); err != nil {
			return fmt.Errorf("ports policy: reading the output chain: %w", err)
		}
		if err = exec(PortsPolicyScript(p, in, out)); err == nil {
			return nil
		}
	}
	return fmt.Errorf("ports policy: %w", err)
}

// IsNFTNoSuchObject reports whether nft's error output says the object (here,
// the chain being listed) does not exist, as opposed to any other failure (a
// timeout, a busy netlink socket), which must never read as "absent": planned
// from an empty listing, every rule would be added again.
func IsNFTNoSuchObject(stderr string) bool {
	return strings.Contains(stderr, "No such file or directory")
}
