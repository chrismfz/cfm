package firewall

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"cfm/internal/config"
)

// Sets the ports policy owns (port sets: type inet_service, flags interval)
// or references. The engines create the portscan pair sets and the debug API
// sets under these names, so there is one copy of each.
const (
	setTCPIn        = "tcp_in_ports"
	setUDPIn        = "udp_in_ports"
	setTCPOut       = "tcp_out_ports"
	setUDPOut       = "udp_out_ports"
	setPSTrackTCP   = "ps_track_tcp_ports"
	setPSTrackUDP   = "ps_track_udp_ports"
	SetPSPairsV4    = "ps_pairs_v4"
	SetPSPairsV6    = "ps_pairs_v6"
	SetPSPairsUDPV4 = "ps_pairs_udp_v4"
	SetPSPairsUDPV6 = "ps_pairs_udp_v6"
	SetDebugAPIV4   = "debug_api_v4"
	SetDebugAPIV6   = "debug_api_v6"
)

const (
	portSetDecl      = "{ type inet_service; flags interval; }"
	outputChainDecl  = "{ type filter hook output priority 0; policy accept; }"
	ruleEstablished  = "ct state established,related accept"
	ruleInvalidDrop  = "ct state invalid drop"
	ruleNewTCPDrop   = "ct state new tcp dport 0-65535 drop"
	ruleNewUDPDrop   = "ct state new udp dport 0-65535 drop"
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

	// Portscan is nil when portscan tracking is off (its rules are then
	// removed). The engine creates the ps_pairs_* sets.
	Portscan *PortscanTracking
}

// PortscanTracking is the portscan part of the ports policy.
type PortscanTracking struct {
	TrackTCP, TrackUDP bool
	Interval           int                // seconds; <= 0 means 60
	Service            []config.PortRange // PS_ONLY_PORTS + PS_PORTS; empty = track ports NOT in TCP_IN/UDP_IN
}

// NewPortsPolicy builds the policy both engines write from the config: the
// debug ports come out of TCP_IN (they are opened per source instead), and
// the portscan service filter is PS_ONLY_PORTS plus PS_PORTS. cfg may be nil
// (no debug ports, no portscan).
func NewPortsPolicy(family, table string, ports *config.PortsConfig, cfg *config.Config) PortsPolicy {
	p := PortsPolicy{Family: family, Table: table, TCPIn: ports.TCPIn, UDPIn: ports.UDPIn, TCPOut: ports.TCPOut, UDPOut: ports.UDPOut}
	if cfg == nil {
		return p
	}
	for _, port := range []int{cfg.Debug.Port, cfg.Debug.TLSPort} {
		if port > 0 && port <= 65535 && !containsInt(p.DebugPorts, port) {
			p.DebugPorts = append(p.DebugPorts, port)
			p.TCPIn = SubtractPort(p.TCPIn, port)
		}
	}
	if ps := cfg.Portscan; ps.Enabled {
		svc := append([]config.PortRange{}, ps.OnlyPorts...)
		for _, port := range ps.Ports {
			port = min(max(port, 0), 65535)
			svc = append(svc, config.PortRange{From: port, To: port})
		}
		p.Portscan = &PortscanTracking{TrackTCP: ps.TrackTCP, TrackUDP: ps.TrackUDP, Interval: ps.Interval, Service: svc}
	}
	return p
}

func containsInt(xs []int, n int) bool {
	for _, x := range xs {
		if x == n {
			return true
		}
	}
	return false
}

// PortsPolicyState is what the planner reads off the live ruleset.
type PortsPolicyState struct {
	Input  string // `nft -a list chain` of input (must exist)
	Output string // the same for output; "" when the chain is absent
	// Sets holds the names of the sets that exist in the table.
	Sets map[string]bool
}

// PortsPolicyScript returns ONE nft script (`nft -f`, a single kernel
// transaction) that brings the port sets and the ports rules of the input and
// output chains to p.
//
// The port sets are always reloaded (flush + elements inside the transaction,
// so no packet ever sees a set empty or half-filled); a set is declared only
// when it is absent, so an existing one with other flags does not fail the
// batch. The output chain is declared only when absent: re-declaring it would
// reset an operator's policy, and fail the batch at another priority.
//
// Rules, per chain: a rule the policy wants and lacks is inserted where it
// belongs (portscan service tracking above the first rule that takes a NEW
// connection, so DNAT'd connections are still tracked; a debug-port accept
// above the drops). The accepts and the catch-all drops it owns stay put while
// they are in order: each exactly once, accepts above the drops, nothing but
// drops (and `ct state invalid drop`) below the first drop. Otherwise they,
// and every other form of a catch-all drop, are deleted and re-added at the
// tail, accepts first, so the drops end up last, below what other features
// inserted above them. Exact copies of the policy's rules are deleted, as are
// portscan and debug-port rules the config no longer has. Output also gets
// OutputLoopbackAccept as its first rule. A converged node gets no rule write.
//
// This replaces a sequence of separate nft runs that deleted the live accepts
// and drops by substring and re-added them one process at a time: on every
// apply the input chain had moments with no default drop or no TCP_IN accept,
// and an error between a delete and its re-add left it that way.
func PortsPolicyScript(p PortsPolicy, st PortsPolicyState) string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	type portSet struct {
		name   string
		ranges []config.PortRange
	}
	sets := []portSet{{setTCPIn, p.TCPIn}, {setUDPIn, p.UDPIn}, {setTCPOut, p.TCPOut}, {setUDPOut, p.UDPOut}}
	ps := p.Portscan
	if ps != nil && len(ps.Service) > 0 {
		sets = append(sets, portSet{setPSTrackTCP, ps.Service})
		if ps.TrackUDP {
			sets = append(sets, portSet{setPSTrackUDP, ps.Service})
		}
	}
	for _, s := range sets {
		if !st.Sets[s.name] {
			add("add set %s %s %s %s", p.Family, p.Table, s.name, portSetDecl)
		}
		add("flush set %s %s %s", p.Family, p.Table, s.name)
		if el := portElements(s.ranges); el != "" {
			add("add element %s %s %s { %s }", p.Family, p.Table, s.name, el)
		}
	}
	if strings.TrimSpace(st.Output) == "" {
		add("add chain %s %s output %s", p.Family, p.Table, outputChainDecl)
	}

	in := chainSpec{
		before:  append(portscanServiceRules(ps), ruleEstablished),
		accepts: []string{"ct state new tcp dport @" + setTCPIn + " accept", "ct state new udp dport @" + setUDPIn + " accept"},
		middle:  append(debugPortRules(p.DebugPorts), portscanUnlistedRules(ps)...),
		drops:   []string{ruleNewTCPDrop, ruleNewUDPDrop},
		after:   []string{ruleInvalidDrop},
		legacy: []string{"tcp dport @" + setTCPIn + " accept", "udp dport @" + setUDPIn + " accept",
			"tcp dport @" + setTCPIn + " ct state new accept", "udp dport @" + setUDPIn + " ct state new accept"},
		stale: isStalePortsRule,
	}
	outc := chainSpec{
		head:    OutputLoopbackAccept,
		before:  []string{ruleEstablished, ruleInvalidDrop},
		accepts: []string{"ct state new tcp dport @" + setTCPOut + " accept", "ct state new udp dport @" + setUDPOut + " accept"},
		drops:   []string{ruleNewTCPDrop, ruleNewUDPDrop},
		legacy:  []string{"tcp dport @" + setTCPOut + " ct state new accept", "udp dport @" + setUDPOut + " ct state new accept"},
	}
	out = append(out, in.plan(p.Family, p.Table, "input", st.Input)...)
	out = append(out, outc.plan(p.Family, p.Table, "output", st.Output)...)
	return strings.Join(out, "\n")
}

// isCatchAllDrop is NOT IsInputDefaultDropLine, on purpose. That one is the
// DNAT accepts' anchor ("insert before the first default drop"): it must find
// the canonical drop, and errs toward matching any NEW-state drop of all
// ports. This one decides what the planner may DELETE, so it is exact: only
// the forms below, never a narrower drop someone else wrote. Both match the
// canonical `ct state new tcp|udp dport 0-65535 drop` the planner writes,
// which is all the anchor ever needs to find.
//
// isCatchAllDrop reports whether a rule is a catch-all port drop in any form
// CFM has written, or nft has printed, it in: with or without `ct state new`,
// in either order, with a counter or a comment. Any copy other than the
// canonical pair is deleted: left above the re-added accepts, one would drop
// every new connection. A drop that narrows it (a source, an interface) is
// not one, and is never touched.
func isCatchAllDrop(key string) bool {
	return catchAllDrops[stripCounterComment(key)]
}

var catchAllDrops = map[string]bool{
	"ct state new tcp dport 0-65535 drop": true, "ct state new udp dport 0-65535 drop": true,
	"tcp dport 0-65535 ct state new drop": true, "udp dport 0-65535 ct state new drop": true,
	"tcp dport 0-65535 drop": true, "udp dport 0-65535 drop": true,
}

var (
	counterRE = regexp.MustCompile(` counter( packets \d+ bytes \d+)?`)
	commentRE = regexp.MustCompile(` comment \S.*$`)
)

func stripCounterComment(key string) string {
	key = counterRE.ReplaceAllString(key, "")
	key = commentRE.ReplaceAllString(key, "")
	return strings.Join(strings.Fields(key), " ")
}

// isStalePortsRule matches the rules only the ports policy writes whose
// content follows the config: portscan tracking (its TTL and mode) and the
// debug-port accepts. One that is not in the current policy is left from an
// earlier config (portscan turned off, another TTL or mode, a debug port
// removed) or, for a TTL of 60s or more, from the old duplicate-adding
// presence check, and is deleted.
func isStalePortsRule(key string) bool {
	if strings.Contains(key, " add @ps_pairs_") {
		return true
	}
	return debugRuleRE.MatchString(key)
}

var debugRuleRE = regexp.MustCompile(`^ct state new tcp dport \d+ ip6? saddr @(self_v4|self_v6|` + SetDebugAPIV4 + `|` + SetDebugAPIV6 + `) accept$`)

// chainSpec is the ports policy's share of one chain, in the order written.
type chainSpec struct {
	head    string   // exactly one copy, as the chain's first rule ("" = none)
	before  []string // added when missing, above the first rule taking a NEW connection
	accepts []string // owned: exactly once, above the drops
	middle  []string // added when missing, between the accepts and the drops
	drops   []string // owned: exactly once, in this order, below every other rule but `after`
	after   []string // added when missing, after the drops; may sit anywhere
	legacy  []string // older forms of the owned accepts: deleted (catch-all drops: isCatchAllDrop)
	// stale matches rules the policy owns by shape; one it no longer wants is deleted.
	stale func(key string) bool
}

func (c chainSpec) plan(family, table, chain, listing string) []string {
	rules := ParseChainRules(listing).rules
	var inserts, deletes, adds []string
	gone := map[string]bool{} // handles this batch deletes
	del := func(h string) {
		gone[h] = true
		deletes = append(deletes, fmt.Sprintf("delete rule %s %s %s handle %s", family, table, chain, h))
	}

	if c.head != "" {
		hk := ruleKey(c.head)
		atHead := len(rules) > 0 && rules[0].key == hk
		if !atHead {
			inserts = append(inserts, fmt.Sprintf("insert rule %s %s %s %s", family, table, chain, c.head))
		}
		for i, r := range rules {
			if r.key == hk && r.handle != "" && !(atHead && i == 0) {
				del(r.handle)
			}
		}
	}

	owned := map[string]bool{}
	for _, s := range append(append(append([]string{}, c.accepts...), c.drops...), c.legacy...) {
		owned[ruleKey(s)] = true
	}
	isOwned := func(key string) bool { return owned[key] || isCatchAllDrop(key) }

	// The rules added when missing: keep the first copy of each, delete the
	// rest, and delete a stale-shaped rule the policy no longer wants.
	want := map[string]bool{}
	for _, s := range append(append(append([]string{}, c.before...), c.middle...), c.after...) {
		want[ruleKey(s)] = true
	}
	has := map[string]bool{}
	for _, r := range rules {
		if r.handle == "" || isOwned(r.key) {
			continue
		}
		switch {
		case want[r.key] && !has[r.key]:
			has[r.key] = true
		case want[r.key], c.stale != nil && c.stale(r.key):
			del(r.handle)
		}
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
	// Insert positions, taken before any delete in the batch (an insert at a
	// handle the same batch then deletes is fine: nft applies the batch in
	// order).
	firstNew, firstNewIdx := "", len(rules)
	for i, r := range rules {
		if r.handle != "" && strings.Contains(" "+r.key+" ", " ct state new ") {
			firstNew, firstNewIdx = r.handle, i
			break
		}
	}

	// A `before` rule must see the packet before ANY rule that takes a NEW
	// connection (a DNAT accept included), not only before the policy's own
	// accepts. One kept below that point (the old code appended portscan
	// tracking enabled later after everything) is moved: deleted and
	// re-inserted above it, in the same batch.
	before := map[string]bool{}
	for _, s := range c.before {
		before[ruleKey(s)] = true
	}
	misplaced := map[string]bool{}
	seenBefore := map[string]bool{}
	for i, r := range rules {
		if r.handle == "" || gone[r.handle] || !before[r.key] || seenBefore[r.key] {
			continue
		}
		seenBefore[r.key] = true
		if i > firstNewIdx {
			misplaced[r.key] = true
			del(r.handle)
		}
	}
	var mb []string
	for _, s := range c.before {
		if !has[ruleKey(s)] || misplaced[ruleKey(s)] {
			mb = append(mb, s)
		}
	}
	mm, ma := missing(c.middle), missing(c.after)
	insertAt := func(h string, list []string) {
		for _, s := range list {
			inserts = append(inserts, fmt.Sprintf("insert rule %s %s %s position %s %s", family, table, chain, h, s))
		}
	}

	// Judge the order on the chain as it will be once this batch's deletes of
	// copies and stale rules have run: a stray copy below the drops is a
	// delete, not a reason to rewrite (and re-handle) every accept and drop.
	var kept []chainRule
	for _, r := range rules {
		if r.handle == "" || !gone[r.handle] {
			kept = append(kept, r)
		}
	}
	if dropHandle, ok := c.converged(kept); ok {
		// Converged implies an accept, which takes a NEW connection, so
		// firstNew is set.
		insertAt(firstNew, mb)
		insertAt(dropHandle, mm)
		adds = append(adds, c.addAll(family, table, chain, ma)...)
		return append(append(inserts, deletes...), adds...)
	}

	for _, r := range rules {
		if r.handle != "" && isOwned(r.key) {
			del(r.handle)
		}
	}
	if firstNew != "" {
		insertAt(firstNew, mb)
		mb = nil
	}
	for _, list := range [][]string{mb, c.accepts, mm, c.drops, ma} {
		adds = append(adds, c.addAll(family, table, chain, list)...)
	}
	return append(append(inserts, deletes...), adds...)
}

func (c chainSpec) addAll(family, table, chain string, list []string) []string {
	var out []string
	for _, s := range list {
		out = append(out, fmt.Sprintf("add rule %s %s %s %s", family, table, chain, s))
	}
	return out
}

// converged reports whether the owned accepts and drops are in order (and
// the handle of the first drop): each exactly once, no other form of a
// catch-all drop and no legacy accept, every `before` rule present above the
// first accept (portscan service tracking must see the packet before an
// accept ends evaluation), the drops in order, and below the first drop
// nothing but the other drops and `after` rules (so the accepts are above it).
// When it is false, the rewrite deletes the accepts and drops and re-adds them
// at the tail, which also puts them back below a misplaced `before` rule.
func (c chainSpec) converged(rules []chainRule) (string, bool) {
	exact := map[string]bool{}
	for _, s := range append(append([]string{}, c.accepts...), c.drops...) {
		exact[ruleKey(s)] = true
	}
	pos := map[string][]int{}
	for i, r := range rules {
		if exact[r.key] {
			pos[r.key] = append(pos[r.key], i)
			continue
		}
		for _, s := range c.legacy {
			if r.key == ruleKey(s) {
				return "", false
			}
		}
		if isCatchAllDrop(r.key) {
			return "", false
		}
	}
	for k := range exact {
		if len(pos[k]) != 1 {
			return "", false
		}
	}
	firstDrop := pos[ruleKey(c.drops[0])][0]
	firstAccept := firstDrop
	for _, s := range c.accepts {
		firstAccept = min(firstAccept, pos[ruleKey(s)][0])
	}
	before := map[string]bool{}
	for _, s := range c.before {
		before[ruleKey(s)] = true
	}
	for _, r := range rules[firstAccept:] {
		if before[r.key] {
			return "", false
		}
	}
	prev := firstDrop
	for _, s := range c.drops[1:] {
		i := pos[ruleKey(s)][0]
		if i < prev {
			return "", false
		}
		prev = i
	}
	tail := map[string]bool{}
	for _, s := range append(append([]string{}, c.drops...), c.after...) {
		tail[ruleKey(s)] = true
	}
	for _, r := range rules[firstDrop:] {
		if !tail[r.key] {
			return "", false
		}
	}
	return rules[firstDrop].handle, true
}

func debugPortRules(ports []int) []string {
	var out []string
	for _, port := range ports {
		out = append(out,
			fmt.Sprintf("ct state new tcp dport %d ip saddr @self_v4 accept", port),
			fmt.Sprintf("ct state new tcp dport %d ip6 saddr @self_v6 accept", port),
			fmt.Sprintf("ct state new tcp dport %d ip saddr @%s accept", port, SetDebugAPIV4),
			fmt.Sprintf("ct state new tcp dport %d ip6 saddr @%s accept", port, SetDebugAPIV6),
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
			fmt.Sprintf("tcp dport %s add @%s { ip saddr . tcp dport timeout %s }", tcpMatch, SetPSPairsV4, ttl),
			fmt.Sprintf("ip6 nexthdr tcp tcp dport %s add @%s { ip6 saddr . tcp dport timeout %s }", tcpMatch, SetPSPairsV6, ttl),
		)
	}
	if ps.TrackUDP {
		out = append(out,
			fmt.Sprintf("udp dport %s add @%s { ip saddr . udp dport timeout %s }", udpMatch, SetPSPairsUDPV4, ttl),
			fmt.Sprintf("ip6 nexthdr udp udp dport %s add @%s { ip6 saddr . udp dport timeout %s }", udpMatch, SetPSPairsUDPV6, ttl),
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

// IsNFTNoSuchObject reports whether nft's error output says the object (here,
// the chain being listed) does not exist, as opposed to any other failure (a
// timeout, a busy netlink socket), which must never read as "absent": planned
// from an empty listing, every rule would be added again.
func IsNFTNoSuchObject(stderr string) bool {
	return strings.Contains(stderr, "No such file or directory")
}

// NFTRead runs a read-only nft command and returns its stdout; an error
// carries nft's stderr text.
type NFTRead func(args ...string) (stdout string, err error)

// ApplyPortsPolicyScript reads the input and output chains and the table's
// sets, plans with PortsPolicyScript and runs the result as one nft
// transaction. A failed transaction changes nothing (the kernel rolls the
// whole batch back), so it is planned again from a fresh read and retried
// once: another writer (a DNAT re-assert, a CLI one-shot) may have moved a
// handle in between.
func ApplyPortsPolicyScript(p PortsPolicy, read NFTRead, exec func(script string) error) error {
	var errs []error
	for attempt := 0; attempt < 2; attempt++ {
		st, err := readPortsPolicyState(p, read)
		if err != nil {
			errs = append(errs, err)
			break
		}
		if err = exec(PortsPolicyScript(p, st)); err == nil {
			return nil
		}
		errs = append(errs, fmt.Errorf("transaction (attempt %d): %w", attempt+1, err))
	}
	return fmt.Errorf("ports policy: %w", errors.Join(errs...))
}

func readPortsPolicyState(p PortsPolicy, read NFTRead) (PortsPolicyState, error) {
	var st PortsPolicyState
	var err error
	if st.Input, err = read("-a", "list", "chain", p.Family, p.Table, "input"); err != nil {
		return st, fmt.Errorf("reading the input chain (EnsureBase creates it): %w", err)
	}
	if st.Output, err = read("-a", "list", "chain", p.Family, p.Table, "output"); err != nil {
		if !IsNFTNoSuchObject(err.Error()) {
			return st, fmt.Errorf("reading the output chain: %w", err)
		}
		st.Output = ""
	}
	sets, err := read("-t", "list", "sets", p.Family)
	if err != nil {
		return st, fmt.Errorf("listing the sets: %w", err)
	}
	st.Sets = SetNamesInTable(sets, p.Family, p.Table)
	return st, nil
}

// SetNamesInTable returns the names of the sets of one table in an
// `nft [-t] list sets <family>` listing (which holds every table of the family).
func SetNamesInTable(listing, family, table string) map[string]bool {
	out := map[string]bool{}
	in := false
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 3 && f[0] == "table":
			in = f[1] == family && f[2] == table
		case in && len(f) >= 2 && f[0] == "set":
			out[f[1]] = true
		}
	}
	return out
}
