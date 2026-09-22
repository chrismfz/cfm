package firewall

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Scoped cPanel DNAT accepts in inet cfm/input: one implementation for both
// backends.
//
// The panel redirect (cfm_panel_redirect: 2083 → 12083, …) only works if the
// input chain accepts the redirected connection on its listener port. CFM adds
// one rule per mapping, placed before the ports policy's default drop:
//
//	tcp dport 12083 ct state new ct status dnat ct original proto-dst 2083 accept comment "cfm_cpanel_dnat:2083:12083"
//
// Both backends manage these rules as nft text: list the chain with handles,
// then insert or delete by handle. The nftlib backend used to write and read
// them over netlink, which failed in two ways:
//
//   - google/nftables v0.3.0 can't read a chain that holds any `ct original|reply
//     …` match. It encodes the conntrack direction as 4 bytes, the kernel dumps
//     it as 1, and the decoder fails the whole dump ("attribute 3 is not a
//     uint32"). These accepts are such rules, so once they existed nftlib could
//     no longer read inet cfm/input: every later ensure or remove failed, and
//     the accept state read "unknown".
//   - Its rules carried a raw user-data tag, which nft does not show as a
//     comment, so the nft backend and `cfm dnat cpanel status` found no managed
//     accept and reported the ports "blocked".
//
// Those older rules have no comment. parsePanelAcceptLine recognises them by
// their exact shape (legacy), so ensure replaces them with tagged rules and
// remove deletes them.

// PanelDNATAcceptNamespace prefixes the comment of every managed panel accept.
const PanelDNATAcceptNamespace = "cfm_cpanel_dnat"

// NFTTextOps is what the shared accept code needs from a backend.
type NFTTextOps struct {
	// ListInput returns `nft -a list chain inet cfm input` (with handles).
	ListInput func() (string, error)
	// Run runs one nft command in script syntax.
	Run func(cmd string) error
}

// PanelDNATAcceptComment is the comment tagging the accept for one mapping.
func PanelDNATAcceptComment(from, to int) string {
	return fmt.Sprintf("%s:%d:%d", PanelDNATAcceptNamespace, from, to)
}

func panelDNATAcceptKey(from, to int) string { return fmt.Sprintf("%d:%d", from, to) }

// PanelDNATAcceptRule is the nft command that installs the accept for one
// mapping: inserted before beforeHandle (the default drop), or appended when
// the chain has no default drop.
func PanelDNATAcceptRule(from, to int, beforeHandle string) string {
	prefix := "add rule inet cfm input"
	if strings.TrimSpace(beforeHandle) != "" {
		prefix = "insert rule inet cfm input position " + strings.TrimSpace(beforeHandle)
	}
	return strings.Join(strings.Fields(fmt.Sprintf(`%s tcp dport %d ct state new ct status dnat ct original proto-dst %d accept comment "%s"`, prefix, to, from, PanelDNATAcceptComment(from, to))), " ")
}

// FirstInputDefaultDropHandle returns the handle of the first default-drop
// rule in an `nft -a list chain inet cfm input` listing, or "" if there is
// none. Scoped DNAT accepts are inserted before it.
func FirstInputDefaultDropHandle(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if !IsInputDefaultDropLine(line) {
			continue
		}
		if h := ruleHandle(line); h != "" {
			return h
		}
	}
	return ""
}

// ruleHandle returns the handle of one `nft -a` listing line, or "".
func ruleHandle(line string) string {
	norm := strings.ReplaceAll(line, `"`, "")
	i := strings.LastIndex(norm, " handle ")
	if i < 0 {
		return ""
	}
	if fields := strings.Fields(norm[i+len(" handle "):]); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// panelAcceptRule is one panel accept found in the input chain.
type panelAcceptRule struct {
	key        string // "from:to"
	handle     string
	legacy     bool // untagged rule from the nftlib backend's old netlink writer
	beforeDrop bool // placed before the default drop, i.e. effective
}

// panelAcceptRules returns every tagged and legacy panel accept in chain order.
func panelAcceptRules(out string) []panelAcceptRule {
	var rules []panelAcceptRule
	seenDrop := false
	for _, line := range strings.Split(out, "\n") {
		if IsInputDefaultDropLine(line) {
			seenDrop = true
			continue
		}
		if r, ok := parsePanelAcceptLine(line); ok {
			r.beforeDrop = !seenDrop
			rules = append(rules, r)
		}
	}
	return rules
}

// parsePanelAcceptLine recognises a panel accept in one listing line: a
// tagged rule by its comment, or a legacy rule by its exact shape,
//
//	ct state new ct status dnat ct original proto-dst 2083 tcp dport 12083 accept
//
// Older nft releases render the original port as hex followed by "[invalid
// type]" (`… proto-dst 0x823 [invalid type] tcp dport 12083 …`), and some
// show the l4proto dependency (`meta l4proto tcp`); both are accepted. A
// legacy match is never looser than that shape, so a rule with any other
// match or a comment is left alone.
func parsePanelAcceptLine(line string) (panelAcceptRule, bool) {
	handle := ruleHandle(line)
	if handle == "" {
		return panelAcceptRule{}, false
	}
	norm := strings.ReplaceAll(line, `"`, "")
	if i := strings.Index(norm, "#"); i >= 0 {
		norm = norm[:i]
	}
	fields := strings.Fields(norm)
	for _, f := range fields {
		if rest, ok := strings.CutPrefix(f, PanelDNATAcceptNamespace+":"); ok {
			if parts := strings.Split(rest, ":"); len(parts) >= 2 {
				return panelAcceptRule{key: parts[0] + ":" + parts[1], handle: handle}, true
			}
		}
	}
	from, to, ok := parseLegacyPanelAccept(fields)
	if !ok {
		return panelAcceptRule{}, false
	}
	return panelAcceptRule{key: panelDNATAcceptKey(from, to), handle: handle, legacy: true}, true
}

func parseLegacyPanelAccept(fields []string) (from, to int, ok bool) {
	prefix := []string{"ct", "state", "new", "ct", "status", "dnat", "ct", "original", "proto-dst"}
	if len(fields) < len(prefix)+5 { // port, tcp, dport, port, accept
		return 0, 0, false
	}
	for i, w := range prefix {
		if fields[i] != w {
			return 0, 0, false
		}
	}
	rest := fields[len(prefix):]
	n := len(rest)
	if rest[n-1] != "accept" || rest[n-3] != "dport" || rest[n-4] != "tcp" {
		return 0, 0, false
	}
	f, err := strconv.ParseUint(rest[0], 0, 16) // "2083" or "0x823"
	if err != nil {
		return 0, 0, false
	}
	t, err := strconv.ParseUint(rest[n-2], 10, 16)
	if err != nil {
		return 0, 0, false
	}
	for _, w := range rest[1 : n-4] {
		switch w {
		case "[invalid", "type]", "meta", "l4proto", "tcp", "6":
		default:
			return 0, 0, false
		}
	}
	return int(f), int(t), true
}

// EnsurePanelDNATAccepts makes each panel mapping have exactly one tagged
// accept before the default drop. A tagged accept already in place is kept.
// Otherwise a new one is inserted first, and only then are the others for
// that mapping (misplaced, duplicate or legacy) deleted, so an accept that
// was working stays in force until its replacement exists.
func EnsurePanelDNATAccepts(ops NFTTextOps) ([]string, error) {
	_ = ops.Run("add table inet cfm")
	_ = ops.Run("add chain inet cfm input { type filter hook input priority 0; policy accept; }")
	// Fail closed on a listing error: without the default-drop handle the
	// accepts would be appended after the drop, where nothing reaches them.
	out, err := ops.ListInput()
	if err != nil {
		return nil, fmt.Errorf("list inet cfm input chain for panel dnat accepts: %w", err)
	}
	beforeHandle := FirstInputDefaultDropHandle(out)
	rules := panelAcceptRules(out)
	changes := []string{}
	for _, m := range PanelDNATMappings() {
		key := panelDNATAcceptKey(m.From, m.To)
		keep := false
		legacy := false
		var stale []string
		for _, r := range rules {
			if r.key != key {
				continue
			}
			if !keep && !r.legacy && r.beforeDrop {
				keep = true
				continue
			}
			legacy = legacy || r.legacy
			stale = append(stale, r.handle)
		}
		if !keep {
			if err := ops.Run(PanelDNATAcceptRule(m.From, m.To, beforeHandle)); err != nil {
				return changes, err
			}
		}
		for _, h := range stale {
			if err := ops.Run("delete rule inet cfm input handle " + h); err != nil {
				return changes, err
			}
		}
		switch {
		case !keep && legacy:
			changes = append(changes, fmt.Sprintf("re-created scoped %d->%d with its %s comment (nft cfm/input)", m.From, m.To, PanelDNATAcceptNamespace))
		case !keep:
			changes = append(changes, fmt.Sprintf("opened scoped %d->%d (nft cfm/input)", m.From, m.To))
		case len(stale) > 0:
			changes = append(changes, fmt.Sprintf("removed %d extra scoped %d->%d (nft cfm/input)", len(stale), m.From, m.To))
		}
	}
	return changes, nil
}

// RemovePanelDNATAccepts deletes every tagged and legacy panel accept. As on
// the nft backend it replaces, a chain that can't be listed is reported as
// nothing to remove, and a failed delete is reported in the changes rather
// than as an error.
func RemovePanelDNATAccepts(ops NFTTextOps) ([]string, error) {
	out, err := ops.ListInput()
	if err != nil {
		return nil, nil
	}
	handles := map[string][]string{}
	for _, r := range panelAcceptRules(out) {
		handles[r.key] = append(handles[r.key], r.handle)
	}
	changes := []string{}
	for _, m := range PanelDNATMappings() {
		hs := handles[panelDNATAcceptKey(m.From, m.To)]
		if len(hs) == 0 {
			changes = append(changes, fmt.Sprintf("scoped %d->%d not found", m.From, m.To))
			continue
		}
		var failed error
		for _, h := range hs {
			if err := ops.Run("delete rule inet cfm input handle " + h); err != nil && failed == nil {
				failed = err
			}
		}
		if failed != nil {
			changes = append(changes, fmt.Sprintf("scoped %d->%d failed (%v)", m.From, m.To, failed))
			continue
		}
		changes = append(changes, fmt.Sprintf("scoped %d->%d removed", m.From, m.To))
	}
	sort.Strings(changes)
	return changes, nil
}

// PanelDNATAcceptState reports each panel listener port as "open" (an accept
// sits before the default drop), "blocked" (the chain lists, but no accept is
// in force) or "unknown" (the chain can't be listed). A legacy accept counts:
// it admits the traffic just the same.
func PanelDNATAcceptState(ops NFTTextOps) map[int]string {
	state := map[int]string{}
	for _, m := range PanelDNATMappings() {
		state[m.To] = "unknown"
	}
	out, err := ops.ListInput()
	if err != nil {
		return state
	}
	rules := panelAcceptRules(out)
	for _, m := range PanelDNATMappings() {
		key := panelDNATAcceptKey(m.From, m.To)
		found, open := false, false
		for _, r := range rules {
			if r.key == key {
				found = true
				open = open || r.beforeDrop
			}
		}
		switch {
		case open:
			state[m.To] = "open"
		case found || out != "":
			state[m.To] = "blocked"
		}
	}
	return state
}
