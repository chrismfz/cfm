package firewall

import (
	"fmt"
	"strings"
)

// IsWebDNATAccept reports whether a rendered `inet cfm input` line is a web
// DNAT accept written by either engine (WebDNATAcceptTagNFT /
// WebDNATAcceptTagNFTLib comment tag).
func IsWebDNATAccept(line string) bool {
	norm := strings.ReplaceAll(line, `"`, "")
	return strings.Contains(norm, WebDNATAcceptTagNFT+":") || strings.Contains(norm, WebDNATAcceptTagNFTLib+":")
}

// EnsureInputAccepts makes `inet cfm input` hold the rules in want (rule
// bodies, written as for `add rule inet cfm input <body>`), each once and
// above the ports policy's default drop, among the rules managed reports as
// its own. It is the web DNAT accepts' counterpart of EnsurePanelDNATAccepts,
// with the same guarantee: a wanted rule already in place is KEPT, untouched.
// A missing one is inserted before the default drop (appended when the chain
// has none), all inserts in one nft batch, and only after that, when prune is
// set, are the managed rules nobody wants (misplaced below the drop,
// duplicated, other ports, the other engine's tag) deleted, best effort: an
// accept that was working stays in force until its replacement exists, and a
// delete that fails (another process removed that handle first) never undoes
// an insert. Pass prune=false while the redirect still points at the rules'
// old target (DNATOn before it moves the redirect), then call again with
// prune=true.
//
// It replaces a delete-everything-then-insert-one-by-one that ran on every
// daemon reload (EnsureDNATAccepts after ApplyPortsPolicy): between the first
// delete and the last insert, every new connection DNAT'd to the edge
// listener (80/443 -> 9080/9043, not in TCP_IN) hit the default drop, for as
// long as a few nft runs take on a node with large sets.
//
// A rule is identified by its comment tag (and a `daddr`, if it has one), not
// its whole printed text: older nft releases print `ct original proto-dst` as
// hex with "[invalid type]" (see parsePanelAcceptLine), and a text match
// would then replace every accept on every reload.
func EnsureInputAccepts(ops NFTTextOps, want []string, managed func(line string) bool, prune bool) ([]string, error) {
	// Fail closed on a listing error: without the default-drop handle the
	// accepts would be appended after the drop, where nothing reaches them,
	// and without the handles the stale ones could not be found. A missing
	// chain is declared and read again (EnsureBase normally made it).
	out, err := ops.ListInput()
	if err != nil {
		_ = ops.Run("add table inet cfm")
		_ = ops.Run("add chain inet cfm input { type filter hook input priority 0; policy accept; }")
		if out, err = ops.ListInput(); err != nil {
			return nil, fmt.Errorf("list inet cfm input chain for accepts: %w", err)
		}
	}
	beforeHandle := FirstInputDefaultDropHandle(out)

	type rule struct {
		id, handle string
		beforeDrop bool
	}
	var rules []rule
	seenDrop := false
	for _, line := range strings.Split(out, "\n") {
		if IsInputDefaultDropLine(line) {
			seenDrop = true
			continue
		}
		h := ruleHandle(line)
		if h == "" || !managed(line) {
			continue
		}
		text := line
		if i := strings.LastIndex(text, "# handle "); i >= 0 {
			text = text[:i]
		}
		rules = append(rules, rule{id: acceptIdentity(text), handle: h, beforeDrop: !seenDrop})
	}

	var inserts, changes []string
	kept := map[string]bool{}
	seen := map[string]bool{}
	for _, w := range want {
		id := acceptIdentity(w)
		if seen[id] {
			continue
		}
		seen[id] = true
		found := false
		for _, r := range rules {
			if !kept[r.handle] && r.beforeDrop && r.id == id {
				kept[r.handle], found = true, true
				break
			}
		}
		if found {
			continue
		}
		if beforeHandle != "" {
			inserts = append(inserts, "insert rule inet cfm input position "+beforeHandle+" "+w)
		} else {
			inserts = append(inserts, "add rule inet cfm input "+w)
		}
		changes = append(changes, "added: "+w)
	}
	if len(inserts) > 0 {
		if err := ops.Run(strings.Join(inserts, "\n")); err != nil {
			return nil, fmt.Errorf("insert inet cfm input accepts: %w", err)
		}
	}
	if !prune {
		return changes, nil
	}
	var stale []string
	for _, r := range rules {
		if !kept[r.handle] {
			stale = append(stale, r.handle)
		}
	}
	if len(stale) == 0 {
		return changes, nil
	}
	// One batch when it goes through; one by one otherwise, so a handle
	// another process already deleted doesn't keep the rest.
	batch := make([]string, len(stale))
	for i, h := range stale {
		batch[i] = "delete rule inet cfm input handle " + h
	}
	if ops.Run(strings.Join(batch, "\n")) == nil {
		for _, h := range stale {
			changes = append(changes, "removed handle "+h)
		}
		return changes, nil
	}
	for i, h := range stale {
		if err := ops.Run(batch[i]); err != nil {
			changes = append(changes, fmt.Sprintf("could not remove handle %s: %v", h, err))
			continue
		}
		changes = append(changes, "removed handle "+h)
	}
	return changes, nil
}

// acceptIdentity is what makes an accept the same rule across nft versions:
// its comment tag, plus a `daddr <addr>` match if it has one. A rule with no
// comment falls back to its printed text.
func acceptIdentity(text string) string {
	f := strings.Fields(strings.ReplaceAll(text, `"`, ""))
	comment, daddr := "", ""
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "comment":
			comment = f[i+1]
		case "daddr":
			daddr = f[i+1]
		}
	}
	if comment == "" {
		return ruleKey(text)
	}
	return comment + " " + daddr
}

// RuleHandle returns the handle of one `nft -a` listing line, or "".
func RuleHandle(line string) string { return ruleHandle(line) }
