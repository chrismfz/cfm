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

// EnsureInputAccepts makes `inet cfm input` hold exactly the rules in want
// (rule bodies, written as for `add rule inet cfm input <body>`), each once
// and above the ports policy's default drop, among the rules managed reports
// as its own. It is the web DNAT accepts' counterpart of
// EnsurePanelDNATAccepts, with the same guarantee: a wanted rule already in
// place is KEPT, untouched. Otherwise it is inserted before the default drop
// (appended when the chain has none), and only after that are the managed
// rules nobody wants (misplaced below the drop, duplicated, other ports, the
// other engine's tag) deleted. Inserts and deletes are one nft batch, so the
// kernel applies them all-or-nothing: an accept that was working stays in
// force until its replacement exists.
//
// It replaces a delete-everything-then-insert-one-by-one that ran on every
// daemon reload (EnsureDNATAccepts after ApplyPortsPolicy): between the first
// delete and the last insert, every new connection DNAT'd to the edge
// listener (80/443 -> 9080/9043, not in TCP_IN) hit the default drop, for as
// long as a few nft runs take on a node with large sets.
//
// A rule is matched on its printed text (ruleKey), so a wanted rule nft
// prints in another order reads as missing: it is inserted again and the old
// copy deleted in the same batch, every apply. That churns but never leaves a
// gap.
func EnsureInputAccepts(ops NFTTextOps, want []string, managed func(line string) bool) ([]string, error) {
	_ = ops.Run("add table inet cfm")
	_ = ops.Run("add chain inet cfm input { type filter hook input priority 0; policy accept; }")
	// Fail closed on a listing error: without the default-drop handle the
	// accepts would be appended after the drop, where nothing reaches them,
	// and without the handles the stale ones could not be found.
	out, err := ops.ListInput()
	if err != nil {
		return nil, fmt.Errorf("list inet cfm input chain for accepts: %w", err)
	}
	beforeHandle := FirstInputDefaultDropHandle(out)

	type rule struct {
		key, handle string
		beforeDrop  bool
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
		rules = append(rules, rule{key: ruleKey(text), handle: h, beforeDrop: !seenDrop})
	}

	var script, changes []string
	kept := map[string]bool{}
	seen := map[string]bool{}
	for _, w := range want {
		k := ruleKey(w)
		if seen[k] {
			continue
		}
		seen[k] = true
		found := false
		for _, r := range rules {
			if !kept[r.handle] && r.beforeDrop && r.key == k {
				kept[r.handle], found = true, true
				break
			}
		}
		if found {
			continue
		}
		if beforeHandle != "" {
			script = append(script, "insert rule inet cfm input position "+beforeHandle+" "+w)
		} else {
			script = append(script, "add rule inet cfm input "+w)
		}
		changes = append(changes, "added: "+w)
	}
	for _, r := range rules {
		if !kept[r.handle] {
			script = append(script, "delete rule inet cfm input handle "+r.handle)
			changes = append(changes, "removed handle "+r.handle)
		}
	}
	if len(script) == 0 {
		return nil, nil
	}
	if err := ops.Run(strings.Join(script, "\n")); err != nil {
		return nil, fmt.Errorf("update inet cfm input accepts: %w", err)
	}
	return changes, nil
}
