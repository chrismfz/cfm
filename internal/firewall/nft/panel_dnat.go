//go:build linux

package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"cfm/internal/firewall"
)

const (
	panelDNATFamily          = "inet"
	panelDNATTable           = "cfm_panel_redirect"
	panelDNATAcceptNamespace = "cfm_cpanel_dnat"
)

func panelDNATScript(priority int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table %s %s\n", panelDNATFamily, panelDNATTable)
	fmt.Fprintf(&b, "add chain %s %s prerouting { type nat hook prerouting priority %d; policy accept; }\n", panelDNATFamily, panelDNATTable, priority)
	b.WriteString("add rule inet cfm_panel_redirect prerouting iif \"lo\" accept\n")
	for _, m := range firewall.PanelDNATMappings() {
		fmt.Fprintf(&b, "add rule inet cfm_panel_redirect prerouting tcp dport %d dnat to :%d\n", m.From, m.To)
	}
	return b.String()
}

func (b *Backend) PanelDNATOn(priority int) error {
	_ = b.nftCmd("delete table inet cfm_panel_redirect")
	return b.nftExpr(panelDNATScript(priority))
}

func (b *Backend) PanelDNATOff() error {
	_ = b.nftCmd("delete table inet cfm_panel_redirect")
	return nil
}

func (b *Backend) PanelDNATStatus() (bool, string, error) {
	out, err := b.nftOut("list table inet cfm_panel_redirect")
	if err != nil {
		msg := err.Error() + out
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") {
			return false, "", nil
		}
		return false, out, err
	}
	if strings.TrimSpace(out) == "" {
		return false, "", nil
	}
	return true, out, nil
}

func panelDNATAcceptComment(from, to int) string {
	return fmt.Sprintf("%s:%d:%d", panelDNATAcceptNamespace, from, to)
}

func panelDNATAcceptKey(from, to int) string { return fmt.Sprintf("%d:%d", from, to) }

func panelManagedRulePlacement(out, key string) (handle string, beforeDefaultDrop bool, ok bool) {
	seenDefaultDrop := false
	for _, line := range strings.Split(out, "\n") {
		if isInputDefaultDropLine(line) {
			seenDefaultDrop = true
		}
		port, h, managed := parsePanelManagedRuleLine(line)
		if managed && port == key {
			return h, !seenDefaultDrop, true
		}
	}
	return "", false, false
}

func isInputDefaultDropLine(line string) bool {
	norm := strings.ReplaceAll(line, `"`, "")
	if !strings.Contains(norm, "ct state new") || !strings.Contains(norm, "dport 0-65535") || !strings.Contains(norm, " drop") {
		return false
	}
	return strings.Contains(norm, "tcp dport 0-65535") || strings.Contains(norm, "udp dport 0-65535")
}

func panelDNATAcceptRuleExpr(from, to int, beforeHandle string) string {
	prefix := "add rule inet cfm input"
	if strings.TrimSpace(beforeHandle) != "" {
		prefix = "insert rule inet cfm input position " + strings.TrimSpace(beforeHandle)
	}
	return strings.Join(strings.Fields(fmt.Sprintf(`%s tcp dport %d ct state new ct status dnat ct original proto-dst %d accept comment "%s"`, prefix, to, from, panelDNATAcceptComment(from, to))), " ")
}

func (b *Backend) EnsurePanelDNATAccepts() ([]string, error) {
	_ = b.nftExpr("add table inet cfm")
	_ = b.nftCmd("add chain inet cfm input { type filter hook input priority 0; policy accept; }")
	out, _ := b.nftOut("-a list chain inet cfm input")
	beforeHandle := firstInputDefaultDropHandle(out)
	changes := []string{}
	for _, m := range firewall.PanelDNATMappings() {
		key := panelDNATAcceptKey(m.From, m.To)
		if handle, beforeDrop, ok := panelManagedRulePlacement(out, key); ok {
			if beforeDrop {
				continue
			}
			if handle != "" {
				if err := b.nftCmd("delete rule inet cfm input handle " + handle); err != nil {
					return changes, err
				}
			}
		}
		if err := b.nftCmd(panelDNATAcceptRuleExpr(m.From, m.To, beforeHandle)); err != nil {
			return changes, err
		}
		changes = append(changes, fmt.Sprintf("opened scoped %d->%d (nft cfm/input)", m.From, m.To))
	}
	return changes, nil
}

func (b *Backend) RemovePanelDNATAccepts() ([]string, error) {
	out, err := b.nftOut("-a list chain inet cfm input")
	if err != nil {
		return nil, nil
	}
	changes := []string{}
	handles := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		port, h, ok := parsePanelManagedRuleLine(line)
		if ok {
			handles[port] = h
		}
	}
	for _, m := range firewall.PanelDNATMappings() {
		key := panelDNATAcceptKey(m.From, m.To)
		h, ok := handles[key]
		if !ok {
			changes = append(changes, fmt.Sprintf("scoped %d->%d not found", m.From, m.To))
			continue
		}
		if err := b.nftCmd("delete rule inet cfm input handle " + h); err != nil {
			changes = append(changes, fmt.Sprintf("scoped %d->%d failed (%v)", m.From, m.To, err))
			continue
		}
		changes = append(changes, fmt.Sprintf("scoped %d->%d removed", m.From, m.To))
	}
	sort.Strings(changes)
	return changes, nil
}

func (b *Backend) PanelDNATAcceptState() map[int]string {
	state := map[int]string{}
	for _, m := range firewall.PanelDNATMappings() {
		state[m.To] = "unknown"
	}
	out, err := b.nftOut("-a list chain inet cfm input")
	if err != nil {
		return state
	}
	for _, m := range firewall.PanelDNATMappings() {
		if strings.Contains(out, fmt.Sprintf("tcp dport %d", m.To)) && strings.Contains(out, panelDNATAcceptComment(m.From, m.To)) && strings.Contains(out, "ct status dnat") {
			state[m.To] = "open"
		} else if out != "" {
			state[m.To] = "blocked"
		}
	}
	return state
}

func parsePanelManagedRuleLine(line string) (string, string, bool) {
	norm := strings.ReplaceAll(line, `"`, "")
	if !strings.Contains(norm, panelDNATAcceptNamespace+":") || !strings.Contains(norm, " handle ") {
		return "", "", false
	}
	h := strings.TrimSpace(norm[strings.LastIndex(norm, " handle ")+8:])
	if fields := strings.Fields(h); len(fields) > 0 {
		h = fields[0]
	}
	parts := strings.Fields(norm)
	for _, part := range parts {
		if strings.HasPrefix(part, panelDNATAcceptNamespace+":") {
			comment := strings.TrimPrefix(part, panelDNATAcceptNamespace+":")
			cparts := strings.Split(comment, ":")
			if len(cparts) >= 2 {
				return cparts[0] + ":" + cparts[1], h, true
			}
		}
	}
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "dport" {
			return parts[i+1], h, true
		}
	}
	return strconv.Itoa(0), h, true
}
