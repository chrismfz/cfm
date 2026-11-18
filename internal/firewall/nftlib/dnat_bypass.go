//go:build linux

package nftlib

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"cfm/internal/firewall"
)

// Bypass rules carry a UserData tag that is DISTINCT from the dnatRuleTag
// namespace so rule parsing can tell them apart from the dport DNAT rules.
// They are still edge-owned: installEdgeDNATRules deletes and re-adds them
// (via dnatBypassIsManaged) as part of the deterministic clean rebuild, so
// they always land between the loopback accept and the dport rules. They
// are rebuilt every time PanelDNATOn / DNATOn is called.
const dnatBypassUserDataPrefix = "cfm_dnat_bypass:v1:"

// dnatBypassRuleID returns the per-entry UserData marker so we can match a
// rule back to its source entry on reconcile (for deletion / dedup).
func dnatBypassRuleID(entry firewall.DNATBypassEntry) string {
	return dnatBypassUserDataPrefix + entry.Value
}

// dnatBypassIsManaged reports whether a rule was installed by this
// module. Used by the reconciler to find existing bypass rules so they
// can be deleted as part of the edge-namespace clean rebuild in
// installEdgeDNATRules; correct ordering relative to the dport DNAT
// rules is enforced by that rebuild, not by the bypass code in
// isolation.
func dnatBypassIsManaged(userData []byte) bool {
	if len(userData) < len(dnatBypassUserDataPrefix) {
		return false
	}
	return string(userData[:len(dnatBypassUserDataPrefix)]) == dnatBypassUserDataPrefix
}

// dnatBypassShowRuleLine renders a bypass rule (by its UserData tag) as the
// nft text the exec engine's `nft list table` shows, for a status listing:
// `ip saddr 192.0.2.1 accept` / `ip6 saddr 2001:db8::/64 accept`. The tag is
// parsed by the same reader as the bypass file (firewall.ParseDNATBypassEntry),
// so the line names what was installed. ok is false for a rule that is not a
// bypass rule or whose tag does not hold an address.
func dnatBypassShowRuleLine(userData []byte) (string, bool) {
	if !dnatBypassIsManaged(userData) {
		return "", false
	}
	e, err := firewall.ParseDNATBypassEntry(string(userData[len(dnatBypassUserDataPrefix):]))
	if err != nil {
		return "", false
	}
	return firewall.DNATBypassMatcher(e) + " " + e.Value + " accept", true
}

// dnatBypassShowLines renders every bypass rule of a chain, in chain order,
// for the web and panel status listings alike.
func dnatBypassShowLines(rules []*nftables.Rule) []string {
	var out []string
	for _, r := range rules {
		if line, ok := dnatBypassShowRuleLine(r.UserData); ok {
			out = append(out, line)
		}
	}
	return out
}

// dnatBypassRuleExprs builds the netlink expression list for one bypass
// entry. The shape is the equivalent of:
//
//	meta nfproto ipv4 ip saddr 84.54.49.205 accept           (single v4 IP)
//	meta nfproto ipv4 ip saddr 84.54.49.0/24 accept          (v4 CIDR)
//	meta nfproto ipv6 ip6 saddr 2001:db8::1 accept           (single v6 IP)
//	meta nfproto ipv6 ip6 saddr 2001:db8::/64 accept         (v6 CIDR)
//
// The leading NFPROTO check is required because the inet-family chain
// receives BOTH IPv4 and IPv6 packets and the network-header offsets
// differ; without the NFPROTO guard, reading source-IP bytes from an
// IPv6 packet at an IPv4 offset would yield garbage. NFPROTO short-
// circuits before the payload read happens.
func dnatBypassRuleExprs(entry firewall.DNATBypassEntry) ([]expr.Any, error) {
	if entry.Value == "" {
		return nil, fmt.Errorf("empty bypass entry")
	}
	var (
		netAddr    net.IP
		mask       net.IPMask
		isV6       = entry.IsV6
		saddrOff   uint32
		saddrLen   uint32
		nfproto    byte
		networkLen int
	)
	if entry.IsCIDR {
		_, n, err := net.ParseCIDR(entry.Value)
		if err != nil {
			return nil, fmt.Errorf("parse CIDR %q: %w", entry.Value, err)
		}
		netAddr = n.IP
		mask = n.Mask
	} else {
		ip := net.ParseIP(entry.Value)
		if ip == nil {
			return nil, fmt.Errorf("parse IP %q", entry.Value)
		}
		netAddr = ip
	}

	if isV6 {
		saddrOff, saddrLen = 8, 16
		nfproto = 10 // NFPROTO_IPV6
		networkLen = 16
		netAddr = netAddr.To16()
	} else {
		saddrOff, saddrLen = 12, 4
		nfproto = 2 // NFPROTO_IPV4
		networkLen = 4
		netAddr = netAddr.To4()
	}
	if netAddr == nil {
		return nil, fmt.Errorf("address-family mismatch for %q", entry.Value)
	}

	exprs := []expr.Any{
		// meta load nfproto => reg 1
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		// cmp eq reg 1 <nfproto>
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		// payload load <saddrLen>b @ network header + <saddrOff> => reg 1
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: saddrOff, Len: saddrLen},
	}

	if entry.IsCIDR {
		// AND the source-IP register with the network mask, then compare
		// to the network address. This is the standard nftables shape for
		// "ip saddr X/N" matches: `bitwise reg1 = (reg1 & mask) ^ 0`.
		xor := make([]byte, networkLen)
		exprs = append(exprs,
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            uint32(networkLen),
				Mask:           []byte(mask),
				Xor:            xor,
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: netAddr},
		)
	} else {
		exprs = append(exprs,
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: netAddr},
		)
	}

	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	return exprs, nil
}

// dnatBypassAddRules emits AddRule calls for every bypass entry in the
// given scope's file. Returns the number of rules added and any per-entry
// parse errors (the caller surfaces these as log warnings so an operator
// notices a malformed entry without aborting the whole DNAT install).
//
// Caller MUST hold b.mu and is responsible for calling Flush() afterwards.
func (b *Backend) dnatBypassAddRules(t *nftables.Table, ch *nftables.Chain, scope firewall.DNATBypassScope) (added int, warnings []string) {
	entries, skipped, err := firewall.LoadDNATBypass(scope.Path())
	if err != nil {
		return 0, []string{fmt.Sprintf("read %s: %v", scope.Path(), err)}
	}
	warnings = append(warnings, skipped...)
	for _, e := range entries {
		exprs, err := dnatBypassRuleExprs(e)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", e.Value, err))
			continue
		}
		b.conn.AddRule(&nftables.Rule{
			Table:    t,
			Chain:    ch,
			UserData: []byte(dnatBypassRuleID(e)),
			Exprs:    exprs,
		})
		added++
	}
	return added, warnings
}

