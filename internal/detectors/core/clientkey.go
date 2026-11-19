package core

import (
	"net/netip"
	"strings"

	"cfm/internal/firewall"
)

// ClientKey is the counter key of a per-client kind ("…|ip"): an IPv6
// client counts as its /64 (firewall.CountKey; docs/edge-ipv6.md "IPv6 /64
// grouping"), so a client rotating its address inside the /64 fills one
// window instead of a fresh one per address; a /64 a guard keeps from being
// banned as a whole counts per address, as its ban is. Any other kind keeps
// key.
//
// Only the COUNT is grouped: the alert still carries a real address
// (Extra["ip"]), which the sink's allow / ignore / self checks read and
// which firewall.ExtendClientBlock widens to the /64 itself.
func ClientKey(kindKey, key string) string {
	if strings.HasSuffix(kindKey, "|ip") {
		return firewall.CountKey(key)
	}
	return key
}

// TagClient records the /64 an IPv6 address was counted as (Extra
// "client"), for the alert's reader; IPv4, ungrouped and guarded addresses
// add nothing.
func TagClient(extra map[string]string, ip string) {
	if c := firewall.CountKey(ip); strings.Contains(c, "/") && extra != nil {
		extra["client"] = c
	}
}

// GuardAllows registers a detector's own allow list (ALLOW_IPS /
// ALLOW_NETS: addresses or CIDRs) as a /64 guard under "allow:"+name: a /64
// that holds an allowed IPv6 address is then counted and banned per address
// (firewall.SetClientNetExempt), as a /64 holding an nft-allowed one is, so
// its neighbours' hits can never ban the allowed address with their /64.
// Called on every (re)build of the detector; an empty list removes it.
func GuardAllows(name string, entries ...[]string) {
	var nets []netip.Prefix
	for _, list := range entries {
		for _, e := range list {
			e = strings.TrimSpace(e)
			if p, err := netip.ParsePrefix(e); err == nil {
				if p.Addr().Unmap().Is6() && !p.Addr().Is4In6() {
					nets = append(nets, p.Masked())
				}
			} else if a, err := netip.ParseAddr(e); err == nil && a.Is6() && !a.Is4In6() {
				nets = append(nets, netip.PrefixFrom(a, 128))
			}
		}
	}
	if len(nets) == 0 {
		firewall.SetClientNetExempt("allow:"+name, nil)
		return
	}
	firewall.SetClientNetExempt("allow:"+name, func(p netip.Prefix) bool {
		for _, n := range nets {
			if n.Overlaps(p) {
				return true
			}
		}
		return false
	})
}
