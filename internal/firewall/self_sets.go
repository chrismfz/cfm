package firewall

import (
	"net"
	"net/netip"
	"sort"
	"strings"

	"cfm/internal/firewall/feedutil"
)

// SelfSetElems is what self_v4/self_v6 hold, for both engines: loopback,
// link-local and each local address, as CIDRs with overlaps merged. The sets
// are interval sets, which refuse overlapping elements (a local link-local
// address lies inside fe80::/10), and both engines write each set in ONE
// transaction, which one refused element would fail whole.
func SelfSetElems(local []string) (v4, v6 []string) {
	v4 = []string{"127.0.0.0/8"}
	v6 = []string{"::1/128", "fe80::/10"}
	for _, s := range local {
		ip := net.ParseIP(s)
		switch {
		case ip == nil:
		case ip.To4() != nil:
			v4 = append(v4, ip.To4().String()+"/32")
		default:
			v6 = append(v6, ip.String()+"/128")
		}
	}
	return feedutil.NormalizeCIDRsV4(v4), feedutil.NormalizeCIDRsV6(v6)
}

// SameSetElems reports whether two element lists name the same addresses and
// prefixes, however each is spelled: nft prints a /32 element of an interval
// set as a bare address, and its own order. An element that does not parse
// (a range "a-b", junk) never matches, so the caller rewrites the set: an
// unreadable content must never read as "already right".
func SameSetElems(have, want []string) bool {
	a, okA := canonPrefixes(have)
	b, okB := canonPrefixes(want)
	if !okA || !okB || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func canonPrefixes(in []string) ([]string, bool) {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		var p netip.Prefix
		if strings.Contains(s, "/") {
			pp, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, false
			}
			p = pp.Masked()
		} else {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, false
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		k := p.String()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Strings(out)
	return out, true
}
