// Package ipkey is the key a per-client control counts and bans on
// (docs/edge-ipv6.md "IPv6 /64 grouping"). configs/lua/cfm_ipkey.lua is its
// edge twin; both run scripts/tests/fixtures/ipkey.txt, so the edge and the
// daemon can never key one client differently.
//
// An IPv6 client is its /64: any VPS or ISP line hands its customer a /64, and
// a client rotating its address inside it would otherwise get a fresh identity
// (counters, rate limits, bans) per address. IPv4 is the address itself; a
// v4-mapped address is IPv4. Loopback, link-local (a /64 there is every
// neighbour on the link), a zoned address and anything unparsable are left
// as they are.
//
// Never key an ALLOW or an exact match on this (an allow widened to a /64
// would allow a whole customer prefix), nor a clearance cookie, nor a log
// line: those stay the full address.
package ipkey

import "net/netip"

// V6Bits is the IPv6 client prefix. One constant: no per-node switch.
const V6Bits = 64

// Client returns the key for the client address s: "2001:db8:1:2::/64" for an
// IPv6 address (netip.Prefix text, RFC 5952), the address for IPv4 (a
// v4-mapped one unmapped), and s unchanged for loopback, link-local, a zoned
// address or anything netip cannot parse.
func Client(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return s
	}
	p, grouped := Prefix(a)
	if !grouped {
		if a.Is4In6() || a.Is4() {
			return a.Unmap().String()
		}
		return s
	}
	return p.String()
}

// Prefix returns the client prefix of a and whether it groups more than one
// address: a /64 for a global IPv6 address (true); a /32 for IPv4 or
// v4-mapped, unmapped (false); a /128 for loopback, link-local or a zoned
// address (false).
func Prefix(a netip.Addr) (netip.Prefix, bool) {
	a = a.Unmap()
	if a.Is4() {
		return netip.PrefixFrom(a, 32), false
	}
	if a.Zone() != "" || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return netip.PrefixFrom(a, 128), false
	}
	p, err := a.Prefix(V6Bits)
	if err != nil {
		return netip.PrefixFrom(a, 128), false
	}
	return p, true
}
