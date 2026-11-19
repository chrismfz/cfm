// Package ipkey is the key a per-client control counts and bans on
// (docs/edge-ipv6.md "IPv6 /64 grouping"). configs/lua/cfm_ipkey.lua is its
// edge twin; both run scripts/tests/fixtures/ipkey.txt, so the edge and the
// daemon can never key one client differently.
//
// An IPv6 client is its /64: any VPS or ISP line hands its customer a /64, and
// a client rotating its address inside it would otherwise get a fresh identity
// (counters, rate limits, bans) per address. IPv4 is the address itself; a
// v4-mapped address is IPv4. Left as they are (never a /64): loopback,
// link-local (a /64 there is every neighbour on the link), any address in
// ::/64 (the unspecified address, IPv4-compatible and IPv4-translated forms:
// that /64 holds ::1, so a ban on it would cover the edge's own origin hop),
// multicast, 64:ff9b::/64 (it holds NAT64's 64:ff9b::/96, each address there
// an IPv4 client), a
// zoned address and anything unparsable. Callers parse their input first: an
// unparsable string comes back as it is and must not be keyed on.
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

// nat64 is the /64 holding the well-known NAT64 prefix 64:ff9b::/96 (RFC
// 6052): a ban on it would cover every NAT64 client.
var nat64 = netip.MustParsePrefix("64:ff9b::/64")

// Prefix returns the client prefix of a and whether it groups more than one
// address: a /64 for an IPv6 address (true); a /32 for IPv4 or v4-mapped,
// unmapped (false); a /128 for the addresses left as they are (Client's
// doc; false); the zero Prefix for an invalid address (false).
func Prefix(a netip.Addr) (netip.Prefix, bool) {
	if !a.IsValid() {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	if a.Is4() {
		return netip.PrefixFrom(a, 32), false
	}
	b := a.As16()
	if a.Zone() != "" || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() ||
		[8]byte(b[:8]) == [8]byte{} || nat64.Contains(a.WithZone("")) {
		return netip.PrefixFrom(a, 128), false
	}
	p, err := a.Prefix(V6Bits)
	if err != nil {
		return netip.PrefixFrom(a, 128), false
	}
	return p, true
}
