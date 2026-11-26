//go:build linux

package nft

import (
	"context"
	"net/netip"
	"strings"

	"cfm/internal/firewall/setprobe"
)

// LookupSetElems asks the kernel which element of set (in table inet table)
// holds each address: single-element netlink gets (setprobe.Lookup), not a
// dump of the set. ipquery.FindMany answers host queries with it, so a
// lookup in a 1M-address feed takes milliseconds instead of the ~16 s
// `nft -j list set` needs. from/to are the element ([from, to], equal for
// an address); ok[i] is false when nothing holds addrs[i]. An error means
// the kernel could not answer for this set, and the caller dumps it.
func (b *Backend) LookupSetElems(ctx context.Context, table, set string, addrs []netip.Addr) (from, to []netip.Addr, ok []bool, err error) {
	m, ok, err := setprobe.Lookup(ctx, table, set, addrs)
	if err != nil {
		return nil, nil, nil, err
	}
	from, to = make([]netip.Addr, len(m)), make([]netip.Addr, len(m))
	for i := range m {
		from[i], to[i] = m[i].From, m[i].To
	}
	return from, to, ok, nil
}

// hasAddrElem answers HasElem for an address with one kernel lookup; false
// in its second result when elem is not an address or the kernel could not
// answer (the caller runs nft then).
func hasAddrElem(b *Backend, set, elem string) (found, ok bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(elem))
	if err != nil {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), setprobe.Timeout)
	defer cancel()
	_, _, held, err := b.LookupSetElems(ctx, tableName, set, []netip.Addr{a.Unmap()})
	if err != nil || len(held) != 1 {
		return false, false
	}
	return held[0], true
}
