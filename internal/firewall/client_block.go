package firewall

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"cfm/internal/ipkey"
	"cfm/internal/logging"
)

// Automatic bans of an IPv6 client take its /64 (docs/edge-ipv6.md "IPv6 /64
// grouping"): a client rotating its address inside the /64 any VPS or ISP
// line hands it would otherwise walk past a ban on one address. The /64 goes
// to block_v6_nets (interval, timeout), which the input chain already drops
// on; IPv4 and the IPv6 addresses ipkey leaves ungrouped (loopback,
// link-local, ::/64, multicast, NAT64) keep the host path. Manual bans
// (the API, `cfm block`) stay exactly what the operator typed.
//
// The /64 is only ever added or extended, as ExtendBlock does for a host. A
// /64 the set cannot take as it is falls back to the host ban, so no ban is
// ever lost to it: one an element of block_v6_nets overlaps without covering
// it for long enough (a manual /48 for one hour, a hand-added /80), and a
// read or write that fails.

// BlockV6Nets is the IPv6 network block set (both backends' EnsureBase).
const BlockV6Nets = "block_v6_nets"

// netBlockMu serialises the read-then-write of a /64 ban: two extends of one
// /64 racing would let the shorter write land last (the exec backend's
// AddBlockNet deletes, then adds).
var netBlockMu sync.Mutex

// ClientNet is the /64 an automatic ban of ip takes; ok is false for IPv4 and
// for the IPv6 addresses ipkey does not group, which are banned as they are.
func ClientNet(ip net.IP) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	return ipkey.Prefix(a.Unmap())
}

// ExtendClientBlock is ExtendBlock for an automatic blocker: an IPv6 client
// is banned as its /64. elem is what was banned (the /64, or the address),
// which the caller hands to the edge ban store (edgeban.BanElem) so the
// edge answers for exactly what nft drops.
func ExtendClientBlock(be Backend, ip net.IP, ttl time.Duration) (elem string, kept bool, err error) {
	res, err := ExtendBlockResult(be, ip, ttl)
	if err != nil {
		return "", false, err
	}
	if res.Added+res.Extended+res.Kept+res.Present == 0 {
		return "", false, fmt.Errorf("not blockable: %v", ip)
	}
	elem = res.Net
	if elem == "" {
		elem = ip.String()
	}
	return elem, res.Kept > 0, nil
}

// BlockClientPermanent is an automatic blocker's permanent ban: an IPv6
// client's /64 (a permanent element of block_v6_nets; an overlapping element
// falls back to the address), else AddBlock of the address. elem as in
// ExtendClientBlock.
func BlockClientPermanent(be Backend, ip net.IP, comment string) (elem string, err error) {
	if p, ok := ClientNet(ip); ok {
		netBlockMu.Lock()
		cov, rerr := netCoverage(be, p)
		var werr error
		write := rerr == nil && (cov.state == covNone || (cov.state == covExact && !cov.permanent))
		if write {
			var old *netCov
			if cov.state == covExact {
				old = &cov
			}
			werr = replaceBlockNet(be, p, nil, old)
		}
		netBlockMu.Unlock()
		switch {
		case rerr == nil && cov.permanent && (cov.state == covExact || cov.state == covWider):
			return cov.elem, nil
		case write && werr == nil:
			return p.String(), nil
		}
		logging.Logf("[firewall] permanent ban of %s as %s: %s; banning the address instead", ip, p, netFallbackWhy(cov, rerr, werr))
	}
	if err := be.AddBlock(ip, comment, nil); err != nil {
		return "", err
	}
	return ip.String(), nil
}

// RemoveClientNet is the unblock side: it removes the /64 an automatic ban of
// ip's client took (unblocking an IPv6 address frees its client, the /64).
// Only an element equal to the /64 is removed: a wider manual ban stays,
// and no element is a no-op. net is "" when ip is not grouped.
func RemoveClientNet(be Backend, ip net.IP) (net string, err error) {
	p, ok := ClientNet(ip)
	if !ok {
		return "", nil
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	return p.String(), be.RemoveBlockNet(p.String())
}

// ExtendBlockNet bans the IPv6 network p for ttl in block_v6_nets, never
// shortening a ban (the TTL ban restore, internal/ttlban). Unlike
// ExtendClientBlock it has no address to fall back to: a p the set cannot
// take as it is is an error.
func ExtendBlockNet(be Backend, p netip.Prefix, ttl time.Duration) (BlockBatchResult, error) {
	if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() {
		return BlockBatchResult{}, fmt.Errorf("not an IPv6 network: %v", p)
	}
	res, done := extendBlockNet(be, nil, p.Masked(), ttl)
	if !done {
		return res, fmt.Errorf("%s: %s cannot take it as it is (see the log)", p, BlockV6Nets)
	}
	return res, nil
}

// extendBlockNet bans p for ttl in block_v6_nets, never shortening a ban.
// done is false when the /64 could not be written as it is (the caller then
// bans the address).
func extendBlockNet(be Backend, ip net.IP, p netip.Prefix, ttl time.Duration) (res BlockBatchResult, done bool) {
	if ttl < time.Second {
		ttl = time.Second // as SplitBlockEntries: "0s" would read as permanent
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	cov, err := netCoverage(be, p)
	var werr error
	if err == nil {
		long := cov.permanent || cov.left >= ttl
		switch {
		case cov.state == covExact && long, cov.state == covWider && long:
			return BlockBatchResult{Kept: 1, Net: cov.elem}, true
		case cov.state == covExact:
			// Shorter: replace it (delete, then add: an add over an existing
			// element keeps its old timeout on nftlib). The /64 is unbanned
			// for an instant at most, while it was banned already.
			if werr = replaceBlockNet(be, p, &ttl, &cov); werr == nil {
				return BlockBatchResult{Extended: 1, Net: p.String()}, true
			}
		case cov.state == covNone:
			if werr = replaceBlockNet(be, p, &ttl, nil); werr == nil {
				return BlockBatchResult{Added: 1, Net: p.String()}, true
			}
		}
	}
	if ip == nil {
		logging.Logf("[firewall] ban of %s for %s: %s", p, ttl, netFallbackWhy(cov, err, werr))
	} else {
		logging.Logf("[firewall] ban of %s as %s for %s: %s; banning the address instead", ip, p, ttl, netFallbackWhy(cov, err, werr))
	}
	return BlockBatchResult{}, false
}

// replaceBlockNet writes p (ttl nil: permanent). old is the element equal to
// p already there (nil: none), deleted first; if the add then fails, it is
// put back with the time it had left, so a failed extend never unbans.
func replaceBlockNet(be Backend, p netip.Prefix, ttl *time.Duration, old *netCov) error {
	if old != nil {
		if err := be.RemoveBlockNet(p.String()); err != nil {
			return err
		}
	}
	err := be.AddBlockNet(p.String(), ttl)
	if err != nil && old != nil {
		var back *time.Duration
		if !old.permanent {
			left := old.left
			if left < time.Second {
				left = time.Second
			}
			back = &left
		}
		if rerr := be.AddBlockNet(p.String(), back); rerr != nil {
			logging.Logf("[firewall] %s: putting back the ban the failed extend deleted failed too: %v", p, rerr)
		}
	}
	return err
}

func netFallbackWhy(cov netCov, readErr, writeErr error) string {
	switch {
	case readErr != nil:
		return fmt.Sprintf("cannot read %s: %v", BlockV6Nets, readErr)
	case writeErr != nil:
		return fmt.Sprintf("cannot write %s: %v", BlockV6Nets, writeErr)
	case cov.state == covWider:
		return fmt.Sprintf("%s holds the wider %s for less time", BlockV6Nets, cov.elem)
	case cov.state == covOverlap:
		return fmt.Sprintf("%s holds the overlapping %s", BlockV6Nets, cov.elem)
	}
	return "not written"
}

type covState int

const (
	covNone    covState = iota // nothing in the set touches p
	covExact                   // an element equal to p
	covWider                   // an element strictly wider than p, covering it
	covOverlap                 // an element overlapping p without covering it
)

type netCov struct {
	state     covState
	elem      string
	permanent bool
	left      time.Duration
}

// netCoverage reads block_v6_nets and says how its elements relate to p. An
// exact or covering element wins over an overlapping one; among covering
// elements, the longest-lasting.
func netCoverage(be Backend, p netip.Prefix) (netCov, error) {
	elems, err := be.ListSetElementsTimed(BlockV6Nets)
	if err != nil {
		return netCov{}, err
	}
	plo, phi := prefixRange(p)
	var best, overlap netCov
	for _, e := range elems {
		lo, hi, ok := ElemRange(e.Elem)
		if !ok || !lo.Is6() {
			continue
		}
		if hi.Less(plo) || phi.Less(lo) {
			continue
		}
		c := netCov{elem: strings.TrimSpace(e.Elem), permanent: e.Expires <= 0, left: e.Expires}
		switch {
		case lo == plo && hi == phi:
			c.state = covExact
		case !plo.Less(lo) && !hi.Less(phi):
			c.state = covWider
		default:
			c.state = covOverlap
			overlap = c
			continue
		}
		if best.state == covNone || outlastsCov(c, best) {
			best = c
		}
	}
	if best.state != covNone {
		return best, nil
	}
	return overlap, nil
}

func outlastsCov(a, b netCov) bool {
	if a.permanent != b.permanent {
		return a.permanent
	}
	return a.left > b.left
}

// prefixRange is p's first and last address.
func prefixRange(p netip.Prefix) (netip.Addr, netip.Addr) {
	p = p.Masked()
	lo := p.Addr()
	b := lo.As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return lo, netip.AddrFrom16(b)
}

// ElemRange reads a set element as nft lists it (an address, a CIDR, or a
// first-last range) as its first and last address.
func ElemRange(s string) (lo, hi netip.Addr, ok bool) {
	s = strings.TrimSpace(s)
	if a, b, isRange := strings.Cut(s, "-"); isRange {
		lo, err1 := netip.ParseAddr(strings.TrimSpace(a))
		hi, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil || lo.Is4() != hi.Is4() || hi.Less(lo) {
			return netip.Addr{}, netip.Addr{}, false
		}
		return lo.Unmap(), hi.Unmap(), true
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, false
		}
		if p.Addr().Is4() {
			lo := p.Masked().Addr()
			v := lo.As4()
			n := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
			n |= uint32(1)<<(32-uint(p.Bits())) - 1
			if p.Bits() == 0 {
				n = ^uint32(0)
			}
			return lo, netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), true
		}
		lo, hi := prefixRange(p)
		return lo, hi, true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	a = a.Unmap()
	return a, a, true
}
