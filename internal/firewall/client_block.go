package firewall

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/ipkey"
	"cfm/internal/logging"
)

// Automatic L7 bans of an IPv6 client take its /64 (docs/edge-ipv6.md "IPv6
// /64 grouping"): a client rotating its address inside the /64 any VPS or ISP
// line hands it would otherwise walk past a ban on one address. The blockers
// that ban this way see a real session (an HTTP request, a login): the
// detector sinks, the challenge server, the admin API's login autoblock. The
// kernel flood / port-scan autoblock counts packets whose source can be
// spoofed and stays per address (ExtendBlockResult), as do manual bans.
//
// The /64s live in their own set, block_v6_clients (interval, timeout), with
// their own drops in `inet cfm input` right after block_v6_nets' (both
// backends' EnsureBase). In block_v6_nets they collided with the operator's
// own IPv6 CIDRs: nft refuses an element overlapping another, so a manual
// /48 (or a cfm.deny one after a reboot) failed over an automatic /64.
//
// A /64 is only ever added or extended, as ExtendBlock does for a host, and
// an extend replaces the element in one transaction (SetElemWriter). The
// address is banned instead when:
//   - the /64 holds an address of this node (self_v6: a provider handing one
//     /64 to several customers' VPSes) or an ignored address or network
//     (ignore_v6 / ignore_v6_nets, and IGNORE_IPS / IGNORE_NETS through
//     SetClientNetExempt): nft has no accept for those, so the ban would
//     drop them;
//   - the backend cannot write the set (no SetElemWriter, a read or write
//     error).
// Allowed addresses need no such care: every allow set is accepted before
// any block drop.

// BlockV6Clients is the set of automatic IPv6 client /64 bans.
const BlockV6Clients = "block_v6_clients"

// SetElemWriter writes one element of a set: both backends implement it.
type SetElemWriter interface {
	// WriteSetElem writes elem to set with ttl (nil: permanent). replace
	// deletes the element equal to elem first, in the same transaction, so
	// it is never absent in between.
	WriteSetElem(set, elem string, ttl *time.Duration, replace bool) error
	// DeleteSetElem deletes elem from set; an element the set does not hold
	// is not an error.
	DeleteSetElem(set, elem string) error
}

// netBlockMu serialises the read-then-write of a /64 ban: two extends of one
// /64 racing would let the shorter write land last.
var netBlockMu sync.Mutex

// clientNetExempt is the daemon's global IGNORE_IPS / IGNORE_NETS check for a
// /64 (SetClientNetExempt).
var clientNetExempt atomic.Pointer[func(netip.Prefix) bool]

// SetClientNetExempt registers f: a /64 for which it returns true is never
// banned as a whole (the address is). The detectors manager sets it to the
// [global] IGNORE_IPS / IGNORE_NETS overlap on every config load; nil clears.
func SetClientNetExempt(f func(netip.Prefix) bool) {
	if f == nil {
		clientNetExempt.Store(nil)
		return
	}
	clientNetExempt.Store(&f)
}

// ClientNet is the /64 an automatic ban of ip takes; ok is false for IPv4 and
// for the IPv6 addresses ipkey does not group, which are banned as they are.
func ClientNet(ip net.IP) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	return ipkey.Prefix(a.Unmap())
}

// ExtendClientBlock is ExtendBlock for an automatic L7 blocker: an IPv6
// client is banned as its /64. elem is what was banned (the /64, or the
// address), which the caller hands to the edge ban store (edgeban.BanElem)
// so the edge answers for exactly what nft drops.
func ExtendClientBlock(be Backend, ip net.IP, ttl time.Duration) (elem string, kept bool, err error) {
	if p, ok := ClientNet(ip); ok {
		if res, done := extendClientNet(be, ip, p, ttl); done {
			return p.String(), res.Kept > 0, nil
		}
	}
	res, err := ExtendBlockResult(be, ip, ttl)
	if err != nil {
		return "", false, err
	}
	if res.Added+res.Extended+res.Kept+res.Present == 0 {
		return "", false, fmt.Errorf("not blockable: %v", ip)
	}
	return ip.String(), res.Kept > 0, nil
}

// BlockClientPermanent is an automatic L7 blocker's permanent ban: an IPv6
// client's /64 (a permanent element of block_v6_clients), else AddBlock of
// the address. elem as in ExtendClientBlock. Like a permanent host ban from a
// detector, it is not written to cfm.deny.
func BlockClientPermanent(be Backend, ip net.IP, comment string) (elem string, err error) {
	if p, ok := ClientNet(ip); ok {
		if _, done := writeClientNet(be, ip, p, nil); done {
			return p.String(), nil
		}
	}
	if err := be.AddBlock(ip, comment, nil); err != nil {
		return "", err
	}
	return ip.String(), nil
}

// ExtendBlockNet bans p for ttl in block_v6_clients, never shortening a ban:
// the TTL ban restore (internal/ttlban). It runs the same guards as an
// automatic ban; with no address to fall back to, a p it cannot write is an
// error.
func ExtendBlockNet(be Backend, p netip.Prefix, ttl time.Duration) (BlockBatchResult, error) {
	if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p != p.Masked() {
		return BlockBatchResult{}, fmt.Errorf("not an IPv6 network: %v", p)
	}
	res, done := extendClientNet(be, nil, p, ttl)
	if !done {
		return res, fmt.Errorf("%s: not written to %s (see the log)", p, BlockV6Clients)
	}
	return res, nil
}

// RemoveClientNet is the unblock side: it removes the /64 an automatic ban
// of ip's client took (unblocking an IPv6 address frees its client, the
// /64). net is "" when ip is not grouped; a /64 the set does not hold is no
// error.
func RemoveClientNet(be Backend, ip net.IP) (net string, err error) {
	p, ok := ClientNet(ip)
	if !ok {
		return "", nil
	}
	w, ok := be.(SetElemWriter)
	if !ok {
		return p.String(), nil // nothing can have written it
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	return p.String(), w.DeleteSetElem(BlockV6Clients, p.String())
}

// RemoveClientPrefix removes the /64 ban p from block_v6_clients (the TTL ban
// restore's undo of an unblock that landed during it); not held is no error.
func RemoveClientPrefix(be Backend, p netip.Prefix) error {
	w, ok := be.(SetElemWriter)
	if !ok {
		return nil
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	return w.DeleteSetElem(BlockV6Clients, p.String())
}

// extendClientNet bans p for ttl, never shortening a ban. done is false when
// the /64 must not or could not be written (the caller bans the address).
func extendClientNet(be Backend, ip net.IP, p netip.Prefix, ttl time.Duration) (BlockBatchResult, bool) {
	if ttl < time.Second {
		ttl = time.Second // as SplitBlockEntries: "0s" would read as permanent
	}
	return writeClientNet(be, ip, p, &ttl)
}

// writeClientNet writes p to block_v6_clients for ttl (nil: permanent),
// never shortening what is there.
func writeClientNet(be Backend, ip net.IP, p netip.Prefix, ttl *time.Duration) (BlockBatchResult, bool) {
	what := p.String()
	if ip != nil {
		what = fmt.Sprintf("%s as %s", ip, p)
	}
	fallback := func(why string) (BlockBatchResult, bool) {
		if ip == nil {
			logging.Logf("[firewall] ban of %s: %s", what, why)
		} else {
			logging.Logf("[firewall] ban of %s: %s; banning the address instead", what, why)
		}
		return BlockBatchResult{}, false
	}
	w, ok := be.(SetElemWriter)
	if !ok {
		return fallback("this backend cannot write " + BlockV6Clients)
	}
	if why, err := clientNetGuard(be, p); err != nil {
		return fallback(fmt.Sprintf("cannot check what the /64 holds: %v", err))
	} else if why != "" {
		return fallback(why)
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	elems, err := be.ListSetElementsTimed(BlockV6Clients)
	if err != nil {
		return fallback(fmt.Sprintf("cannot read %s: %v", BlockV6Clients, err))
	}
	exists, permanent, left := false, false, time.Duration(0)
	for _, e := range elems {
		lo, hi, ok := ElemRange(e.Elem)
		if !ok {
			continue
		}
		if plo, phi := prefixRange(p); lo == plo && hi == phi {
			exists, permanent, left = true, e.Expires <= 0, e.Expires
			break
		}
	}
	switch {
	case exists && permanent:
		return BlockBatchResult{Kept: 1, Net: p.String()}, true
	case exists && ttl != nil && left >= *ttl:
		return BlockBatchResult{Kept: 1, Net: p.String()}, true
	}
	if err := w.WriteSetElem(BlockV6Clients, p.String(), ttl, exists); err != nil {
		return fallback(fmt.Sprintf("cannot write %s: %v", BlockV6Clients, err))
	}
	if exists {
		return BlockBatchResult{Extended: 1, Net: p.String()}, true
	}
	return BlockBatchResult{Added: 1, Net: p.String()}, true
}

// clientNetGuardSets are the sets whose addresses a /64 ban must not drop:
// nft accepts none of them before the block drops.
var clientNetGuardSets = []string{"self_v6", "ignore_v6", "ignore_v6_nets"}

// clientNetGuard says why p must not be banned as a whole ("" when it may).
func clientNetGuard(be Backend, p netip.Prefix) (string, error) {
	if f := clientNetExempt.Load(); f != nil && (*f)(p) {
		return "the /64 holds an IGNORE_IPS / IGNORE_NETS address", nil
	}
	plo, phi := prefixRange(p)
	for _, set := range clientNetGuardSets {
		elems, err := be.ListSetElementsTimed(set)
		if err != nil {
			return "", fmt.Errorf("%s: %w", set, err)
		}
		for _, e := range elems {
			lo, hi, ok := ElemRange(e.Elem)
			if !ok || !lo.Is6() {
				continue
			}
			if !hi.Less(plo) && !phi.Less(lo) {
				if set == "self_v6" {
					return fmt.Sprintf("the /64 holds this node's own address (%s)", strings.TrimSpace(e.Elem)), nil
				}
				return fmt.Sprintf("the /64 holds %s (%s)", strings.TrimSpace(e.Elem), set), nil
			}
		}
	}
	return "", nil
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
			if p.Bits() == 0 {
				n = ^uint32(0)
			} else {
				n |= uint32(1)<<(32-uint(p.Bits())) - 1
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
