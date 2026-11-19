package firewall

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
//   - the /64 holds an address of this node (its interfaces, and self_v6: a
//     provider handing one /64 to several customers' VPSes), an ignored
//     address or network (ignore_v6 / ignore_v6_nets, and IGNORE_IPS /
//     IGNORE_NETS), or a trusted proxy's range (Cloudflare's: a detector that
//     saw a proxy's own address must not ban the proxy's /64). The last two
//     come through SetClientNetExempt. nft has no accept for any of them
//     before its drops;
//   - the backend cannot write the set (no SetElemWriter, a read or write
//     error).
//   - the /64 holds an allowed address or network: nft would still accept
//     it (every allow set comes before the drops), but the edge ban store
//     never answers a /64 an allow touches and the TTL restore drops one, so
//     a /64 ban there would hold only for direct clients and not survive a
//     restart. The small manual allow sets are read here; the fleet's
//     (allow_ext_*) come from the edge ban store's snapshot, registered as
//     "allow_sets".

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

// ErrClientNetGuarded is ExtendBlockNet's answer for a /64 a guard refuses
// (it holds this node's address, an ignored one, a trusted proxy's): the
// TTL ban restore counts it excluded, not failed.
var ErrClientNetGuarded = errors.New("the /64 holds an address it must not drop")

// clientNetExempt holds the daemon's checks for a /64, by name
// (SetClientNetExempt).
var (
	clientNetExemptMu sync.Mutex
	clientNetExempt   atomic.Pointer[map[string]func(netip.Prefix) bool]
)

// SetClientNetExempt registers f under name: a /64 for which it returns true
// is never banned as a whole (the address is). The detectors manager
// registers "ignore" ([global] IGNORE_IPS / IGNORE_NETS, on every config
// load), the edge ban store "trusted_proxies"; nil removes name.
func SetClientNetExempt(name string, f func(netip.Prefix) bool) {
	clientNetExemptMu.Lock()
	defer clientNetExemptMu.Unlock()
	next := map[string]func(netip.Prefix) bool{}
	if cur := clientNetExempt.Load(); cur != nil {
		for k, v := range *cur {
			next[k] = v
		}
	}
	if f == nil {
		delete(next, name)
	} else {
		next[name] = f
	}
	clientNetExempt.Store(&next)
}

// ClientNetExempted reports which registered check refuses p ("" when none).
func ClientNetExempted(p netip.Prefix) string {
	cur := clientNetExempt.Load()
	if cur == nil {
		return ""
	}
	for name, f := range *cur {
		if f(p) {
			return name
		}
	}
	return ""
}

// localAddrs are this node's interface addresses (a var: tests replace it).
var localAddrs = net.InterfaceAddrs

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
		if _, done, _ := writeClientNet(be, ip, p, nil); done {
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
	if ttl < time.Second {
		ttl = time.Second
	}
	res, done, guarded := writeClientNet(be, nil, p, &ttl)
	switch {
	case guarded != "":
		return BlockBatchResult{}, fmt.Errorf("%s: %s: %w", p, guarded, ErrClientNetGuarded)
	case !done:
		return res, fmt.Errorf("%s: not written to %s (see the log)", p, BlockV6Clients)
	}
	return res, nil
}

// RemoveClientNets is RemoveClientNet for many addresses (a mass unblock):
// the /64s deduplicated, block_v6_clients read once, only the /64s it holds
// deleted. The result maps each address whose /64 could not be checked or
// deleted to the error (an address not grouped, or whose /64 is not held,
// has none).
func RemoveClientNets(be Backend, ips []net.IP) map[string]error {
	byNet := map[netip.Prefix][]string{}
	for _, ip := range ips {
		if p, ok := ClientNet(ip); ok {
			byNet[p] = append(byNet[p], ip.String())
		}
	}
	if len(byNet) == 0 {
		return nil
	}
	w, ok := be.(SetElemWriter)
	if !ok {
		return nil // nothing can have written them
	}
	fail := func(nets []netip.Prefix, err error) map[string]error {
		out := map[string]error{}
		for _, p := range nets {
			for _, ip := range byNet[p] {
				out[ip] = err
			}
		}
		return out
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	elems, err := be.ListSetElementsTimed(BlockV6Clients)
	if err != nil {
		all := make([]netip.Prefix, 0, len(byNet))
		for p := range byNet {
			all = append(all, p)
		}
		if IsMissingSet(err) {
			return nil // a table from before the set: nothing to free
		}
		return fail(all, fmt.Errorf("read %s: %w", BlockV6Clients, err))
	}
	held := map[netip.Prefix]bool{}
	for p := range byNet {
		plo, phi := prefixRange(p)
		for _, e := range elems {
			if lo, hi, ok := ElemRange(e.Elem); ok && lo == plo && hi == phi {
				held[p] = true
				break
			}
		}
	}
	var out map[string]error
	for p := range byNet {
		if !held[p] {
			continue
		}
		if err := w.DeleteSetElem(BlockV6Clients, p.String()); err != nil {
			if out == nil {
				out = map[string]error{}
			}
			for k, v := range fail([]netip.Prefix{p}, err) {
				out[k] = v
			}
		}
	}
	return out
}

// IsMissingSet reports nft's (or nftlib's) error for a set or table that does
// not exist (a table an older daemon built): ENOENT, "No such file or
// directory". Not any "not found": a missing nft binary ("executable file
// not found") is a failure.
func IsMissingSet(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOENT) && !errors.Is(err, exec.ErrNotFound) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such file or directory")
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
	if err := w.DeleteSetElem(BlockV6Clients, p.String()); err != nil && !IsMissingSet(err) {
		return p.String(), err
	}
	return p.String(), nil // removed, not held, or a table from before the set
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
	res, done, _ := writeClientNet(be, ip, p, &ttl)
	return res, done
}

// writeClientNet writes p to block_v6_clients for ttl (nil: permanent),
// never shortening what is there. guarded names why a guard refused p ("" when
// none did).
func writeClientNet(be Backend, ip net.IP, p netip.Prefix, ttl *time.Duration) (res BlockBatchResult, done bool, guarded string) {
	what := p.String()
	if ip != nil {
		what = fmt.Sprintf("%s as %s", ip, p)
	}
	fallback := func(why string) (BlockBatchResult, bool, string) {
		if ip == nil {
			logging.Logf("[firewall] ban of %s: %s", what, why)
		} else {
			logging.Logf("[firewall] ban of %s: %s; banning the address instead", what, why)
		}
		return BlockBatchResult{}, false, ""
	}
	w, ok := be.(SetElemWriter)
	if !ok {
		return fallback("this backend cannot write " + BlockV6Clients)
	}
	if why, err := clientNetGuard(be, p); err != nil {
		return fallback(fmt.Sprintf("cannot check what the /64 holds: %v", err))
	} else if why != "" {
		r, d, _ := fallback(why)
		return r, d, why
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
		return BlockBatchResult{Kept: 1, Net: p.String()}, true, ""
	case exists && ttl != nil && left >= *ttl:
		return BlockBatchResult{Kept: 1, Net: p.String()}, true, ""
	}
	if err := w.WriteSetElem(BlockV6Clients, p.String(), ttl, exists); err != nil {
		return fallback(fmt.Sprintf("cannot write %s: %v", BlockV6Clients, err))
	}
	if exists {
		return BlockBatchResult{Extended: 1, Net: p.String()}, true, ""
	}
	return BlockBatchResult{Added: 1, Net: p.String()}, true, ""
}

// clientNetGuardSets are the sets whose addresses a /64 ban must not cover:
// this node's, the ignored (nft accepts neither before its drops), and the
// small manual allow sets (the rest of the allows: "allow_sets").
var clientNetGuardSets = []string{"self_v6", "ignore_v6", "ignore_v6_nets", "allow_v6", "allow_dyn_v6", "allow_v6_nets"}

// clientNetGuard says why p must not be banned as a whole ("" when it may).
func clientNetGuard(be Backend, p netip.Prefix) (string, error) {
	if name := ClientNetExempted(p); name != "" {
		return fmt.Sprintf("the /64 is refused by the %s check", name), nil
	}
	// This node's own addresses, from its interfaces: self_v6 below is
	// rewritten (flushed, then filled) on every refresh, and a read in
	// between would miss them.
	if addrs, err := localAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && p.Contains(ip.Unmap()) {
					return fmt.Sprintf("the /64 holds this node's own address (%s)", ip), nil
				}
			}
		}
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
