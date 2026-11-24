//go:build linux

package setprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// ErrIntervalSet is HostTimes' answer for an interval set: its elements are
// ranges, and an exact host answer would take Lookup's interval walk. The
// caller dumps the set instead.
var ErrIntervalSet = errors.New("setprobe: interval set, not a host set")

// HostTime is the kernel's answer for one address of a host set: whether the
// set holds it and, if so, the time it has left. Expires is 0 for an element
// without a timeout (permanent); a timed element read at its last instant
// reports a millisecond, never 0 (the convention of the backends' dumps,
// which firewall.PlanBlockBatch reads).
type HostTime struct {
	Found   bool
	Expires time.Duration
}

// HostTimes answers, for each address, whether the host set (a hash set in
// table inet table, e.g. block_v4) holds it and for how long: one
// NFT_MSG_GETSETELEM per address over one connection, whatever the set's
// size. A one-address ban used to dump the whole block set first (the
// never-shorten read of AddBlockBatch): with 50 000 bans that was most of the
// daemon's CPU on the EL8 nodes (2026-11-24).
//
// Any failure (no netlink, the table or set missing, an interval set, a reply
// it cannot read) is an error for the whole call, and the caller dumps the
// set instead.
func HostTimes(ctx context.Context, table, set string, addrs []netip.Addr) ([]HostTime, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("setprobe: dial: %w", err)
	}
	defer c.Close()
	k := &nlKernel{c: c, ctx: ctx, table: table, set: set}
	flags, klen, err := k.setInfo()
	if err != nil {
		return nil, err
	}
	if flags&unix.NFT_SET_INTERVAL != 0 {
		return nil, fmt.Errorf("%w: %s", ErrIntervalSet, set)
	}
	out := make([]HostTime, len(addrs))
	for i, a := range addrs {
		a = a.Unmap()
		if a.BitLen()/8 != int(klen) {
			return nil, fmt.Errorf("setprobe: %s has %d-byte keys, %s is not one", set, klen, a)
		}
		data, err := request(table, set, a.AsSlice(), 0)
		if err != nil {
			return nil, err
		}
		msgs, err := k.execute(unix.NFT_MSG_GETSETELEM, data)
		if errors.Is(err, unix.ENOENT) {
			continue // not in the set
		}
		if err != nil {
			return nil, fmt.Errorf("setprobe: get %s in %s: %w", a, set, err)
		}
		r, err := firstElemReply(msgs)
		if err != nil {
			return nil, fmt.Errorf("setprobe: %s in %s: %w", a, set, err)
		}
		if r.key != a {
			return nil, fmt.Errorf("setprobe: %s answered %s for %s", set, r.key, a)
		}
		out[i] = HostTime{Found: true, Expires: r.left()}
	}
	return out, nil
}

// elemReply is the first element of a NEWSETELEM reply.
type elemReply struct {
	key        netip.Addr
	flags      uint32 // NFTA_SET_ELEM_FLAGS (an interval end)
	hasTimeout bool
	expiration time.Duration // time left, as the kernel reports it
}

// left is the element's remaining time in the backends' convention (see
// HostTime).
func (r elemReply) left() time.Duration {
	if !r.hasTimeout {
		return 0
	}
	if r.expiration <= 0 {
		return time.Millisecond
	}
	return r.expiration
}

// firstElemReply reads the element out of a get's reply messages; an answer
// without one is an error (see errNoElem).
func firstElemReply(msgs []netlink.Message) (elemReply, error) {
	for _, m := range msgs {
		if len(m.Data) < 4 {
			continue
		}
		r, ok, err := parseElemReply(m.Data[4:])
		if err != nil {
			return elemReply{}, err
		}
		if ok {
			return r, nil
		}
	}
	return elemReply{}, errNoElem
}

// parseElemReply reads the first element of a NEWSETELEM reply body (after
// nfgenmsg): its key, flags, whether it has a timeout, and the time it has left
// (NFTA_SET_ELEM_EXPIRATION, milliseconds, big endian).
func parseElemReply(b []byte) (elemReply, bool, error) {
	var r elemReply
	var found bool
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return r, false, err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		if ad.Type() != unix.NFTA_SET_ELEM_LIST_ELEMENTS {
			continue
		}
		ad.Nested(func(l *netlink.AttributeDecoder) error {
			for l.Next() && !found {
				if l.Type() != unix.NFTA_LIST_ELEM {
					continue
				}
				l.Nested(func(e *netlink.AttributeDecoder) error {
					e.ByteOrder = binary.BigEndian
					var cur elemReply
					var keyOK bool
					for e.Next() {
						switch e.Type() {
						case unix.NFTA_SET_ELEM_KEY:
							e.Nested(func(k *netlink.AttributeDecoder) error {
								for k.Next() {
									if k.Type() == unix.NFTA_DATA_VALUE {
										if a, ok := netip.AddrFromSlice(k.Bytes()); ok {
											cur.key, keyOK = a, true
										}
									}
								}
								return nil
							})
						case unix.NFTA_SET_ELEM_FLAGS:
							cur.flags = e.Uint32()
						case unix.NFTA_SET_ELEM_TIMEOUT:
							cur.hasTimeout = true
						case unix.NFTA_SET_ELEM_EXPIRATION:
							// Timed too: newer kernels leave the timeout out when
							// it equals the set's default.
							cur.hasTimeout = true
							cur.expiration = time.Duration(e.Uint64()) * time.Millisecond
						}
					}
					if keyOK {
						r, found = cur, true
					}
					return nil
				})
			}
			return nil
		})
	}
	return r, found, ad.Err()
}

// HostProbe is HostTimes on table inet cfm for net.IP addresses, bounded by
// Timeout: the shape of firewall.HostProbe, which both engines' block and
// allow batches plan from.
func HostProbe(set string, ips []net.IP) (found []bool, expires []time.Duration, err error) {
	addrs := make([]netip.Addr, len(ips))
	for i, ip := range ips {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, nil, fmt.Errorf("setprobe: %v is not an address", ip)
		}
		addrs[i] = a.Unmap()
	}
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	ans, err := HostTimes(ctx, "cfm", set, addrs)
	if err != nil {
		return nil, nil, err
	}
	found, expires = make([]bool, len(ans)), make([]time.Duration, len(ans))
	for i, a := range ans {
		found[i], expires[i] = a.Found, a.Expires
	}
	return found, expires, nil
}

// IntervalHas answers whether the interval set (in table inet table) holds
// exactly the interval [from, to] as one element (Lookup's interval walk for
// from, in one ruleset generation). An interval that covers from but is not
// [from, to] is "no", as a dump read by exact range would say. It does not
// answer the time left: a 4.18 kernel (EL8) answers an interval get without
// the element's timeout, which a dump shows (block_v6_clients on orion,
// 2026-11-24), so the caller dumps for that. Any failure is an error.
func IntervalHas(ctx context.Context, table, set string, from, to netip.Addr) (bool, error) {
	from, to = from.Unmap(), to.Unmap()
	if to.BitLen() != from.BitLen() || to.Less(from) {
		return false, fmt.Errorf("setprobe: %s-%s is not an interval", from, to)
	}
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return false, fmt.Errorf("setprobe: dial: %w", err)
	}
	defer c.Close()
	k := &nlKernel{c: c, ctx: ctx, table: table, set: set}
	flags, _, err := k.setInfo()
	if err != nil {
		return false, err
	}
	if flags&unix.NFT_SET_INTERVAL == 0 {
		return false, fmt.Errorf("setprobe: %s is not an interval set", set)
	}
	m, ok, err := lookup(k, set, []netip.Addr{from})
	if err != nil {
		return false, err
	}
	return ok[0] && m[0].From == from && m[0].To == to, nil
}
