//go:build linux

package setprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// ErrAmbiguous is Lookup's answer when the kernel's reply cannot be trusted:
// an interval set has an interval END exactly at the address asked, which a
// 4.18 kernel can answer "absent" for even when the next interval starts
// there (see Lookup). The caller reads the set some other way.
var ErrAmbiguous = errors.New("setprobe: interval boundary, the kernel's answer is ambiguous")

// Match is the element of a set that holds an address: the address itself
// (From == To) in a hash set, or the interval [From, To] (To inclusive) of an
// interval set.
type Match struct{ From, To netip.Addr }

// Lookup answers, for each address, which element of set (in table inet
// table) holds it, with one connection and a handful of single-element
// NFT_MSG_GETSETELEM requests per address: the kernel looks the key up in
// the set (nft_get_set_elem → set->ops->get), whatever the set's size. The
// result is aligned with addrs; ok[i] is false when the kernel answered that
// no element holds addrs[i]. Any failure — no netlink, a kernel that cannot
// answer a get, ErrAmbiguous — is an error for the whole call, and the
// caller dumps the set instead.
//
// A hash set answers an exact match. An interval set (rbtree) answers with
// the START of the interval holding the key (on 4.18, 5.14 and 6.x: the
// closest element at or below the key, when it is a start), and the end is
// found with more gets (see intervalEnd). One kernel defect is worked
// around: on 4.18, __nft_rbtree_get stops at the first node whose key equals
// the one asked, and when that is the END of the previous interval (an
// adjacent interval: nft and nftlib write 10.0.0.0/25 and 10.0.0.128/25 as
// end 10.0.0.128 + start 10.0.0.128) it answers ENOENT although the start is
// there. 5.14 walks past that end. So a miss on an interval set where an end
// sits at the key is checked one address further on (see interval).
func Lookup(ctx context.Context, table, set string, addrs []netip.Addr) ([]Match, []bool, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("setprobe: dial: %w", err)
	}
	defer c.Close()
	p := &prober{c: c, ctx: ctx, table: table, set: set}
	flags, klen, err := p.setInfo()
	if err != nil {
		return nil, nil, err
	}
	out := make([]Match, len(addrs))
	ok := make([]bool, len(addrs))
	for i, a := range addrs {
		a = a.Unmap()
		if a.BitLen()/8 != int(klen) {
			return nil, nil, fmt.Errorf("setprobe: %s has %d-byte keys, %s is not one", set, klen, a)
		}
		if flags&unix.NFT_SET_INTERVAL != 0 {
			out[i], ok[i], err = p.interval(a)
		} else {
			var k netip.Addr
			k, _, ok[i], err = p.get(a, 0)
			if ok[i] && k != a {
				err = fmt.Errorf("setprobe: %s answered %s for %s", set, k, a)
			}
			out[i] = Match{From: a, To: a}
		}
		if err != nil {
			return nil, nil, err
		}
	}
	return out, ok, nil
}

type prober struct {
	c          *netlink.Conn
	ctx        context.Context
	table, set string
}

func (p *prober) execute(typ int, data []byte) ([]netlink.Message, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	dl := time.Now().Add(Timeout)
	if d, ok := p.ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = p.c.SetDeadline(dl)
	// Acknowledge, and read up to the ACK: a reply and the ACK after it
	// can come in separate datagrams (Execute would leave the ACK to be
	// read as the next request's answer), and a 6.x kernel answers an
	// END-element get that finds nothing with an ACK alone, no reply and
	// no error (seen on 6.18), which without the ACK flag never returns.
	req, err := p.c.Send(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | typ),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	})
	if err != nil {
		return nil, err
	}
	var out []netlink.Message
	for {
		msgs, err := p.c.Receive()
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Sequence != req.Header.Sequence {
				continue // a stale answer to an earlier request
			}
			if m.Header.Type == netlink.Error {
				return out, nil // the ACK (an error is Receive's err)
			}
			out = append(out, m)
		}
	}
}

// setInfo reads the set's flags and key length (NFT_MSG_GETSET, one set).
func (p *prober) setInfo() (flags, klen uint32, err error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.NFTA_SET_TABLE, p.table)
	ae.String(unix.NFTA_SET_NAME, p.set)
	attrs, err := ae.Encode()
	if err != nil {
		return 0, 0, fmt.Errorf("setprobe: encode: %w", err)
	}
	msgs, err := p.execute(unix.NFT_MSG_GETSET, append([]byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0}, attrs...))
	if err != nil {
		return 0, 0, fmt.Errorf("setprobe: get set %s: %w", p.set, err)
	}
	for _, m := range msgs {
		if len(m.Data) < 4 {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[4:])
		if err != nil {
			return 0, 0, fmt.Errorf("setprobe: set %s: %w", p.set, err)
		}
		ad.ByteOrder = binary.BigEndian
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_SET_FLAGS:
				flags = ad.Uint32()
			case unix.NFTA_SET_KEY_LEN:
				klen = ad.Uint32()
			}
		}
		if err := ad.Err(); err != nil {
			return 0, 0, fmt.Errorf("setprobe: set %s: %w", p.set, err)
		}
	}
	if klen != 4 && klen != 16 {
		return 0, 0, fmt.Errorf("setprobe: set %s: key length %d is not an address", p.set, klen)
	}
	return flags, klen, nil
}

// get sends one GETSETELEM for key (with elemFlags, 0 or
// NFT_SET_ELEM_INTERVAL_END) and returns the element the kernel answered
// with: its key and flags, found=false on ENOENT.
func (p *prober) get(key netip.Addr, elemFlags uint32) (netip.Addr, uint32, bool, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.NFTA_SET_ELEM_LIST_TABLE, p.table)
	ae.String(unix.NFTA_SET_ELEM_LIST_SET, p.set)
	ae.Nested(unix.NFTA_SET_ELEM_LIST_ELEMENTS, func(l *netlink.AttributeEncoder) error {
		l.Nested(unix.NFTA_LIST_ELEM, func(e *netlink.AttributeEncoder) error {
			e.Nested(unix.NFTA_SET_ELEM_KEY, func(k *netlink.AttributeEncoder) error {
				k.Bytes(unix.NFTA_DATA_VALUE, key.AsSlice())
				return nil
			})
			if elemFlags != 0 {
				e.ByteOrder = binary.BigEndian
				e.Uint32(unix.NFTA_SET_ELEM_FLAGS, elemFlags)
			}
			return nil
		})
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return netip.Addr{}, 0, false, fmt.Errorf("setprobe: encode: %w", err)
	}
	msgs, err := p.execute(unix.NFT_MSG_GETSETELEM, append([]byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0}, attrs...))
	if errors.Is(err, unix.ENOENT) {
		return netip.Addr{}, 0, false, nil
	}
	if err != nil {
		return netip.Addr{}, 0, false, fmt.Errorf("setprobe: get %s in %s: %w", key, p.set, err)
	}
	for _, m := range msgs {
		if len(m.Data) < 4 {
			continue
		}
		k, f, ok, err := parseElem(m.Data[4:])
		if err != nil {
			return netip.Addr{}, 0, false, fmt.Errorf("setprobe: %s in %s: %w", key, p.set, err)
		}
		if ok {
			return k, f, true, nil
		}
	}
	return netip.Addr{}, 0, false, fmt.Errorf("setprobe: %s in %s: %w", key, p.set, errNoElem)
}

// errNoElem is a get the kernel acknowledged without an element: what 6.18
// answers an END-element get that finds no end (an interval running to the
// top of the address space). An END probe reads it as "no end"; a plain get
// as an error, since nothing documents it.
var errNoElem = errors.New("the kernel acknowledged the get without an element")

// getEnd is get for an END element, errNoElem read as "none".
func (p *prober) getEnd(key netip.Addr) (netip.Addr, uint32, bool, error) {
	k, f, ok, err := p.get(key, unix.NFT_SET_ELEM_INTERVAL_END)
	if errors.Is(err, errNoElem) {
		return netip.Addr{}, 0, false, nil
	}
	return k, f, ok, err
}

// parseElem reads the first element of a NEWSETELEM reply: its key and flags.
func parseElem(b []byte) (netip.Addr, uint32, bool, error) {
	var key netip.Addr
	var flags uint32
	var found bool
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return key, 0, false, err
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
					for e.Next() {
						switch e.Type() {
						case unix.NFTA_SET_ELEM_KEY:
							e.Nested(func(k *netlink.AttributeDecoder) error {
								for k.Next() {
									if k.Type() == unix.NFTA_DATA_VALUE {
										if a, ok := netip.AddrFromSlice(k.Bytes()); ok {
											key, found = a, true
										}
									}
								}
								return nil
							})
						case unix.NFTA_SET_ELEM_FLAGS:
							flags = e.Uint32()
						}
					}
					return nil
				})
			}
			return nil
		})
	}
	return key, flags, found, ad.Err()
}

// interval finds the interval of an interval set that holds a.
func (p *prober) interval(a netip.Addr) (Match, bool, error) {
	start, f, ok, err := p.get(a, 0)
	if err != nil {
		return Match{}, false, err
	}
	if !ok {
		// The 4.18 defect (see Lookup): with an end at a, a start there
		// may have been missed. Ask one address further on: inside an
		// interval that starts at a, the closest element below a+1 is that
		// start (the tree orders a start after an end of the same key).
		// That answer is only trustworthy when no element sits at a+1: a
		// descent meets a node of the key it looks for if one exists, and
		// 4.18 then answers from that node alone. So: an answer of a is a
		// hit; "absent" with no end at a+1 is a miss (a start at a+1 would
		// have been the answer); anything else is ambiguous.
		_, _, endAt, err := p.exactEnd(a)
		if err != nil || !endAt {
			return Match{}, false, err
		}
		next := a.Next()
		if !next.IsValid() {
			return Match{}, false, ErrAmbiguous
		}
		start, f, ok, err = p.get(next, 0)
		if err != nil {
			return Match{}, false, err
		}
		if !ok {
			_, _, endNext, err := p.exactEnd(next)
			if err == nil && endNext {
				err = ErrAmbiguous
			}
			return Match{}, false, err
		}
		if start != a {
			return Match{}, false, ErrAmbiguous
		}
	}
	if f&unix.NFT_SET_ELEM_INTERVAL_END != 0 || a.Less(start) || start.BitLen() != a.BitLen() {
		return Match{}, false, fmt.Errorf("setprobe: %s answered %s (flags %#x) for %s", p.set, start, f, a)
	}
	to, err := p.intervalEnd(start, a)
	if err != nil {
		return Match{}, false, err
	}
	return Match{From: start, To: to}, true, nil
}

// exactEnd reports whether an interval END element sits exactly at a.
func (p *prober) exactEnd(a netip.Addr) (netip.Addr, uint32, bool, error) {
	k, f, ok, err := p.getEnd(a)
	if err != nil || !ok {
		return k, f, false, err
	}
	return k, f, k == a && f&unix.NFT_SET_ELEM_INTERVAL_END != 0, nil
}

// intervalEnd returns the last address of the interval that starts at start
// and holds a: the largest x for which the kernel answers start. That answer
// holds from start up to the interval's end and never after it (past the
// end the closest element below is that end, or a later start), so the end
// is found bit by bit. A 5.14+ kernel names the end directly when asked for
// an END element (the closest end above a key); that guess is used when two
// gets confirm it, so most lookups take three gets, not 32 or 128.
func (p *prober) intervalEnd(start, a netip.Addr) (netip.Addr, error) {
	in := func(x netip.Addr) (bool, error) {
		k, f, ok, err := p.get(x, 0)
		return ok && k == start && f&unix.NFT_SET_ELEM_INTERVAL_END == 0, err
	}
	if end, f, ok, err := p.getEnd(a); err != nil {
		return netip.Addr{}, err
	} else if ok && f&unix.NFT_SET_ELEM_INTERVAL_END != 0 && a.Less(end) && end.BitLen() == a.BitLen() {
		last := end.Prev()
		inLast, err := in(last)
		if err != nil {
			return netip.Addr{}, err
		}
		inEnd, err := in(end)
		if err != nil {
			return netip.Addr{}, err
		}
		if inLast && !inEnd {
			return last, nil
		}
	}
	to := a
	for bit := a.BitLen() - 1; bit >= 0; bit-- {
		x, ok := addPow2(to, bit)
		if !ok {
			continue
		}
		yes, err := in(x)
		if err != nil {
			return netip.Addr{}, err
		}
		if yes {
			to = x
		}
	}
	return to, nil
}

// addPow2 returns a + 2^bit, false when that overflows the address space.
func addPow2(a netip.Addr, bit int) (netip.Addr, bool) {
	b := a.AsSlice()
	i := len(b) - 1 - bit/8
	carry := uint16(1) << (bit % 8)
	for ; i >= 0 && carry != 0; i-- {
		s := uint16(b[i]) + carry
		b[i], carry = byte(s), s>>8
	}
	if carry != 0 {
		return netip.Addr{}, false
	}
	r, _ := netip.AddrFromSlice(b)
	return r, true
}
