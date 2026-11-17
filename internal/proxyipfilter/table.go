package proxyipfilter

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"strings"
)

// table is one source's addresses in a compact, read-only form: IPv4 hosts as
// a sorted []uint32 (4 bytes each: the 268 k-entry fleet blacklist is ~1 MB),
// IPv4 networks and ranges as merged [lo,hi] pairs, IPv6 the same way. A lookup
// is a binary search, with no allocation and no lock (the table is never
// written after build).
type table struct {
	v4     []uint32
	v4r    []r32
	v6     []netip.Addr
	v6r    []r128
	n, bad int // elements kept, and those that did not parse
}

type r32 struct{ lo, hi uint32 }
type r128 struct{ lo, hi netip.Addr }

// buildTable parses set / feed elements: "1.2.3.4", "1.2.3.0/24", "lo-hi"
// (nft's rendering of an interval), IPv4 or IPv6.
func buildTable(elems []string) table {
	var t table
	for _, e := range elems {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		switch {
		case strings.Contains(e, "/"):
			p, err := netip.ParsePrefix(e)
			if err != nil || p.Addr().Is4In6() {
				t.bad++
				continue
			}
			p = p.Masked()
			lo := p.Addr().Unmap()
			if lo.Is4() && p.Bits() == 32 || lo.Is6() && p.Bits() == 128 {
				t.addHost(lo)
			} else {
				t.addRange(lo, lastAddr(p))
			}
		case strings.Contains(e, "-"):
			i := strings.Index(e, "-")
			lo, err1 := netip.ParseAddr(strings.TrimSpace(e[:i]))
			hi, err2 := netip.ParseAddr(strings.TrimSpace(e[i+1:]))
			if err1 != nil || err2 != nil || lo.Unmap().Is4() != hi.Unmap().Is4() {
				t.bad++
				continue
			}
			lo, hi = lo.Unmap(), hi.Unmap()
			if hi.Less(lo) {
				lo, hi = hi, lo
			}
			t.addRange(lo, hi)
		default:
			a, err := netip.ParseAddr(e)
			if err != nil {
				t.bad++
				continue
			}
			t.addHost(a.Unmap())
		}
		t.n++
	}
	t.finish()
	return t
}

func (t *table) addHost(a netip.Addr) {
	if a.Is4() {
		t.v4 = append(t.v4, v4u(a))
		return
	}
	t.v6 = append(t.v6, a.WithZone(""))
}

func (t *table) addRange(lo, hi netip.Addr) {
	if lo.Is4() {
		t.v4r = append(t.v4r, r32{v4u(lo), v4u(hi)})
		return
	}
	t.v6r = append(t.v6r, r128{lo.WithZone(""), hi.WithZone("")})
}

func (t *table) finish() {
	sort.Slice(t.v4, func(i, j int) bool { return t.v4[i] < t.v4[j] })
	t.v4 = dedupU32(t.v4)
	sort.Slice(t.v6, func(i, j int) bool { return t.v6[i].Less(t.v6[j]) })
	t.v6 = dedupAddr(t.v6)
	sort.Slice(t.v4r, func(i, j int) bool { return t.v4r[i].lo < t.v4r[j].lo })
	t.v4r = merge32(t.v4r)
	sort.Slice(t.v6r, func(i, j int) bool { return t.v6r[i].lo.Less(t.v6r[j].lo) })
	t.v6r = merge128(t.v6r)
}

func (t *table) contains(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is4() {
		u := v4u(a)
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i] >= u })
		if i < len(t.v4) && t.v4[i] == u {
			return true
		}
		// The last range starting at or below u.
		j := sort.Search(len(t.v4r), func(i int) bool { return t.v4r[i].lo > u }) - 1
		return j >= 0 && u <= t.v4r[j].hi
	}
	a = a.WithZone("")
	i := sort.Search(len(t.v6), func(i int) bool { return !t.v6[i].Less(a) })
	if i < len(t.v6) && t.v6[i] == a {
		return true
	}
	j := sort.Search(len(t.v6r), func(i int) bool { return a.Less(t.v6r[i].lo) }) - 1
	return j >= 0 && !t.v6r[j].hi.Less(a)
}

func v4u(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func lastAddr(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		lo := v4u(p.Addr())
		hi := lo | (^uint32(0) >> uint(p.Bits()))
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], hi)
		return netip.AddrFrom4(b)
	}
	b := p.Addr().As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom16(b)
}

func dedupU32(s []uint32) []uint32 {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func dedupAddr(s []netip.Addr) []netip.Addr {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// merge32 joins overlapping or adjacent ranges, so the "last range starting
// at or below" search is exact.
func merge32(s []r32) []r32 {
	out := s[:0]
	for _, r := range s {
		if n := len(out); n > 0 && (r.lo <= out[n-1].hi || out[n-1].hi != ^uint32(0) && r.lo == out[n-1].hi+1) {
			if r.hi > out[n-1].hi {
				out[n-1].hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func merge128(s []r128) []r128 {
	out := s[:0]
	for _, r := range s {
		if n := len(out); n > 0 && (!out[n-1].hi.Less(r.lo) || out[n-1].hi.Next() == r.lo) {
			if out[n-1].hi.Less(r.hi) {
				out[n-1].hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}
