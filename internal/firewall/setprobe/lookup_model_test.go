//go:build linux

package setprobe

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// rbKernel models an interval set's rbtree as the kernel builds and reads
// it: a binary tree in which a node's LEFT child holds the greater keys,
// built with __nft_rbtree_insert's rule (a start goes left of an end of the
// same key), and read with __nft_rbtree_get as written in 4.18 or in 5.14
// (6.12's is the same as 5.14's). The tree is not rebalanced: rotations keep
// the in-order sequence, so the insertion orders the tests shuffle give
// other valid shapes, and so the different first equal-key node a descent
// meets. Only this machine's kernel runs the live test; this is what pins
// Lookup's answers on the fleet's 4.18 (EL8) and 5.14 (EL9).
type rbKernel struct {
	root  *rbNode
	v418  bool
	gens  []uint32 // gen() answers, in turn; the last repeats
	nGen  int
	nGet  int
	onGet func(n int) // called before each get (tests change the set)
}

type rbNode struct {
	key         uint32
	end         bool
	left, right *rbNode
}

func (k *rbKernel) insert(key uint32, end bool) {
	p := &k.root
	for *p != nil {
		n := *p
		switch {
		case n.key < key:
			p = &n.left
		case n.key > key:
			p = &n.right
		case n.end && !end:
			p = &n.left
		case !n.end && end:
			p = &n.right
		default:
			panic(fmt.Sprintf("duplicate %d end=%v", key, end))
		}
	}
	*p = &rbNode{key: key, end: end}
}

func (k *rbKernel) setInfo() (uint32, uint32, error) { return unix.NFT_SET_INTERVAL, 4, nil }

func (k *rbKernel) gen() (uint32, error) {
	if len(k.gens) == 0 {
		return 1, nil
	}
	g := k.gens[min(k.nGen, len(k.gens)-1)]
	k.nGen++
	return g, nil
}

func (k *rbKernel) get(key netip.Addr, flags uint32) (netip.Addr, uint32, bool, error) {
	if k.onGet != nil {
		k.onGet(k.nGet)
	}
	k.nGet++
	b := key.As4()
	q := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	wantEnd := flags&unix.NFT_SET_ELEM_INTERVAL_END != 0
	var n *rbNode
	if k.v418 {
		n = k.get418(q, wantEnd)
	} else {
		n = k.get514(q, wantEnd)
	}
	if n == nil {
		return netip.Addr{}, 0, false, nil
	}
	var f uint32
	if n.end {
		f = unix.NFT_SET_ELEM_INTERVAL_END
	}
	return addr4(n.key), f, true, nil
}

// get418 is 4.18's __nft_rbtree_get (every element active).
func (k *rbKernel) get418(q uint32, wantEnd bool) *rbNode {
	var interval *rbNode
	for n := k.root; n != nil; {
		switch {
		case n.key < q:
			interval = n
			n = n.left
		case n.key > q:
			n = n.right
		default:
			if n.end == wantEnd {
				return n
			}
			return nil
		}
	}
	if interval != nil && !interval.end {
		return interval
	}
	return nil
}

// get514 is 5.14's (and 6.12's) __nft_rbtree_get.
func (k *rbKernel) get514(q uint32, wantEnd bool) *rbNode {
	var interval *rbNode
	for n := k.root; n != nil; {
		switch {
		case n.key < q:
			if !wantEnd {
				interval = n
			}
			n = n.left
		case n.key > q:
			if wantEnd {
				interval = n
			}
			n = n.right
		default:
			if n.end == wantEnd {
				return n
			}
			if n.end {
				interval = nil
			}
			n = n.left
		}
	}
	if interval != nil && interval.end == wantEnd {
		return interval
	}
	return nil
}

func addr4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// ivs is a set's content as [first, last] intervals, the way nft and
// nftlib write it: a start at first and an end at last+1 (none when last is
// the top address), plus nft's end element at 0.0.0.0 when no interval
// starts there.
type iv struct{ first, last uint32 }

func build(ivs []iv, v418 bool, rng *rand.Rand) *rbKernel {
	type el struct {
		key uint32
		end bool
	}
	var els []el
	zero := false
	for _, x := range ivs {
		els = append(els, el{x.first, false})
		if x.last != 0xffffffff {
			els = append(els, el{x.last + 1, true})
		}
		zero = zero || x.first == 0
	}
	if !zero {
		els = append(els, el{0, true})
	}
	rng.Shuffle(len(els), func(i, j int) { els[i], els[j] = els[j], els[i] })
	k := &rbKernel{v418: v418}
	for _, e := range els {
		k.insert(e.key, e.end)
	}
	return k
}

func a4(s string) uint32 {
	b := netip.MustParseAddr(s).As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Every address around every boundary, on both kernels' get and many tree
// shapes: Lookup answers what the set holds, or ErrAmbiguous, and only at
// an address where an interval ends (an end element sits there). It never
// answers a wrong interval, nor "absent" for an address the set holds —
// the 4.18 defect the miss path works around (adjacent /25s, adjacent
// single hosts).
func TestLookupOnModelledRBTrees(t *testing.T) {
	ivs := []iv{
		{a4("0.0.0.0"), a4("0.255.255.255")},
		{a4("10.0.0.0"), a4("10.0.0.127")},
		{a4("10.0.0.128"), a4("10.0.0.255")},
		{a4("10.0.1.5"), a4("10.0.1.5")},
		{a4("10.0.1.6"), a4("10.0.1.6")},
		{a4("10.0.1.7"), a4("10.0.1.9")},
		{a4("10.0.2.0"), a4("10.0.2.9")},
		{a4("10.0.2.11"), a4("10.0.2.11")},
		{a4("10.0.2.12"), a4("10.0.2.20")},
		{a4("192.0.2.0"), a4("192.0.2.255")},
		{a4("255.255.255.0"), a4("255.255.255.255")},
	}
	var qs []uint32
	for _, x := range ivs {
		for _, b := range []uint32{x.first, x.last} {
			for d := -2; d <= 2; d++ {
				qs = append(qs, b+uint32(d))
			}
		}
	}
	qs = append(qs, a4("8.8.8.8"), a4("10.0.0.77"), a4("192.0.2.200"))
	holding := func(q uint32) *iv {
		for i := range ivs {
			if ivs[i].first <= q && q <= ivs[i].last {
				return &ivs[i]
			}
		}
		return nil
	}
	endAt := func(q uint32) bool {
		for _, x := range ivs {
			if x.last != 0xffffffff && x.last+1 == q {
				return true
			}
		}
		return false
	}
	for _, v418 := range []bool{true, false} {
		ambiguous := 0
		for seed := int64(0); seed < 200; seed++ {
			k := build(ivs, v418, rand.New(rand.NewSource(seed)))
			for _, q := range qs {
				a := addr4(q)
				m, ok, err := lookup(k, "n4", []netip.Addr{a})
				w := holding(q)
				switch {
				case errors.Is(err, ErrAmbiguous) && endAt(q):
					ambiguous++
				case err != nil:
					t.Fatalf("4.18=%v seed %d: %s: %v", v418, seed, a, err)
				case w == nil && ok[0]:
					t.Fatalf("4.18=%v seed %d: %s found in %v, the set does not hold it", v418, seed, a, m[0])
				case w != nil && !ok[0]:
					t.Fatalf("4.18=%v seed %d: %s not found, the set holds it in %s-%s", v418, seed, a, addr4(w.first), addr4(w.last))
				case w != nil && (m[0].From != addr4(w.first) || m[0].To != addr4(w.last)):
					t.Fatalf("4.18=%v seed %d: %s in %v, want %s-%s", v418, seed, a, m[0], addr4(w.first), addr4(w.last))
				}
			}
		}
		t.Logf("4.18=%v: %d ambiguous answers in %d lookups", v418, ambiguous, 200*len(qs))
	}
}

// A lookup that saw the generation change is done again, and fails with
// ErrChanged when it changes every time. Here a feed replace commits in the
// middle of an interval-end search: the set first holds 10.0.0.0/8, then
// 10.0.0.0/16. A lookup that mixed the two would report a range that never
// existed.
func TestLookupRetriesWhenTheRulesetChanges(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	old := []iv{{a4("10.0.0.0"), a4("10.255.255.255")}}
	repl := []iv{{a4("10.0.0.0"), a4("10.0.255.255")}}
	k := build(old, false, rng)
	k.gens = []uint32{1, 2, 2, 2}
	k.onGet = func(n int) {
		if n == 2 { // part-way through the first attempt
			k.root = build(repl, false, rng).root
		}
	}
	m, ok, err := lookup(k, "n4", []netip.Addr{netip.MustParseAddr("10.0.7.9")})
	if err != nil || !ok[0] {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if m[0].From != netip.MustParseAddr("10.0.0.0") || m[0].To != netip.MustParseAddr("10.0.255.255") {
		t.Errorf("got %v, want the new content, 10.0.0.0/16", m[0])
	}
	if k.nGen != 4 {
		t.Errorf("generation read %d times, want 4 (two attempts)", k.nGen)
	}

	k = build(old, false, rng)
	k.gens = []uint32{1, 2, 3, 4, 5, 6, 7}
	if _, _, err := lookup(k, "n4", []netip.Addr{netip.MustParseAddr("10.0.7.9")}); !errors.Is(err, ErrChanged) {
		t.Errorf("a generation that keeps changing: err %v, want ErrChanged", err)
	}
}
