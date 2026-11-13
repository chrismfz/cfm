package ipquery

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

// lookupBE is fakeBE with the kernel's single-element lookup, answered from
// the same fixed set contents (the element holding the address, as a range),
// so a lookup answer can be compared with a dump's.
type lookupBE struct {
	*fakeBE
	looked map[string]int
	fail   map[string]bool
}

func (l *lookupBE) LookupSetElems(ctx context.Context, table, set string, addrs []netip.Addr) ([]netip.Addr, []netip.Addr, []bool, error) {
	l.looked[set]++
	if l.fail[set] {
		return nil, nil, nil, errors.New("kernel cannot answer")
	}
	raw, ok := l.sets[set]
	if !ok {
		return nil, nil, nil, errors.New("no such set")
	}
	idx := indexSet([]byte(raw))
	from, to, found := make([]netip.Addr, len(addrs)), make([]netip.Addr, len(addrs)), make([]bool, len(addrs))
	for i, a := range addrs {
		for _, e := range idx.Match(Query{Addr: a}) {
			found[i] = true
			switch e.kind {
			case 'h':
				from[i], to[i] = e.addr, e.addr
			case 'n':
				from[i], to[i] = e.prefix.Addr(), lastAddr(e.prefix)
			default:
				from[i], to[i] = e.addr, e.to
			}
		}
	}
	return from, to, found, nil
}

func withLookup(be *fakeBE) *lookupBE {
	return &lookupBE{fakeBE: be, looked: map[string]int{}, fail: map[string]bool{}}
}

// Address queries are answered by the kernel lookup, with the hits a dump
// gives (an address, a prefix, a range), and no set is dumped.
func TestFindMany_AddressQueriesUseLookups(t *testing.T) {
	args := []string{"198.51.100.9", "192.0.2.77", "10.1.2.3", "203.0.113.15", "::ffff:198.51.100.8", "2001:db8::1", "8.8.8.8"}
	for name, mk := range map[string]func() *fakeBE{"nft": nftBackend, "nftlib": nftlibBackend} {
		t.Run(name, func(t *testing.T) {
			want, err := FindMany(context.Background(), mk(), args)
			if err != nil {
				t.Fatal(err)
			}
			be := withLookup(mk())
			got, err := FindMany(context.Background(), be, args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("lookup hits %v, dump hits %v", got, want)
			}
			if !reflect.DeepEqual(be.listed, map[string]int{"table": 1}) {
				t.Errorf("reads = %v, want the table listing only", be.listed)
			}
			wantLooked := map[string]int{"block_v4": 1, "block_ext_v4_nets_MYBLOCK": 1, "allow_v6": 1}
			if !reflect.DeepEqual(be.looked, wantLooked) {
				t.Errorf("lookups = %v, want one per set: %v", be.looked, wantLooked)
			}
		})
	}
}

// A CIDR query is an overlap, which no lookup answers: its family's sets are
// dumped (and answer that family's address queries too); the other family's
// sets are still looked up.
func TestFindMany_CIDRQueryDumpsItsFamily(t *testing.T) {
	be := withLookup(nftBackend())
	res, err := FindMany(context.Background(), be, []string{"198.51.100.0/24", "10.1.2.3", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := matches(res["198.51.100.0/24"]); len(got) != 2 {
		t.Errorf("CIDR hits %q, want both block_v4 addresses", got)
	}
	if got := matches(res["10.1.2.3"]); !reflect.DeepEqual(got, []string{"block_ext_v4_nets_MYBLOCK cidr 10.0.0.0/8 BLOCK MYBLOCK"}) {
		t.Errorf("10.1.2.3 hits %q", got)
	}
	if want := map[string]int{"table": 1, "block_v4": 1, "block_ext_v4_nets_MYBLOCK": 1}; !reflect.DeepEqual(be.listed, want) {
		t.Errorf("dumps = %v, want %v", be.listed, want)
	}
	if want := map[string]int{"allow_v6": 1}; !reflect.DeepEqual(be.looked, want) {
		t.Errorf("lookups = %v, want %v", be.looked, want)
	}
}

// A lookup the kernel cannot answer (an old kernel, an ambiguous interval
// boundary) is not "not found": that set is dumped instead.
func TestFindMany_FailedLookupDumpsTheSet(t *testing.T) {
	be := withLookup(nftBackend())
	be.fail["block_ext_v4_nets_MYBLOCK"] = true
	res, err := FindMany(context.Background(), be, []string{"192.0.2.77"})
	if err != nil {
		t.Fatal(err)
	}
	if got := matches(res["192.0.2.77"]); !reflect.DeepEqual(got, []string{"block_ext_v4_nets_MYBLOCK cidr 192.0.2.0/24 BLOCK MYBLOCK"}) {
		t.Errorf("hits %q", got)
	}
	if want := map[string]int{"table": 1, "block_ext_v4_nets_MYBLOCK": 1}; !reflect.DeepEqual(be.listed, want) {
		t.Errorf("dumps = %v, want %v", be.listed, want)
	}
}

// rangeEntry renders an element the way nft prints it, so a lookup's Match
// equals a dump's.
func TestRangeEntry(t *testing.T) {
	for _, c := range []struct{ from, to, want string }{
		{"192.0.2.7", "192.0.2.7", "192.0.2.7"},
		{"10.0.0.0", "10.255.255.255", "10.0.0.0/8"},
		{"0.0.0.0", "255.255.255.255", "0.0.0.0/0"},
		{"10.0.0.128", "10.0.0.255", "10.0.0.128/25"},
		{"10.0.0.0", "10.0.0.1", "10.0.0.0/31"},
		{"10.0.0.1", "10.0.0.2", "10.0.0.1-10.0.0.2"},
		{"10.0.0.0", "10.0.0.2", "10.0.0.0-10.0.0.2"},
		{"10.0.0.0", "10.0.1.127", "10.0.0.0-10.0.1.127"},
		{"2001:db8::", "2001:db8::ffff:ffff:ffff:ffff", "2001:db8::/64"},
		{"2001:db8::1", "2001:db8::9", "2001:db8::1-2001:db8::9"},
	} {
		e, ok := rangeEntry(netip.MustParseAddr(c.from), netip.MustParseAddr(c.to))
		if !ok || e.String() != c.want {
			t.Errorf("rangeEntry(%s, %s) = %v %v, want %s", c.from, c.to, e, ok, c.want)
		}
		if p, ok := ParseEntry(c.want); !ok || p != e {
			t.Errorf("%s: rangeEntry %+v, ParseEntry %+v", c.want, e, p)
		}
	}
	if _, ok := rangeEntry(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")); ok {
		t.Error("a reversed range is not an element")
	}
	if _, ok := rangeEntry(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("::1")); ok {
		t.Error("a range across families is not an element")
	}
}
