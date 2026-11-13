package ipquery

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"

	"cfm/internal/firewall"
)

// fakeBE serves ListTableJSON/ListSetJSON from fixed JSON and counts calls;
// any other Backend method panics.
type fakeBE struct {
	firewall.Backend
	table  []byte
	sets   map[string]string
	listed map[string]int
}

func (f *fakeBE) ListTableJSON(fam, table string) ([]byte, error) {
	f.listed["table"]++
	return f.table, nil
}

func (f *fakeBE) ListSetJSON(fam, table, set string) ([]byte, error) {
	f.listed[set]++
	s, ok := f.sets[set]
	if !ok {
		return nil, fmt.Errorf("no set %s", set)
	}
	return []byte(s), nil
}

// nft -j shapes: a timed element is {"elem":{"val":…}}, a prefix is
// {"prefix":…} (also inside "val"), an unaligned interval is {"range":[…]}.
func nftBackend() *fakeBE {
	set := func(name, typ, elems string) string {
		return fmt.Sprintf(`{"set":{"family":"inet","name":%q,"table":"cfm","type":%s,"elem":[%s]}}`, name, typ, elems)
	}
	return &fakeBE{
		table: []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}},` +
			set("block_v4", `"ipv4_addr"`, `"198.51.100.8"`) + `,` +
			set("block_ext_v4_nets_MYBLOCK", `"ipv4_addr"`, `{"prefix":{"addr":"10.0.0.0","len":8}}`) + `,` +
			set("ps_pairs_v4", `["ipv4_addr","inet_service"]`, ``) + `,` +
			set("allow_v6", `"ipv6_addr"`, ``) + `]}`),
		sets: map[string]string{
			"block_v4": `{"nftables":[{"metainfo":{}},` + set("block_v4", `"ipv4_addr"`,
				`"198.51.100.8",{"elem":{"val":"198.51.100.9","timeout":3600,"expires":100}}`) + `]}`,
			"block_ext_v4_nets_MYBLOCK": `{"nftables":[{"metainfo":{}},` + set("block_ext_v4_nets_MYBLOCK", `"ipv4_addr"`,
				`{"prefix":{"addr":"10.0.0.0","len":8}},`+
					`{"elem":{"val":{"prefix":{"addr":"192.0.2.0","len":24}},"timeout":3600,"expires":100}},`+
					`{"range":["203.0.113.10","203.0.113.20"]}`) + `]}`,
			"allow_v6": `{"nftables":[{"metainfo":{}},` + set("allow_v6", `"ipv6_addr"`, ``) + `]}`,
		},
		listed: map[string]int{},
	}
}

// nftlib's own shapes: the table's set_info lists the named address sets
// with their key type (meters such as syn_v4 are only in "sets"), a set
// lists elements as strings (an interval set's as CIDRs or "first-last").
func nftlibBackend() *fakeBE {
	return &fakeBE{
		table: []byte(`{"family":"inet","table":"cfm","sets":["allow_v6","block_ext_v4_nets_MYBLOCK","block_v4","ps_pairs_v4","syn_v4","tcp_in_ports"],` +
			`"set_info":[{"name":"allow_v6","type":"ipv6_addr"},{"name":"block_ext_v4_nets_MYBLOCK","type":"ipv4_addr"},` +
			`{"name":"block_v4","type":"ipv4_addr"},{"name":"ps_pairs_v4","type":"ipv4_addr . inet_service"},{"name":"tcp_in_ports","type":"inet_service"}]}`),
		sets: map[string]string{
			"block_v4":                  `{"family":"inet","table":"cfm","set":"block_v4","elements":["198.51.100.8","198.51.100.9"]}`,
			"block_ext_v4_nets_MYBLOCK": `{"family":"inet","table":"cfm","set":"block_ext_v4_nets_MYBLOCK","elements":["10.0.0.0/8","192.0.2.0/24","203.0.113.10-203.0.113.20"]}`,
			"allow_v6":                  `{"family":"inet","table":"cfm","set":"allow_v6","elements":[]}`,
		},
		listed: map[string]int{},
	}
}

func matches(hits []Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.Set+" "+h.Via+" "+h.Match+" "+h.Action+" "+h.Feed)
	}
	sort.Strings(out)
	return out
}

func TestFindMany_BothBackends(t *testing.T) {
	queries := map[string][]string{
		"198.51.100.9": {"block_v4 host 198.51.100.9 BLOCK "},
		"192.0.2.77":   {"block_ext_v4_nets_MYBLOCK cidr 192.0.2.0/24 BLOCK MYBLOCK"},
		"10.1.2.3":     {"block_ext_v4_nets_MYBLOCK cidr 10.0.0.0/8 BLOCK MYBLOCK"},
		"192.0.2.0/25": {"block_ext_v4_nets_MYBLOCK cidr 192.0.2.0/24 BLOCK MYBLOCK"},
		"198.51.100.0/24": {
			"block_v4 host 198.51.100.8 BLOCK ",
			"block_v4 host 198.51.100.9 BLOCK ",
		},
		"::ffff:198.51.100.8": {"block_v4 host 198.51.100.8 BLOCK "},
		"2001:db8::1":         nil,
		"8.8.8.8":             nil,
	}
	for name, mk := range map[string]func() *fakeBE{"nft": nftBackend, "nftlib": nftlibBackend} {
		t.Run(name, func(t *testing.T) {
			be := mk()
			var args []string
			for q := range queries {
				args = append(args, q)
			}
			args = append(args, "203.0.113.15")
			res, err := FindMany(context.Background(), be, args)
			if err != nil {
				t.Fatal(err)
			}
			for q, want := range queries {
				if got := matches(res[q]); !reflect.DeepEqual(got, want) {
					t.Errorf("%s: hits %q, want %q", q, got, want)
				}
				if res[q] == nil {
					t.Errorf("%s: nil hits, want an empty list", q)
				}
			}
			if got := matches(res["203.0.113.15"]); len(got) != 1 || !strings.Contains(got[0], "cidr 203.0.113.10-203.0.113.20") {
				t.Errorf("range: hits %q", got)
			}
			// One listing of the table and one dump per set, however many
			// queries; never a set of another type.
			want := map[string]int{"table": 1, "block_v4": 1, "block_ext_v4_nets_MYBLOCK": 1, "allow_v6": 1}
			if !reflect.DeepEqual(be.listed, want) {
				t.Errorf("reads = %v, want %v", be.listed, want)
			}
		})
	}
}

func TestFindMany_OnlyTheQueriedFamilies(t *testing.T) {
	be := nftlibBackend()
	if _, err := FindMany(context.Background(), be, []string{"198.51.100.9", "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if be.listed["allow_v6"] != 0 {
		t.Errorf("dumped a v6 set for v4 queries")
	}
}

func TestFindMany_InvalidArgument(t *testing.T) {
	for _, bad := range []string{"", "nope", "1.2.3.0/99"} {
		if _, err := FindMany(context.Background(), nftBackend(), []string{"1.2.3.4", bad}); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if _, err := Find(nftBackend(), "1.2.3.4/33"); err == nil || !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("Find: err = %v, want invalid CIDR", err)
	}
}

// Out of time between set dumps: what was read stands, with an error.
func TestFindMany_ContextEndsBetweenSets(t *testing.T) {
	be := nftlibBackend()
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	wrapped := &cancelAfter{fakeBE: be, n: 1, cancel: cancel, calls: &calls}
	res, err := FindMany(ctx, wrapped, []string{"10.1.2.3", "198.51.100.9"})
	if err == nil || !strings.Contains(err.Error(), "set 2 of 2") {
		t.Fatalf("err = %v, want a partial-read error", err)
	}
	// The manual block_v4 is read before the feed's set.
	if calls != 1 || len(res["10.1.2.3"]) != 0 || len(res["198.51.100.9"]) != 1 {
		t.Errorf("after %d dumps: %v", calls, res)
	}
}

// cancelAfter cancels ctx once n sets have been dumped.
type cancelAfter struct {
	*fakeBE
	n      int
	cancel func()
	calls  *int
}

func (c *cancelAfter) ListSetJSON(fam, table, set string) ([]byte, error) {
	*c.calls++
	if *c.calls >= c.n {
		c.cancel()
	}
	return c.fakeBE.ListSetJSON(fam, table, set)
}

// Block and allow sets are read before the others, so a lookup that runs out
// of time keeps those answers.
func TestFindMany_BlockAndAllowSetsFirst(t *testing.T) {
	var order []string
	be := &orderBE{fakeBE: &fakeBE{
		table: []byte(`{"set_info":[{"name":"th_syn_v4","type":"ipv4_addr"},{"name":"self_v4","type":"ipv4_addr"},` +
			`{"name":"allow_v4","type":"ipv4_addr"},{"name":"block_ext_v4_hosts_X","type":"ipv4_addr"}]}`),
		sets:   map[string]string{"th_syn_v4": `{}`, "self_v4": `{}`, "allow_v4": `{}`, "block_ext_v4_hosts_X": `{}`},
		listed: map[string]int{},
	}, order: &order}
	if _, err := FindMany(context.Background(), be, []string{"10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"allow_v4", "block_ext_v4_hosts_X", "th_syn_v4", "self_v4"}; !reflect.DeepEqual(order, want) {
		t.Errorf("read order %v, want %v", order, want)
	}
}

type orderBE struct {
	*fakeBE
	order *[]string
}

func (o *orderBE) ListSetJSON(fam, table, set string) ([]byte, error) {
	*o.order = append(*o.order, set)
	return o.fakeBE.ListSetJSON(fam, table, set)
}

func TestIndex_ZeroValue(t *testing.T) {
	var x Index[int]
	if !x.Add("10.0.0.0/8", 1) || len(x.Match(Query{Addr: netip.MustParseAddr("10.1.1.1")})) != 1 {
		t.Error("a zero Index must be usable")
	}
}

// Index.Match gives what a scan of every entry would, in entry order.
func TestIndex_MatchesAScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	addr := func() netip.Addr {
		if rng.Intn(4) == 0 {
			return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(rng.Intn(4))})
		}
		return netip.AddrFrom4([4]byte{10, byte(rng.Intn(3)), byte(rng.Intn(3)), byte(rng.Intn(8))})
	}
	idx := NewIndex[int]()
	var entries []Entry
	for i := 0; i < 400; i++ {
		a := addr()
		var s string
		switch rng.Intn(3) {
		case 0:
			s = a.String()
		case 1:
			s = netip.PrefixFrom(a, a.BitLen()-rng.Intn(20)).String()
		default:
			b := addr()
			for b.BitLen() != a.BitLen() {
				b = addr()
			}
			s = a.String() + "-" + b.String()
		}
		e, ok := ParseEntry(s)
		if !ok {
			t.Fatalf("ParseEntry(%q) failed", s)
		}
		idx.AddEntry(e, len(entries))
		entries = append(entries, e)
	}
	for i := 0; i < 500; i++ {
		a := addr()
		q := Query{Addr: a}
		if rng.Intn(3) == 0 {
			q = Query{Prefix: netip.PrefixFrom(a, a.BitLen()-rng.Intn(24)).Masked(), IsCIDR: true}
		}
		var want []int
		for j, e := range entries {
			if (q.IsCIDR && e.overlaps(q.Prefix)) || (!q.IsCIDR && e.overlaps(netip.PrefixFrom(q.Addr, q.Addr.BitLen()))) {
				want = append(want, j)
			}
		}
		if got := idx.Match(q); !reflect.DeepEqual(got, want) && (len(got) > 0 || len(want) > 0) {
			t.Fatalf("query %+v: got %v, want %v", q, got, want)
		}
	}
}

func TestParseEntry(t *testing.T) {
	for s, want := range map[string]string{
		"1.2.3.4":                 "1.2.3.4",
		" 1.2.3.4 ":               "1.2.3.4",
		"1.2.3.4/24":              "1.2.3.0/24",
		"::ffff:1.2.3.0/120":      "1.2.3.0/24",
		"::ffff:1.2.3.4":          "1.2.3.4",
		"1.2.3.1-1.2.3.10":        "1.2.3.1-1.2.3.10",
		"1.2.3.10-1.2.3.1":        "1.2.3.1-1.2.3.10",
		"2001:db8::1-2001:db8::9": "2001:db8::1-2001:db8::9",
		"2001:db8::/64":           "2001:db8::/64",
	} {
		e, ok := ParseEntry(s)
		if !ok || e.String() != want {
			t.Errorf("ParseEntry(%q) = %q, %v; want %q", s, e.String(), ok, want)
		}
	}
	for _, bad := range []string{"", "x", "abc-def", "1.2.3.4/33", "fe80::1%eth0", "1.2.3", "1.2.3.4-2001:db8::1"} {
		if _, ok := ParseEntry(bad); ok {
			t.Errorf("ParseEntry(%q) should fail", bad)
		}
	}
}

// A set whose dump fails is reported, not read as "not found": a block set
// that timed out used to be skipped, and the IP it holds looked unblocked.
func TestFindMany_UnreadSetIsReported(t *testing.T) {
	be := nftlibBackend()
	delete(be.sets, "block_v4")
	res, err := FindMany(context.Background(), be, []string{"198.51.100.9", "10.1.2.3"})
	if err == nil || !strings.Contains(err.Error(), "could not read 1 set(s): block_v4") {
		t.Fatalf("err = %v, want the unread block_v4 named", err)
	}
	if len(res["10.1.2.3"]) != 1 {
		t.Errorf("hits from the sets that were read must stand: %v", res)
	}
}

// The exec backend's set listing (no elements) is used when the backend has
// one: the full table dump carries every feed element and timed out.
func TestFindMany_PrefersSetListing(t *testing.T) {
	be := &setsBE{fakeBE: nftBackend()}
	if _, err := FindMany(context.Background(), be, []string{"198.51.100.9"}); err != nil {
		t.Fatal(err)
	}
	if be.lists != 1 || be.listed["table"] != 0 {
		t.Errorf("list sets=%d full=%d, want the set listing only", be.lists, be.listed["table"])
	}
}

// An nft that rejects the listing falls back to the full dump; one that ran
// out of time does not (the full dump is slower), and says so.
func TestFindMany_SetListingFallback(t *testing.T) {
	be := &setsBE{fakeBE: nftBackend(), err: fmt.Errorf("nft: unknown option")}
	res, err := FindMany(context.Background(), be, []string{"198.51.100.9"})
	if err != nil || be.listed["table"] != 1 || len(res["198.51.100.9"]) != 1 {
		t.Errorf("rejected listing: err=%v full=%d res=%v, want the full dump's answer", err, be.listed["table"], res)
	}
	be = &setsBE{fakeBE: nftBackend(), err: fmt.Errorf("nft -j -t list sets inet: %w", context.DeadlineExceeded)}
	_, err = FindMany(context.Background(), be, []string{"198.51.100.9"})
	if err == nil || !strings.Contains(err.Error(), "list sets") || be.listed["table"] != 0 {
		t.Errorf("timed-out listing: err=%v full=%d, want the listing's error and no full dump", err, be.listed["table"])
	}
}

type setsBE struct {
	*fakeBE
	lists int
	err   error
}

func (t *setsBE) ListSetsJSON(ctx context.Context, fam string) ([]byte, error) {
	t.lists++
	if t.err != nil {
		return nil, t.err
	}
	return t.fakeBE.table, nil
}

// A feed's union (what the rules drop on) answers; a per-feed copy is read
// only when the union matched, to name the feed, and `nft list sets` lists
// other tables' sets too.
func TestFindMany_FeedUnionAnswersPerFeedNames(t *testing.T) {
	set := func(table, name string) string {
		return fmt.Sprintf(`{"set":{"family":"inet","name":%q,"table":%q,"type":"ipv4_addr"}}`, name, table)
	}
	elems := func(name, e string) string {
		return fmt.Sprintf(`{"nftables":[{"set":{"name":%q,"table":"cfm","type":"ipv4_addr","elem":[%s]}}]}`, name, e)
	}
	mk := func() *fakeBE {
		return &fakeBE{
			table: []byte(`{"nftables":[` + set("cfm", "block_ext_v4_hosts") + `,` + set("cfm", "block_ext_v4_hosts_MYBLOCK") + `,` +
				set("cfm", "block_ext_v4_hosts_OTHER") + `,` + set("other", "block_v4") + `]}`),
			sets: map[string]string{
				"block_ext_v4_hosts":         elems("block_ext_v4_hosts", `"192.0.2.7","192.0.2.8"`),
				"block_ext_v4_hosts_MYBLOCK": elems("block_ext_v4_hosts_MYBLOCK", `"192.0.2.7"`),
				"block_ext_v4_hosts_OTHER":   elems("block_ext_v4_hosts_OTHER", ``),
			},
			listed: map[string]int{},
		}
	}

	// Not in the union: no per-feed set is read.
	be := mk()
	if res, err := FindMany(context.Background(), be, []string{"203.0.113.1"}); err != nil || len(res["203.0.113.1"]) != 0 {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if be.listed["block_ext_v4_hosts"] != 1 || be.listed["block_ext_v4_hosts_MYBLOCK"] != 0 || be.listed["block_v4"] != 0 {
		t.Errorf("dumps = %v: only the union (and no other table's set)", be.listed)
	}

	// In the union and a copy: the copy names the feed.
	be = mk()
	res, err := FindMany(context.Background(), be, []string{"192.0.2.7", "192.0.2.8"})
	if err != nil {
		t.Fatal(err)
	}
	if h := res["192.0.2.7"]; len(h) != 1 || h[0].Feed != "MYBLOCK" || h[0].Action != "BLOCK" {
		t.Errorf("192.0.2.7 = %+v, want one MYBLOCK hit", h)
	}
	// In the union only (a copy left short by a failed refill): still blocked.
	if h := res["192.0.2.8"]; len(h) != 1 || h[0].Set != "block_ext_v4_hosts" {
		t.Errorf("192.0.2.8 = %+v, want the union's hit", h)
	}

	// A copy that can't be read leaves the union's answer, and no error.
	be = mk()
	delete(be.sets, "block_ext_v4_hosts_MYBLOCK")
	res, err = FindMany(context.Background(), be, []string{"192.0.2.7"})
	if err != nil || len(res["192.0.2.7"]) != 1 || res["192.0.2.7"][0].Set != "block_ext_v4_hosts" {
		t.Errorf("res=%v err=%v, want the union's hit", res, err)
	}
}

// A union with one feed is named after it without dumping the copy: the
// second dump doubled a feed lookup's time.
func TestFindMany_SingleFeedUnionNamedWithoutDump(t *testing.T) {
	set := func(name string) string {
		return fmt.Sprintf(`{"set":{"family":"inet","name":%q,"table":"cfm","type":"ipv4_addr"}}`, name)
	}
	be := &fakeBE{
		table: []byte(`{"nftables":[` + set("block_ext_v4_hosts") + `,` + set("block_ext_v4_hosts_MYBLOCK") + `]}`),
		sets: map[string]string{
			"block_ext_v4_hosts": `{"nftables":[{"set":{"name":"block_ext_v4_hosts","type":"ipv4_addr","elem":["192.0.2.7"]}}]}`,
		},
		listed: map[string]int{},
	}
	res, err := FindMany(context.Background(), be, []string{"192.0.2.7"})
	if err != nil {
		t.Fatal(err)
	}
	if h := res["192.0.2.7"]; len(h) != 1 || h[0].Set != "block_ext_v4_hosts" || h[0].Feed != "MYBLOCK" {
		t.Errorf("hits = %+v, want the union's hit named MYBLOCK", h)
	}
	if be.listed["block_ext_v4_hosts_MYBLOCK"] != 0 {
		t.Errorf("dumps = %v: the single feed's copy is not read", be.listed)
	}
}
