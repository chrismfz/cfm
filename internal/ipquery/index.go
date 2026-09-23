package ipquery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"cfm/internal/firewall"
)

// Query is a parsed IP or CIDR argument. A v4-mapped IPv6 address is taken as
// the IPv4 address it maps.
type Query struct {
	Addr   netip.Addr   // an IP query
	Prefix netip.Prefix // a CIDR query, masked
	IsCIDR bool
}

// ParseQuery parses an IP or a CIDR, with the syntax net.ParseIP and
// net.ParseCIDR accept.
func ParseQuery(s string) (Query, error) {
	if strings.Contains(s, "/") {
		p, ok := parsePrefix(s)
		if !ok {
			return Query{}, fmt.Errorf("invalid CIDR %q", s)
		}
		return Query{Prefix: p, IsCIDR: true}, nil
	}
	a, ok := parseAddr(s)
	if !ok {
		return Query{}, fmt.Errorf("invalid IP %q", s)
	}
	return Query{Addr: a}, nil
}

func (q Query) family() string {
	a := q.Addr
	if q.IsCIDR {
		a = q.Prefix.Addr()
	}
	if a.Is4() {
		return "v4"
	}
	return "v6"
}

func parseAddr(s string) (netip.Addr, bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(ip)
	return a.Unmap(), ok
}

func parsePrefix(s string) (netip.Prefix, bool) {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	bits, _ := n.Mask.Size()
	if a.Is4In6() && bits >= 96 {
		a, bits = a.Unmap(), bits-96
	}
	return netip.PrefixFrom(a, bits).Masked(), true
}

// Entry is one stored address, prefix or address range.
type Entry struct {
	kind     byte // 'h' address, 'n' prefix, 'r' range
	addr, to netip.Addr
	prefix   netip.Prefix
}

// ParseEntry parses an address, a CIDR, or a "from-to" range — the forms
// cfm's sets and the list files hold. A range's ends must be of one family.
func ParseEntry(s string) (Entry, bool) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "-"); i > 0 {
		from, ok1 := parseAddr(strings.TrimSpace(s[:i]))
		to, ok2 := parseAddr(strings.TrimSpace(s[i+1:]))
		if ok1 && ok2 {
			if from.BitLen() != to.BitLen() {
				return Entry{}, false
			}
			if to.Less(from) {
				from, to = to, from
			}
			return Entry{kind: 'r', addr: from, to: to}, true
		}
	}
	if strings.Contains(s, "/") {
		p, ok := parsePrefix(s)
		return Entry{kind: 'n', prefix: p}, ok
	}
	a, ok := parseAddr(s)
	return Entry{kind: 'h', addr: a}, ok
}

// IsAddr reports whether the entry is a single address.
func (e Entry) IsAddr() bool { return e.kind == 'h' }

func (e Entry) String() string {
	switch e.kind {
	case 'h':
		return e.addr.String()
	case 'n':
		return e.prefix.String()
	}
	return e.addr.String() + "-" + e.to.String()
}

func (e Entry) overlaps(p netip.Prefix) bool {
	switch e.kind {
	case 'h':
		return p.Contains(e.addr)
	case 'n':
		return p.Overlaps(e.prefix)
	}
	return p.Contains(e.addr) || p.Contains(e.to) || e.holds(p.Addr())
}

func (e Entry) holds(a netip.Addr) bool {
	return e.addr.BitLen() == a.BitLen() && e.addr.Compare(a) <= 0 && a.Compare(e.to) <= 0
}

// Index answers, for many queries, which of its entries hold an address or
// overlap a prefix, without scanning the entries per query: an address is a
// map lookup per stored prefix length, and only ranges (rare) are scanned.
// Results keep the order the entries were added in.
type Index[T any] struct {
	entries []Entry
	vals    []T
	addrs   map[netip.Addr][]int
	nets    map[int]map[netip.Addr][]int // prefix length → masked address
	ranges  []int
}

// NewIndex returns an empty Index (so does new(Index[T])).
func NewIndex[T any]() *Index[T] { return &Index[T]{} }

// Add parses entry (see ParseEntry) and adds it; false if it doesn't parse.
func (x *Index[T]) Add(entry string, v T) bool {
	e, ok := ParseEntry(entry)
	if ok {
		x.AddEntry(e, v)
	}
	return ok
}

func (x *Index[T]) AddEntry(e Entry, v T) {
	if x.addrs == nil {
		x.addrs, x.nets = map[netip.Addr][]int{}, map[int]map[netip.Addr][]int{}
	}
	i := len(x.entries)
	x.entries = append(x.entries, e)
	x.vals = append(x.vals, v)
	switch e.kind {
	case 'h':
		x.addrs[e.addr] = append(x.addrs[e.addr], i)
	case 'n':
		m := x.nets[e.prefix.Bits()]
		if m == nil {
			m = map[netip.Addr][]int{}
			x.nets[e.prefix.Bits()] = m
		}
		m[e.prefix.Addr()] = append(m[e.prefix.Addr()], i)
	default:
		x.ranges = append(x.ranges, i)
	}
}

// Match returns the values of the entries that hold q's address, or that
// overlap q's prefix.
func (x *Index[T]) Match(q Query) []T {
	var pos []int
	if q.IsCIDR {
		for i, e := range x.entries {
			if e.overlaps(q.Prefix) {
				pos = append(pos, i)
			}
		}
	} else {
		pos = append(pos, x.addrs[q.Addr]...)
		for bits, m := range x.nets {
			if p, err := q.Addr.Prefix(bits); err == nil {
				pos = append(pos, m[p.Addr()]...)
			}
		}
		for _, i := range x.ranges {
			if x.entries[i].holds(q.Addr) {
				pos = append(pos, i)
			}
		}
		sort.Ints(pos)
	}
	out := make([]T, len(pos))
	for j, i := range pos {
		out[j] = x.vals[i]
	}
	return out
}

// FindMany answers Find for many IPs/CIDRs at once: one listing of the table
// and one dump of each relevant set, however many queries — Find used to dump
// every set of the family for each one. Results are keyed by the argument as
// given; an argument that is not an IP or CIDR is an error. When ctx ends
// between two set dumps, FindMany returns what the sets read so far hold,
// with an error saying how far it got.
//
// It reads both backends' JSON: the nft backend's `nft -j` output
// ({"nftables":[…]}) and nftlib's own ({"sets":[…]} for the table,
// {"elements":[…]} for a set). Find read only the first, so on nftlib nodes it
// found nothing.
func FindMany(ctx context.Context, be firewall.Backend, args []string) (map[string][]Hit, error) {
	qs := make(map[string]Query, len(args))
	fams := map[string]bool{}
	for _, a := range args {
		q, err := ParseQuery(a)
		if err != nil {
			return nil, err
		}
		qs[a] = q
		fams[q.family()] = true
	}
	out := make(map[string][]Hit, len(qs))
	for a := range qs {
		out[a] = []Hit{}
	}
	if len(qs) == 0 {
		return out, nil
	}

	tblOut, err := be.ListTableJSON("inet", "cfm")
	if err != nil {
		return nil, fmt.Errorf("cannot read nftables table inet cfm (maybe needs sudo?): %v\n%s", err, string(tblOut))
	}
	sets := cfmSets(tblOut)
	for i, sd := range sets {
		if !fams[sd.family] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("stopped at set %d of %d: %w", i+1, len(sets), err)
		}
		so, err := be.ListSetJSON("inet", "cfm", sd.name)
		if err != nil {
			continue
		}
		idx := indexSet(so)
		for a, q := range qs {
			if q.family() != sd.family {
				continue
			}
			for _, e := range idx.Match(q) {
				via := "cidr"
				if e.IsAddr() {
					via = "host"
				}
				out[a] = append(out[a], Hit{Set: sd.name, Action: sd.action, Scope: via, Match: e.String(), Feed: sd.feed, Family: sd.family, Via: via})
			}
		}
	}
	return out, nil
}

var addrType = map[string]string{"v4": "ipv4_addr", "v6": "ipv6_addr"}

// cfmSets lists the table's classifiable address sets, in table order, from
// either backend's table JSON: nft's {"nftables":[{"set":{…}}]} or nftlib's
// "set_info" (which, like nft's listing, leaves out meters). A set counts
// when its name classifies and its key type is an address of the name's
// family; a concatenated type (an array in nft's JSON) is not.
func cfmSets(tableJSON []byte) []setDesc {
	type named struct {
		Name string `json:"name"`
		Type any    `json:"type"`
	}
	var doc struct {
		Nftables []struct {
			Set *named `json:"set,omitempty"`
		} `json:"nftables"`
		SetInfo []named `json:"set_info"` // nftlib
	}
	_ = json.Unmarshal(tableJSON, &doc)
	all := doc.SetInfo
	for _, n := range doc.Nftables {
		if n.Set != nil {
			all = append(all, *n.Set)
		}
	}
	var out []setDesc
	for _, n := range all {
		sd := classifySetName(n.Name)
		if sd.name != "" && n.Type == addrType[sd.family] {
			out = append(out, sd)
		}
	}
	return out
}

// indexSet parses a set dump from either backend: nft's {"nftables":[{"set":
// {"elem":[…]}}]} or nftlib's {"elements":[…]}. An element is an address, a
// prefix or a range, bare or wrapped as {"elem":{"val":…, "timeout":…}} — the
// form an element with a timeout takes, so a TTL'd prefix is {"elem":{"val":
// {"prefix":…}}}.
func indexSet(raw []byte) *Index[Entry] {
	idx := NewIndex[Entry]()
	var root struct {
		Nftables []struct {
			Set *struct {
				Elem     []any `json:"elem"`
				Elements []any `json:"elements"`
			} `json:"set,omitempty"`
		} `json:"nftables"`
		Elements []any `json:"elements"` // nftlib
	}
	if json.Unmarshal(raw, &root) != nil {
		return idx
	}
	elems := root.Elements
	for _, n := range root.Nftables {
		if n.Set != nil {
			elems = append(elems, n.Set.Elem...)
			elems = append(elems, n.Set.Elements...)
		}
	}
	for _, e := range elems {
		if s := elemString(e); s != "" {
			if en, ok := ParseEntry(s); ok {
				idx.AddEntry(en, en)
			}
		}
	}
	return idx
}

// elemString renders an nft JSON set element as an address, "addr/len" or
// "from-to"; "" for anything else.
func elemString(e any) string {
	switch v := e.(type) {
	case string:
		return v
	case map[string]any:
		switch {
		case v["elem"] != nil:
			return elemString(v["elem"])
		case v["val"] != nil:
			return elemString(v["val"])
		case v["prefix"] != nil:
			p, _ := v["prefix"].(map[string]any)
			addr, _ := p["addr"].(string)
			l, ok := p["len"].(float64)
			if addr != "" && ok {
				return fmt.Sprintf("%s/%d", addr, int(l))
			}
		case v["range"] != nil:
			r, _ := v["range"].([]any)
			if len(r) == 2 {
				a, _ := r[0].(string)
				b, _ := r[1].(string)
				if a != "" && b != "" {
					return a + "-" + b
				}
			}
		}
	}
	return ""
}
