package firewall

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// netFake models the sets a client /64 ban touches (block_v6_clients, the
// guard's self_v6 / ignore sets) next to the host set extendFake models,
// through SetElemWriter as both backends implement it.
type netFake struct {
	extendFake
	sets     map[string]map[string]time.Duration // set -> elem -> left (0 = permanent)
	readErr  map[string]error
	writeErr error
	writes   []string // "set elem replace"
}

func newNetFake() *netFake {
	return &netFake{
		extendFake: extendFake{left: map[string]time.Duration{}},
		sets:       map[string]map[string]time.Duration{},
		readErr:    map[string]error{},
	}
}

func (f *netFake) set(name string) map[string]time.Duration {
	if f.sets[name] == nil {
		f.sets[name] = map[string]time.Duration{}
	}
	return f.sets[name]
}

func (f *netFake) ListSetElementsTimed(set string) ([]SetElementTimed, error) {
	if err := f.readErr[set]; err != nil {
		return nil, err
	}
	var out []SetElementTimed
	for e, d := range f.set(set) {
		out = append(out, SetElementTimed{Elem: e, Expires: d})
	}
	return out, nil
}

func (f *netFake) WriteSetElem(set, elem string, ttl *time.Duration, replace bool) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	if _, exists := f.set(set)[elem]; exists && !replace {
		return errors.New("element exists") // nft would keep the old timeout
	}
	f.writes = append(f.writes, set+" "+elem)
	f.set(set)[elem] = 0
	if ttl != nil {
		f.set(set)[elem] = *ttl
	}
	return nil
}

func (f *netFake) DeleteSetElem(set, elem string) error {
	delete(f.set(set), elem)
	return nil
}

const (
	v6a  = "2001:db8:1:2::a"
	v6b  = "2001:db8:1:2:ffff::b"
	net6 = "2001:db8:1:2::/64"
)

func TestExtendClientBlockBansTheV6Slash64(t *testing.T) {
	f := newNetFake()
	elem, kept, err := ExtendClientBlock(f, net.ParseIP(v6a), 6*time.Hour)
	if err != nil || kept || elem != net6 || f.set(BlockV6Clients)[net6] != 6*time.Hour {
		t.Fatalf("first ban: elem=%q kept=%v err=%v sets=%v", elem, kept, err, f.sets)
	}
	if len(f.left) != 0 {
		t.Fatalf("the address must not be banned on its own: %v", f.left)
	}
	// Another address of the same /64, shorter: kept, nothing written.
	n := len(f.writes)
	elem, kept, err = ExtendClientBlock(f, net.ParseIP(v6b), time.Hour)
	if err != nil || !kept || elem != net6 || f.set(BlockV6Clients)[net6] != 6*time.Hour || len(f.writes) != n {
		t.Fatalf("1h in a 6h /64: elem=%q kept=%v err=%v sets=%v", elem, kept, err, f.sets)
	}
	// Longer: replaced (one transaction in the backends).
	elem, kept, err = ExtendClientBlock(f, net.ParseIP(v6b), 24*time.Hour)
	if err != nil || kept || elem != net6 || f.set(BlockV6Clients)[net6] != 24*time.Hour {
		t.Fatalf("24h over 6h: elem=%q kept=%v err=%v sets=%v", elem, kept, err, f.sets)
	}
	// Permanent stays permanent.
	f.set(BlockV6Clients)[net6] = 0
	if _, kept, _ := ExtendClientBlock(f, net.ParseIP(v6a), 48*time.Hour); !kept || f.set(BlockV6Clients)[net6] != 0 {
		t.Fatalf("48h over permanent: kept=%v sets=%v", kept, f.sets)
	}
	// Under a second: one second, never "0s" (permanent).
	g := newNetFake()
	if _, _, err := ExtendClientBlock(g, net.ParseIP(v6a), time.Millisecond); err != nil || g.set(BlockV6Clients)[net6] != time.Second {
		t.Fatalf("1ms: err=%v sets=%v", err, g.sets)
	}
	// The operator's block_v6_nets is never read or written for it.
	h := newNetFake()
	h.set("block_v6_nets")["2001:db8:1::/48"] = time.Minute
	if elem, _, _ := ExtendClientBlock(h, net.ParseIP(v6a), time.Hour); elem != net6 || h.set("block_v6_nets")["2001:db8:1::/48"] != time.Minute {
		t.Fatalf("with a manual /48: elem=%q sets=%v", elem, h.sets)
	}
}

// A /64 holding this node's address or an ignored one is never banned as a
// whole (nft accepts none of them before the drops): the address is.
func TestExtendClientBlockGuards(t *testing.T) {
	for name, setup := range map[string]func(*netFake){
		"self address":   func(f *netFake) { f.set("self_v6")["2001:db8:1:2::1/128"] = 0 },
		"ignored host":   func(f *netFake) { f.set("ignore_v6")["2001:db8:1:2::77"] = 0 },
		"ignored net":    func(f *netFake) { f.set("ignore_v6_nets")["2001:db8:1::/48"] = 0 },
		"IGNORE_IPS":     func(f *netFake) { SetClientNetExempt(func(p netip.Prefix) bool { return p.String() == net6 }) },
		"a guard unread": func(f *netFake) { f.readErr["self_v6"] = errors.New("nft busy") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { SetClientNetExempt(nil) })
			f := newNetFake()
			setup(f)
			elem, _, err := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour)
			if err != nil || elem != v6a || f.left[v6a] != time.Hour || len(f.set(BlockV6Clients)) != 0 {
				t.Fatalf("elem=%q err=%v left=%v clients=%v, want the address banned", elem, err, f.left, f.set(BlockV6Clients))
			}
			if elem, err := BlockClientPermanent(f, net.ParseIP(v6a), "c"); err != nil || elem != v6a {
				t.Fatalf("permanent: elem=%q err=%v", elem, err)
			}
		})
	}
	// Elsewhere: no effect.
	f := newNetFake()
	f.set("self_v6")["2001:db8:9::1/128"] = 0
	f.set("self_v6")["::1/128"] = 0
	f.set("self_v6")["fe80::/10"] = 0
	f.set("ignore_v6")["198.51.100.7"] = 0
	if elem, _, _ := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour); elem != net6 {
		t.Fatalf("unrelated guard elements: elem=%q", elem)
	}
}

func TestExtendClientBlockFallsBackToTheAddress(t *testing.T) {
	for name, mut := range map[string]func(*netFake){
		"read fails":  func(f *netFake) { f.readErr[BlockV6Clients] = errors.New("nft busy") },
		"write fails": func(f *netFake) { f.writeErr = errors.New("refused") },
	} {
		f := newNetFake()
		mut(f)
		elem, _, err := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour)
		if err != nil || elem != v6a || f.left[v6a] != time.Hour {
			t.Errorf("%s: elem=%q err=%v left=%v, want the address banned", name, elem, err, f.left)
		}
	}
	// A backend without SetElemWriter: the address.
	e := &extendFake{left: map[string]time.Duration{}}
	if elem, _, err := ExtendClientBlock(e, net.ParseIP(v6a), time.Hour); err != nil || elem != v6a {
		t.Errorf("no SetElemWriter: elem=%q err=%v", elem, err)
	}
	// Not grouped: IPv4, v4-mapped, loopback, link-local, ::/64, NAT64.
	for _, s := range []string{"203.0.113.9", "::ffff:203.0.113.9", "::1", "fe80::1", "::2", "64:ff9b::1.2.3.4"} {
		f := newNetFake()
		ip := net.ParseIP(s)
		elem, _, err := ExtendClientBlock(f, ip, time.Hour)
		if err != nil || elem != ip.String() || len(f.set(BlockV6Clients)) != 0 {
			t.Errorf("%s: elem=%q err=%v sets=%v, want the address only", s, elem, err, f.sets)
		}
	}
}

// The kernel autoblock's path (packets, whose source can be spoofed) stays
// per address.
func TestExtendBlockResultStaysPerAddress(t *testing.T) {
	f := newNetFake()
	res, err := ExtendBlockResult(f, net.ParseIP(v6a), time.Hour)
	if err != nil || res.Added != 1 || res.Net != "" || f.left[v6a] != time.Hour || len(f.set(BlockV6Clients)) != 0 {
		t.Fatalf("res=%+v err=%v left=%v sets=%v", res, err, f.left, f.sets)
	}
}

func TestBlockClientPermanent(t *testing.T) {
	f := newNetFake()
	elem, err := BlockClientPermanent(f, net.ParseIP(v6a), "c")
	if err != nil || elem != net6 || f.set(BlockV6Clients)[net6] != 0 {
		t.Fatalf("new: elem=%q err=%v sets=%v", elem, err, f.sets)
	}
	// A TTL'd /64 becomes permanent.
	f = newNetFake()
	f.set(BlockV6Clients)[net6] = time.Hour
	if elem, err := BlockClientPermanent(f, net.ParseIP(v6b), "c"); err != nil || elem != net6 || f.set(BlockV6Clients)[net6] != 0 {
		t.Fatalf("over a 1h /64: elem=%q err=%v sets=%v", elem, err, f.sets)
	}
	// IPv4: the address.
	f = newNetFake()
	if elem, err := BlockClientPermanent(f, net.ParseIP("203.0.113.9"), "c"); err != nil || elem != "203.0.113.9" || len(f.set(BlockV6Clients)) != 0 {
		t.Fatalf("v4: elem=%q err=%v", elem, err)
	}
}

func TestRemoveClientNetAndExtendBlockNet(t *testing.T) {
	f := newNetFake()
	f.set(BlockV6Clients)[net6] = time.Hour
	if n, err := RemoveClientNet(f, net.ParseIP(v6b)); err != nil || n != net6 || len(f.set(BlockV6Clients)) != 0 {
		t.Fatalf("RemoveClientNet: %q %v %v", n, err, f.sets)
	}
	if n, _ := RemoveClientNet(f, net.ParseIP("203.0.113.9")); n != "" {
		t.Fatalf("IPv4: %q", n)
	}
	// The TTL ban restore.
	p := netip.MustParsePrefix(net6)
	if res, err := ExtendBlockNet(f, p, time.Hour); err != nil || res.Added != 1 {
		t.Fatalf("ExtendBlockNet: %+v %v", res, err)
	}
	if _, err := ExtendBlockNet(f, netip.MustParsePrefix("2001:db8:1:2::1/64"), time.Hour); err == nil {
		t.Fatal("a non-canonical prefix must be refused")
	}
	f.writeErr = errors.New("refused")
	if _, err := ExtendBlockNet(f, netip.MustParsePrefix("2001:db8:5:6::/64"), time.Hour); err == nil {
		t.Fatal("a write failure must be reported (no address to fall back to)")
	}
}

func TestElemRange(t *testing.T) {
	for _, c := range []struct{ in, lo, hi string }{
		{"2001:db8:1:2::/64", "2001:db8:1:2::", "2001:db8:1:2:ffff:ffff:ffff:ffff"},
		{"2001:db8::/32", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"::/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2001:db8::1", "2001:db8::1", "2001:db8::1"},
		{"2001:db8::1-2001:db8::9", "2001:db8::1", "2001:db8::9"},
		{"198.51.100.0/24", "198.51.100.0", "198.51.100.255"},
		{"0.0.0.0/0", "0.0.0.0", "255.255.255.255"},
		{"10.0.0.7/32", "10.0.0.7", "10.0.0.7"},
	} {
		lo, hi, ok := ElemRange(c.in)
		if !ok || lo.String() != c.lo || hi.String() != c.hi {
			t.Errorf("ElemRange(%q) = %v %v %v, want %s %s", c.in, lo, hi, ok, c.lo, c.hi)
		}
	}
	for _, bad := range []string{"", "x", "2001:db8::9-2001:db8::1", "10.0.0.1-2001:db8::1", "2001:db8::/129"} {
		if _, _, ok := ElemRange(bad); ok {
			t.Errorf("ElemRange(%q) parsed", bad)
		}
	}
}

func TestChainRulesAnchorHandle(t *testing.T) {
	listing := `table inet cfm {
	chain input {
		type filter hook input priority filter; policy drop;
		ip6 saddr @self_v6 accept # handle 4
		ip6 saddr @block_v6_nets drop # handle 21
		ct state established,related ip6 saddr @block_v6_nets drop # handle 30
		ip6 saddr @block_v6_nets drop # handle 55
	}
}`
	c := ParseChainRules(listing)
	if h := c.AnchorHandle(`ip6 saddr @block_v6_clients drop`); h != "21" {
		t.Errorf("early anchor: %q, want the first copy's 21", h)
	}
	if h := c.AnchorHandle(`ct state established,related ip6 saddr @block_v6_clients drop`); h != "30" {
		t.Errorf("est/rel anchor: %q", h)
	}
	if h := c.AnchorHandle(`ip6 saddr @block_v6 drop`); h != "" {
		t.Errorf("an unanchored rule: %q", h)
	}
	if h := ParseChainRules("").AnchorHandle(`ip6 saddr @block_v6_clients drop`); h != "" {
		t.Errorf("a new chain: %q", h)
	}
}
