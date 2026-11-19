package firewall

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// netFake models the sets a client /64 ban touches (block_v6_clients, the
// guard's self_v6 / ignore sets) next to the host set extendFake models,
// through SetElemWriter as both backends implement it.
type netFake struct {
	extendFake
	sets      map[string]map[string]time.Duration // set -> elem -> left (0 = permanent)
	readErr   map[string]error
	writeErr  error
	deleteErr error
	batchErr  error
	batches   int
	reads     map[string]int
	writes    []string // "set elem"
	deletes   []string // "set elem"
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
	if f.reads == nil {
		f.reads = map[string]int{}
	}
	f.reads[set]++
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

func (f *netFake) WriteSetElems(set string, elems []SetElemWrite) error {
	f.batches++
	if f.batchErr != nil {
		return f.batchErr // all or none, as one transaction
	}
	for _, e := range elems {
		if err := f.WriteSetElem(set, e.Elem, e.TTL, e.Replace); err != nil {
			return err
		}
	}
	return nil
}

func (f *netFake) DeleteSetElem(set, elem string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletes = append(f.deletes, set+" "+elem)
	delete(f.set(set), elem)
	return nil
}

// testLocalAddrs stands in for the interfaces (the real ones would make the
// tests depend on the machine they run on).
var testLocalAddrs []string

func init() {
	guardCacheTTL = 0                         // each ban reads its guards (TestGuardViewIsCached sets it)
	procIPv6Route = "/nonexistent/ipv6_route" // no gateways but the tests' own
	localAddrs = func() ([]net.Addr, error) {
		var out []net.Addr
		for _, s := range testLocalAddrs {
			ip, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, err
			}
			n.IP = ip
			out = append(out, n)
		}
		return out, nil
	}
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
		"self address": func(f *netFake) { f.set("self_v6")["2001:db8:1:2::1/128"] = 0 },
		"ignored host": func(f *netFake) { f.set("ignore_v6")["2001:db8:1:2::77"] = 0 },
		"ignored net":  func(f *netFake) { f.set("ignore_v6_nets")["2001:db8:1::/48"] = 0 },
		"IGNORE_IPS": func(f *netFake) {
			SetClientNetExempt("ignore", func(p netip.Prefix) bool { return p.String() == net6 })
		},
		"trusted proxy": func(f *netFake) {
			SetClientNetExempt("trusted_proxies", func(p netip.Prefix) bool { return p.String() == net6 })
		},
		"interface addr": func(f *netFake) { testLocalAddrs = []string{"2001:db8:1:2::9/64"} },
		"allowed host":   func(f *netFake) { f.set("allow_v6")["2001:db8:1:2::55"] = 0 },
		"allowed dyn":    func(f *netFake) { f.set("allow_dyn_v6")["2001:db8:1:2::56"] = 0 },
		"allowed net":    func(f *netFake) { f.set("allow_v6_nets")["2001:db8:1:2:8000::/65"] = 0 },
		"fleet allow": func(f *netFake) {
			SetClientNetExempt("allow_sets", func(p netip.Prefix) bool { return p.String() == net6 })
		},
		"a guard unread": func(f *netFake) { f.readErr["self_v6"] = errors.New("nft busy") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() {
				SetClientNetExempt("ignore", nil)
				SetClientNetExempt("trusted_proxies", nil)
				SetClientNetExempt("allow_sets", nil)
				testLocalAddrs = nil
			})
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

// ExtendBlockNet (the TTL ban restore) reports a guarded /64 with
// ErrClientNetGuarded, so the restore counts it excluded, not failed.
func TestExtendBlockNetGuarded(t *testing.T) {
	f := newNetFake()
	f.set("ignore_v6")["2001:db8:1:2::77"] = 0
	_, err := ExtendBlockNet(f, netip.MustParsePrefix(net6), time.Hour)
	if !errors.Is(err, ErrClientNetGuarded) || len(f.set(BlockV6Clients)) != 0 {
		t.Fatalf("err=%v sets=%v", err, f.sets)
	}
}

// A mass unblock reads block_v6_clients once and deletes only the /64s it
// holds, once each; a table from before the set frees nothing, without error.
func TestRemoveClientNets(t *testing.T) {
	f := newNetFake()
	f.set(BlockV6Clients)[net6] = time.Hour
	f.set(BlockV6Clients)["2001:db8:9:9::/64"] = time.Hour
	ips := []net.IP{net.ParseIP(v6a), net.ParseIP(v6b), net.ParseIP("2001:db8:5:5::1"), net.ParseIP("203.0.113.9")}
	if errs := RemoveClientNets(f, ips); len(errs) != 0 {
		t.Fatalf("errs=%v", errs)
	}
	if _, ok := f.set(BlockV6Clients)[net6]; ok || len(f.set(BlockV6Clients)) != 1 {
		t.Fatalf("after: %v (want only the unrelated /64 left)", f.sets)
	}
	// One delete, for the /64 the set held; none for the one it did not.
	if len(f.deletes) != 1 || f.deletes[0] != BlockV6Clients+" "+net6 {
		t.Fatalf("deletes %v, want the held /64 once", f.deletes)
	}
	g := newNetFake()
	g.readErr[BlockV6Clients] = errors.New(`nft: Error: No such file or directory; set block_v6_clients`)
	if errs := RemoveClientNets(g, ips); len(errs) != 0 {
		t.Fatalf("missing set: errs=%v", errs)
	}
	h := newNetFake()
	h.readErr[BlockV6Clients] = errors.New("nft busy")
	if errs := RemoveClientNets(h, ips); errs[v6a] == nil || errs[v6b] == nil || errs["203.0.113.9"] != nil {
		t.Fatalf("read error: errs=%v", errs)
	}
}

// Present: an anchored rule counts only as itself, never inside its
// `ct state established,related` twin.
func TestChainRulesPresentIsExactForAnchoredRules(t *testing.T) {
	c := ParseChainRules("chain input {\n\tct state established,related ip6 saddr @block_v6_clients drop # handle 9\n}")
	if c.Present(`ip6 saddr @block_v6_clients drop`) {
		t.Fatal("the plain drop read present inside its est/rel twin")
	}
	if !c.Present(`ct state established,related ip6 saddr @block_v6_clients drop`) {
		t.Fatal("the est/rel drop itself is present")
	}
	if !c.Present(`ip6 saddr @block_v6_nets drop`) == c.Has(`ip6 saddr @block_v6_nets drop`) {
		t.Fatal("an unanchored rule keeps Has's answer")
	}
}

// RemoveClientNet: a table from before block_v6_clients (no such set) frees
// nothing, without error; any other failure is reported.
func TestRemoveClientNetMissingSet(t *testing.T) {
	f := newNetFake()
	f.deleteErr = errors.New(`nft: Error: No such file or directory; did you mean set 'block_v6_nets'?`)
	if _, err := RemoveClientNet(f, net.ParseIP(v6a)); err != nil {
		t.Fatalf("missing set: %v", err)
	}
	f.deleteErr = errors.New("nft: exec: \"nft\": executable file not found in $PATH")
	if _, err := RemoveClientNet(f, net.ParseIP(v6a)); err == nil {
		t.Fatal("a missing nft binary must be an error, not a missing set")
	}
}

func TestIsMissingSet(t *testing.T) {
	for err, want := range map[error]bool{
		nil:            false,
		syscall.ENOENT: true,
		errors.New("Error: No such file or directory"):   true,
		errors.New("executable file not found in $PATH"): false,
		exec.ErrNotFound:        false,
		errors.New("not found"): false,
	} {
		if got := IsMissingSet(err); got != want {
			t.Errorf("IsMissingSet(%v) = %v, want %v", err, got, want)
		}
	}
}

// Until the edge ban store registers its allow snapshot ("allow_sets"), the
// guard reads the fleet whitelist's IPv6 sets itself (boot, before the first
// reconcile); once it is registered, it does not.
func TestGuardReadsTheFleetWhitelistWithoutASnapshot(t *testing.T) {
	f := newNetFake()
	f.set("allow_ext_v6_hosts")["2001:db8:1:2::55"] = 0
	if elem, _, _ := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour); elem != v6a {
		t.Fatalf("no snapshot: elem=%q, want the address (the fleet whitelist read directly)", elem)
	}
	SetClientNetExempt("allow_sets", func(netip.Prefix) bool { return false })
	t.Cleanup(func() { SetClientNetExempt("allow_sets", nil) })
	g := newNetFake()
	g.set("allow_ext_v6_hosts")["2001:db8:1:2::55"] = 0
	if elem, _, _ := ExtendClientBlock(g, net.ParseIP(v6a), time.Hour); elem != net6 {
		t.Fatalf("with a snapshot: elem=%q, want the /64 (the snapshot decides)", elem)
	}
}

// The TTL ban restore's batch: one guard read and one read of the set for all
// of them, one transaction per chunk; kept, extended, added and guarded sorted
// out; a refused chunk retried one by one.
func TestExtendBlockNets(t *testing.T) {
	f := newNetFake()
	f.set(BlockV6Clients)["2001:db8:1:1::/64"] = 0             // permanent: kept
	f.set(BlockV6Clients)["2001:db8:1:2::/64"] = 2 * time.Hour // longer: kept
	f.set(BlockV6Clients)["2001:db8:1:3::/64"] = time.Minute   // shorter: extended
	f.set("ignore_v6")["2001:db8:1:5::7"] = 0                  // guarded
	bans := []NetBan{
		{netip.MustParsePrefix("2001:db8:1:1::/64"), time.Hour},
		{netip.MustParsePrefix("2001:db8:1:2::/64"), time.Hour},
		{netip.MustParsePrefix("2001:db8:1:3::/64"), time.Hour},
		{netip.MustParsePrefix("2001:db8:1:4::/64"), time.Hour},
		{netip.MustParsePrefix("2001:db8:1:5::/64"), time.Hour},
		{netip.MustParsePrefix("2001:db8:1:6::1/64"), time.Hour}, // not canonical
	}
	res, guarded, failed := ExtendBlockNets(f, bans)
	if res.Kept != 2 || res.Extended != 1 || res.Added != 1 || len(guarded) != 1 || guarded[0].String() != "2001:db8:1:5::/64" || len(failed) != 1 {
		t.Fatalf("res=%+v guarded=%v failed=%v", res, guarded, failed)
	}
	if f.reads[BlockV6Clients] != 1 || f.reads["self_v6"] != 1 || f.batches != 1 {
		t.Fatalf("reads=%v batches=%d, want one of each", f.reads, f.batches)
	}
	if f.set(BlockV6Clients)["2001:db8:1:3::/64"] != time.Hour || f.set(BlockV6Clients)["2001:db8:1:1::/64"] != 0 {
		t.Fatalf("set after: %v", f.set(BlockV6Clients))
	}
	// A refused transaction: one at a time.
	g := newNetFake()
	g.batchErr = errors.New("message too long")
	res, _, failed = ExtendBlockNets(g, bans[3:4])
	if res.Added != 1 || len(failed) != 0 || g.set(BlockV6Clients)["2001:db8:1:4::/64"] != time.Hour {
		t.Fatalf("one-by-one fallback: res=%+v failed=%v set=%v", res, failed, g.sets)
	}
	// The same /64 twice: one write, at the longer TTL.
	d := newNetFake()
	twice := []NetBan{{netip.MustParsePrefix("2001:db8:1:4::/64"), time.Hour}, {netip.MustParsePrefix("2001:db8:1:4::/64"), 2 * time.Hour}}
	if res, _, failed := ExtendBlockNets(d, twice); res.Added != 1 || len(failed) != 0 || d.set(BlockV6Clients)["2001:db8:1:4::/64"] != 2*time.Hour {
		t.Fatalf("twice: res=%+v failed=%v set=%v", res, failed, d.sets)
	}
	// Many: chunked.
	h := newNetFake()
	var many []NetBan
	for i := 0; i < netBatchChunk+10; i++ {
		many = append(many, NetBan{netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 9, byte(i >> 8), byte(i)}), 64), time.Hour})
	}
	if res, _, failed := ExtendBlockNets(h, many); res.Added != len(many) || len(failed) != 0 || h.batches != 2 {
		t.Fatalf("chunked: res=%+v failed=%d batches=%d", res, len(failed), h.batches)
	}
}

// Never shortened, exactly: an equal TTL keeps the ban, a second longer
// extends it.
func TestExtendClientBlockNeverShortensAtTheEdge(t *testing.T) {
	f := newNetFake()
	f.set(BlockV6Clients)[net6] = time.Hour
	if _, kept, _ := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour); !kept || len(f.writes) != 0 {
		t.Fatalf("equal TTL: kept=%v writes=%v", kept, f.writes)
	}
	if _, kept, _ := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour+time.Second); kept || f.set(BlockV6Clients)[net6] != time.Hour+time.Second {
		t.Fatalf("a second longer: kept=%v set=%v", kept, f.sets)
	}
	if _, kept, _ := ExtendClientBlock(f, net.ParseIP(v6a), 59*time.Minute); !kept || f.set(BlockV6Clients)[net6] != time.Hour+time.Second {
		t.Fatalf("shorter: kept=%v set=%v", kept, f.sets)
	}
}

// The default-route gateway's /64 is never banned as a whole (dropping the
// router's neighbour discovery would cut the node's IPv6).
func TestGuardKeepsTheDefaultGatewaysSlash64(t *testing.T) {
	dir := t.TempDir()
	route := dir + "/ipv6_route"
	// dest ::/0 via 2001:db8:1:2:2ff:ff:ff:ff (eth0), and a non-default route.
	content := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db800010002002ff00ff00ff0ff 00000400 00000001 00000000 00000003     eth0\n" +
		"20010db8000900000000000000000000 40 00000000000000000000000000000000 00 20010db8000500000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
	if err := os.WriteFile(route, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := procIPv6Route
	procIPv6Route = route
	t.Cleanup(func() { procIPv6Route = old })
	f := newNetFake()
	if elem, _, _ := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour); elem != v6a {
		t.Fatalf("a /64 holding the default gateway: elem=%q, want the address", elem)
	}
	if elem, _, _ := ExtendClientBlock(f, net.ParseIP("2001:db8:5::9"), time.Hour); elem != "2001:db8:5::/64" {
		t.Fatalf("a non-default route's next hop is no guard: elem=%q", elem)
	}
}

// A live ban reuses the guard view for guardCacheTTL on one backend.
func TestGuardViewIsCached(t *testing.T) {
	guardCacheTTL = time.Minute
	t.Cleanup(func() { guardCacheTTL = 0; ResetGuardCache() })
	f := newNetFake()
	_, _, _ = ExtendClientBlock(f, net.ParseIP(v6a), time.Hour)
	_, _, _ = ExtendClientBlock(f, net.ParseIP("2001:db8:7:7::1"), time.Hour)
	if f.reads["self_v6"] != 1 {
		t.Fatalf("self_v6 read %d times, want once within the cache TTL", f.reads["self_v6"])
	}
	g := newNetFake() // another backend: its own read
	_, _, _ = ExtendClientBlock(g, net.ParseIP(v6a), time.Hour)
	if g.reads["self_v6"] != 1 {
		t.Fatalf("another backend reused the cache: %v", g.reads)
	}
}

func TestParseClientTarget(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":           "192.0.2.1",
		"2001:db8:1:2::a":     "2001:db8:1:2::a",
		"2001:db8:1:2::/64":   "2001:db8:1:2::",
		"2001:db8:1:2::5/64":  "2001:db8:1:2::", // the /64 it names
		"2001:db8:1::/48":     "",
		"192.0.2.0/24":        "",
		"::ffff:192.0.2.0/64": "",
		"fe80::/64":           "", // ungrouped: no client /64
		"64:ff9b::/64":        "",
		"not-an-ip":           "",
	} {
		got := ""
		if ip := ParseClientTarget(in); ip != nil {
			got = ip.String()
		}
		if got != want {
			t.Errorf("ParseClientTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
