package firewall

import (
	"errors"
	"net"
	"testing"
	"time"
)

// netFake models block_v6_nets (elements as nft lists them, with time left)
// next to the host set extendFake models. AddBlockNet does not replace an
// existing element (nftlib keeps its old timeout): a caller that wants a
// longer one must delete it first.
type netFake struct {
	extendFake
	nets     map[string]time.Duration // 0 = permanent
	readErr  error
	writeErr error
	failAdds int // the next failAdds AddBlockNet calls fail
	writes   int
}

func newNetFake() *netFake {
	return &netFake{extendFake: extendFake{left: map[string]time.Duration{}}, nets: map[string]time.Duration{}}
}

func (f *netFake) ListSetElementsTimed(set string) ([]SetElementTimed, error) {
	if set != BlockV6Nets {
		return nil, errors.New("unexpected set " + set)
	}
	if f.readErr != nil {
		return nil, f.readErr
	}
	var out []SetElementTimed
	for e, d := range f.nets {
		out = append(out, SetElementTimed{Elem: e, Expires: d})
	}
	return out, nil
}

func (f *netFake) AddBlockNet(cidr string, ttl *time.Duration) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	if f.failAdds > 0 {
		f.failAdds--
		return errors.New("add refused")
	}
	f.writes++
	if _, ok := f.nets[cidr]; ok {
		return nil // kept as it is, like an add over an existing element
	}
	f.nets[cidr] = 0
	if ttl != nil {
		f.nets[cidr] = *ttl
	}
	return nil
}

func (f *netFake) RemoveBlockNet(cidr string) error {
	delete(f.nets, cidr)
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
	if err != nil || kept || elem != net6 || f.nets[net6] != 6*time.Hour {
		t.Fatalf("first ban: elem=%q kept=%v err=%v nets=%v", elem, kept, err, f.nets)
	}
	if len(f.left) != 0 {
		t.Fatalf("the address must not be banned on its own: %v", f.left)
	}
	// Another address of the same /64, shorter: the /64 ban is kept.
	elem, kept, err = ExtendClientBlock(f, net.ParseIP(v6b), time.Hour)
	if err != nil || !kept || elem != net6 || f.nets[net6] != 6*time.Hour {
		t.Fatalf("1h in a 6h /64: elem=%q kept=%v err=%v nets=%v", elem, kept, err, f.nets)
	}
	// Longer: extended (deleted, then added; the fake add does not replace).
	elem, kept, err = ExtendClientBlock(f, net.ParseIP(v6b), 24*time.Hour)
	if err != nil || kept || elem != net6 || f.nets[net6] != 24*time.Hour {
		t.Fatalf("24h over 6h: elem=%q kept=%v err=%v nets=%v", elem, kept, err, f.nets)
	}
	// Permanent stays permanent.
	f.nets[net6] = 0
	if _, kept, _ := ExtendClientBlock(f, net.ParseIP(v6a), 48*time.Hour); !kept || f.nets[net6] != 0 {
		t.Fatalf("48h over permanent: kept=%v nets=%v", kept, f.nets)
	}
	// Under a second: one second, never "0s" (permanent).
	g := newNetFake()
	if _, _, err := ExtendClientBlock(g, net.ParseIP(v6a), time.Millisecond); err != nil || g.nets[net6] != time.Second {
		t.Fatalf("1ms: err=%v nets=%v", err, g.nets)
	}
}

func TestExtendClientBlockWiderAndOverlapping(t *testing.T) {
	// A wider element lasting at least as long covers it: kept, named.
	f := newNetFake()
	f.nets["2001:db8::/32"] = 0
	elem, kept, err := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour)
	if err != nil || !kept || elem != "2001:db8::/32" || f.writes != 0 {
		t.Fatalf("under a permanent /32: elem=%q kept=%v err=%v writes=%d", elem, kept, err, f.writes)
	}
	// A wider one ending sooner: the /64 cannot go in under it, so the
	// address is banned for the full time (never a lost ban).
	f = newNetFake()
	f.nets["2001:db8:1::/48"] = time.Minute
	elem, kept, err = ExtendClientBlock(f, net.ParseIP(v6a), time.Hour)
	if err != nil || kept || elem != v6a || f.left[v6a] != time.Hour || f.writes != 0 {
		t.Fatalf("under a 1m /48: elem=%q kept=%v err=%v left=%v writes=%d", elem, kept, err, f.left, f.writes)
	}
	// A range form, as nft may print an interval.
	f = newNetFake()
	f.nets["2001:db8:1:2::-2001:db8:1:2:ffff:ffff:ffff:ffff"] = 2 * time.Hour
	if elem, kept, _ := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour); !kept || elem == v6a {
		t.Fatalf("an equal range must count as the /64: elem=%q kept=%v", elem, kept)
	}
	// A narrower element inside the /64: it cannot be written, the address is.
	f = newNetFake()
	f.nets["2001:db8:1:2::/80"] = 0
	elem, _, err = ExtendClientBlock(f, net.ParseIP(v6a), time.Hour)
	if err != nil || elem != v6a || f.left[v6a] != time.Hour {
		t.Fatalf("overlapping /80: elem=%q err=%v left=%v", elem, err, f.left)
	}
	// Elements elsewhere do not matter.
	f = newNetFake()
	f.nets["2001:db8:1:3::/64"] = time.Minute
	f.nets["198.51.100.0/24"] = 0
	if elem, _, _ := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour); elem != net6 {
		t.Fatalf("unrelated elements: elem=%q nets=%v", elem, f.nets)
	}
}

func TestExtendClientBlockFallsBackToTheAddress(t *testing.T) {
	for name, mut := range map[string]func(*netFake){
		"read fails":  func(f *netFake) { f.readErr = errors.New("nft busy") },
		"write fails": func(f *netFake) { f.writeErr = errors.New("refused") },
	} {
		f := newNetFake()
		mut(f)
		elem, _, err := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour)
		if err != nil || elem != v6a || f.left[v6a] != time.Hour {
			t.Errorf("%s: elem=%q err=%v left=%v, want the address banned", name, elem, err, f.left)
		}
	}
	// Not grouped: IPv4, v4-mapped, loopback, link-local, ::/64, NAT64.
	for _, s := range []string{"203.0.113.9", "::ffff:203.0.113.9", "::1", "fe80::1", "::2", "64:ff9b::1.2.3.4"} {
		f := newNetFake()
		ip := net.ParseIP(s)
		elem, _, err := ExtendClientBlock(f, ip, time.Hour)
		if err != nil || elem != ip.String() || len(f.nets) != 0 {
			t.Errorf("%s: elem=%q err=%v nets=%v, want the address only", s, elem, err, f.nets)
		}
	}
}

func TestBlockClientPermanent(t *testing.T) {
	f := newNetFake()
	elem, err := BlockClientPermanent(f, net.ParseIP(v6a), "c")
	if err != nil || elem != net6 || f.nets[net6] != 0 {
		t.Fatalf("new: elem=%q err=%v nets=%v", elem, err, f.nets)
	}
	// A TTL'd /64 becomes permanent.
	f = newNetFake()
	f.nets[net6] = time.Hour
	if elem, err := BlockClientPermanent(f, net.ParseIP(v6b), "c"); err != nil || elem != net6 || f.nets[net6] != 0 {
		t.Fatalf("over a 1h /64: elem=%q err=%v nets=%v", elem, err, f.nets)
	}
	// Under a permanent wider element: kept.
	f = newNetFake()
	f.nets["2001:db8::/32"] = 0
	if elem, err := BlockClientPermanent(f, net.ParseIP(v6a), "c"); err != nil || elem != "2001:db8::/32" || f.writes != 0 {
		t.Fatalf("under a permanent /32: elem=%q err=%v writes=%d", elem, err, f.writes)
	}
	// Overlapping: the address, permanently.
	f = newNetFake()
	f.nets["2001:db8:1:2::/80"] = time.Hour
	if elem, err := BlockClientPermanent(f, net.ParseIP(v6a), "c"); err != nil || elem != v6a || f.left[v6a] != 0 {
		t.Fatalf("overlapping: elem=%q err=%v left=%v", elem, err, f.left)
	}
	// IPv4: the address.
	f = newNetFake()
	if elem, err := BlockClientPermanent(f, net.ParseIP("203.0.113.9"), "c"); err != nil || elem != "203.0.113.9" || len(f.nets) != 0 {
		t.Fatalf("v4: elem=%q err=%v", elem, err)
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

// An extend deletes the shorter /64 first; if the add then fails, the old
// ban is put back (and the address banned for the new time): a failed
// extend never leaves the /64 unbanned.
func TestExtendClientBlockFailedExtendPutsTheOldBanBack(t *testing.T) {
	f := newNetFake()
	f.nets[net6] = 10 * time.Minute
	f.failAdds = 1
	elem, _, err := ExtendClientBlock(f, net.ParseIP(v6a), time.Hour)
	if err != nil || elem != v6a || f.left[v6a] != time.Hour {
		t.Fatalf("elem=%q err=%v left=%v, want the address banned for 1h", elem, err, f.left)
	}
	if got, ok := f.nets[net6]; !ok || got != 10*time.Minute {
		t.Fatalf("the /64's old ban was not put back: %v", f.nets)
	}
}
