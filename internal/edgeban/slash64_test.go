package edgeban

import (
	"net"
	"testing"
	"time"
)

// An IPv6 client's automatic ban is its /64 (firewall.ExtendClientBlock):
// the store keys it as nft holds it and answers every address of the /64.
func TestSlash64BanAnswersTheWholeSlash64(t *testing.T) {
	s, now := newTestStore(t)
	s.AddElem("2001:db8:1:2::/64", dur(6*time.Hour), "waf_security", false)
	s.Reconcile(snap(now.Add(time.Second), nil, blk("2001:db8:1:2::/64", 6*time.Hour)))
	for _, ip := range []string{"2001:db8:1:2::a", "2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:DB8:1:2::77"} {
		if ok, left := s.Banned(ip); !ok || left != 6*time.Hour {
			t.Errorf("%s: %v %v, want banned 6h", ip, ok, left)
		}
	}
	if ok, _ := s.Banned("2001:db8:1:3::a"); ok {
		t.Error("the next /64 is not banned")
	}
	if l := s.List(); len(l) != 1 || l[0].IP != "2001:db8:1:2::/64" {
		t.Errorf("List = %v, want the /64 key", l)
	}
	// A host ban next to it still answers on its own.
	s.Add(net.ParseIP("2001:db8:9::1"), dur(time.Hour), "manual", true)
	if ok, _ := s.Banned("2001:db8:9::1"); !ok {
		t.Error("a host ban must still answer")
	}
}

// Only a /64 exactly as ipkey groups a client is a key: any other CIDR (a
// manual /48, an IPv4 net, the ::/64 that holds ::1) is no edge ban.
func TestSlash64KeyOf(t *testing.T) {
	for in, want := range map[string]string{
		"2001:db8:1:2::/64":   "2001:db8:1:2::/64",
		"2001:DB8:1:2::/64":   "2001:db8:1:2::/64",
		"2001:db8::/48":       "",
		"2001:db8:1:2::1/64":  "", // not the network address
		"2001:db8:1:2::/80":   "",
		"::/64":               "",
		"fe80::/64":           "",
		"198.51.100.0/24":     "",
		"198.51.100.7":        "198.51.100.7",
		"::ffff:198.51.100.7": "198.51.100.7",
		"2001:db8:1:2::a":     "2001:db8:1:2::a",
		"garbage":             "",
		"2001:db8:1:2::/64 ":  "2001:db8:1:2::/64",
	} {
		if got := keyOf(in); got != want {
			t.Errorf("keyOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// nft keeps the /64 only: a reconcile keeps it, and drops it once nft does.
func TestSlash64Reconcile(t *testing.T) {
	s, now := newTestStore(t)
	s.AddElem("2001:db8:1:2::/64", dur(6*time.Hour), "webdetector", false)
	s.Reconcile(snap(now.Add(time.Second), nil, blk("2001:db8:1:2::/64", time.Hour)))
	if ok, left := s.Banned("2001:db8:1:2::5"); !ok || left != time.Hour {
		t.Fatalf("clamped to nft's 1h: %v %v", ok, left)
	}
	s.Reconcile(snap(now.Add(2*time.Second), nil))
	if ok, _ := s.Banned("2001:db8:1:2::5"); ok {
		t.Fatal("gone from nft: must not be banned")
	}
}

// An allow or a trusted proxy range touching any of the /64 keeps the edge
// from answering it (fail toward not blocking): the edge cannot tell the
// allowed address from the rest. nft still drops the rest for direct clients.
func TestSlash64AllowOrProxyOverlapNeverAnswers(t *testing.T) {
	s, now := newTestStore(t)
	s.AddElem("2001:db8:1:2::/64", dur(6*time.Hour), "waf_security", false)
	s.Reconcile(snap(now.Add(time.Second), []string{"2001:db8:9::1"}, blk("2001:db8:1:2::/64", 6*time.Hour)))
	if ok, _ := s.Banned("2001:db8:1:2::5"); !ok {
		t.Fatal("an unrelated allow must not stop it")
	}
	// An allow of one address inside the /64: the next reconcile drops it,
	// and until then it is not answered.
	s.Reconcile(snap(now.Add(2*time.Second), []string{"2001:db8:1:2::77"}, blk("2001:db8:1:2::/64", 6*time.Hour)))
	if ok, _ := s.Banned("2001:db8:1:2::5"); ok {
		t.Fatal("an allow inside the /64 must stop the edge answering it")
	}
	if len(s.List()) != 0 {
		t.Fatalf("List = %v, want empty", s.List())
	}
	// A trusted proxy range overlapping it.
	s2, now2 := newTestStore(t)
	s2.AddElem("2001:db8:1:2::/64", dur(time.Hour), "waf_security", false)
	s2.Reconcile(snap(now2.Add(time.Second), nil, blk("2001:db8:1:2::/64", time.Hour)))
	_, cf, _ := net.ParseCIDR("2001:db8::/32")
	SetTrustedProxies([]*net.IPNet{cf})
	t.Cleanup(func() { SetTrustedProxies(nil) })
	if ok, _ := s2.Banned("2001:db8:1:2::5"); ok {
		t.Fatal("a /64 inside a trusted proxy range must never be answered")
	}
	if len(s2.List()) != 0 {
		t.Fatalf("List = %v, want empty", s2.List())
	}
}

// Unblocking any address of the /64 frees the /64 (the client); the /64 key
// itself unblocks too. Persisted /64 keys load back.
func TestSlash64RemoveAndPersistence(t *testing.T) {
	s, now := newTestStore(t)
	s.AddElem("2001:db8:1:2::/64", dur(6*time.Hour), "waf_security", false)
	s.AddElem("2001:db8:5:6::/64", dur(6*time.Hour), "waf_security", false)
	s2 := New(s.path)
	s2.now = s.now
	s2.Load()
	if s2.Len() != 2 {
		t.Fatalf("persisted /64 keys: Len = %d, want 2", s2.Len())
	}
	s.Remove("2001:db8:1:2::abcd")
	s.Remove("2001:db8:5:6::/64")
	s.Reconcile(snap(now.Add(time.Second), nil, blk("2001:db8:1:2::/64", time.Hour), blk("2001:db8:5:6::/64", time.Hour)))
	if s.Len() != 0 {
		t.Fatalf("after the unblocks: Len = %d, want 0", s.Len())
	}
}
