package edgeban

import (
	"cfm/internal/firewall"
	"cfm/internal/proxyipfilter"
	"net"
	"net/netip"
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

// A /64 banned AFTER the reconcile that saw an allow inside it is not answered
// either (answers checks the allow sets on every lookup, not only Reconcile).
func TestSlash64AddedBetweenReconcilesRespectsAllows(t *testing.T) {
	s, now := newTestStore(t)
	s.Reconcile(snap(now.Add(time.Second), []string{"2001:db8:1:2::77"}))
	s.AddElem("2001:db8:1:2::/64", dur(time.Hour), "waf_security", false)
	if ok, _ := s.Banned("2001:db8:1:2::5"); ok {
		t.Fatal("a /64 an allow touches must not be answered, reconcile or not")
	}
	if len(s.List()) != 0 {
		t.Fatalf("List = %v, want empty", s.List())
	}
	s.AddElem("2001:db8:3:4::/64", dur(time.Hour), "waf_security", false)
	if ok, _ := s.Banned("2001:db8:3:4::5"); !ok {
		t.Fatal("a /64 no allow touches must be answered")
	}
}

// The edge ban store tells the firewall which /64s it must never ban as a
// whole: a trusted proxy's range (SetTrustedProxies) and any the allow sets
// touch (the last reconcile's read, the fleet whitelist included).
func TestSlash64ExemptsRegisteredWithTheFirewall(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8:1:2::/64")
	if got := firewall.ClientNetExempted(p); got != "" {
		t.Fatalf("nothing registered yet refuses it: %q", got)
	}
	_, cf, _ := net.ParseCIDR("2001:db8::/32")
	SetTrustedProxies([]*net.IPNet{cf})
	if got := firewall.ClientNetExempted(p); got != "trusted_proxies" {
		t.Fatalf("a /64 inside a trusted proxy range: %q", got)
	}
	SetTrustedProxies(nil)
	if got := firewall.ClientNetExempted(p); got != "" {
		t.Fatalf("after clearing the proxies: %q", got)
	}

	s, now := newTestStore(t)
	SetDefault(s)
	t.Cleanup(func() { SetDefault(nil) })
	s.Reconcile(snap(now.Add(time.Second), []string{"2001:db8:1:2::77"}))
	if got := firewall.ClientNetExempted(p); got != "allow_sets" {
		t.Fatalf("a /64 an allow touches: %q", got)
	}
	if got := firewall.ClientNetExempted(netip.MustParsePrefix("2001:db8:1:3::/64")); got != "" {
		t.Fatalf("the next /64: %q", got)
	}
}

// Unban lifts the proxied-client filter for the address only: forgetting the
// client's whole /64 there would lift every source (the fleet blacklist,
// other addresses' bans) for all of it.
func TestUnbanForgetsTheAddressOnlyInTheProxiedFilter(t *testing.T) {
	proxyipfilter.ResetForTest()
	t.Cleanup(proxyipfilter.ResetForTest)
	proxyipfilter.SetModes("enforce", "enforce")
	proxyipfilter.SetFeed("fleet", false, nil, []string{"2001:db8:1:2::/64"})
	if enforce, listed := proxyipfilter.Decide("2001:db8:1:2::6", "x"); !enforce || !listed {
		t.Fatalf("setup: the fleet-listed /64 is not blocked (%v %v)", enforce, listed)
	}
	Unban("2001:db8:1:2::5")
	if enforce, _ := proxyipfilter.Decide("2001:db8:1:2::5", "x"); enforce {
		t.Error("the unblocked address is still filtered")
	}
	if enforce, _ := proxyipfilter.Decide("2001:db8:1:2::6", "x"); !enforce {
		t.Error("another address of the /64 lost the fleet blacklist's block")
	}
}

// The allow snapshot is registered with the firewall only once the Default
// store holds one, and withdrawn on Clear (the firewall then reads the fleet
// whitelist itself).
func TestAllowExemptFollowsTheSnapshot(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8:1:2::/64")
	s, now := newTestStore(t)
	SetDefault(s)
	t.Cleanup(func() { SetDefault(nil); firewall.SetClientNetExempt("allow_sets", nil) })
	s.Reconcile(snap(now.Add(time.Second), []string{"2001:db8:1:2::77"}))
	if got := firewall.ClientNetExempted(p); got != "allow_sets" {
		t.Fatalf("after a reconcile: %q", got)
	}
	s.Clear()
	if got := firewall.ClientNetExempted(p); got != "" {
		t.Fatalf("after Clear the snapshot must be withdrawn: %q", got)
	}
}
