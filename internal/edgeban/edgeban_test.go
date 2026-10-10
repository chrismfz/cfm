package edgeban

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfm/internal/firewall"
)

func dur(d time.Duration) *time.Duration { return &d }

func newTestStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 9, 20, 0, 0, 0, time.UTC)
	s := New(filepath.Join(t.TempDir(), "edgeban.json"))
	s.now = func() time.Time { return now }
	return s, &now
}

// blk is one nft block element with left remaining (0 = permanent).
func blk(ip string, left time.Duration) firewall.SetElementTimed {
	return firewall.SetElementTimed{Elem: ip, Expires: left}
}

// snap is a complete nft read that began at readAt.
func snap(readAt time.Time, allows []string, blocks ...firewall.SetElementTimed) Snapshot {
	return Snapshot{Blocks: blocks, Allows: allows, ReadAt: readAt}
}

func TestNotReadyBeforeReconcile(t *testing.T) {
	s, _ := newTestStore(t)
	s.Add(net.ParseIP("34.153.214.160"), dur(time.Hour), "waf_security", false)
	if ok, _ := s.Banned("34.153.214.160"); ok {
		t.Fatal("banned before the first reconcile: must fail toward not blocking")
	}
}

func TestAddExtendKeepExact(t *testing.T) {
	s, now := newTestStore(t)
	ip := net.ParseIP("34.153.214.160")
	s.Add(ip, dur(7*24*time.Hour), "waf_security", false)
	s.Add(ip, dur(time.Hour), "webdetector", false) // never shortens
	s.Reconcile(snap(now.Add(-time.Minute), nil, blk("34.153.214.160", 7*24*time.Hour)))
	if ok, left := s.Banned("34.153.214.160"); !ok || left != 7*24*time.Hour {
		t.Fatalf("after 7d then 1h: banned=%v left=%v, want 7d", ok, left)
	}
	s.Add(ip, dur(time.Hour), "manual", true) // a manual ban sets the operator's TTL
	if ok, left := s.Banned("34.153.214.160"); !ok || left != time.Hour {
		t.Fatalf("exact 1h: banned=%v left=%v", ok, left)
	}
	s.Add(ip, nil, "detector", false) // permanent outlasts
	if ok, left := s.Banned("34.153.214.160"); !ok || left != 0 {
		t.Fatalf("permanent: banned=%v left=%v", ok, left)
	}
	if ok, _ := s.Banned("::ffff:34.153.214.160"); !ok {
		t.Fatal("IPv4-mapped form not matched")
	}
	if ok, _ := s.Banned("34.153.214.161"); ok {
		t.Fatal("another address banned")
	}
}

func TestExpiryAndKillSwitch(t *testing.T) {
	s, now := newTestStore(t)
	s.Add(net.ParseIP("203.0.113.5"), dur(time.Hour), "waf_security", false)
	s.Reconcile(snap(now.Add(-time.Minute), nil, blk("203.0.113.5", time.Hour)))
	SetEnabled(false)
	ok, _ := s.Banned("203.0.113.5")
	SetEnabled(true)
	if ok {
		t.Fatal("EDGE_BAN off must answer false")
	}
	*now = now.Add(61 * time.Minute)
	if ok, _ := s.Banned("203.0.113.5"); ok {
		t.Fatal("expired ban still answered")
	}
}

func TestReconcileNarrowsOnly(t *testing.T) {
	s, now := newTestStore(t)
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		s.Add(net.ParseIP(ip), dur(6*time.Hour), "waf_security", false)
	}
	s.Reconcile(snap(now.Add(time.Second), []string{"198.51.100.4"},
		blk("198.51.100.1", 6*time.Hour), // kept
		blk("198.51.100.2", time.Hour),   // nft ends earlier: clamp
		blk("198.51.100.4", 6*time.Hour), // but allowed: dropped
		blk("192.0.2.9", 0),              // nft-only (cfm.deny): never imported
		// .3 missing from nft: unblocked from the CLI / flushed / expired
	))
	if ok, left := s.Banned("198.51.100.1"); !ok || left != 6*time.Hour {
		t.Errorf(".1: %v %v", ok, left)
	}
	if ok, left := s.Banned("198.51.100.2"); !ok || left != time.Hour {
		t.Errorf(".2 must be clamped to nft's 1h: %v %v", ok, left)
	}
	if ok, _ := s.Banned("198.51.100.3"); ok {
		t.Error(".3 is gone from nft: must not be banned")
	}
	if ok, _ := s.Banned("198.51.100.4"); ok {
		t.Error(".4 is allowed: must not be banned")
	}
	if ok, _ := s.Banned("192.0.2.9"); ok {
		t.Error("an nft-only ban must not be imported")
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
}

// A ban written after the nft read began is not "missing from nft": the read
// predates it (review of b2073f6: a 7d ban landing mid-read was dropped).
func TestReconcileKeepsBanAddedDuringRead(t *testing.T) {
	s, now := newTestStore(t)
	readAt := *now
	*now = now.Add(2 * time.Second)
	s.Add(net.ParseIP("203.0.113.40"), dur(7*24*time.Hour), "waf_security", false)
	s.Reconcile(snap(readAt, nil)) // the read saw nothing
	if ok, _ := s.Banned("203.0.113.40"); !ok {
		t.Fatal("a ban added after the read began was dropped")
	}
	// The next read, after the ban, does decide.
	s.Reconcile(snap(now.Add(time.Second), nil))
	if ok, _ := s.Banned("203.0.113.40"); ok {
		t.Fatal("a later read without it must drop it")
	}
}

// Every nft allow set counts: hosts, nets (the fleet whitelist, cfm allow
// CIDR), ranges — nft accepts before any block drop.
func TestAllowSetsWinImmediately(t *testing.T) {
	s, now := newTestStore(t)
	ips := []string{"52.96.0.10", "192.0.2.15", "2001:db8::7", "203.0.113.60"}
	var blocks []firewall.SetElementTimed
	for _, ip := range ips {
		s.Add(net.ParseIP(ip), nil, "waf_security", false)
		blocks = append(blocks, blk(ip, 0))
	}
	s.Reconcile(snap(now.Add(-time.Minute), []string{"52.96.0.0/14", "192.0.2.10-192.0.2.20", "2001:db8::/32"}, blocks...))
	for _, ip := range ips[:3] {
		if ok, _ := s.Banned(ip); ok {
			t.Errorf("%s is allowed by an nft allow set: must not be banned", ip)
		}
	}
	if ok, _ := s.Banned("203.0.113.60"); !ok {
		t.Error("an address no allow covers must stay banned")
	}
	// A ban added after the allow snapshot is not answered either.
	s.Add(net.ParseIP("52.97.1.1"), nil, "manual", true)
	if ok, _ := s.Banned("52.97.1.1"); ok {
		t.Error("a new ban of an allowed address was answered")
	}
}

func TestClear(t *testing.T) {
	s, now := newTestStore(t)
	s.Add(net.ParseIP("203.0.113.70"), nil, "manual", true)
	s.Reconcile(snap(now.Add(-time.Minute), nil, blk("203.0.113.70", 0)))
	s.Clear()
	if ok, _ := s.Banned("203.0.113.70"); ok || s.Len() != 0 {
		t.Fatal("Clear left a ban")
	}
}

func TestRemoveAndPersistence(t *testing.T) {
	s, now := newTestStore(t)
	s.Add(net.ParseIP("203.0.113.7"), dur(time.Hour), "manual", true)
	s.Add(net.ParseIP("203.0.113.8"), nil, "waf_security", false)
	s.Remove("203.0.113.7")
	if _, err := os.Stat(s.path); err != nil {
		t.Fatalf("not persisted: %v", err)
	}
	s2 := New(s.path)
	s2.now = s.now
	s2.Load()
	if s2.Ready() {
		t.Fatal("a loaded store must not answer before reconcile")
	}
	s2.Reconcile(snap(now.Add(time.Minute), nil, blk("203.0.113.8", 0)))
	if ok, _ := s2.Banned("203.0.113.8"); !ok {
		t.Error("persisted permanent ban lost")
	}
	if ok, _ := s2.Banned("203.0.113.7"); ok {
		t.Error("removed ban came back")
	}
}

func TestWebSection(t *testing.T) {
	for _, s := range []string{"waf_security", "webdetector", "challenge_solver_farm", "challenge_cookie_discard", "modsec", "cfm_endpoints", "cpanel", "WAF_SECURITY"} {
		if !WebSection(s) {
			t.Errorf("%s should be a web section", s)
		}
	}
	for _, s := range []string{"ssh_auth", "exim_security", "dovecot_auth", "ftpd", "mysql", "health", "ngm_auth", ""} {
		if WebSection(s) {
			t.Errorf("%s should not be a web section", s)
		}
	}
}

func TestNilStoreHelpers(t *testing.T) {
	SetDefault(nil)
	Ban(net.ParseIP("203.0.113.1"), nil, "x", false)
	Unban("203.0.113.1")
	if ok, _ := IsBanned("203.0.113.1"); ok {
		t.Fatal("no store installed: nothing is banned")
	}
}

// A trusted proxy's own address is never answered (a Cloudflare Worker's
// subrequest names a Cloudflare address in CF-Connecting-IP).
func TestTrustedProxyAddressNeverBanned(t *testing.T) {
	nets := ParseTrustedProxies("# comment\nset_real_ip_from 173.245.48.0/20;\nset_real_ip_from 2a06:98c0::/29;\nset_real_ip_from 198.51.100.77;\nreal_ip_header CF-Connecting-IP;\n")
	if len(nets) != 3 {
		t.Fatalf("parsed %d ranges, want 3", len(nets))
	}
	SetTrustedProxies(nets)
	t.Cleanup(func() { SetTrustedProxies(nil) })
	s, now := newTestStore(t)
	for _, ip := range []string{"2a06:98c0:3600::103", "173.245.48.9", "198.51.100.77", "203.0.113.90"} {
		s.Add(net.ParseIP(ip), nil, "waf_security", false)
	}
	s.Reconcile(snap(now.Add(-time.Minute), nil, blk("2a06:98c0:3600::103", 0), blk("173.245.48.9", 0), blk("198.51.100.77", 0), blk("203.0.113.90", 0)))
	for _, ip := range []string{"2a06:98c0:3600::103", "173.245.48.9", "198.51.100.77"} {
		if ok, _ := s.Banned(ip); ok {
			t.Errorf("%s is a trusted proxy address: must never be edge-banned", ip)
		}
	}
	if ok, _ := s.Banned("203.0.113.90"); !ok {
		t.Error("an ordinary client must stay banned")
	}
}

// List is what Banned answers, sorted: no allowed, trusted-proxy or expired
// address, nothing before the first reconcile or while switched off.
func TestListMatchesBanned(t *testing.T) {
	s := New("")
	now := time.Now()
	s.now = func() time.Time { return now }
	short := time.Minute
	for _, ip := range []string{"203.0.113.9", "198.51.100.1", "192.0.2.10", "173.245.48.10"} {
		s.Add(net.ParseIP(ip), nil, "waf_security", false)
	}
	s.Add(net.ParseIP("198.51.100.2"), &short, "webdetector", false)
	if got := s.List(); got != nil {
		t.Fatalf("before the first reconcile: %v", got)
	}
	s.Reconcile(Snapshot{
		Blocks: []firewall.SetElementTimed{{Elem: "203.0.113.9"}, {Elem: "198.51.100.1"}, {Elem: "192.0.2.10"},
			{Elem: "173.245.48.10"}, {Elem: "198.51.100.2", Expires: time.Minute}},
		Allows: []string{"192.0.2.0/24"},
		ReadAt: now.Add(-time.Second),
	})
	_, cf, _ := net.ParseCIDR("173.245.48.0/20")
	SetTrustedProxies([]*net.IPNet{cf})
	defer SetTrustedProxies(nil)

	var ips []string
	for _, it := range s.List() {
		ips = append(ips, it.IP)
		if ok, _ := s.Banned(it.IP); !ok {
			t.Errorf("List has %s, Banned says no", it.IP)
		}
	}
	if want := "198.51.100.1 198.51.100.2 203.0.113.9"; strings.Join(ips, " ") != want {
		t.Fatalf("List = %v, want %s (sorted; no allowed or proxy address)", ips, want)
	}
	now = now.Add(2 * time.Minute)
	if got := len(s.List()); got != 2 {
		t.Errorf("after the timed ban expired: %d items, want 2", got)
	}
	SetEnabled(false)
	defer SetEnabled(true)
	if got := s.List(); got != nil {
		t.Errorf("switched off: %v", got)
	}
}
