package edgeban

import (
	"net"
	"os"
	"path/filepath"
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

func blocked(ip string, left time.Duration, now time.Time) firewall.BlockedEntry {
	e := firewall.BlockedEntry{IP: net.ParseIP(ip)}
	if left > 0 {
		exp := now.Add(left)
		e.Expires = &exp
	}
	return e
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
	s.Reconcile([]firewall.BlockedEntry{blocked("34.153.214.160", 7*24*time.Hour, *now)}, nil)
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
	// IPv4-mapped is the same address.
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
	s.Reconcile([]firewall.BlockedEntry{blocked("203.0.113.5", time.Hour, *now)}, nil)
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
	s.Reconcile([]firewall.BlockedEntry{
		blocked("198.51.100.1", 6*time.Hour, *now), // kept
		blocked("198.51.100.2", time.Hour, *now),   // nft ends earlier: clamp
		blocked("198.51.100.4", 6*time.Hour, *now), // but allowed: dropped
		blocked("192.0.2.9", 0, *now),              // nft-only (cfm.deny): never imported
		// .3 missing from nft: unblocked from the CLI / flushed / expired
	}, []firewall.BlockedEntry{{IP: net.ParseIP("198.51.100.4")}})
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
	if s2.Banned("203.0.113.8"); s2.Ready() {
		t.Fatal("a loaded store must not answer before reconcile")
	}
	s2.Reconcile([]firewall.BlockedEntry{blocked("203.0.113.8", 0, *now)}, nil)
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
	for _, s := range []string{"ssh_auth", "exim_security", "dovecot_auth", "ftpd", "mysql", "health", ""} {
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
