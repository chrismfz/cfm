//go:build linux

package bantest

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/ttlban"
)

// RunClientSlash64Bans drives an engine's automatic IPv6 bans against a live
// nft (docs/edge-ipv6.md "IPv6 /64 grouping"): an IPv6 client is banned as
// its /64 in block_v6_nets, a ban is only ever added or extended, a wider
// element ending sooner makes it fall back to the address, an unblock frees
// the /64, and a /64 TTL ban survives the table going (internal/ttlban).
// Gated like RunTTLBansSurviveRestart; it refuses to run outside an empty
// network namespace.
func RunClientSlash64Bans(t *testing.T, newBackend func() firewall.Backend) {
	t.Helper()
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "" {
		t.Fatalf("refusing to run: this namespace already has tables (not an isolated netns?):\n%s", out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm").Run() })

	start := func() firewall.Backend {
		t.Helper()
		be := newBackend()
		if err := be.EnsureBase(); err != nil {
			t.Fatalf("EnsureBase: %v", err)
		}
		return be
	}
	elems := func(be firewall.Backend, set string) map[string]time.Duration {
		t.Helper()
		got, err := be.ListSetElementsTimed(set)
		if err != nil {
			t.Fatalf("list %s: %v", set, err)
		}
		m := map[string]time.Duration{}
		for _, e := range got {
			m[e.Elem] = e.Expires
		}
		return m
	}
	const (
		a    = "2001:db8:1:2::a"
		b    = "2001:db8:1:2:ffff::b"
		slsh = "2001:db8:1:2::/64"
	)
	be := start()

	// A ban takes the /64, not the address.
	elem, kept, err := firewall.ExtendClientBlock(be, net.ParseIP(a), time.Hour)
	if err != nil || kept || elem != slsh {
		t.Fatalf("first ban: elem=%q kept=%v err=%v", elem, kept, err)
	}
	if n := elems(be, firewall.BlockV6Nets); n[slsh] < 59*time.Minute || len(n) != 1 {
		t.Fatalf("block_v6_nets after the ban: %v", n)
	}
	if h := elems(be, "block_v6"); len(h) != 0 {
		t.Fatalf("the address must not be banned on its own: %v", h)
	}
	// Shorter, from another address of the /64: kept.
	if elem, kept, err = firewall.ExtendClientBlock(be, net.ParseIP(b), 10*time.Minute); err != nil || !kept || elem != slsh {
		t.Fatalf("10m in a 1h /64: elem=%q kept=%v err=%v", elem, kept, err)
	}
	if n := elems(be, firewall.BlockV6Nets); n[slsh] < 59*time.Minute {
		t.Fatalf("a shorter ban shortened the /64: %v", n)
	}
	// Longer: extended, still one element.
	if elem, kept, err = firewall.ExtendClientBlock(be, net.ParseIP(b), 3*time.Hour); err != nil || kept || elem != slsh {
		t.Fatalf("3h over 1h: elem=%q kept=%v err=%v", elem, kept, err)
	}
	if n := elems(be, firewall.BlockV6Nets); n[slsh] < 179*time.Minute || len(n) != 1 {
		t.Fatalf("after the extend: %v", n)
	}
	// Permanent, then a TTL ban leaves it permanent.
	if elem, err := firewall.BlockClientPermanent(be, net.ParseIP(a), "test"); err != nil || elem != slsh {
		t.Fatalf("permanent: elem=%q err=%v", elem, err)
	}
	if _, kept, _ := firewall.ExtendClientBlock(be, net.ParseIP(a), time.Hour); !kept || elems(be, firewall.BlockV6Nets)[slsh] != 0 {
		t.Fatalf("1h over a permanent /64: kept=%v nets=%v", kept, elems(be, firewall.BlockV6Nets))
	}
	// The unblock frees it.
	if n, err := firewall.RemoveClientNet(be, net.ParseIP(b)); err != nil || n != slsh {
		t.Fatalf("RemoveClientNet: %q %v", n, err)
	}
	if n := elems(be, firewall.BlockV6Nets); len(n) != 0 {
		t.Fatalf("after the unblock: %v", n)
	}
	if _, err := firewall.RemoveClientNet(be, net.ParseIP(b)); err != nil {
		t.Fatalf("a second unblock must be a no-op: %v", err)
	}

	// A wider manual ban ending sooner: the /64 cannot go in under it, the
	// address is banned for the full time.
	ttl := time.Minute
	if err := be.AddBlockNet("2001:db8:1::/48", &ttl); err != nil {
		t.Fatal(err)
	}
	if elem, _, err := firewall.ExtendClientBlock(be, net.ParseIP(a), time.Hour); err != nil || elem != net.ParseIP(a).String() {
		t.Fatalf("under a 1m /48: elem=%q err=%v", elem, err)
	}
	if h := elems(be, "block_v6"); h[net.ParseIP(a).String()] < 59*time.Minute {
		t.Fatalf("the fallback address ban: %v", h)
	}
	if err := be.RemoveBlockNet("2001:db8:1::/48"); err != nil {
		t.Fatal(err)
	}

	// A /64 TTL ban survives the table going (ttlban).
	if _, _, err := firewall.ExtendClientBlock(be, net.ParseIP("2001:db8:5:6::1"), 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ttlbans.json")
	s := ttlban.New(path)
	if _, err := s.Restore(be, nil); err != nil {
		t.Fatal(err)
	}
	var all []firewall.SetElementTimed
	readAt := time.Now()
	for _, set := range ttlban.Sets {
		got, err := be.ListSetElementsTimed(set)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, got...)
	}
	if err := s.Snapshot(readAt, all); err != nil {
		t.Fatal(err)
	}
	if err := be.DropEverything(); err != nil {
		t.Fatalf("DropEverything: %v", err)
	}
	be = start()
	if n := elems(be, firewall.BlockV6Nets); len(n) != 0 {
		t.Fatalf("the dropped table still holds %v; the test proves nothing", n)
	}
	l := ttlban.New(path)
	if err := l.Load(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Restore(be, nil); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if n := elems(be, firewall.BlockV6Nets); n["2001:db8:5:6::/64"] < 119*time.Minute {
		t.Fatalf("the /64 TTL ban did not come back: %v", n)
	}
}
