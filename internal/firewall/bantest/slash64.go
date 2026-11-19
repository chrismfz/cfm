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

// RunClientSlash64Bans drives an engine's automatic IPv6 client bans against
// a live nft (docs/edge-ipv6.md "IPv6 /64 grouping"):
//   - a ban takes the /64 in block_v6_clients, only ever added or extended;
//   - the operator's own IPv6 CIDRs (block_v6_nets) never collide with it;
//   - a /64 holding this node's address or an ignored one bans the address;
//   - an unblock frees the /64, and a /64 TTL ban survives the table going;
//   - on a chain from before block_v6_clients, EnsureBase places its drops
//     right after block_v6_nets', below the self / allow accepts.
//
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
	nft := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("nft", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %v: %v\n%s", args, err, out)
		}
		return string(out)
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
	if n := elems(be, firewall.BlockV6Clients); n[slsh] < 59*time.Minute || len(n) != 1 {
		t.Fatalf("%s after the ban: %v", firewall.BlockV6Clients, n)
	}
	if h := elems(be, "block_v6"); len(h) != 0 {
		t.Fatalf("the address must not be banned on its own: %v", h)
	}
	// Shorter, from another address of the /64: kept.
	if elem, kept, err = firewall.ExtendClientBlock(be, net.ParseIP(b), 10*time.Minute); err != nil || !kept || elem != slsh {
		t.Fatalf("10m in a 1h /64: elem=%q kept=%v err=%v", elem, kept, err)
	}
	if n := elems(be, firewall.BlockV6Clients); n[slsh] < 59*time.Minute {
		t.Fatalf("a shorter ban shortened the /64: %v", n)
	}
	// Longer: extended in one transaction, still one element.
	if elem, kept, err = firewall.ExtendClientBlock(be, net.ParseIP(b), 3*time.Hour); err != nil || kept || elem != slsh {
		t.Fatalf("3h over 1h: elem=%q kept=%v err=%v", elem, kept, err)
	}
	if n := elems(be, firewall.BlockV6Clients); n[slsh] < 179*time.Minute || len(n) != 1 {
		t.Fatalf("after the extend: %v", n)
	}
	// Permanent, then a TTL ban leaves it permanent.
	if elem, err := firewall.BlockClientPermanent(be, net.ParseIP(a), "test"); err != nil || elem != slsh {
		t.Fatalf("permanent: elem=%q err=%v", elem, err)
	}
	if _, kept, _ := firewall.ExtendClientBlock(be, net.ParseIP(a), time.Hour); !kept || elems(be, firewall.BlockV6Clients)[slsh] != 0 {
		t.Fatalf("1h over a permanent /64: kept=%v set=%v", kept, elems(be, firewall.BlockV6Clients))
	}

	// The operator's own CIDRs never collide with it (the review of 8fc59f9:
	// in block_v6_nets, a /48 over an automatic /64 was refused).
	if err := be.AddBlockNet("2001:db8:1::/48", nil); err != nil {
		t.Fatalf("a manual /48 over an automatic /64: %v", err)
	}
	if err := be.RemoveBlockNet("2001:db8:1::/48"); err != nil {
		t.Fatal(err)
	}

	// The unblock frees it; a second one is a no-op.
	if n, err := firewall.RemoveClientNet(be, net.ParseIP(b)); err != nil || n != slsh {
		t.Fatalf("RemoveClientNet: %q %v", n, err)
	}
	if n := elems(be, firewall.BlockV6Clients); len(n) != 0 {
		t.Fatalf("after the unblock: %v", n)
	}
	if _, err := firewall.RemoveClientNet(be, net.ParseIP(b)); err != nil {
		t.Fatalf("a second unblock must be a no-op: %v", err)
	}

	// A /64 holding this node's own address, or an ignored one, is never
	// banned as a whole: the address is.
	nft("add", "element", "inet", "cfm", "self_v6", "{ 2001:db8:7:7::1/128 }")
	if elem, _, err := firewall.ExtendClientBlock(be, net.ParseIP("2001:db8:7:7::99"), time.Hour); err != nil || elem != "2001:db8:7:7::99" {
		t.Fatalf("a /64 with this node in it: elem=%q err=%v", elem, err)
	}
	if err := be.AddIgnore(net.ParseIP("2001:db8:8:8::5"), nil); err != nil {
		t.Fatal(err)
	}
	if elem, _, err := firewall.ExtendClientBlock(be, net.ParseIP("2001:db8:8:8::99"), time.Hour); err != nil || elem != "2001:db8:8:8::99" {
		t.Fatalf("a /64 with an ignored address in it: elem=%q err=%v", elem, err)
	}
	if n := elems(be, firewall.BlockV6Clients); len(n) != 0 {
		t.Fatalf("guarded /64s were written: %v", n)
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
	if n := elems(be, firewall.BlockV6Clients); len(n) != 0 {
		t.Fatalf("the dropped table still holds %v; the test proves nothing", n)
	}
	l := ttlban.New(path)
	if err := l.Load(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Restore(be, nil); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if n := elems(be, firewall.BlockV6Clients); n["2001:db8:5:6::/64"] < 119*time.Minute {
		t.Fatalf("the /64 TTL ban did not come back: %v", n)
	}

	// An upgrade: a chain from before block_v6_clients (its two drops gone).
	// EnsureBase must add them right after block_v6_nets', not on top.
	chain := firewall.ParseChainRules(nft("-a", "list", "chain", "inet", "cfm", "input"))
	for _, r := range firewall.BaseRuleAnchors {
		h := chain.FirstHandle(r.Expr)
		if h == "" {
			t.Fatalf("a fresh chain lacks %q", r.Expr)
		}
		nft("delete", "rule", "inet", "cfm", "input", "handle", h)
	}
	be = start()
	be = start() // and again: nothing added twice
	listing := nft("list", "chain", "inet", "cfm", "input")
	var lines []string
	for _, l := range strings.Split(listing, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	idx := func(rule string) int {
		at := -1
		for i, l := range lines {
			if l == rule {
				if at >= 0 {
					t.Fatalf("%q twice in the chain:\n%s", rule, listing)
				}
				at = i
			}
		}
		return at
	}
	for _, r := range firewall.BaseRuleAnchors {
		e, an := idx(r.Expr), -1
		for i, l := range lines {
			if l == r.Anchor {
				an = i
				break
			}
		}
		if e < 0 || an < 0 || e != an+1 {
			t.Fatalf("after an upgrade %q is at %d, its anchor %q at %d; want right after:\n%s", r.Expr, e, r.Anchor, an, listing)
		}
	}
	if self := idx(`ip6 saddr @self_v6 accept`); self < 0 || self > idx(`ip6 saddr @block_v6_clients drop`) {
		t.Fatalf("the self accept must stay above the /64 drop:\n%s", listing)
	}
}
