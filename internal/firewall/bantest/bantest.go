//go:build linux

// Package bantest holds the live-nft check both firewall engines run on
// their TTL bans across a daemon restart, so the assertions are written once.
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

// RunTTLBansSurviveRestart drives an engine against a live nft:
//
//  1. A restart is a new backend running EnsureBase over the existing table.
//     It must keep every set element: the TTL bans with their timeouts and a
//     permanent one (2026-10-21: an upgrade freed every TTL ban; the rpm
//     %post ran `cfm disable`, and this pins that the daemon itself never
//     does the same).
//  2. A table that does go (`cfm disable`, a reboot) is rebuilt by
//     EnsureBase, and the persisted store brings the TTL bans back for the
//     time they have left, less the one unblocked (Forget) and the one an
//     allow now covers.
//
// newBackend is called once per "daemon start". Gated like the other live
// tests; it refuses to run outside an empty network namespace.
func RunTTLBansSurviveRestart(t *testing.T, newBackend func() firewall.Backend) {
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
	left := func(be firewall.Backend, set, ip string) (time.Duration, bool) {
		t.Helper()
		elems, err := be.ListSetElementsTimed(set)
		if err != nil {
			t.Fatalf("list %s: %v", set, err)
		}
		want := net.ParseIP(ip)
		for _, e := range elems {
			if got := net.ParseIP(e.Elem); got != nil && got.Equal(want) {
				return e.Expires, true // 0 = permanent
			}
		}
		return 0, false
	}
	ttl := func(d time.Duration) *time.Duration { return &d }

	const (
		week     = "198.51.100.51" // WAF/AUTH_BURST, 168h
		hour     = "198.51.100.52" // 1h
		v6       = "2001:db8:6102:50cd::"
		perm     = "198.51.100.53" // cfm.deny
		unbanned = "198.51.100.54"
		allowed  = "198.51.100.55"
	)
	be := start()
	for ip, d := range map[string]time.Duration{week: 168 * time.Hour, hour: time.Hour, v6: 168 * time.Hour, unbanned: time.Hour, allowed: time.Hour} {
		if err := be.AddBlock(net.ParseIP(ip), "", ttl(d)); err != nil {
			t.Fatalf("AddBlock %s: %v", ip, err)
		}
	}
	if err := be.AddBlock(net.ParseIP(perm), "", nil); err != nil {
		t.Fatal(err)
	}

	// 1) Restart over the live table: nothing may go.
	be = start()
	be = start() // and again: an upgrade restarts the daemon twice
	for ip, min := range map[string]time.Duration{week: 167 * time.Hour, hour: 59 * time.Minute, unbanned: 59 * time.Minute, allowed: 59 * time.Minute} {
		if d, ok := left(be, "block_v4", ip); !ok || d < min {
			t.Fatalf("after EnsureBase on a live table: %s present=%v left=%s, want > %s", ip, ok, d, min)
		}
	}
	if d, ok := left(be, "block_v6", v6); !ok || d < 167*time.Hour {
		t.Fatalf("after EnsureBase on a live table: %s present=%v left=%s", v6, ok, d)
	}
	if d, ok := left(be, "block_v4", perm); !ok || d != 0 {
		t.Fatalf("after EnsureBase on a live table: permanent %s present=%v left=%s", perm, ok, d)
	}

	// 2) The daemon persists what nft holds, an unblock forgets one, then the
	// table goes. The next start restores the rest for the time it has left.
	path := filepath.Join(t.TempDir(), "ttlbans.json")
	s := ttlban.New(path)
	if _, err := s.Restore(be, nil); err != nil {
		t.Fatal(err)
	}
	var elems []firewall.SetElementTimed
	readAt := time.Now()
	for _, set := range ttlban.Sets {
		got, err := be.ListSetElementsTimed(set)
		if err != nil {
			t.Fatal(err)
		}
		elems = append(elems, got...)
	}
	if err := s.Snapshot(readAt, elems); err != nil {
		t.Fatal(err)
	}
	if err := be.RemoveBlock(net.ParseIP(unbanned)); err != nil {
		t.Fatal(err)
	}
	_ = s.Forget(unbanned)
	if err := be.DropEverything(); err != nil {
		t.Fatalf("DropEverything: %v", err)
	}

	be = start()
	if _, ok := left(be, "block_v4", week); ok {
		t.Fatal("the dropped table still holds the ban; the test proves nothing")
	}
	l := ttlban.New(path) // the next daemon start reads the file
	if err := l.Load(); err != nil {
		t.Fatal(err)
	}
	res, err := l.Restore(be, func(ip net.IP) bool { return ip.String() == allowed })
	if err != nil {
		t.Fatalf("Restore: %v (%+v)", err, res)
	}
	for ip, min := range map[string]time.Duration{week: 167 * time.Hour, hour: 58 * time.Minute} {
		d, ok := left(be, "block_v4", ip)
		if !ok || d == 0 || d < min {
			t.Fatalf("restored %s: present=%v left=%s, want a timed ban > %s", ip, ok, d, min)
		}
	}
	if d, ok := left(be, "block_v4", hour); ok && d > time.Hour {
		t.Fatalf("restore lengthened %s to %s", hour, d)
	}
	if d, ok := left(be, "block_v6", v6); !ok || d < 167*time.Hour {
		t.Fatalf("restored %s: present=%v left=%s", v6, ok, d)
	}
	for _, ip := range []string{unbanned, allowed} {
		if _, ok := left(be, "block_v4", ip); ok {
			t.Fatalf("%s came back after a restart", ip)
		}
	}
	// The permanent ban is cfm.deny's to re-apply, never the store's.
	if _, ok := left(be, "block_v4", perm); ok {
		t.Fatal("the store restored a permanent ban")
	}
}
