//go:build linux

// Package feedtest holds the live-nft check both firewall engines run on a
// blocklist feed apply, so the assertions are written once.
package feedtest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cfm/internal/blocklists"
	"cfm/internal/firewall"
	"cfm/internal/firewall/setprobe"
)

// DefaultHosts is how many addresses the test feed carries: large enough that
// the old flush-then-batches refill left the union partial for long enough to
// be seen (~130 nft runs on the exec engine, ~200 netlink batches on nftlib).
// CFM_FEEDTEST_HOSTS overrides it, e.g. 1000000 to time a fleet-size union,
// or to push the batch past wmem_max under `unshare -r` and exercise the
// chunked fallback (which then fails step 1: the fallback has the gap).
const DefaultHosts = 200_000

// RunFeedReplaceIsAtomic drives an engine's ApplyFeed against a live nft and
// pins that a feed apply never unblocks an address the feed keeps:
//
//  1. While a changed feed is applied (an address dropped, one added, and a
//     /24 replaced by the /16 that covers it), a prober outside the backend
//     keeps asking the kernel whether the unions the base rules drop on still
//     hold an address the feed keeps (the LAST one written, so a refill in
//     batches misses it for almost its whole run) and one inside the /24 →
//     /16. A single miss fails the test.
//  2. After it, the unions hold exactly the new content.
//  3. An unchanged apply after another process emptied a union (`nft flush
//     set`, as `cfm reset` from the CLI does to the whole table) writes it
//     again: a skip-if-unchanged must not trust its own memory of the set.
//  4. A replace with an element the engine cannot write applies whole or
//     changes nothing.
//
// newBackend builds the engine. Gated like the other live tests; it refuses
// to run outside an empty network namespace.
func RunFeedReplaceIsAtomic(t *testing.T, newBackend func() firewall.Backend) {
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

	be := newBackend()
	if err := be.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}

	n := DefaultHosts
	if v, err := strconv.Atoi(os.Getenv("CFM_FEEDTEST_HOSTS")); err == nil && v >= 2 && v <= 4_000_000 {
		n = v
	}
	hosts := make([]string, n)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("%d.%d.%d.%d", 100+(i>>22), 64+((i>>16)&63), (i>>8)&255, i&255)
	}
	var (
		dropped = hosts[0]   // gone in round 2
		kept    = hosts[n-1] // the last one written
	)
	const (
		added = "198.51.100.200" // new in round 2
		inNet = "192.168.1.5"    // in 192.168.1.0/24, then in 192.168.0.0/16
		v6    = "2001:db8:1::5"
	)
	nets1 := []string{"192.168.1.0/24", "192.168.7.0/24"}
	for i := 0; i < 2000; i++ {
		nets1 = append(nets1, fmt.Sprintf("172.%d.%d.0/24", 16+(i>>8), i&255))
	}
	nets2 := append([]string{"192.168.0.0/16"}, nets1[2:]...)

	feed := blocklists.Feed{Name: "LIVETEST", Type: blocklists.TypeBlock}
	apply := func(v4 []string) {
		t.Helper()
		start := time.Now()
		if err := be.ApplyFeed(context.Background(), feed, &blocklists.FetchResult{V4: v4, V6: []string{v6}}); err != nil {
			t.Fatalf("ApplyFeed: %v", err)
		}
		t.Logf("ApplyFeed %d elems: %s", len(v4), time.Since(start).Round(time.Millisecond))
	}
	// One netlink lookup per probe (~0.1 ms); `nft get element` loads the
	// whole set first and would probe a few times a second at best.
	has := func(set, elem string) bool {
		ok, err := setprobe.Holds(set, elem)
		if err != nil {
			t.Errorf("probe %s %s: %v", set, elem, err)
		}
		return ok
	}
	want := func(set, elem string, present bool) {
		t.Helper()
		if got := has(set, elem); got != present {
			t.Fatalf("%s holds %s = %v, want %v", set, elem, got, present)
		}
	}

	apply(append(append([]string{}, hosts...), nets1...))
	want("block_ext_v4_hosts", kept, true)
	want("block_ext_v4_hosts", dropped, true)
	want("block_ext_v4_nets", inNet, true)
	want("block_ext_v6_hosts", v6, true)

	// 1) Apply a changed feed while a prober watches the unions.
	var (
		stop     atomic.Bool
		probes   atomic.Int64
		missMu   sync.Mutex
		misses   []string
		proberWG sync.WaitGroup
	)
	probe := func(set, elem string) {
		defer proberWG.Done()
		for !stop.Load() {
			probes.Add(1)
			if !has(set, elem) {
				missMu.Lock()
				misses = append(misses, fmt.Sprintf("%s %s at %s", set, elem, time.Now().Format("15:04:05.000")))
				missMu.Unlock()
			}
		}
	}
	proberWG.Add(3)
	go probe("block_ext_v4_hosts", kept)
	go probe("block_ext_v4_nets", inNet)
	go probe("block_ext_v6_hosts", v6)
	round2 := append(append([]string{added}, hosts[1:]...), nets2...)
	apply(round2)
	stop.Store(true)
	proberWG.Wait()
	if probes.Load() < 100 {
		t.Fatalf("only %d probes ran; the test proves nothing", probes.Load())
	}
	if len(misses) > 0 {
		t.Fatalf("a feed apply unblocked an address the feed keeps (%d of %d probes), first: %s",
			len(misses), probes.Load(), misses[0])
	}
	t.Logf("%d probes during the apply, no miss", probes.Load())

	// 2) The new content, and only it.
	want("block_ext_v4_hosts", added, true)
	want("block_ext_v4_hosts", dropped, false)
	want("block_ext_v4_hosts", kept, true)
	want("block_ext_v4_nets", "192.168.200.1", true) // only the /16 covers it
	want("block_ext_v4_nets", inNet, true)

	// 3) Another process empties the unions; an unchanged apply restores them.
	for _, set := range []string{"block_ext_v4_hosts", "block_ext_v4_nets", "block_ext_v6_hosts"} {
		if out, err := exec.Command("nft", "flush", "set", "inet", "cfm", set).CombinedOutput(); err != nil {
			t.Fatalf("flush %s: %v: %s", set, err, out)
		}
	}
	want("block_ext_v4_hosts", kept, false)
	apply(round2)
	want("block_ext_v4_hosts", kept, true)
	want("block_ext_v4_hosts", added, true)
	want("block_ext_v4_nets", inNet, true)
	want("block_ext_v6_hosts", v6, true)

	// 4) Unchanged again, nothing emptied: the unions are skipped (timing only;
	// the per-feed set has no TTL here, so it is skipped too).
	apply(round2)
	want("block_ext_v4_hosts", kept, true)

	// 5) A replace carrying an element the engine cannot write either applies
	// whole (nftlib drops what it cannot parse) or fails and leaves the old
	// content in place (nft refuses the whole script). Never the old batched
	// write's flush and partial refill: the set must not lose `added`, which
	// only the old content holds, unless the new content was applied.
	err := be.ReplaceSetFlushAdd("block_ext_v4_hosts", []string{kept, "999.1.1.1"}, nil)
	if err != nil {
		t.Logf("replace with a bad element: %v", err)
		want("block_ext_v4_hosts", added, true)
		want("block_ext_v4_hosts", dropped, false)
	} else {
		want("block_ext_v4_hosts", added, false)
	}
	want("block_ext_v4_hosts", kept, true)
}
