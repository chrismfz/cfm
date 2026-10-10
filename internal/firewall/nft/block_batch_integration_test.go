//go:build linux

package nft

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// TestLiveNFTExtendBlock runs ExtendBlock against a real `nft`: it adds,
// extends, keeps a longer or permanent ban, and two automatic bans of one
// address at once never leave the shorter one (hostBatchMu; without it both
// read the old element, both plan a replace, and the last commit wins).
//
// It writes the `inet cfm` table, so it is gated like the DNAT test:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nft/ -run LiveNFTExtendBlock -v
func TestLiveNFTExtendBlock(t *testing.T) {
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if out, err := exec.Command("nft", "list", "table", "inet", "cfm").CombinedOutput(); err == nil {
		s := string(out)
		if strings.Contains(s, "allow_v4") || strings.Contains(s, "block_v4") || strings.Contains(s, "hook input") {
			t.Fatalf("refusing to run: a populated `inet cfm` table already exists — run this test inside an isolated netns (unshare -rn)")
		}
	}
	nftRun := func(script string) {
		t.Helper()
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -f -: %v\n%s", err, out)
		}
	}
	nftRun(`add table inet cfm
flush table inet cfm
add set inet cfm block_v4 { type ipv4_addr; flags timeout; }
add set inet cfm block_v6 { type ipv6_addr; flags timeout; }`)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm").Run() })

	b := New()
	left := func(ip string) (time.Duration, bool) {
		t.Helper()
		elems, err := b.ListSetElementsTimed("block_v4")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range elems {
			if e.Elem == ip {
				return e.Expires, true // 0 = permanent
			}
		}
		return 0, false
	}
	ext := func(ip string, ttl time.Duration) bool {
		t.Helper()
		kept, err := firewall.ExtendBlock(b, net.ParseIP(ip), ttl)
		if err != nil {
			t.Fatalf("ExtendBlock(%s, %s): %v", ip, ttl, err)
		}
		return kept
	}

	const ip = "192.0.2.10"
	if ext(ip, time.Hour) {
		t.Error("a new ban reported kept")
	}
	if ext(ip, 7*24*time.Hour) {
		t.Error("an extension reported kept")
	}
	if !ext(ip, time.Hour) {
		t.Error("a shorter ban over a 7d one did not report kept")
	}
	if d, ok := left(ip); !ok || d < 6*24*time.Hour {
		t.Fatalf("after 1h over 7d: present=%v left=%s, want ~7d", ok, d)
	}

	const perm = "192.0.2.11"
	if err := b.AddBlock(net.ParseIP(perm), "", nil); err != nil {
		t.Fatal(err)
	}
	if !ext(perm, time.Hour) {
		t.Error("a ttl ban over a permanent one did not report kept")
	}
	if d, ok := left(perm); !ok || d != 0 {
		t.Fatalf("permanent ban: present=%v left=%s, want permanent", ok, d)
	}

	// The read-failure fallback: an exclusive create keeps an existing ban.
	if exists, err := b.CreateBlock(net.ParseIP(perm), time.Hour); err != nil || !exists {
		t.Fatalf("CreateBlock over a permanent ban: exists=%v err=%v", exists, err)
	}
	if d, ok := left(perm); !ok || d != 0 {
		t.Fatalf("CreateBlock touched a permanent ban: present=%v left=%s", ok, d)
	}
	// A sub-second TTL must not become "timeout 0s", i.e. permanent.
	const sub = "192.0.2.15"
	if _, err := b.CreateBlock(net.ParseIP(sub), 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if d, ok := left(sub); ok && d == 0 {
		t.Fatal("CreateBlock(500ms) made a permanent ban")
	}
	const fresh = "192.0.2.13"
	if exists, err := b.CreateBlock(net.ParseIP(fresh), time.Hour); err != nil || exists {
		t.Fatalf("CreateBlock of a new address: exists=%v err=%v", exists, err)
	}
	if d, ok := left(fresh); !ok || d < 50*time.Minute || d > time.Hour {
		t.Fatalf("CreateBlock: present=%v left=%s, want ~1h", ok, d)
	}

	// A manual permanent ban racing an automatic 1h one: the permanent one
	// must stand (AddBlock holds the same lock as the batch).
	const manual = "192.0.2.14"
	for round := 0; round < 15; round++ {
		nftRun("flush set inet cfm block_v4\nadd element inet cfm block_v4 { " + manual + " timeout 30m }")
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := b.AddBlock(net.ParseIP(manual), "", nil); err != nil {
				t.Errorf("round %d AddBlock: %v", round, err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := firewall.ExtendBlock(b, net.ParseIP(manual), time.Hour); err != nil {
				t.Errorf("round %d ExtendBlock: %v", round, err)
			}
		}()
		wg.Wait()
		if d, ok := left(manual); !ok || d != 0 {
			t.Fatalf("round %d: permanent + 1h left present=%v left=%s, want permanent", round, ok, d)
		}
	}

	// Two bans of one address at once, many rounds: the 7d one must stand.
	const race = "192.0.2.12"
	for round := 0; round < 15; round++ {
		nftRun("flush set inet cfm block_v4\nadd element inet cfm block_v4 { " + race + " timeout 30m }")
		var wg sync.WaitGroup
		for _, ttl := range []time.Duration{7 * 24 * time.Hour, time.Hour, 7 * 24 * time.Hour, time.Hour} {
			wg.Add(1)
			go func(ttl time.Duration) {
				defer wg.Done()
				if _, err := firewall.ExtendBlock(b, net.ParseIP(race), ttl); err != nil {
					t.Errorf("round %d ExtendBlock(%s): %v", round, ttl, err)
				}
			}(ttl)
		}
		wg.Wait()
		if d, ok := left(race); !ok || d < 6*24*time.Hour {
			t.Fatalf("round %d: concurrent 7d + 1h left present=%v left=%s, want ~7d", round, ok, d)
		}
	}
}
