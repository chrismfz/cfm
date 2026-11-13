//go:build linux

package setprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestLiveNFTLookup checks Lookup against a real kernel and nft: hash and
// interval sets, adjacent intervals (an end and a start at one key, the
// 4.18 case Lookup works around), ranges, intervals at both ends of the
// address space, IPv6, timeouts. Every answer is compared with the interval
// nft itself lists, for fixed and random addresses.
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/setprobe/ -run LiveNFTLookup -v
func TestLiveNFTLookup(t *testing.T) {
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if out, err := exec.Command("nft", "list", "table", "inet", "cfm").CombinedOutput(); err == nil && strings.Contains(string(out), "hook input") {
		t.Fatalf("refusing to run: a live `inet cfm` table exists — run this test inside an isolated netns (unshare -rn)")
	}
	script := `add table inet cfm
flush table inet cfm
add set inet cfm h4 { type ipv4_addr; flags timeout; }
add set inet cfm h6 { type ipv6_addr; }
add set inet cfm n4 { type ipv4_addr; flags interval; }
add set inet cfm t4 { type ipv4_addr; flags interval, timeout; }
add set inet cfm n6 { type ipv6_addr; flags interval; }
add element inet cfm h4 { 192.0.2.7, 192.0.2.8 timeout 1h }
add element inet cfm h6 { 2001:db8::7 }
add element inet cfm n4 { 0.0.0.0/8, 10.0.0.0/25, 10.0.0.128/25, 10.0.1.5, 10.0.1.6, 10.0.2.0-10.0.2.9, 10.0.2.11, 10.0.2.12-10.0.2.20, 255.255.255.0/24 }
add element inet cfm t4 { 198.51.100.0/24 timeout 1h, 198.51.101.0/24 timeout 1h }
add element inet cfm n6 { 2001:db8::/64, 2001:db8:0:1::/64, 2001:db8:1::5, ffff:ffff:ffff:ffff::/64 }
`
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f -: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm").Run() })

	fixed := map[string][]string{
		"h4": {"192.0.2.7", "192.0.2.8", "192.0.2.9", "0.0.0.0", "255.255.255.255"},
		"h6": {"2001:db8::7", "2001:db8::8"},
		"n4": {"0.0.0.0", "0.255.255.255", "1.0.0.0", "10.0.0.0", "10.0.0.127", "10.0.0.128", "10.0.0.255",
			"10.0.1.0", "10.0.1.4", "10.0.1.5", "10.0.1.6", "10.0.1.7", "10.0.2.0", "10.0.2.9", "10.0.2.10",
			"10.0.2.11", "10.0.2.12", "10.0.2.20", "10.0.2.21", "255.255.254.255", "255.255.255.0", "255.255.255.255"},
		"t4": {"198.51.100.0", "198.51.100.255", "198.51.101.0", "198.51.101.255", "198.51.102.0"},
		"n6": {"2001:db8::", "2001:db8::ffff:ffff:ffff:ffff", "2001:db8:0:1::", "2001:db8:0:2::", "2001:db8:1::5",
			"2001:db8:1::6", "ffff:ffff:ffff:ffff::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::"},
	}
	rng := rand.New(rand.NewSource(1))
	for set, qs := range fixed {
		want := nftIntervals(t, set)
		var addrs []netip.Addr
		for _, q := range qs {
			addrs = append(addrs, netip.MustParseAddr(q))
		}
		// Random addresses near every element boundary.
		for _, iv := range want {
			for _, a := range []netip.Addr{iv[0], iv[1]} {
				for d := 0; d < 3; d++ {
					addrs = append(addrs, a)
					if a = a.Next(); !a.IsValid() {
						break
					}
				}
			}
			if iv[0].Prev().IsValid() {
				addrs = append(addrs, iv[0].Prev())
			}
		}
		for i := 0; i < 200; i++ {
			b := want[rng.Intn(len(want))][0].AsSlice()
			b[len(b)-1] ^= byte(rng.Intn(256))
			b[len(b)-2] ^= byte(rng.Intn(4))
			a, _ := netip.AddrFromSlice(b)
			addrs = append(addrs, a)
		}
		// One call for all, then one per address: an ambiguous boundary
		// fails a whole call, and the caller dumps the set.
		if _, _, err := Lookup(context.Background(), "cfm", set, addrs); err != nil && !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("%s: %v", set, err)
		}
		ambiguous := 0
		for _, a := range addrs {
			var w *[2]netip.Addr
			boundary := false
			for j := range want {
				if want[j][0].Compare(a) <= 0 && a.Compare(want[j][1]) <= 0 {
					w = &want[j]
				}
				boundary = boundary || want[j][1].Next() == a
			}
			m, ok, err := Lookup(context.Background(), "cfm", set, []netip.Addr{a})
			switch {
			case errors.Is(err, ErrAmbiguous) && boundary:
				// Only where an interval ends exactly at a.
				ambiguous++
			case err != nil:
				t.Errorf("%s: %s: %v", set, a, err)
			case w == nil && ok[0]:
				t.Errorf("%s: %s found in %v, nft lists no element holding it", set, a, m[0])
			case w != nil && !ok[0]:
				t.Errorf("%s: %s not found, nft lists %v", set, a, *w)
			case w != nil && (m[0].From != w[0] || m[0].To != w[1]):
				t.Errorf("%s: %s in %v, nft lists %v", set, a, m[0], *w)
			}
		}
		t.Logf("%s: %d addresses, %d ambiguous boundaries", set, len(addrs), ambiguous)
	}
	if _, _, err := Lookup(context.Background(), "cfm", "h4", []netip.Addr{netip.MustParseAddr("2001:db8::1")}); err == nil {
		t.Error("an IPv6 address in an IPv4 set: want an error")
	}
	if _, _, err := Lookup(context.Background(), "cfm", "missing", []netip.Addr{netip.MustParseAddr("192.0.2.7")}); err == nil {
		t.Error("a missing set: want an error")
	}
}

// nftIntervals lists set's elements as [first, last] with nft -j.
func nftIntervals(t *testing.T, set string) [][2]netip.Addr {
	t.Helper()
	out, err := exec.Command("nft", "-j", "list", "set", "inet", "cfm", set).Output()
	if err != nil {
		t.Fatalf("nft list set %s: %v", set, err)
	}
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []any `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var res [][2]netip.Addr
	var walk func(e any) [2]netip.Addr
	walk = func(e any) [2]netip.Addr {
		switch v := e.(type) {
		case string:
			a := netip.MustParseAddr(v)
			return [2]netip.Addr{a, a}
		case map[string]any:
			if x, ok := v["elem"]; ok {
				return walk(x)
			}
			if x, ok := v["val"]; ok {
				return walk(x)
			}
			if p, ok := v["prefix"].(map[string]any); ok {
				pf := netip.PrefixFrom(netip.MustParseAddr(p["addr"].(string)), int(p["len"].(float64)))
				last := pf.Addr().AsSlice()
				for i := pf.Bits(); i < len(last)*8; i++ {
					last[i/8] |= 0x80 >> (i % 8)
				}
				l, _ := netip.AddrFromSlice(last)
				return [2]netip.Addr{pf.Addr(), l}
			}
			if r, ok := v["range"].([]any); ok {
				return [2]netip.Addr{netip.MustParseAddr(r[0].(string)), netip.MustParseAddr(r[1].(string))}
			}
		}
		panic(fmt.Sprintf("element %v", e))
	}
	for _, n := range doc.Nftables {
		if n.Set != nil {
			for _, e := range n.Set.Elem {
				res = append(res, walk(e))
			}
		}
	}
	return res
}
