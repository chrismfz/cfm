//go:build linux

package setprobe

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestLiveNFTHostTimes checks HostProbe against a real kernel: a timed
// element reports its time left, a permanent one 0, an absent one not
// found, and an interval set is refused (the caller dumps). It is the read
// every automatic ban plans from on both engines (firewall.ReadHostElems).
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/setprobe/ -run LiveNFTHostTimes -v
func TestLiveNFTHostTimes(t *testing.T) {
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
	script := `add table inet cfm
flush table inet cfm
add set inet cfm hb4 { type ipv4_addr; flags timeout; }
add set inet cfm hb6 { type ipv6_addr; flags timeout; }
add set inet cfm hd4 { type ipv4_addr; flags timeout; timeout 2h; }
add set inet cfm iv6 { type ipv6_addr; flags interval, timeout; }
add element inet cfm hb4 { 192.0.2.7 timeout 7d, 192.0.2.8, 192.0.2.9 timeout 1h }
add element inet cfm hb6 { 2001:db8::7 timeout 1h, 2001:db8::8 }
add element inet cfm hd4 { 192.0.2.20, 192.0.2.21 timeout 3h }
add element inet cfm iv6 { 2001:db8:1::/64 timeout 1h }
`
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f -: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm").Run() })

	type want struct {
		ip        string
		found     bool
		permanent bool
		around    time.Duration // time left, when timed
	}
	check := func(set string, cases []want) {
		t.Helper()
		ips := make([]net.IP, len(cases))
		for i, c := range cases {
			ips[i] = net.ParseIP(c.ip)
		}
		found, expires, err := HostProbe(set, ips)
		if err != nil {
			t.Fatalf("HostProbe(%s): %v", set, err)
		}
		for i, c := range cases {
			switch {
			case found[i] != c.found:
				t.Errorf("%s %s: found=%v, want %v", set, c.ip, found[i], c.found)
			case !c.found:
			case c.permanent && expires[i] != 0:
				t.Errorf("%s %s: left %s, want permanent (0)", set, c.ip, expires[i])
			case !c.permanent && (expires[i] <= 0 || expires[i] > c.around || expires[i] < c.around-time.Minute):
				t.Errorf("%s %s: left %s, want ~%s", set, c.ip, expires[i], c.around)
			}
		}
	}
	check("hb4", []want{
		{ip: "192.0.2.7", found: true, around: 7 * 24 * time.Hour},
		{ip: "192.0.2.8", found: true, permanent: true},
		{ip: "192.0.2.9", found: true, around: time.Hour},
		{ip: "192.0.2.10"},
		{ip: "::ffff:192.0.2.7", found: true, around: 7 * 24 * time.Hour}, // IPv4-mapped reads as IPv4
	})
	check("hb6", []want{
		{ip: "2001:db8::7", found: true, around: time.Hour},
		{ip: "2001:db8::8", found: true, permanent: true},
		{ip: "2001:db8::9"},
	})
	// A set with a default timeout: an element that takes it (the kernel may
	// leave the timeout attribute out, the expiration stays) is timed.
	check("hd4", []want{
		{ip: "192.0.2.20", found: true, around: 2 * time.Hour},
		{ip: "192.0.2.21", found: true, around: 3 * time.Hour},
	})
	if _, _, err := HostProbe("iv6", []net.IP{net.ParseIP("2001:db8:1::5")}); !errors.Is(err, ErrIntervalSet) {
		t.Errorf("interval set: err=%v, want ErrIntervalSet", err)
	}
	if _, _, err := HostProbe("missing", []net.IP{net.ParseIP("192.0.2.7")}); err == nil {
		t.Error("a missing set answered without an error")
	}
	if _, _, err := HostProbe("hb4", []net.IP{net.ParseIP("2001:db8::7")}); err == nil {
		t.Error("an IPv6 address in an IPv4 set answered without an error")
	}
}
