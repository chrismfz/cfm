//go:build linux

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"cfm/internal/config"
)

// TestPortsPolicyScript_LiveNFT drives PortsPolicyScript against the real nft.
// Gated like the other live nft tests, and it refuses to run anywhere but an
// empty network namespace:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/ -run LiveNFT -v
func TestPortsPolicyScript_LiveNFT(t *testing.T) {
	if os.Getenv("CFM_NFT_INTEGRATION") != "1" {
		t.Skip("set CFM_NFT_INTEGRATION=1 (root + nft, isolated netns) to run")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	nft := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("nft", args...).CombinedOutput() // #nosec G204 -- test, fixed binary
		if err != nil {
			t.Fatalf("nft %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	if tables := strings.TrimSpace(nft("list", "tables")); tables != "" {
		t.Fatalf("refusing to run: this namespace already has tables (not a fresh netns?):\n%s", tables)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "cfm").Run() })
	apply := func(script string) {
		t.Helper()
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -f: %v\n%s\nscript:\n%s", err, out, script)
		}
	}
	listing := func(chain string) string { return nft("-a", "list", "chain", "inet", "cfm", chain) }
	read := func(args ...string) (string, error) {
		out, err := exec.Command("nft", args...).Output() // #nosec G204 -- test, fixed binary
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%w: %s", err, ee.Stderr)
		}
		return string(out), err
	}
	st := func() PortsPolicyState {
		t.Helper()
		s, err := readPortsPolicyState(PortsPolicy{Family: "inet", Table: "cfm"}, read)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	rulesOf := func(chain string) []string {
		var out []string
		for _, r := range ParseChainRules(listing(chain)).rules {
			out = append(out, r.key)
		}
		return out
	}
	ruleLines := func(script string) []string {
		var out []string
		for _, l := range strings.Split(script, "\n") {
			if strings.Contains(l, " rule ") {
				out = append(out, l)
			}
		}
		return out
	}

	// What EnsureBase leaves (abridged) plus the sets the engines create.
	apply(`add table inet cfm
add set inet cfm self_v4 { type ipv4_addr; }
add set inet cfm self_v6 { type ipv6_addr; }
add set inet cfm debug_api_v4 { type ipv4_addr; flags timeout; }
add set inet cfm debug_api_v6 { type ipv6_addr; flags timeout; }
add set inet cfm ps_pairs_v4 { type ipv4_addr . inet_service; flags timeout; }
add set inet cfm ps_pairs_v6 { type ipv6_addr . inet_service; flags timeout; }
add set inet cfm ps_pairs_udp_v4 { type ipv4_addr . inet_service; flags timeout; }
add set inet cfm ps_pairs_udp_v6 { type ipv6_addr . inet_service; flags timeout; }
add chain inet cfm input { type filter hook input priority -50; policy accept; }
add rule inet cfm input iif "lo" accept
add rule inet cfm input ip saddr @self_v4 accept
add rule inet cfm input ct state established,related accept`)

	p := PortsPolicy{
		Family: "inet", Table: "cfm",
		TCPIn:      []config.PortRange{{From: 22, To: 22}, {From: 80, To: 80}, {From: 443, To: 443}, {From: 49000, To: 65535}},
		UDPIn:      []config.PortRange{{From: 0, To: 65535}},
		TCPOut:     []config.PortRange{{From: 25, To: 25}, {From: 53, To: 53}, {From: 80, To: 80}, {From: 443, To: 443}},
		UDPOut:     []config.PortRange{{From: 53, To: 53}},
		DebugPorts: []int{6060},
		Portscan:   &PortscanTracking{TrackTCP: true, TrackUDP: true, Interval: 3600, Service: []config.PortRange{{From: 0, To: 40000}}},
	}

	// 1) Fresh node: the whole policy in one transaction.
	apply(PortsPolicyScript(p, st()))
	in := rulesOf("input")
	want := []string{
		`iif lo accept`, `ip saddr @self_v4 accept`, `ct state established,related accept`,
		`tcp dport @ps_track_tcp_ports add @ps_pairs_v4 { ip saddr . tcp dport timeout 1h }`,
		`ip6 nexthdr tcp tcp dport @ps_track_tcp_ports add @ps_pairs_v6 { ip6 saddr . tcp dport timeout 1h }`,
		`udp dport @ps_track_udp_ports add @ps_pairs_udp_v4 { ip saddr . udp dport timeout 1h }`,
		`ip6 nexthdr udp udp dport @ps_track_udp_ports add @ps_pairs_udp_v6 { ip6 saddr . udp dport timeout 1h }`,
		`ct state new tcp dport @tcp_in_ports accept`, `ct state new udp dport @udp_in_ports accept`,
		`ct state new tcp dport 6060 ip saddr @self_v4 accept`, `ct state new tcp dport 6060 ip6 saddr @self_v6 accept`,
		`ct state new tcp dport 6060 ip saddr @debug_api_v4 accept`, `ct state new tcp dport 6060 ip6 saddr @debug_api_v6 accept`,
		`ct state new tcp dport 0-65535 drop`, `ct state new udp dport 0-65535 drop`, `ct state invalid drop`,
	}
	if strings.Join(in, "\n") != strings.Join(want, "\n") {
		t.Fatalf("input after a fresh apply:\n%s\nwant:\n%s", strings.Join(in, "\n"), strings.Join(want, "\n"))
	}
	wantOut := []string{
		`oif lo accept`, `ct state established,related accept`, `ct state invalid drop`,
		`ct state new tcp dport @tcp_out_ports accept`, `ct state new udp dport @udp_out_ports accept`,
		`ct state new tcp dport 0-65535 drop`, `ct state new udp dport 0-65535 drop`,
	}
	if got := rulesOf("output"); strings.Join(got, "\n") != strings.Join(wantOut, "\n") {
		t.Fatalf("output after a fresh apply:\n%s", strings.Join(got, "\n"))
	}
	if s := nft("list", "set", "inet", "cfm", "tcp_out_ports"); !strings.Contains(s, "elements = { 25, 53, 80, 443 }") {
		t.Fatalf("tcp_out_ports:\n%s", s)
	}

	// 2) Re-apply: the printed rules are recognised (timeout 1h, quotes), so
	// not one rule is written, only the sets reloaded.
	if rl := ruleLines(PortsPolicyScript(p, st())); len(rl) != 0 {
		t.Fatalf("re-apply on a converged node wrote rules:\n%s", strings.Join(rl, "\n"))
	}

	// 3) Other features insert above the drops (DNAT accepts); a converged
	// chain still writes nothing and they stay above the drops.
	handles := ParseChainRules(listing("input")).rules
	var drop string
	for _, r := range handles {
		if r.key == ruleKey(ruleNewTCPDrop) {
			drop = r.handle
		}
	}
	apply(`insert rule inet cfm input position ` + drop + ` tcp dport 9080 ct state new accept comment "cfm_dnat_accept:x"`)
	if rl := ruleLines(PortsPolicyScript(p, st())); len(rl) != 0 {
		t.Fatalf("an accept inserted above the drops triggered a rewrite:\n%s", strings.Join(rl, "\n"))
	}

	// 4) An older node: bare drops, duplicates, a rule appended BELOW the drops.
	// One transaction fixes all of it; the stray rule ends up above the drops.
	apply(`add rule inet cfm input tcp dport 0-65535 drop
add rule inet cfm input ct state new tcp dport @tcp_in_ports accept
add rule inet cfm input tcp dport 8443 accept`)
	apply(PortsPolicyScript(p, st()))
	in = rulesOf("input")
	n := len(in)
	// (`ct state invalid drop` was present, so it keeps its place, as on titan.)
	if in[n-2] != ruleKey(ruleNewTCPDrop) || in[n-1] != ruleKey(ruleNewUDPDrop) {
		t.Fatalf("drops not last after the repair:\n%s", strings.Join(in, "\n"))
	}
	count := map[string]int{}
	for _, k := range in {
		count[k]++
	}
	for _, k := range []string{"ct state new tcp dport @tcp_in_ports accept", ruleNewTCPDrop, "tcp dport 8443 accept", ruleInvalidDrop} {
		if count[ruleKey(k)] != 1 {
			t.Fatalf("%q appears %d times:\n%s", k, count[ruleKey(k)], strings.Join(in, "\n"))
		}
	}
	if count[ruleKey("tcp dport 0-65535 drop")] != 0 {
		t.Fatalf("bare drop survived:\n%s", strings.Join(in, "\n"))
	}
	if rl := ruleLines(PortsPolicyScript(p, st())); len(rl) != 0 {
		t.Fatalf("not converged after the repair:\n%s", strings.Join(rl, "\n"))
	}

	// 5) A stricter TCP_OUT lands together with everything else.
	p.TCPOut = []config.PortRange{{From: 443, To: 443}}
	apply(PortsPolicyScript(p, st()))
	if s := nft("list", "set", "inet", "cfm", "tcp_out_ports"); !strings.Contains(s, "elements = { 443 }") {
		t.Fatalf("tcp_out_ports after tightening:\n%s", s)
	}

	// 6) An operator's output policy survives an apply (the chain is never
	// re-declared once it exists).
	apply(`add chain inet cfm output { type filter hook output priority 0; policy drop; }`)
	apply(PortsPolicyScript(p, st()))
	if s := nft("list", "chain", "inet", "cfm", "output"); !strings.Contains(s, "policy drop;") {
		t.Fatalf("output policy reset:\n%s", s)
	}
	apply(`add chain inet cfm output { type filter hook output priority 0; policy accept; }`)

	// 7) A port set that exists with other flags is reloaded, not re-declared
	// (re-declaring it fails the whole batch with "File exists").
	apply(`flush chain inet cfm output
delete set inet cfm tcp_out_ports
add set inet cfm tcp_out_ports { type inet_service; flags interval,timeout; }`)
	apply(PortsPolicyScript(p, st()))
	if s := nft("list", "set", "inet", "cfm", "tcp_out_ports"); !strings.Contains(s, "443") {
		t.Fatalf("tcp_out_ports with other flags not reloaded:\n%s", s)
	}
}
