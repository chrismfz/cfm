//go:build linux

package nft

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"cfm/internal/config"
)

// TestApplyPortsPolicyIsAtomicAndStable drives the real engine against a live
// nft: EnsureBase, the ports policy, the web DNAT accepts, then the ports
// policy again. The re-apply must not rewrite a single rule (every handle
// stays), the DNAT accepts stay above the drops, and a stricter TCP_OUT keeps
// the loopback exemption. Gated like the DNAT integration test; run it in an
// isolated netns:
//
//	unshare -rn env CFM_NFT_INTEGRATION=1 go test ./internal/firewall/nft/ -run ApplyPortsPolicyIsAtomic -v
func TestApplyPortsPolicyIsAtomicAndStable(t *testing.T) {
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
	t.Cleanup(func() {
		for _, tbl := range []string{"cfm", "cfm_redirect"} {
			_ = exec.Command("nft", "delete", "table", "inet", tbl).Run()
		}
	})

	cfg := &config.Config{}
	cfg.Ports = config.PortsConfig{
		TCPIn:  []config.PortRange{{From: 22, To: 22}, {From: 80, To: 80}, {From: 443, To: 443}, {From: 9080, To: 9080}},
		UDPIn:  []config.PortRange{{From: 0, To: 65535}},
		TCPOut: []config.PortRange{{From: 0, To: 65535}},
		UDPOut: []config.PortRange{{From: 0, To: 65535}},
	}
	cfg.Debug.Port = 6060
	cfg.Portscan = config.PortscanConfig{Enabled: true, TrackTCP: true, TrackUDP: true, Interval: 3600, OnlyPorts: []config.PortRange{{From: 0, To: 40000}}}
	b := New()
	b.cfg = cfg

	if err := b.EnsureBase(); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	if err := b.ApplyPortsPolicy(&cfg.Ports); err != nil {
		t.Fatalf("ApplyPortsPolicy: %v", err)
	}
	if err := b.DNATOn("inet", "cfm_redirect", 9080, 9043); err != nil {
		t.Fatalf("DNATOn: %v", err)
	}
	list := func(chain string) string {
		out, err := exec.Command("nft", "-a", "list", "chain", "inet", "cfm", chain).CombinedOutput()
		if err != nil {
			t.Fatalf("list %s: %v\n%s", chain, err, out)
		}
		return string(out)
	}
	before := list("input") + list("output")

	// Re-apply: not one rule rewritten (a rewritten rule gets a new handle).
	if err := b.ApplyPortsPolicy(&cfg.Ports); err != nil {
		t.Fatalf("ApplyPortsPolicy (re-apply): %v", err)
	}
	if after := list("input") + list("output"); after != before {
		t.Fatalf("a re-apply changed the chains:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	in := list("input")
	idx := func(re string) int {
		lines := strings.Split(in, "\n")
		for i, l := range lines {
			if regexp.MustCompile(re).MatchString(l) {
				return i
			}
		}
		return -1
	}
	acc, dnat, drop := idx(`ct state new tcp dport @tcp_in_ports accept`), idx(`cfm_(edge_)?dnat_accept:web_http_tcp`), idx(`^\s*ct state new tcp dport 0-65535 drop`)
	if acc < 0 || dnat < 0 || drop < 0 || acc > drop || dnat > drop {
		t.Fatalf("want the tcp_in accept (%d) and the DNAT accept (%d) above the drop (%d):\n%s", acc, dnat, drop, in)
	}
	if !strings.Contains(in, "timeout 1h") || strings.Count(in, "add @ps_pairs_v4") != 1 {
		t.Fatalf("portscan rule (3600s = 1h) missing or duplicated:\n%s", in)
	}

	// Tighten TCP_OUT: it lands with the loopback exemption first.
	cfg.Ports.TCPOut = []config.PortRange{{From: 443, To: 443}}
	if err := b.ApplyPortsPolicy(&cfg.Ports); err != nil {
		t.Fatalf("ApplyPortsPolicy (strict TCP_OUT): %v", err)
	}
	out := list("output")
	first := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "# handle") && !strings.Contains(l, "chain output") {
			first = strings.TrimSpace(l)
			break
		}
	}
	if !strings.HasPrefix(first, `oif "lo" accept`) {
		t.Fatalf("output does not start with the loopback accept:\n%s", out)
	}
	set, _ := exec.Command("nft", "list", "set", "inet", "cfm", "tcp_out_ports").CombinedOutput()
	if !strings.Contains(string(set), "elements = { 443 }") {
		t.Fatalf("tcp_out_ports:\n%s", set)
	}
}
