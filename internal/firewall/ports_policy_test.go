package firewall

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"cfm/internal/config"
)

// The input chains of two live nodes (2026-10-03), as `nft -a list chain`
// printed them: titan runs the nft engine, orion nftlib. Note the different
// place of `ct state invalid drop` and of the DNAT accepts.
const titanInput = `table inet cfm {
	chain input { # handle 1
		type filter hook input priority -50; policy accept;
		iif "lo" accept # handle 59
		ip saddr @self_v4 accept # handle 58
		ip saddr @block_v4 drop # handle 46
		ct state established,related ip saddr @block_v4 drop # handle 60
		ct state established,related accept # handle 68
		jump flood # handle 69
		tcp dport @ps_track_tcp_ports add @ps_pairs_v4 { ip saddr . tcp dport timeout 30s } # handle 290
		ip6 nexthdr tcp tcp dport @ps_track_tcp_ports add @ps_pairs_v6 { ip6 saddr . tcp dport timeout 30s } # handle 291
		udp dport @ps_track_udp_ports add @ps_pairs_udp_v4 { ip saddr . udp dport timeout 30s } # handle 292
		ip6 nexthdr udp udp dport @ps_track_udp_ports add @ps_pairs_udp_v6 { ip6 saddr . udp dport timeout 30s } # handle 293
		ct state new tcp dport 6060 ip saddr @self_v4 accept # handle 296
		ct state new tcp dport 6060 ip6 saddr @self_v6 accept # handle 297
		ct state new tcp dport 6060 ip saddr @debug_api_v4 accept # handle 298
		ct state new tcp dport 6060 ip6 saddr @debug_api_v6 accept # handle 299
		ct state new tcp dport 6061 ip saddr @self_v4 accept # handle 300
		ct state new tcp dport 6061 ip6 saddr @self_v6 accept # handle 301
		ct state new tcp dport 6061 ip saddr @debug_api_v4 accept # handle 302
		ct state new tcp dport 6061 ip6 saddr @debug_api_v6 accept # handle 303
		tcp dport 12083 ct state new ct status dnat ct original proto-dst 2083 accept comment "cfm_cpanel_dnat:2083:12083" # handle 317
		ct state invalid drop # handle 306
		ct state new tcp dport @tcp_in_ports accept # handle 485
		ct state new udp dport @udp_in_ports accept # handle 486
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080" # handle 491
		ct state new tcp dport 0-65535 drop # handle 487
		ct state new udp dport 0-65535 drop # handle 488
	}
}
`

const orionInput = `table inet cfm {
	chain input { # handle 1
		type filter hook input priority -50; policy accept;
		iif "lo" accept # handle 60
		ct state established,related accept # handle 69
		jump flood # handle 70
		tcp dport @ps_track_tcp_ports add @ps_pairs_v4 { ip saddr . tcp dport timeout 30s } # handle 291
		ip6 nexthdr tcp tcp dport @ps_track_tcp_ports add @ps_pairs_v6 { ip6 saddr . tcp dport timeout 30s } # handle 292
		udp dport @ps_track_udp_ports add @ps_pairs_udp_v4 { ip saddr . udp dport timeout 30s } # handle 293
		ip6 nexthdr udp udp dport @ps_track_udp_ports add @ps_pairs_udp_v6 { ip6 saddr . udp dport timeout 30s } # handle 294
		ct state new tcp dport @tcp_in_ports accept # handle 295
		ct state new udp dport @udp_in_ports accept # handle 296
		ct state new tcp dport 6060 ip saddr @self_v4 accept # handle 297
		ct state new tcp dport 6060 ip6 saddr @self_v6 accept # handle 298
		ct state new tcp dport 6060 ip saddr @debug_api_v4 accept # handle 299
		ct state new tcp dport 6060 ip6 saddr @debug_api_v6 accept # handle 300
		ct state new tcp dport 6061 ip saddr @self_v4 accept # handle 301
		ct state new tcp dport 6061 ip6 saddr @self_v6 accept # handle 302
		ct state new tcp dport 6061 ip saddr @debug_api_v4 accept # handle 303
		ct state new tcp dport 6061 ip6 saddr @debug_api_v6 accept # handle 304
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_edge_dnat_accept:web_http_tcp:80:9080" # handle 314
		tcp dport 12222 ct state new ct status dnat ct original proto-dst 2222 accept comment "cfm_cpanel_dnat:2222:12222" # handle 323
		ct state new tcp dport 0-65535 drop # handle 305
		ct state new udp dport 0-65535 drop # handle 306
		ct state invalid drop # handle 307
	}
}
`

// The output chain as this release leaves it.
const convergedOutput = `table inet cfm {
	chain output { # handle 280
		type filter hook output priority filter; policy accept;
		oif "lo" accept # handle 400
		ct state established,related accept # handle 308
		ct state invalid drop # handle 309
		ct state new tcp dport @tcp_out_ports accept # handle 310
		ct state new udp dport @udp_out_ports accept # handle 311
		ct state new tcp dport 0-65535 drop # handle 312
		ct state new udp dport 0-65535 drop # handle 313
	}
}
`

// The policy both nodes run: debug ports 6060/6061, portscan with a service
// filter and a 30s TTL.
func liveNodePolicy() PortsPolicy {
	return PortsPolicy{
		Family: "inet", Table: "cfm",
		TCPIn:      []config.PortRange{{From: 22, To: 22}, {From: 443, To: 443}},
		UDPIn:      []config.PortRange{{From: 0, To: 65535}},
		TCPOut:     []config.PortRange{{From: 0, To: 65535}},
		UDPOut:     []config.PortRange{{From: 0, To: 65535}},
		DebugPorts: []int{6060, 6061},
		Portscan:   &PortscanTracking{TrackTCP: true, TrackUDP: true, Interval: 30, Service: []config.PortRange{{From: 0, To: 40000}}},
	}
}

func ruleLinesOf(script string) []string {
	var out []string
	for _, l := range strings.Split(script, "\n") {
		if strings.Contains(l, " rule ") {
			out = append(out, l)
		}
	}
	return out
}

// On the live nodes' chains (both engines' layouts) a re-apply writes no rule:
// steady state is the set reload alone, with no window for any packet.
func TestPortsPolicyScript_LiveNodesAreConverged(t *testing.T) {
	for name, in := range map[string]string{"titan": titanInput, "orion": orionInput} {
		if rl := ruleLinesOf(PortsPolicyScript(liveNodePolicy(), in, convergedOutput)); len(rl) != 0 {
			t.Errorf("%s: a re-apply wrote rules:\n%s", name, strings.Join(rl, "\n"))
		}
	}
}

// The sets are reloaded inside the same script: flush and elements together,
// never a moment with an empty set.
func TestPortsPolicyScript_SetsReloadedInTheTransaction(t *testing.T) {
	p := liveNodePolicy()
	p.TCPIn = []config.PortRange{{From: 443, To: 443}, {From: 80, To: 80}, {From: 81, To: 90}, {From: 22, To: 22}}
	s := PortsPolicyScript(p, titanInput, convergedOutput)
	for _, want := range []string{
		"add set inet cfm tcp_in_ports { type inet_service; flags interval; }\nflush set inet cfm tcp_in_ports\nadd element inet cfm tcp_in_ports { 22, 80-90, 443 }",
		"add element inet cfm ps_track_tcp_ports { 0-40000 }",
		"add element inet cfm ps_track_udp_ports { 0-40000 }",
		"add chain inet cfm output { type filter hook output priority 0; policy accept; }",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

// An older node: the pre-ct-state drop, the order IsInputDefaultDropLine also
// accepts, a duplicated accept and a rule appended below the drops. All of it
// is deleted and the policy re-added at the tail, accepts first, drops last.
func TestPortsPolicyScript_RepairsAnOlderChain(t *testing.T) {
	in := strings.Replace(titanInput, "\t\tct state new udp dport 0-65535 drop # handle 488\n",
		"\t\tct state new udp dport 0-65535 drop # handle 488\n"+
			"\t\ttcp dport 0-65535 drop # handle 500\n"+
			"\t\ttcp dport 0-65535 ct state new drop # handle 501\n"+
			"\t\tct state new tcp dport @tcp_in_ports accept # handle 502\n"+
			"\t\ttcp dport 8443 accept # handle 503\n", 1)
	got := ruleLinesOf(PortsPolicyScript(liveNodePolicy(), in, convergedOutput))
	want := []string{
		"delete rule inet cfm input handle 485",
		"delete rule inet cfm input handle 486",
		"delete rule inet cfm input handle 487",
		"delete rule inet cfm input handle 488",
		"delete rule inet cfm input handle 500",
		"delete rule inet cfm input handle 501",
		"delete rule inet cfm input handle 502",
		"add rule inet cfm input ct state new tcp dport @tcp_in_ports accept",
		"add rule inet cfm input ct state new udp dport @udp_in_ports accept",
		"add rule inet cfm input ct state new tcp dport 0-65535 drop",
		"add rule inet cfm input ct state new udp dport 0-65535 drop",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A rule another feature appended below the drops (an EnsureBase tail rule
// from a CLI one-shot, a DNAT accept with no drop to insert before) is brought
// back above them, as the old delete-and-re-append did on every apply.
func TestPortsPolicyScript_RuleBelowTheDropsTriggersARewrite(t *testing.T) {
	in := strings.Replace(orionInput, "\t\tct state invalid drop # handle 307\n",
		"\t\tct state invalid drop # handle 307\n\t\tjump flood # handle 600\n", 1)
	got := ruleLinesOf(PortsPolicyScript(liveNodePolicy(), in, convergedOutput))
	if len(got) == 0 || got[len(got)-1] != "add rule inet cfm input ct state new udp dport 0-65535 drop" {
		t.Fatalf("drops not re-added last:\n%s", strings.Join(got, "\n"))
	}
	for _, l := range got {
		if strings.Contains(l, "handle 600") || strings.Contains(l, "handle 307") {
			t.Fatalf("touched a rule it does not own:\n%s", strings.Join(got, "\n"))
		}
	}
}

// Portscan rules left by an earlier TTL (and the copies the old presence check
// piled up for a TTL of 60s or more, printed "1m" but looked for as "60s") and
// a dropped debug port are deleted; the current ones are kept in place.
func TestPortsPolicyScript_DeletesStalePortscanAndDebugRules(t *testing.T) {
	in := strings.Replace(titanInput, "\t\tct state new tcp dport 6060 ip saddr @self_v4 accept # handle 296\n",
		"\t\ttcp dport @ps_track_tcp_ports add @ps_pairs_v4 { ip saddr . tcp dport timeout 1m } # handle 700\n"+
			"\t\ttcp dport @ps_track_tcp_ports add @ps_pairs_v4 { ip saddr . tcp dport timeout 1m } # handle 701\n"+
			"\t\ttcp dport @ps_track_tcp_ports add @ps_pairs_v4 { ip saddr . tcp dport timeout 30s } # handle 702\n"+
			"\t\tct state new tcp dport 6060 ip saddr @self_v4 accept # handle 296\n", 1)
	p := liveNodePolicy()
	p.DebugPorts = []int{6060} // 6061 dropped from the config
	got := ruleLinesOf(PortsPolicyScript(p, in, convergedOutput))
	want := []string{
		"delete rule inet cfm input handle 700",
		"delete rule inet cfm input handle 701",
		"delete rule inet cfm input handle 702", // a second copy of a current rule
		"delete rule inet cfm input handle 300",
		"delete rule inet cfm input handle 301",
		"delete rule inet cfm input handle 302",
		"delete rule inet cfm input handle 303",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// EnsureBase's own rules are never deleted, whatever they look like.
func TestPortsPolicyScript_NeverTouchesOtherRules(t *testing.T) {
	in := strings.Replace(titanInput, "\t\tct state new tcp dport @tcp_in_ports accept # handle 485\n", "", 1)
	for _, l := range ruleLinesOf(PortsPolicyScript(liveNodePolicy(), in, convergedOutput)) {
		for _, h := range []string{"handle 59", "handle 58", "handle 46", "handle 60", "handle 68", "handle 69", "handle 317", "handle 491", "handle 306"} {
			if strings.HasSuffix(l, h) {
				t.Errorf("deletes a rule it does not own: %s", l)
			}
		}
	}
}

// A fresh node (no output chain yet): output gets its whole policy, the
// loopback accept first.
func TestPortsPolicyScript_FreshOutput(t *testing.T) {
	got := ruleLinesOf(PortsPolicyScript(liveNodePolicy(), titanInput, ""))
	want := []string{
		`insert rule inet cfm output oif "lo" accept`,
		"add rule inet cfm output ct state established,related accept",
		"add rule inet cfm output ct state invalid drop",
		"add rule inet cfm output ct state new tcp dport @tcp_out_ports accept",
		"add rule inet cfm output ct state new udp dport @udp_out_ports accept",
		"add rule inet cfm output ct state new tcp dport 0-65535 drop",
		"add rule inet cfm output ct state new udp dport 0-65535 drop",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s", strings.Join(got, "\n"))
	}
}

// Only an exact copy of the loopback accept AS THE FIRST RULE counts: a
// narrower rule containing it (an operator's per-port workaround) does not,
// and a copy further down is replaced by one at the head.
func TestPortsPolicyScript_OutputLoopbackHead(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"narrower rule": {
			`oif "lo" accept # handle 400`, `tcp dport 3306 oif "lo" accept # handle 400`,
			`insert rule inet cfm output oif "lo" accept`,
		},
		"copy below the head": {
			"\t\toif \"lo\" accept # handle 400\n\t\tct state established,related accept # handle 308\n",
			"\t\tct state established,related accept # handle 308\n\t\toif \"lo\" accept # handle 400\n",
			"insert rule inet cfm output oif \"lo\" accept\ndelete rule inet cfm output handle 400",
		},
		"duplicate": {
			"\t\toif \"lo\" accept # handle 400\n", "\t\toif \"lo\" accept # handle 400\n\t\toif \"lo\" accept # handle 401\n",
			"delete rule inet cfm output handle 401",
		},
	}
	for name, c := range cases {
		out := strings.Replace(convergedOutput, c.from, c.to, 1)
		if out == convergedOutput {
			t.Fatalf("%s: fixture not changed", name)
		}
		got := strings.Join(ruleLinesOf(PortsPolicyScript(liveNodePolicy(), titanInput, out)), "\n")
		if got != c.want {
			t.Errorf("%s: got\n%s\nwant\n%s", name, got, c.want)
		}
	}
}

func TestNFTDuration(t *testing.T) {
	for sec, want := range map[int]string{0: "1m", -5: "1m", 1: "1s", 30: "30s", 60: "1m", 90: "1m30s", 3600: "1h", 86400: "1d", 90061: "1d1h1m1s"} {
		if got := NFTDuration(sec); got != want {
			t.Errorf("NFTDuration(%d) = %q, want %q", sec, got, want)
		}
	}
}

func TestNormalizePortRanges(t *testing.T) {
	got := NormalizePortRanges([]config.PortRange{{From: 443, To: 443}, {From: 80, To: 80}, {From: 81, To: 85}, {From: 84, To: 90}, {From: 70000, To: 70001}, {From: 10, To: 5}})
	want := []config.PortRange{{From: 80, To: 90}, {From: 443, To: 443}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := NormalizePortRanges([]config.PortRange{{From: 22, To: 22}, {From: 0, To: 65535}}); len(got) != 1 || got[0] != (config.PortRange{From: 0, To: 65535}) {
		t.Fatalf("full range: got %v", got)
	}
}

func TestApplyPortsPolicyScript(t *testing.T) {
	ok := func(chain string) (string, bool, error) {
		if chain == "input" {
			return titanInput, true, nil
		}
		return convergedOutput, true, nil
	}

	t.Run("a read error writes nothing", func(t *testing.T) {
		err := ApplyPortsPolicyScript(liveNodePolicy(),
			func(string) (string, bool, error) { return "", true, errors.New("timed out") },
			func(s string) error { t.Fatalf("wrote after a failed read:\n%s", s); return nil })
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no input chain is an error, not an empty chain", func(t *testing.T) {
		err := ApplyPortsPolicyScript(liveNodePolicy(),
			func(string) (string, bool, error) { return "", false, nil },
			func(s string) error { t.Fatalf("wrote without an input chain:\n%s", s); return nil })
		if err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("a failed transaction is re-planned from a fresh read once", func(t *testing.T) {
		reads, execs := 0, 0
		err := ApplyPortsPolicyScript(liveNodePolicy(),
			func(c string) (string, bool, error) { reads++; return ok(c) },
			func(string) error {
				execs++
				if execs == 1 {
					return errors.New("Could not process rule: No such file or directory")
				}
				return nil
			})
		if err != nil || execs != 2 || reads != 4 {
			t.Fatalf("err=%v execs=%d reads=%d", err, execs, reads)
		}
	})
	t.Run("two failures are returned", func(t *testing.T) {
		execs := 0
		err := ApplyPortsPolicyScript(liveNodePolicy(), ok, func(string) error { execs++; return errors.New("busy") })
		if err == nil || execs != 2 {
			t.Fatalf("err=%v execs=%d", err, execs)
		}
	})
	t.Run("an absent output chain is planned as fresh", func(t *testing.T) {
		var script string
		err := ApplyPortsPolicyScript(liveNodePolicy(),
			func(c string) (string, bool, error) {
				if c == "output" {
					return "", false, nil
				}
				return titanInput, true, nil
			},
			func(s string) error { script = s; return nil })
		if err != nil || !strings.Contains(script, `insert rule inet cfm output oif "lo" accept`) {
			t.Fatalf("err=%v script:\n%s", err, script)
		}
	})
}

func TestIsNFTNoSuchObject(t *testing.T) {
	if !IsNFTNoSuchObject("Error: No such file or directory\nlist chain inet cfm output") {
		t.Fatal("missing chain not recognised")
	}
	if IsNFTNoSuchObject("Error: Could not process rule: Device or resource busy") || IsNFTNoSuchObject("") {
		t.Fatal("another failure read as a missing chain")
	}
}

// Both engines' ApplyPortsPolicy must hand the whole policy to the shared
// transaction (firewall.ApplyPortsPolicyScript), and write no rule or set of
// their own. Read from the AST, so a commented-out call does not count.
func TestApplyPortsPolicy_BothEnginesUseTheSharedTransaction(t *testing.T) {
	for _, f := range []string{"nft/ports.go", "nftlib/ports_nftlib.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var body *ast.BlockStmt
		for _, d := range file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "ApplyPortsPolicy" && fd.Recv != nil {
				body = fd.Body
			}
		}
		if body == nil {
			t.Fatalf("%s: ApplyPortsPolicy not found", f)
		}
		last, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
		var call *ast.CallExpr
		if ok && len(last.Results) == 1 {
			call, _ = last.Results[0].(*ast.CallExpr)
		}
		sel, _ := func() (*ast.SelectorExpr, bool) {
			if call == nil {
				return nil, false
			}
			s, ok := call.Fun.(*ast.SelectorExpr)
			return s, ok
		}()
		if sel == nil || sel.Sel.Name != "ApplyPortsPolicyScript" {
			t.Errorf("%s: ApplyPortsPolicy must end with `return firewall.ApplyPortsPolicyScript(...)`", f)
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok {
				for _, w := range []string{"add rule", "insert rule", "delete rule", "flush set", "add element"} {
					if strings.Contains(lit.Value, w) {
						t.Errorf("%s: ApplyPortsPolicy writes %q itself, outside the transaction", f, w)
					}
				}
			}
			return true
		})
	}
}
