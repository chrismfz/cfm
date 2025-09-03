package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"os/exec"
	cfg "cfm/internal/config"
)

// ApplySynproxyPolicy installs SYNPROXY rules in the flood chain so that
// PortFlood/Connlimit enforcement τρέχουν πρώτα.
//
// Δημιουργεί:
//   - set inet cfm synproxy_ports  (type inet_service)
//   - counters: synproxy_probe_v4, synproxy_probe_v6, synproxy_challenge, synproxy_pass
//   - rules (hybrid):
//       * PROBE (πάνω-πάνω στη flood, μόνο counter, ΧΩΡΙΣ verdict)
//           - v4: tcp dport @synproxy_ports tcp flags syn counter name synproxy_probe_v4
//           - v6: ip6 nexthdr tcp tcp dport @synproxy_ports tcp flags syn counter name synproxy_probe_v6
//       * CHALLENGE/PASS (στο ΤΕΛΟΣ της flood)
//           - v4 challenge: tcp dport @synproxy_ports tcp flags syn synproxy ... counter name synproxy_challenge drop
//           - v6 challenge: ip6 nexthdr tcp tcp dport @synproxy_ports tcp flags syn synproxy ... counter name synproxy_challenge drop
//           - v4 pass:      tcp dport @synproxy_ports ct state new,untracked tcp flags & ack == ack counter name synproxy_pass accept
//           - v6 pass:      ip6 nexthdr tcp tcp dport @synproxy_ports ct state new,untracked tcp flags & ack == ack counter name synproxy_pass accept
//
// Σημείωση: To "pass" δέχεται ΜΟΝΟ τα πρώτα ACK μετά το cookie. Δεν κάνει accept τα SYN.
func (b *Backend) ApplySynproxyPolicy(sp *cfg.SynproxyConfig, ports *cfg.PortsConfig, _ int) error {

_ = exec.Command("modprobe", "nf_synproxy_core").Run()

	// Αν είναι off → καθάρισε μόνο το set (best-effort) και βγες.
	if sp == nil || !sp.Enable {
		_ = b.runCmd("delete set inet cfm synproxy_ports")
		return nil
	}

	// 1) Συγκέντρωση θυρών: explicit + TCP_IN (αν AutoTCPIn).
	targetPorts := collectSynproxyPorts(sp, ports)
	if len(targetPorts) == 0 {
		return nil
	}

	// 2) Ensure set synproxy_ports { type inet_service; }
	if err := b.ensureSet("synproxy_ports", "inet_service"); err != nil {
		return fmt.Errorf("ensure synproxy_ports set: %w", err)
	}
	// Flush (ή create αν έλειπε)
	if err := b.runCmd("flush set inet cfm synproxy_ports"); err != nil {
		_ = b.runCmd("create set inet cfm synproxy_ports { type inet_service; }")
	}

	// 3) Γέμισε elements
	elems := make([]string, 0, len(targetPorts))
	for _, p := range targetPorts {
		elems = append(elems, strconv.Itoa(p))
	}
	if err := b.nftCmd(fmt.Sprintf("add element inet cfm synproxy_ports { %s }", strings.Join(elems, ", "))); err != nil {
		return fmt.Errorf("add elements to synproxy_ports: %w", err)
	}

	// 4) Build synproxy options
	opts := buildSynproxyOptions(sp)

	// 4.5) HYBRID: probe counters πολύ νωρίς στη flood (πάνω-πάνω), μόνο μέτρηση
	// Ensure counters
	_ = b.nftExpr("add counter inet cfm synproxy_probe_v4")
	_ = b.nftExpr("add counter inet cfm synproxy_probe_v6")
	// Insert at position 0 για να προηγούνται ΟΛΩΝ (synrate/portflood/connlimit/synproxy)
	_ = b.nftExpr("insert rule inet cfm flood position 0 tcp dport @synproxy_ports tcp flags syn counter name synproxy_probe_v4")
	_ = b.nftExpr("insert rule inet cfm flood position 0 ip6 nexthdr tcp tcp dport @synproxy_ports tcp flags syn counter name synproxy_probe_v6")

	// 5) Ensure named counters (πριν τα challenge/pass rules)
	_ = b.nftExpr("add counter inet cfm synproxy_challenge")
	_ = b.nftExpr("add counter inet cfm synproxy_pass")

	// 6) Γράψιμο challenge/pass rules στο ΤΕΛΟΣ της flood (portflood/connlimit προηγούνται)
	chain := "flood"

	// v4 challenge: SYN με synproxy, μετράμε challenge, drop SYN ώστε να μη ρουφηχτεί από new-accept
	expr4Challenge := fmt.Sprintf(
		"add rule inet cfm %s tcp dport @synproxy_ports tcp flags syn %s counter name synproxy_challenge drop",
		chain, opts,
	)
	// v6 challenge
	expr6Challenge := fmt.Sprintf(
		"add rule inet cfm %s ip6 nexthdr tcp tcp dport @synproxy_ports tcp flags syn %s counter name synproxy_challenge drop",
		chain, opts,
	)

	// v4 pass: δέξου ΜΟΝΟ ACK μετά το cookie
	expr4Pass := fmt.Sprintf(
		"add rule inet cfm %s tcp dport @synproxy_ports ct state new,untracked tcp flags & ack == ack counter name synproxy_pass accept",
		chain,
	)
	// v6 pass
	expr6Pass := fmt.Sprintf(
		"add rule inet cfm %s ip6 nexthdr tcp tcp dport @synproxy_ports ct state new,untracked tcp flags & ack == ack counter name synproxy_pass accept",
		chain,
	)

	if err := b.nftExpr(expr4Challenge); err != nil {
		return fmt.Errorf("synproxy v4 challenge rule failed: %w", err)
	}
	if err := b.nftExpr(expr6Challenge); err != nil {
		return fmt.Errorf("synproxy v6 challenge rule failed: %w", err)
	}
	if err := b.nftExpr(expr4Pass); err != nil {
		return fmt.Errorf("synproxy v4 pass rule failed: %w", err)
	}
	if err := b.nftExpr(expr6Pass); err != nil {
		return fmt.Errorf("synproxy v6 pass rule failed: %w", err)
	}

	return nil
}

// Συγχώνευση explicit SYNPROXY ports με TCP_IN όταν AutoTCPIn=1.
func collectSynproxyPorts(sp *cfg.SynproxyConfig, ports *cfg.PortsConfig) []int {
	uniq := map[int]struct{}{}

	// Explicit από config (string "80,443" ή []int)
	for _, p := range parsePortList(sp.Ports) {
		if p > 0 && p <= 65535 {
			uniq[p] = struct{}{}
		}
	}

	// Merge TCP_IN αν ζητήθηκε
	if sp.AutoTCPIn && ports != nil {
		for _, p := range parsePortList(ports.TCPIn) {
			if p > 0 && p <= 65535 {
				uniq[p] = struct{}{}
			}
		}
	}

	out := make([]int, 0, len(uniq))
	for p := range uniq {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// Δέχεται είτε []int είτε string με διαχωριστικά , ; κενά.
func parsePortList(v any) []int {
	switch t := v.(type) {
	case nil:
		return nil
	case []int:
		cp := make([]int, len(t))
		copy(cp, t)
		return cp
	case string:
		var res []int
		split := func(r rune) bool { return r == ',' || r == ' ' || r == ';' }
		for _, tok := range strings.FieldsFunc(t, split) {
			if tok == "" {
				continue
			}
			n, err := strconv.Atoi(tok)
			if err == nil && n > 0 && n <= 65535 {
				res = append(res, n)
			}
		}
		return res
	default:
		return nil
	}
}

func buildSynproxyOptions(sp *cfg.SynproxyConfig) string {
	parts := []string{"synproxy"}
	if sp.MSS > 0 {
		parts = append(parts, "mss", strconv.Itoa(sp.MSS))
	}
	if sp.WScale > 0 {
		parts = append(parts, "wscale", strconv.Itoa(sp.WScale))
	}
	if sp.SACK {
		parts = append(parts, "sack-perm")
	}
	if sp.TStamp {
		parts = append(parts, "timestamp")
	}
	return strings.Join(parts, " ")
}
