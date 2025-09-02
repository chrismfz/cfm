package nft

import (
	"fmt"
	"strings"
	"sort"

	"cfm/internal/config"
)

// sets για ports (type inet_service)
const (
	setTCPIn  = "tcp_in_ports"
	setUDPIn  = "udp_in_ports"
	setTCPOut = "tcp_out_ports"
	setUDPOut = "udp_out_ports"
)

// port-scan tracking sets
const (
	psPairsV4     = "ps_pairs_v4"
	psPairsV6     = "ps_pairs_v6"
	psPairsUDPV4  = "ps_pairs_udp_v4"
	psPairsUDPV6  = "ps_pairs_udp_v6"
)

// απλό ensure για port-set (ΧΩΡΙΣ flags timeout)
func (b *Backend) ensurePortSet(name string) error {
	// για ranges στο set: flags interval
	if !b.setExists(name) {
		return b.nftCmd(fmt.Sprintf(
			`add set %s %s %s { type inet_service; flags interval; }`,
			family, tableName, name,
		))
	}
	return nil
}

// normalize then flush + add elements όπως "80, 443, 7770-7800"
func normalizeRanges(prs []config.PortRange) []config.PortRange {
	if len(prs) == 0 { return prs }

	// αν υπάρχει full-range -> ένα range
	for _, r := range prs {
		if r.From == 0 && r.To == 65535 {
			return []config.PortRange{{0, 65535}}
		}
	}

	// sort by From, then To
	rs := make([]config.PortRange, 0, len(prs))
	rs = append(rs, prs...)
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].From == rs[j].From {
			return rs[i].To < rs[j].To
		}
		return rs[i].From < rs[j].From
	})

	// merge overlapping/adjacent
	out := make([]config.PortRange, 0, len(rs))
	cur := rs[0]
	for i := 1; i < len(rs); i++ {
		r := rs[i]
		if r.From <= cur.To+1 {
			if r.To > cur.To {
				cur.To = r.To
			}
		} else {
			out = append(out, cur)
			cur = r
		}
	}
	out = append(out, cur)
	return out
}

func (b *Backend) replacePortSet(name string, prs []config.PortRange) error {
	// Κανονικοποίηση για καθαρά intervals
	prs = normalizeRanges(prs)

	if err := b.nftExpr(fmt.Sprintf(`flush set %s %s %s;`, family, tableName, name)); err != nil {
		return err
	}
	if len(prs) == 0 {
		return nil
	}
	elems := make([]string, 0, len(prs))
	for _, r := range prs {
		if r.From == r.To {
			elems = append(elems, fmt.Sprintf("%d", r.From))
		} else {
			elems = append(elems, fmt.Sprintf("%d-%d", r.From, r.To))
		}
	}
	expr := fmt.Sprintf("add element %s %s %s { %s };",
		family, tableName, name, strings.Join(elems, ", "))
	return b.nftExpr(expr)
}

// Εφαρμογή πολιτικής ports (μπαίνουν ΜΕΤΑ τα base allow/block & jump flood)
// Εφαρμογή πολιτικής ports (μπαίνουν ΜΕΤΑ τα base allow/block & jump flood)
func (b *Backend) ApplyPortsPolicy(cfg *config.PortsConfig) error {
	// ΣΚΟΠΙΜΑ δεν κάνουμε b.cfg = cfg, γιατί εδώ παίρνουμε μόνο Ports ranges.
	// Το full b.cfg (*config.Config) ορίζεται αλλού (daemon / ApplyFloodRules).

	// chains: input υπάρχει ήδη. Θέλουμε και output.
	if !b.chainExists("output") {
		if err := b.nftCmd(fmt.Sprintf(
			`add chain %s %s output { type filter hook output priority 0; policy accept; }`,
			family, tableName)); err != nil {
			return err
		}
	}

	// ensure sets
	for _, s := range []string{setTCPIn, setUDPIn, setTCPOut, setUDPOut} {
		if err := b.ensurePortSet(s); err != nil { return err }
	}

	// load set contents
	if err := b.replacePortSet(setTCPIn, cfg.TCPIn); err != nil { return err }
	if err := b.replacePortSet(setUDPIn, cfg.UDPIn); err != nil { return err }
	if err := b.replacePortSet(setTCPOut, cfg.TCPOut); err != nil { return err }
	if err := b.replacePortSet(setUDPOut, cfg.UDPOut); err != nil { return err }

	// INPUT rules (με απλή σύνταξη ώστε ruleExists να ταιριάζει με `nft list`)
	addRule := func(chain, expr string) error {
		if !b.ruleExists(chain, expr) {
			return b.nftCmd(fmt.Sprintf(`add rule %s %s %s %s`, family, tableName, chain, expr))
		}
		return nil
	}

	// 1) Επιτρέπουμε ό,τι είναι στο set
	if err := addRule("input", `tcp dport @`+setTCPIn+` accept`); err != nil { return err }
	if err := addRule("input", `udp dport @`+setUDPIn+` accept`); err != nil { return err }

	// 2) Port-scan tracking: γράψε τα ζεύγη (srcIP . dport) για Ο,ΤΙ δεν είναι στα allowed sets
	//    -> από το νέο schema τα flags είναι στο b.cfg.Portscan
	if b.cfg != nil && b.cfg.Portscan.Enabled {
		ps := b.cfg.Portscan
		b.ensurePortscanSets()

		// TCP (IPv4 & IPv6)
		if ps.TrackTCP {
			// IPv4
			if err := addRule("input",
				fmt.Sprintf(`tcp dport != @%s add @%s { ip saddr . tcp dport timeout %ds }`,
					setTCPIn, psPairsV4, ps.Interval)); err != nil { return err }
			// IPv6
			if err := addRule("input",
				fmt.Sprintf(`ip6 nexthdr tcp tcp dport != @%s add @%s { ip6 saddr . tcp dport timeout %ds }`,
					setTCPIn, psPairsV6, ps.Interval)); err != nil { return err }
		}

		// UDP (IPv4 & IPv6)
		if ps.TrackUDP {
			if err := addRule("input",
				fmt.Sprintf(`udp dport != @%s add @%s { ip saddr . udp dport timeout %ds }`,
					setUDPIn, psPairsUDPV4, ps.Interval)); err != nil { return err }
			if err := addRule("input",
				fmt.Sprintf(`udp dport != @%s add @%s { ip6 saddr . udp dport timeout %ds }`,
					setUDPIn, psPairsUDPV6, ps.Interval)); err != nil { return err }
		}
	}

	// 3) Τέλος, τα γενικά DROP
	if err := addRule("input", `tcp dport 0-65535 drop`); err != nil { return err }
	if err := addRule("input", `udp dport 0-65535 drop`); err != nil { return err }

	// OUTPUT (όμοια λογική για εξερχόμενα)
	if err := addRule("output", `tcp dport @`+setTCPOut+` accept`); err != nil { return err }
	if err := addRule("output", `udp dport @`+setUDPOut+` accept`); err != nil { return err }
	if err := addRule("output", `tcp dport 0-65535 drop`); err != nil { return err }
	if err := addRule("output", `udp dport 0-65535 drop`); err != nil { return err }

	return nil
}
