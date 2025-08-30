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

// απλό ensure για port-set (ΧΩΡΙΣ flags timeout)
func (b *Backend) ensurePortSet(name string) error {
    // Προϋπόθεση για ranges στο set: flags interval (και καλό το auto-merge)
    if !b.setExists(name) {
        return b.nftCmd(fmt.Sprintf(
            `add set %s %s %s { type inet_service; flags interval; }`,
            family, tableName, name,
        ))
    }
    return nil
}



//normalize then  flush + add elements όπως "80, 443, 7770-7800"

// normalizeRanges: sort + merge overlapping/adjacent, drop subsumed
func normalizeRanges(prs []config.PortRange) []config.PortRange {
    if len(prs) == 0 {
        return prs
    }

    // if any full-range -> just one range
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

    // merge
    out := make([]config.PortRange, 0, len(rs))
    cur := rs[0]
    for i := 1; i < len(rs); i++ {
        r := rs[i]
        // overlap ή είναι συνεχόμενα (π.χ. 80-90 και 91-100)
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
    // Πρώτα κανονικοποίηση για να μην έχουμε conflicting intervals
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

// Εφαρμογή πολιτικής ports (κανόνες έρχονται ΜΕΤΑ τους allow/block κανόνες)
func (b *Backend) ApplyPortsPolicy(cfg *config.PortsConfig) error {
 b.cfg = cfg
	// chains: input υπάρχει ήδη. Θέλουμε και output.
	if !b.chainExists("output") {
		if err := b.nftCmd(fmt.Sprintf(`add chain %s %s output { type filter hook output priority 0; policy accept; }`, family, tableName)); err != nil {
			return err
		}
	}

	// ensure sets
	for _, s := range []string{setTCPIn, setUDPIn, setTCPOut, setUDPOut} {
		if err := b.ensurePortSet(s); err != nil { return err }
	}

	// load set contents
	if err := b.replacePortSet(setTCPIn,  cfg.TCPIn);  err != nil { return err }
	if err := b.replacePortSet(setUDPIn,  cfg.UDPIn);  err != nil { return err }
	if err := b.replacePortSet(setTCPOut, cfg.TCPOut); err != nil { return err }
	if err := b.replacePortSet(setUDPOut, cfg.UDPOut); err != nil { return err }

	// INPUT rules (μπαίνουν ΜΕΤΑ τους υπάρχοντες allow/drop κανόνες)
	addRule := func(chain, expr string) error {
		if !b.ruleExists(chain, expr) {
			return b.nftCmd(fmt.Sprintf(`add rule %s %s %s %s`, family, tableName, chain, expr))
		}
		return nil
	}

	// επιτρέπουμε ό,τι είναι στο set, αλλιώς drop για TCP/UDP
	if err := addRule("input", `meta l4proto tcp tcp dport @`+setTCPIn+` accept`); err != nil { return err }
	if err := addRule("input", `meta l4proto udp udp dport @`+setUDPIn+` accept`); err != nil { return err }
	if err := addRule("input", `meta l4proto tcp tcp dport 0-65535 drop`); err != nil { return err }
	if err := addRule("input", `meta l4proto udp udp dport 0-65535 drop`); err != nil { return err }

	// OUTPUT (όμοια λογική για εξερχόμενα)
	if err := addRule("output", `meta l4proto tcp tcp dport @`+setTCPOut+` accept`); err != nil { return err }
	if err := addRule("output", `meta l4proto udp udp dport @`+setUDPOut+` accept`); err != nil { return err }
	if err := addRule("output", `meta l4proto tcp tcp dport 0-65535 drop`); err != nil { return err }
	if err := addRule("output", `meta l4proto udp udp dport 0-65535 drop`); err != nil { return err }

	return nil
}
