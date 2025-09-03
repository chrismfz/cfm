package nft

import (
	"fmt"
	"strings"
	"sort"
	"os/exec"
	"cfm/internal/config"
        "cfm/internal/logging"

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




// ApplyPortsPolicy συνθέτει τα allow/drop των θυρών και (προαιρετικά) το port-scan tracking.
func (b *Backend) ApplyPortsPolicy(cfg *config.PortsConfig) error {
    // μικρό summary
    logging.Logf("[ports] applying policy: tcp_in=%d ranges, udp_in=%d, tcp_out=%d, udp_out=%d",
        len(cfg.TCPIn), len(cfg.UDPIn), len(cfg.TCPOut), len(cfg.UDPOut))

    // ensure OUTPUT chain
    if !b.chainExists("output") {
        if err := b.nftCmd(fmt.Sprintf(
            `add chain %s %s output { type filter hook output priority 0; policy accept; }`,
            family, tableName)); err != nil {
            return err
        }
    }

    // ensure base port sets
    for _, s := range []string{setTCPIn, setUDPIn, setTCPOut, setUDPOut} {
        if err := b.ensurePortSet(s); err != nil { return err }
    }

    // load contents
    if err := b.replacePortSet(setTCPIn,  cfg.TCPIn);  err != nil { return err }
    if err := b.replacePortSet(setUDPIn,  cfg.UDPIn);  err != nil { return err }
    if err := b.replacePortSet(setTCPOut, cfg.TCPOut); err != nil { return err }
    if err := b.replacePortSet(setUDPOut, cfg.UDPOut); err != nil { return err }

    // helper: idempotent rule add (ίδιο expr όπως το “nft list”)
    addRule := func(chain, expr string) error {
        if !b.ruleExists(chain, expr) {
            return b.nftCmd(fmt.Sprintf(`add rule %s %s %s %s`, family, tableName, chain, expr))
        }
        return nil
    }


delRule := func(chain, contains string) {
    out, err := exec.Command("nft", "-a", "list", "chain", family, tableName, chain).CombinedOutput()
    if err != nil { return }
    for _, ln := range strings.Split(string(out), "\n") {
        s := strings.TrimSpace(ln)
        if s == "" || !strings.Contains(s, contains) { continue }
        // βρες handle στο "# handle N"
        idx := strings.LastIndex(s, "# handle ")
        if idx < 0 { continue }
        h := strings.TrimSpace(s[idx+len("# handle "):])
        if sp := strings.Fields(h); len(sp) > 0 { h = sp[0] }
        _, _ = exec.Command("nft", "delete", "rule", family, tableName, chain, "handle", h).CombinedOutput()
    }
}



    // -------------------------
    // Port-scan tracking (πριν τα accepts ΟΤΑΝ έχεις φίλτρο υπηρεσιών)
    // -------------------------
    hasSvcFilter := false
    if b.cfg != nil && b.cfg.Portscan.Enabled {
        ps := b.cfg.Portscan
        b.ensurePortscanSets()

        pairTTL := ps.Interval
        if pairTTL <= 0 { pairTTL = 60 }

        // Συγκρότηση service filter από PS_ONLY_PORTS (ranges) + PS_PORTS (single)
        svc := make([]config.PortRange, 0, len(ps.OnlyPorts)+len(ps.Ports))
        svc = append(svc, ps.OnlyPorts...)
        for _, p := range ps.Ports {
            if p < 0 { p = 0 }
            if p > 65535 { p = 65535 }
            svc = append(svc, config.PortRange{From: p, To: p})
        }
        hasSvcFilter = len(svc) > 0

        logging.Logf("[ports] portscan: enabled=%v interval=%ds track_tcp=%v track_udp=%v only_ranges=%d focus_ports=%d",
            ps.Enabled, ps.Interval, ps.TrackTCP, ps.TrackUDP, len(ps.OnlyPorts), len(ps.Ports))

        if hasSvcFilter {
            const trackTCP = "ps_track_tcp_ports"
            const trackUDP = "ps_track_udp_ports"

            // sets τύπου inet_service
            if err := b.ensurePortSet(trackTCP); err != nil { return err }
            if err := b.replacePortSet(trackTCP, svc); err != nil { return err }
            if ps.TrackUDP {
                if err := b.ensurePortSet(trackUDP); err != nil { return err }
                if err := b.replacePortSet(trackUDP, svc); err != nil { return err }
            }
            logging.Logf("[ports] ps_track_tcp_ports loaded (%d entries)", len(svc))

            // positive-match tracking ΠΡΙΝ τα accepts
            if ps.TrackTCP {
                if err := addRule("input",
                    fmt.Sprintf(`tcp dport @%s add @%s { ip saddr . tcp dport timeout %ds }`,
                        trackTCP, psPairsV4, pairTTL)); err != nil { return err }
                if err := addRule("input",
                    fmt.Sprintf(`ip6 nexthdr tcp tcp dport @%s add @%s { ip6 saddr . tcp dport timeout %ds }`,
                        trackTCP, psPairsV6, pairTTL)); err != nil { return err }
            }
            if ps.TrackUDP {
                if err := addRule("input",
                    fmt.Sprintf(`udp dport @%s add @%s { ip saddr . udp dport timeout %ds }`,
                        trackUDP, psPairsUDPV4, pairTTL)); err != nil { return err }
                if err := addRule("input",
                    fmt.Sprintf(`ip6 nexthdr udp udp dport @%s add @%s { ip6 saddr . udp dport timeout %ds }`,
                        trackUDP, psPairsUDPV6, pairTTL)); err != nil { return err }
            }
        }
    }


_ = addRule("input", `ct state established,related accept`)
_ = addRule("input", `ct state invalid drop`)


// --- Allow lists (INPUT) ---
// Καθάρισε παλιούς “γυμνούς” κανόνες:
delRule("input", `tcp dport @`+setTCPIn+` accept`)
delRule("input", `udp dport @`+setUDPIn+` accept`)

// ΝΕΟΙ: μόνο για NEW
if err := addRule("input", `ct state new tcp dport @`+setTCPIn+` accept`); err != nil { return err }
if err := addRule("input", `ct state new udp dport @`+setUDPIn+` accept`); err != nil { return err }

    // -------------------------
    // Port-scan tracking (ΜΕΤΑ τα accepts όταν ΔΕΝ έχεις φίλτρο υπηρεσιών)
    // -------------------------
    if b.cfg != nil && b.cfg.Portscan.Enabled && !hasSvcFilter {
        ps := b.cfg.Portscan
        pairTTL := ps.Interval
        if pairTTL <= 0 { pairTTL = 60 }

        if ps.TrackTCP {
            if err := addRule("input",
                fmt.Sprintf(`tcp dport != @%s add @%s { ip saddr . tcp dport timeout %ds }`,
                    setTCPIn, psPairsV4, pairTTL)); err != nil { return err }
            if err := addRule("input",
                fmt.Sprintf(`ip6 nexthdr tcp tcp dport != @%s add @%s { ip6 saddr . tcp dport timeout %ds }`,
                    setTCPIn, psPairsV6, pairTTL)); err != nil { return err }
        }
        if ps.TrackUDP {
            if err := addRule("input",
                fmt.Sprintf(`udp dport != @%s add @%s { ip saddr . udp dport timeout %ds }`,
                    setUDPIn, psPairsUDPV4, pairTTL)); err != nil { return err }
            if err := addRule("input",
                fmt.Sprintf(`ip6 nexthdr udp udp dport != @%s add @%s { ip6 saddr . udp dport timeout %ds }`,
                    setUDPIn, psPairsUDPV6, pairTTL)); err != nil { return err }
        }
    }

    // -------------------------
    // Default DROPs (INPUT)
    // -------------------------
// --- Default DROPs (INPUT) ---
// Καθάρισε παλιούς
delRule("input", `tcp dport 0-65535 drop`)
delRule("input", `udp dport 0-65535 drop`)

// ΝΕΟΙ: NEW-only
if err := addRule("input", `ct state new tcp dport 0-65535 drop`); err != nil { return err }
if err := addRule("input", `ct state new udp dport 0-65535 drop`); err != nil { return err }

    // -------------------------
    // OUTPUT policy
    // -------------------------

_ = addRule("output", `ct state established,related accept`)
_ = addRule("output", `ct state invalid drop`)

// καθάρισε παλιούς “γυμνούς” drops στο OUTPUT
delRule("output", `tcp dport 0-65535 drop`)
delRule("output", `udp dport 0-65535 drop`)

// accept μόνο για NEW
if err := addRule("output", `ct state new tcp dport @`+setTCPOut+` accept`); err != nil { return err }
if err := addRule("output", `ct state new udp dport @`+setUDPOut+` accept`); err != nil { return err }

// catch-all NEW drops
if err := addRule("output", `ct state new tcp dport 0-65535 drop`); err != nil { return err }
if err := addRule("output", `ct state new udp dport 0-65535 drop`); err != nil { return err }



    return nil
}
