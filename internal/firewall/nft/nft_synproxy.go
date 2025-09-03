package nft

import (
	"fmt"
	"os/exec"
	"strings"

	cfg "cfm/internal/config"
)

func (b *Backend) ApplySynproxyPolicy(sp *cfg.SynproxyConfig, ports *cfg.PortsConfig, inputPrio int) error {
	if sp == nil || !sp.Enable {
		// best-effort: καθάρισε παλιό set αν υπάρχει
		_ = b.runCmd("delete set inet cfm synproxy_ports")
		// (οι κανόνες δεν πειράζονται εδώ για ασφάλεια)
		return nil
	}

	// 0) modprobe nf_synproxy_core (ήσυχα)
	_ = exec.Command("modprobe", "nf_synproxy_core").Run()

	// 1) Φτιάξε set για extra ports (αν έχεις)
	hasExtra := len(sp.Ports) > 0
	if hasExtra {
		_ = b.runCmd("delete set inet cfm synproxy_ports")
		if err := b.runCmd("add set inet cfm synproxy_ports { type inet_service; flags interval; }"); err != nil {
			// αν υπάρχει ήδη, προσπάθησε απλά flush
			_ = b.runCmd("flush set inet cfm synproxy_ports")
		}
		if len(sp.Ports) > 0 {
			var elems []string
			for _, p := range sp.Ports { elems = append(elems, fmt.Sprintf("%d", p)) }
			_ = b.runCmd(fmt.Sprintf("add element inet cfm synproxy_ports { %s }", strings.Join(elems, ",")))
		}
	}

	// 2) Σύνθεση επιλογών synproxy
	// tcp option maxseg size set <MSS> synproxy mss <MSS> wscale <W> [sack-perm] [tstamp]
	opts := fmt.Sprintf("tcp option maxseg size set %d synproxy mss %d wscale %d", sp.MSS, sp.MSS, sp.WScale)
	if sp.SACK   { opts += " sack-perm" }
	if sp.TStamp { opts += " tstamp" }

	// helper: φτιάξε δύο κανόνες (challenge+pass) για ένα selector (set/ports)
	addRules := func(selector string) {
		// Challenge: μόνο SYN
		_ = b.runCmd(fmt.Sprintf(
			"add rule inet cfm input tcp dport %s tcp flags syn %s counter name synproxy_challenge",
			selector, opts,
		))
		// Pass: επιτρέπεις SYN μετά το challenge (new/untracked SYN|ACK)
		_ = b.runCmd(fmt.Sprintf(
			"add rule inet cfm input tcp dport %s ct state new,untracked tcp flags & (syn|ack) == syn counter name synproxy_pass accept",
			selector,
		))
	}

	// 3) Κάνε cleanup παλιών κανόνων για να μην διπλασιάζονται
	//    Σβήνουμε κανόνες με τα counters "synproxy_challenge"/"synproxy_pass"
	_ = b.deleteRulesByCounter("synproxy_challenge")
	_ = b.deleteRulesByCounter("synproxy_pass")

	// 4) Κανόνες για TCP_IN (αν ζητήθηκε) και για extra set
	if sp.AutoTCPIn {
		addRules("@tcp_in_ports")
	}
	if hasExtra {
		addRules("@synproxy_ports")
	}
	return nil
}

// deleteRulesByCounter σκανάρει την chain 'input' και σβήνει ό,τι έχει συγκεκριμένο counter name.
func (b *Backend) deleteRulesByCounter(counter string) error {
	out, err := b.runCmdOutput("list chain inet cfm input")
	if err != nil { return err }
	lines := strings.Split(out, "\n")
	var handles []string
	for _, ln := range lines {
		if strings.Contains(ln, "counter name "+counter) && strings.Contains(ln, "handle") {
			// ... handle N at end of line
			i := strings.LastIndex(ln, "handle ")
			if i > 0 {
				h := strings.TrimSpace(ln[i+len("handle "):])
				handles = append(handles, h)
			}
		}
	}
	for _, h := range handles {
		_ = b.runCmd(fmt.Sprintf("delete rule inet cfm input handle %s", h))
	}
	return nil
}
