//go:build linux

package nftlib

import (
	"fmt"
	"strings"
	"time"

	"cfm/internal/firewall"

	"github.com/google/nftables"
)

const panelDNATTableName = "cfm_panel_redirect"

func panelDNATSpecs() []dnatRuleSpec {
	maps := firewall.PanelDNATMappings()
	specs := make([]dnatRuleSpec, 0, len(maps))
	for _, m := range maps {
		specs = append(specs, dnatRuleSpec{family: nftables.TableFamilyINet, proto: 6, dport: uint16(m.From), toPort: uint16(m.To)})
	}
	return specs
}

func (b *Backend) PanelDNATOn(priority int) (err error) {
	start := time.Now()
	b.logPhase("PanelDNATOn", "start", 0, nil, fmt.Sprintf("op=dnat scope=cpanel priority=%d", priority))
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("PanelDNATOn", st, time.Since(start), err, fmt.Sprintf("op=dnat scope=cpanel priority=%d", priority))
	}()
	if priority < -300 {
		priority = -300
	}
	if priority > 300 {
		priority = 300
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	t := &nftables.Table{Name: panelDNATTableName, Family: nftables.TableFamilyINet}
	old, err := b.findTable(panelDNATTableName, nftables.TableFamilyINet)
	if err != nil {
		// Without knowing whether the table exists we can't delete it first,
		// and adding on top of a live table would duplicate every rule.
		return fmt.Errorf("nftlib: look up %s: %w", panelDNATTableName, err)
	}
	if old != nil {
		b.conn.DelTable(old)
		if err := b.conn.Flush(); err != nil {
			return err
		}
	}
	prio := nftables.ChainPriority(priority)
	policy := nftables.ChainPolicyAccept
	ch := &nftables.Chain{Name: "prerouting", Table: t, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: &prio, Policy: &policy}
	b.conn.AddTable(t)
	b.conn.AddChain(ch)
	b.conn.AddRule(&nftables.Rule{Table: t, Chain: ch, UserData: []byte(dnatLoopbackAcceptTag), Exprs: dnatLoopbackAcceptExprs()})
	// Source-IP bypass: peers in /etc/cfm/cfm.dnat_cpanel_bypass skip the
	// cPanel panel DNAT entirely. Added BETWEEN the loopback accept rule
	// and the dport DNAT rules so nftables first-match-wins guarantees
	// the bypass short-circuits before NAT translation runs. Since
	// PanelDNATOn rebuilds the table from scratch on every call, the
	// fresh add-order here is also the eval-order in the running chain.
	if _, warnings := b.dnatBypassAddRules(t, ch, firewall.DNATBypassScopeCpanel); len(warnings) > 0 {
		for _, w := range warnings {
			b.logPhase("PanelDNATOn", "warn", 0, nil, fmt.Sprintf("bypass entry: %s", w))
		}
	}
	for _, spec := range panelDNATSpecs() {
		b.conn.AddRule(&nftables.Rule{Table: t, Chain: ch, UserData: []byte(spec.id()), Exprs: dnatRuleExprs(spec)})
	}
	return b.conn.Flush()
}

func (b *Backend) PanelDNATOff() (err error) {
	start := time.Now()
	b.logPhase("PanelDNATOff", "start", 0, nil, "op=dnat scope=cpanel")
	defer func() {
		st := "ok"
		if err != nil {
			st = "fail"
		}
		b.logPhase("PanelDNATOff", st, time.Since(start), err, "op=dnat scope=cpanel")
	}()
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ferr := b.findTable(panelDNATTableName, nftables.TableFamilyINet)
	if ferr != nil || t == nil {
		return ferr
	}
	b.conn.DelTable(t)
	return b.conn.Flush()
}

func (b *Backend) PanelDNATStatus() (bool, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ch, err := b.getPanelDNATTableAndChain()
	if err != nil || ch == nil {
		return false, "", err
	}
	rules, err := b.conn.GetRules(t, ch)
	if err != nil {
		return false, "", err
	}
	if len(rules) == 0 {
		return false, "", nil
	}
	return true, panelDNATShowText(rules, b.dnatPriority()), nil
}

func panelDNATShowText(rules []*nftables.Rule, priority int) string {
	var out strings.Builder
	out.WriteString("table inet cfm_panel_redirect {\n")
	out.WriteString("  chain prerouting {\n")
	fmt.Fprintf(&out, "    type nat hook prerouting priority %d; policy accept;\n\n", priority)
	for _, r := range rules {
		if dnatLoopbackAcceptMatches(r) {
			out.WriteString("    iif \"lo\" accept\n")
			continue
		}
		spec, ok := parseDNATRuleSpecID(string(r.UserData))
		if ok && dnatRuleMatches(r, spec) {
			fmt.Fprintf(&out, "    %s\n", dnatShowRuleLine(spec))
		}
	}
	out.WriteString("  }\n}\n")
	return out.String()
}

func (b *Backend) getPanelDNATTableAndChain() (*nftables.Table, *nftables.Chain, error) {
	t := &nftables.Table{Name: panelDNATTableName, Family: nftables.TableFamilyINet}
	chains, err := b.conn.ListChains()
	if err != nil {
		return nil, nil, err
	}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == panelDNATTableName && ch.Table.Family == nftables.TableFamilyINet && ch.Name == "prerouting" {
			return t, ch, nil
		}
	}
	return t, nil, nil
}

func (b *Backend) findTable(name string, family nftables.TableFamily) (*nftables.Table, error) {
	tables, err := b.conn.ListTables()
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		if t.Name == name && t.Family == family {
			return t, nil
		}
	}
	return nil, nil
}

// panelAcceptOps drives the shared panel-accept code (firewall.
// EnsurePanelDNATAccepts & co) through the nft CLI, like the web DNAT accepts
// in challenge.go. These rules must not be read over netlink:
// google/nftables v0.3.0 can't decode the `ct original proto-dst` match they
// carry, and a chain holding one fails the whole GetRules dump — see
// internal/firewall/panel_dnat_accepts.go. Nothing in this backend reads
// inet cfm/input over netlink.
func (b *Backend) panelAcceptOps() firewall.NFTTextOps {
	return firewall.NFTTextOps{
		ListInput: func() (string, error) { return b.ListChainText("inet", cfmTableName, "input") },
		Run:       b.nftExec,
	}
}

func (b *Backend) EnsurePanelDNATAccepts() ([]string, error) {
	return firewall.EnsurePanelDNATAccepts(b.panelAcceptOps())
}

func (b *Backend) RemovePanelDNATAccepts() ([]string, error) {
	return firewall.RemovePanelDNATAccepts(b.panelAcceptOps())
}

func (b *Backend) PanelDNATAcceptState() map[int]string {
	return firewall.PanelDNATAcceptState(b.panelAcceptOps())
}
