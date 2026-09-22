//go:build linux

package nft

import (
	"fmt"
	"strings"
	"time"

	"cfm/internal/firewall"
)

const (
	panelDNATFamily = "inet"
	panelDNATTable  = "cfm_panel_redirect"
)

func panelDNATScript(priority int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table %s %s\n", panelDNATFamily, panelDNATTable)
	fmt.Fprintf(&b, "add chain %s %s prerouting { type nat hook prerouting priority %d; policy accept; }\n", panelDNATFamily, panelDNATTable, priority)
	b.WriteString("add rule inet cfm_panel_redirect prerouting iif \"lo\" accept\n")
	// Source-IP bypass: peers listed in /etc/cfm/cfm.dnat_cpanel_bypass
	// skip the panel DNAT redirect entirely. Use case: cluster nodes and
	// migration sources (e.g. cPanel-to-cPanel WHM Transfer Tool source
	// hosts) whose traffic needs to reach cpsrvd directly without the
	// challenge / WAF intermediation. Loaded from disk on every script
	// render so add/remove via CLI takes effect on the next reload.
	entries, skipped, _ := firewall.LoadDNATBypass(firewall.DNATBypassCpanelPath)
	for _, line := range firewall.DNATBypassRuleExprs(entries, panelDNATFamily, panelDNATTable, "prerouting") {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	for _, warn := range skipped {
		fmt.Fprintf(&b, "# WARNING: cfm.dnat_cpanel_bypass skipped entry: %s\n", warn)
	}
	for _, m := range firewall.PanelDNATMappings() {
		fmt.Fprintf(&b, "add rule inet cfm_panel_redirect prerouting tcp dport %d dnat to :%d\n", m.From, m.To)
	}
	return b.String()
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
	_ = b.nftCmd("delete table inet cfm_panel_redirect")
	return b.nftExpr(panelDNATScript(priority))
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
	_ = b.nftCmd("delete table inet cfm_panel_redirect")
	return nil
}

func (b *Backend) PanelDNATStatus() (bool, string, error) {
	out, err := b.nftOut("list table inet cfm_panel_redirect")
	if err != nil {
		msg := err.Error() + out
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") {
			return false, "", nil
		}
		return false, out, err
	}
	if strings.TrimSpace(out) == "" {
		return false, "", nil
	}
	return true, out, nil
}

// panelAcceptOps drives the shared panel-accept code with this backend's nft
// runner. Listing is argv mode (ListChainText): a script-mode `-a` list is a
// syntax error, which once made the accepts land after the default drop and
// the state report every panel port "blocked".
func (b *Backend) panelAcceptOps() firewall.NFTTextOps {
	return firewall.NFTTextOps{
		ListInput: func() (string, error) { return b.ListChainText(family, tableName, "input") },
		Run:       b.nftCmd,
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
