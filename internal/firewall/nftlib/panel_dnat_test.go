//go:build linux

package nftlib

import (
	"strings"
	"testing"

	"cfm/internal/config"
	"cfm/internal/firewall"

	"github.com/google/nftables"
)

func TestPanelDNATSpecsCoverCanonicalMappings(t *testing.T) {
	specs := panelDNATSpecs()
	mappings := firewall.PanelDNATMappings()
	if len(specs) != len(mappings) {
		t.Fatalf("panelDNATSpecs() returned %d specs, want %d", len(specs), len(mappings))
	}
	for i, m := range mappings {
		spec := specs[i]
		if spec.family != nftables.TableFamilyINet || spec.proto != 6 || int(spec.dport) != m.From || int(spec.toPort) != m.To || spec.sourceSet != "" || spec.toAddr != nil {
			t.Fatalf("spec[%d]=%#v, want inet tcp %d->%d unscoped", i, spec, m.From, m.To)
		}
	}
}

// The panel chain's status text carries the panel chain's OWN priority, as the
// kernel lists it, not the web redirect's NFT_DNAT_PRIORITY (which it used to
// print), and lists the source-IP bypass rules like the exec engine's raw
// table does.
func TestPanelDNATShowTextUsesThePanelChainPriority(t *testing.T) {
	b := &Backend{cfg: &config.Config{}}
	b.cfg.NFT.DNATPriority = -99 // the web redirect
	if b.dnatPriority() != -99 {
		t.Fatalf("web dnat priority = %d, want -99", b.dnatPriority())
	}
	panelPrio := nftables.ChainPriority(-101) // the panel chain, as ListChains reports it
	spec := panelDNATSpecs()[0]
	rules := []*nftables.Rule{
		{UserData: []byte(dnatLoopbackAcceptTag), Exprs: dnatLoopbackAcceptExprs()},
		{UserData: []byte(dnatBypassUserDataPrefix + "192.0.2.7")},
		{UserData: []byte(dnatBypassUserDataPrefix + "2001:db8::/64")},
		{UserData: []byte(spec.id()), Exprs: dnatRuleExprs(spec)},
	}
	out := panelDNATShowText(rules, &panelPrio)
	if !strings.Contains(out, "priority -101;") || strings.Contains(out, "priority -99") {
		t.Fatalf("status must show the panel chain's -101, not the web -99:\n%s", out)
	}
	for _, want := range []string{"iif \"lo\" accept", "ip saddr 192.0.2.7 accept", "ip6 saddr 2001:db8::/64 accept", dnatShowRuleLine(spec)} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "192.0.2.7") > strings.Index(out, dnatShowRuleLine(spec)) {
		t.Errorf("bypass rules must be listed before the DNAT rules (chain order):\n%s", out)
	}
	if out := panelDNATShowText(rules, nil); strings.Contains(out, "priority -") {
		t.Errorf("an unreported priority must not be invented:\n%s", out)
	}
}

func TestDNATBypassShowRuleLineRejectsForeignRules(t *testing.T) {
	for _, ud := range []string{"", "cfm_dnat:v1:x", dnatBypassUserDataPrefix + "not-an-ip"} {
		if l, ok := dnatBypassShowRuleLine([]byte(ud)); ok {
			t.Errorf("%q rendered as %q", ud, l)
		}
	}
}
