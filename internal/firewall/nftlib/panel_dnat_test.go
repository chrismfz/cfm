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
	// The tag is read like the bypass file: a host CIDR is masked.
	if l, ok := dnatBypassShowRuleLine([]byte(dnatBypassUserDataPrefix + "192.0.2.7/24")); !ok || l != "ip saddr 192.0.2.0/24 accept" {
		t.Errorf("CIDR tag rendered %q ok=%t", l, ok)
	}
	for _, ud := range []string{"", "cfm_dnat:v1:x", dnatBypassUserDataPrefix + "not-an-ip", dnatBypassUserDataPrefix} {
		if l, ok := dnatBypassShowRuleLine([]byte(ud)); ok {
			t.Errorf("%q rendered as %q", ud, l)
		}
	}
}

// `cfm dnat` (web scope) lists the bypass rules too, before the DNAT rules as
// in the chain, and the lines its callers parse are unchanged: the listener
// ports (firewall.ParseDNATListenerPorts) and the live priority.
func TestDNATShowTextListsBypassRules(t *testing.T) {
	http := dnatRuleSpec{family: nftables.TableFamilyINet, proto: 6, dport: 80, toPort: 9080}
	https := dnatRuleSpec{family: nftables.TableFamilyINet, proto: 6, dport: 443, toPort: 9043}
	rules := []*nftables.Rule{
		{UserData: []byte(dnatLoopbackAcceptTag), Exprs: dnatLoopbackAcceptExprs()},
		{UserData: []byte(dnatBypassUserDataPrefix + "198.51.100.0/24")},
		{UserData: []byte(http.id()), Exprs: dnatRuleExprs(http)},
		{UserData: []byte(https.id()), Exprs: dnatRuleExprs(https)},
	}
	live := nftables.ChainPriority(-101)
	out := dnatShowText("inet", "cfm_redirect", rules, &live, -99)
	if !strings.Contains(out, "ip saddr 198.51.100.0/24 accept") {
		t.Fatalf("web status lacks the bypass rule:\n%s", out)
	}
	if strings.Index(out, "198.51.100.0/24") > strings.Index(out, dnatShowRuleLine(http)) {
		t.Errorf("bypass rules must come before the DNAT rules:\n%s", out)
	}
	if !strings.Contains(out, "priority -101;") {
		t.Errorf("want the live priority -101:\n%s", out)
	}
	if h, hs, ok := firewall.ParseDNATListenerPorts(out); !ok || h != 9080 || hs != 9043 {
		t.Errorf("listener ports = %d/%d ok=%t, want 9080/9043:\n%s", h, hs, ok, out)
	}
	if out := dnatShowText("inet", "cfm_redirect", rules, nil, -99); !strings.Contains(out, "priority -99;") {
		t.Errorf("no live priority: want the configured -99:\n%s", out)
	}
	// Bypass rules alone are not a DNAT: no CFM DNAT rule, no listing.
	if out := dnatShowText("inet", "cfm_redirect", rules[:2], &live, -99); out != "" {
		t.Errorf("a chain without DNAT rules must render empty, got:\n%s", out)
	}
}
