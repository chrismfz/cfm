//go:build linux

package nftlib

import (
	"testing"

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

func TestPanelDNATAcceptExprIdentityCoversCanonicalMappings(t *testing.T) {
	for _, m := range firewall.PanelDNATMappings() {
		rule := panelDNATAcceptID(m.From, m.To)
		if rule == "" {
			t.Fatalf("empty accept id for %d->%d", m.From, m.To)
		}
	}
}
