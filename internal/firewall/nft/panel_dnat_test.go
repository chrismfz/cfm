//go:build linux

package nft

import (
	"fmt"
	"strings"
	"testing"

	"cfm/internal/firewall"
)

func TestPanelDNATScriptCoversCanonicalMappings(t *testing.T) {
	script := panelDNATScript(-101)
	for _, m := range firewall.PanelDNATMappings() {
		want := fmt.Sprintf("tcp dport %d dnat to :%d", m.From, m.To)
		if !strings.Contains(script, want) {
			t.Fatalf("panel DNAT script missing %q:\n%s", want, script)
		}
	}
	if got, want := strings.Count(script, " dnat to :"), len(firewall.PanelDNATMappings()); got != want {
		t.Fatalf("panel DNAT script has %d mappings, want %d:\n%s", got, want, script)
	}
}
