//go:build linux

package nft

import (
	"strings"
	"testing"
)

// panelManagedRulePlacement must classify a managed panel accept by its
// position relative to the default drop — this is what makes PanelDNATAcceptState
// report "blocked" (not "open") for an accept stranded after the drop.
func TestPanelManagedRulePlacement(t *testing.T) {
	chain := `table inet cfm {
	chain input {
		ct state new tcp dport 12082 ct status dnat ct original proto-dst 2082 accept comment "cfm_cpanel_dnat:2082:12082" # handle 5
		ct state new tcp dport 0-65535 drop # handle 8
		ct state new udp dport 0-65535 drop # handle 9
		ct state new tcp dport 12083 ct status dnat ct original proto-dst 2083 accept comment "cfm_cpanel_dnat:2083:12083" # handle 10
	}
}`
	if h, before, ok := panelManagedRulePlacement(chain, "2082:12082"); !ok || !before || h != "5" {
		t.Errorf("2082:12082 = (%q,%v,%v), want (5,true,true) — before the drop", h, before, ok)
	}
	if h, before, ok := panelManagedRulePlacement(chain, "2083:12083"); !ok || before || h != "10" {
		t.Errorf("2083:12083 = (%q,%v,%v), want (10,false,true) — after the drop", h, before, ok)
	}
	if _, _, ok := panelManagedRulePlacement(chain, "2086:12086"); ok {
		t.Errorf("2086:12086 ok=true, want false (absent)")
	}
}

// nftOut runs `nft -f -` (script mode); a leading-dash arg is a CLI flag and a
// syntax error there. The runtime guard must reject it before executing nft, so
// a mistaken `nftOut("-a list …")` can never silently return garbage again.
func TestNftOutRejectsLeadingFlag(t *testing.T) {
	b := New()
	out, err := b.nftOut("-a list chain inet cfm input")
	if err == nil {
		t.Fatalf("nftOut(\"-a list …\") returned nil error; want a rejection (out=%q)", out)
	}
	if !strings.Contains(err.Error(), "script mode") {
		t.Errorf("unexpected error text: %v", err)
	}
	// A normal script expression is still accepted by the guard (it will fail
	// later for other reasons in a sandbox, but not on the leading-dash check).
	if _, err := b.nftOut("list tables"); err != nil && strings.Contains(err.Error(), "starts with a CLI flag") {
		t.Errorf("guard wrongly rejected a non-flag expression: %v", err)
	}
}
