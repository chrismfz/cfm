//go:build linux

package nft

import (
	"strings"
	"testing"
)

func TestDNATAcceptRuleExprCanInsertBeforeDefaultDropHandle(t *testing.T) {
	spec := dnatAcceptRuleSpecs(9080, 9043)[0]
	chain := `table inet cfm {
		chain input {
			ct state new tcp dport 0-65535 drop # handle 41
			ct state new udp dport 0-65535 drop # handle 42
		}
	}`
	handle := firstInputDefaultDropHandle(chain)
	if handle != "41" {
		t.Fatalf("firstInputDefaultDropHandle() = %q, want 41", handle)
	}
	got := dnatAcceptRuleExpr(spec, handle)
	if !strings.HasPrefix(got, "insert rule inet cfm input position 41 ") {
		t.Fatalf("DNAT accept rule was not handle-inserted before default drops: %q", got)
	}
	if strings.HasPrefix(got, "add rule inet cfm input ") {
		t.Fatalf("DNAT accept rule used append syntax that can place it after default drops: %q", got)
	}
}

// ParseDNATListenerPorts behaviour is covered in the firewall package
// (internal/firewall/dnat_accepts_test.go); the nft-side parseDNATListenerPorts
// is a thin delegator.

func TestDNATAcceptRuleExprsCoverTCPAndUDPWithoutSourceSet(t *testing.T) {
	specs := dnatAcceptRuleSpecs(9080, 9043)
	want := []string{
		`add rule inet cfm input tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080"`,
		`add rule inet cfm input tcp dport 9043 ct state new ct status dnat ct original proto-dst 443 accept comment "cfm_dnat_accept:web_https_tcp:443:9043"`,
		`add rule inet cfm input udp dport 9043 ct state new ct status dnat ct original proto-dst 443 accept comment "cfm_dnat_accept:web_https_udp:443:9043"`,
	}
	if len(specs) != len(want) {
		t.Fatalf("dnatAcceptRuleSpecs() returned %d specs, want %d: %#v", len(specs), len(want), specs)
	}
	for i, spec := range specs {
		got := dnatAcceptRuleExpr(spec, "")
		if got != want[i] {
			t.Fatalf("dnatAcceptRuleExpr(%d) = %q, want %q", i, got, want[i])
		}
		if strings.Contains(got, " saddr @") {
			t.Fatalf("dnatAcceptRuleExpr(%d) = %q, want no source-set membership requirement", i, got)
		}
	}
}
