//go:build linux

package nft

import (
	"strings"
	"testing"
)

// The insert position (before the default drop) is EnsureInputAccepts' job,
// tested in the firewall package.

// ParseDNATListenerPorts behaviour is covered in the firewall package
// (internal/firewall/dnat_accepts_test.go); the nft-side parseDNATListenerPorts
// is a thin delegator.

func TestDNATAcceptRuleBodiesCoverTCPAndUDPWithoutSourceSet(t *testing.T) {
	specs := dnatAcceptRuleSpecs(9080, 9043)
	want := []string{
		`tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080"`,
		`tcp dport 9043 ct state new ct status dnat ct original proto-dst 443 accept comment "cfm_dnat_accept:web_https_tcp:443:9043"`,
		`udp dport 9043 ct state new ct status dnat ct original proto-dst 443 accept comment "cfm_dnat_accept:web_https_udp:443:9043"`,
	}
	if len(specs) != len(want) {
		t.Fatalf("dnatAcceptRuleSpecs() returned %d specs, want %d: %#v", len(specs), len(want), specs)
	}
	for i, spec := range specs {
		got := dnatAcceptRuleBody(spec)
		if got != want[i] {
			t.Fatalf("dnatAcceptRuleBody(%d) = %q, want %q", i, got, want[i])
		}
		if strings.Contains(got, " saddr @") {
			t.Fatalf("dnatAcceptRuleBody(%d) = %q, want no source-set membership requirement", i, got)
		}
	}
}
