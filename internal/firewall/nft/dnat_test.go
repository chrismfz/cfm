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

func TestParseDNATListenerPorts(t *testing.T) {
	out := `table inet cfm_redirect {
	chain prerouting {
		type nat hook prerouting priority -99; policy accept;
		iif "lo" accept
		tcp dport 80 dnat to :9080
		tcp dport 443 dnat to :9043
		udp dport 443 dnat to :9043
	}
}`
	httpPort, httpsPort, ok := parseDNATListenerPorts(out)
	if !ok {
		t.Fatalf("parseDNATListenerPorts ok=false on canonical listing")
	}
	if httpPort != 9080 || httpsPort != 9043 {
		t.Fatalf("parseDNATListenerPorts = %d/%d, want 9080/9043", httpPort, httpsPort)
	}
}

func TestParseDNATListenerPortsCustom(t *testing.T) {
	out := `tcp dport 80 dnat to 127.0.0.1:9000
tcp dport 443 dnat to :9001
udp dport 443 dnat to :9001`
	httpPort, httpsPort, ok := parseDNATListenerPorts(out)
	if !ok || httpPort != 9000 || httpsPort != 9001 {
		t.Fatalf("parseDNATListenerPorts = (%d,%d,%v), want (9000,9001,true)", httpPort, httpsPort, ok)
	}
}

func TestParseDNATListenerPortsMissing(t *testing.T) {
	if _, _, ok := parseDNATListenerPorts(""); ok {
		t.Fatalf("expected ok=false on empty input")
	}
	if _, _, ok := parseDNATListenerPorts("tcp dport 80 dnat to :9080"); ok {
		t.Fatalf("expected ok=false when only http listener is present (no https)")
	}
}

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
