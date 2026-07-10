package firewall

import "testing"

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
	httpPort, httpsPort, ok := ParseDNATListenerPorts(out)
	if !ok {
		t.Fatalf("ParseDNATListenerPorts ok=false on canonical listing")
	}
	if httpPort != 9080 || httpsPort != 9043 {
		t.Fatalf("ParseDNATListenerPorts = %d/%d, want 9080/9043", httpPort, httpsPort)
	}
}

func TestParseDNATListenerPortsCustom(t *testing.T) {
	out := `tcp dport 80 dnat to 127.0.0.1:9000
tcp dport 443 dnat to :9001
udp dport 443 dnat to :9001`
	httpPort, httpsPort, ok := ParseDNATListenerPorts(out)
	if !ok || httpPort != 9000 || httpsPort != 9001 {
		t.Fatalf("ParseDNATListenerPorts = (%d,%d,%v), want (9000,9001,true)", httpPort, httpsPort, ok)
	}
}

func TestParseDNATListenerPortsMissing(t *testing.T) {
	if _, _, ok := ParseDNATListenerPorts(""); ok {
		t.Fatalf("expected ok=false on empty input")
	}
	if _, _, ok := ParseDNATListenerPorts("tcp dport 80 dnat to :9080"); ok {
		t.Fatalf("expected ok=false when only http listener is present (no https)")
	}
}

func TestIsInputDefaultDropLine(t *testing.T) {
	drops := []string{
		`ct state new tcp dport 0-65535 drop # handle 8`,
		`ct state new udp dport 0-65535 drop # handle 9`,
		`tcp dport 0-65535 ct state new drop`, // reordered by nft
	}
	for _, l := range drops {
		if !IsInputDefaultDropLine(l) {
			t.Errorf("IsInputDefaultDropLine(%q) = false, want true", l)
		}
	}
	nonDrops := []string{
		`ct state invalid drop # handle 10`,                 // not NEW, no 0-65535
		`ct state new tcp dport @tcp_in_ports accept`,       // accept
		`ct state new tcp dport 9080 ct status dnat accept`, // scoped accept, specific port
		`ct state established,related accept`,
	}
	for _, l := range nonDrops {
		if IsInputDefaultDropLine(l) {
			t.Errorf("IsInputDefaultDropLine(%q) = true, want false", l)
		}
	}
}
