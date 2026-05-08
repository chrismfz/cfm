//go:build linux

package nftlib

import (
	"net"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestParseListenHostPort(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantHost string
		wantPort int
		wantOK   bool
	}{
		{name: "port only", addr: "9080", wantPort: 9080, wantOK: true},
		{name: "wildcard", addr: ":9080", wantPort: 9080, wantOK: true},
		{name: "loopback ipv4", addr: "127.0.0.1:9080", wantHost: "127.0.0.1", wantPort: 9080, wantOK: true},
		{name: "loopback ipv6", addr: "[::1]:9043", wantHost: "::1", wantPort: 9043, wantOK: true},
		{name: "dedicated ipv4", addr: "192.0.2.10:9080", wantHost: "192.0.2.10", wantPort: 9080, wantOK: true},
		{name: "dedicated ipv6", addr: "[2001:db8::10]:9043", wantHost: "2001:db8::10", wantPort: 9043, wantOK: true},
		{name: "bad port", addr: "127.0.0.1:0", wantHost: "127.0.0.1"},
		{name: "missing port", addr: "127.0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotHost, gotPort, gotOK := parseListenHostPort(tc.addr)
			if gotHost != tc.wantHost || gotPort != tc.wantPort || gotOK != tc.wantOK {
				t.Fatalf("parseListenHostPort(%q) = (%q, %d, %v), want (%q, %d, %v)", tc.addr, gotHost, gotPort, gotOK, tc.wantHost, tc.wantPort, tc.wantOK)
			}
		})
	}
}

func TestDNATRuleSpecIdentityParsing(t *testing.T) {
	specs := []dnatRuleSpec{
		{family: nftables.TableFamilyIPv4, proto: 6, dport: 80, toPort: 9080, sourceSet: setChalV4, toAddr: net.ParseIP("127.0.0.1")},
		{family: nftables.TableFamilyIPv4, proto: 6, dport: 443, toPort: 9043, sourceSet: "self_v4", toAddr: net.ParseIP("192.0.2.10")},
		{family: nftables.TableFamilyIPv6, proto: 17, dport: 443, toPort: 9043, sourceSet: setChalV6, toAddr: net.ParseIP("::1")},
		{family: nftables.TableFamilyIPv6, proto: 6, dport: 80, toPort: 9080, sourceSet: "self_v6", toAddr: net.ParseIP("2001:db8::10")},
		{family: nftables.TableFamilyIPv4, proto: 6, dport: 80, toPort: 9080, sourceSet: setChalV4},
	}
	for _, spec := range specs {
		got, ok := parseDNATRuleSpecID(spec.id())
		if !ok {
			t.Fatalf("parseDNATRuleSpecID(%q) returned !ok", spec.id())
		}
		if got.id() != spec.id() {
			t.Fatalf("round trip id = %q, want %q", got.id(), spec.id())
		}
		rule := &nftables.Rule{UserData: []byte(spec.id()), Exprs: dnatRuleExprs(spec)}
		if !dnatRuleMatches(rule, spec) {
			t.Fatalf("dnatRuleMatches failed for %q", spec.id())
		}
	}
	if _, ok := parseDNATRuleSpecID("cfm-dnat-managed:v1:p6:d80:t9080"); ok {
		t.Fatal("old unscoped v1 managed DNAT id parsed as current rule")
	}
}

func TestDNATRuleSpecIdentityPortBoundaries(t *testing.T) {
	for _, port := range []uint16{1, 80, 443, 65535} {
		spec := dnatRuleSpec{family: nftables.TableFamilyIPv4, proto: 6, dport: port, toPort: port, sourceSet: setChalV4}
		got, ok := parseDNATRuleSpecID(spec.id())
		if !ok {
			t.Fatalf("parseDNATRuleSpecID(%q) returned !ok", spec.id())
		}
		if got.dport != port || got.toPort != port {
			t.Fatalf("parseDNATRuleSpecID(%q) ports = d%d t%d, want d%d t%d", spec.id(), got.dport, got.toPort, port, port)
		}
	}
}

func TestDNATRuleSpecIdentityRejectsOutOfRangeComponents(t *testing.T) {
	valid := dnatRuleSpec{family: nftables.TableFamilyIPv4, proto: 6, dport: 80, toPort: 9080, sourceSet: setChalV4}.id()
	tests := []struct {
		name string
		id   string
	}{
		{name: "zero dport", id: strings.Replace(valid, ":d80:", ":d0:", 1)},
		{name: "negative dport", id: strings.Replace(valid, ":d80:", ":d-1:", 1)},
		{name: "overflowing dport", id: strings.Replace(valid, ":d80:", ":d65536:", 1)},
		{name: "huge dport", id: strings.Replace(valid, ":d80:", ":d18446744073709551616:", 1)},
		{name: "zero toPort", id: strings.Replace(valid, ":t9080:", ":t0:", 1)},
		{name: "negative toPort", id: strings.Replace(valid, ":t9080:", ":t-1:", 1)},
		{name: "overflowing toPort", id: strings.Replace(valid, ":t9080:", ":t65536:", 1)},
		{name: "huge toPort", id: strings.Replace(valid, ":t9080:", ":t18446744073709551616:", 1)},
		{name: "overflowing protocol", id: strings.Replace(valid, ":p6:", ":p256:", 1)},
		{name: "huge protocol", id: strings.Replace(valid, ":p6:", ":p18446744073709551616:", 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseDNATRuleSpecID(tc.id); ok {
				t.Fatalf("parseDNATRuleSpecID(%q) returned ok", tc.id)
			}
		})
	}
}

func TestDNATOnRejectsInvalidPortsBeforeNetlink(t *testing.T) {
	b := &Backend{}
	tests := []struct {
		name      string
		httpPort  int
		httpsPort int
	}{
		{name: "zero http", httpPort: 0, httpsPort: 443},
		{name: "zero https", httpPort: 80, httpsPort: 0},
		{name: "negative http", httpPort: -1, httpsPort: 443},
		{name: "negative https", httpPort: 80, httpsPort: -1},
		{name: "overflowing http", httpPort: 65536, httpsPort: 443},
		{name: "overflowing https", httpPort: 80, httpsPort: 65536},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := b.DNATOn("", "", tc.httpPort, tc.httpsPort); err == nil {
				t.Fatalf("DNATOn(%d, %d) returned nil error", tc.httpPort, tc.httpsPort)
			}
		})
	}
}

func TestDNATUnscopedWantedSpecsDoNotRequireChallengeSource(t *testing.T) {
	specs := dnatUnscopedWantedSpecs(nftables.TableFamilyINet, 9080, 9043)
	want := []struct {
		proto  uint8
		dport  uint16
		toPort uint16
		line   string
	}{
		{proto: 6, dport: 80, toPort: 9080, line: "tcp dport 80 dnat to :9080"},
		{proto: 6, dport: 443, toPort: 9043, line: "tcp dport 443 dnat to :9043"},
		{proto: 17, dport: 443, toPort: 9043, line: "udp dport 443 dnat to :9043"},
	}
	if len(specs) != len(want) {
		t.Fatalf("dnatUnscopedWantedSpecs() returned %d specs, want %d: %#v", len(specs), len(want), specs)
	}
	for i, spec := range specs {
		if spec.sourceSet != "" {
			t.Fatalf("DNATOn spec %d has sourceSet %q, want unscoped", i, spec.sourceSet)
		}
		if spec.family != nftables.TableFamilyINet || spec.proto != want[i].proto || spec.dport != want[i].dport || spec.toPort != want[i].toPort || spec.toAddr != nil {
			t.Fatalf("DNATOn spec %d = %#v, want family inet proto=%d dport=%d toPort=%d with no target address", i, spec, want[i].proto, want[i].dport, want[i].toPort)
		}
		for _, ex := range dnatRuleExprs(spec) {
			if _, ok := ex.(*expr.Lookup); ok {
				t.Fatalf("DNATOn spec %d installed source-set lookup in %#v", i, dnatRuleExprs(spec))
			}
		}
		line := dnatShowRuleLine(spec)
		if line != want[i].line {
			t.Fatalf("dnatShowRuleLine(DNATOn spec %d) = %q, want %q", i, line, want[i].line)
		}
		if strings.Contains(line, "saddr @challenge_") || strings.Contains(line, "saddr @self_") {
			t.Fatalf("DNATOn rule line is unexpectedly source-scoped: %q", line)
		}
	}

	accepts := []string{
		`add rule inet cfm input ct state new ct status dnat ct original proto-dst 80 tcp dport 9080 accept comment "cfm_dnat_accept:web_http_tcp:80:9080"`,
		`add rule inet cfm input ct state new ct status dnat ct original proto-dst 443 tcp dport 9043 accept comment "cfm_dnat_accept:web_https_tcp:443:9043"`,
		`add rule inet cfm input ct state new ct status dnat ct original proto-dst 443 udp dport 9043 accept comment "cfm_dnat_accept:web_https_udp:443:9043"`,
	}
	for i, spec := range specs {
		got := dnatAcceptRuleExpr(spec)
		if got != accepts[i] {
			t.Fatalf("dnatAcceptRuleExpr(DNATOn spec %d) = %q, want %q", i, got, accepts[i])
		}
		if strings.Contains(got, " saddr @") {
			t.Fatalf("DNATOn accept rule is unexpectedly source-scoped: %q", got)
		}
	}
}

func TestDNATLoopbackAcceptRuleMatchesIIFLoAccept(t *testing.T) {
	rule := &nftables.Rule{UserData: []byte(dnatLoopbackAcceptTag), Exprs: dnatLoopbackAcceptExprs()}
	if !dnatLoopbackAcceptMatches(rule) {
		t.Fatalf("dnatLoopbackAcceptMatches() returned false for generated iif lo accept rule")
	}
	meta, ok := rule.Exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyIIFNAME {
		t.Fatalf("loopback accept first expr = %#v, want iifname meta load", rule.Exprs[0])
	}
	verdict, ok := rule.Exprs[2].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictAccept {
		t.Fatalf("loopback accept verdict = %#v, want accept", rule.Exprs[2])
	}
}

func TestDNATWantedSpecsAreSourceScopedAndHostScoped(t *testing.T) {
	specs := dnatWantedSpecs("127.0.0.1", 9080, "2001:db8::10", 9043)
	assertHasSpec := func(fam nftables.TableFamily, proto uint8, dport uint16, setName, addr string) {
		t.Helper()
		for _, spec := range specs {
			if spec.family == fam && spec.proto == proto && spec.dport == dport && spec.sourceSet == setName && dnatAddrID(spec.toAddr) == addr {
				return
			}
		}
		t.Fatalf("missing family=%d proto=%d dport=%d sourceSet=%s addr=%s in %#v", fam, proto, dport, setName, addr, specs)
	}
	assertHasSpec(nftables.TableFamilyIPv4, 6, 80, setChalV4, "127.0.0.1")
	assertHasSpec(nftables.TableFamilyIPv4, 6, 80, "self_v4", "127.0.0.1")
	assertHasSpec(nftables.TableFamilyIPv6, 6, 443, setChalV6, "2001:db8::10")
	assertHasSpec(nftables.TableFamilyIPv6, 17, 443, "self_v6", "2001:db8::10")
	for _, spec := range specs {
		if spec.sourceSet == "" {
			t.Fatalf("unscoped DNAT spec would redirect unrelated external sources: %#v", spec)
		}
		if spec.family == nftables.TableFamilyIPv6 && spec.dport == 80 {
			t.Fatalf("IPv4-only loopback HTTP listener produced IPv6 DNAT spec: %#v", spec)
		}
		if spec.family == nftables.TableFamilyIPv4 && spec.dport == 443 {
			t.Fatalf("IPv6 dedicated HTTPS listener produced IPv4 DNAT spec: %#v", spec)
		}
	}
}

func TestDNATRuleExprsIncludeSourceLookupAndDestination(t *testing.T) {
	spec := dnatRuleSpec{family: nftables.TableFamilyIPv6, proto: 6, dport: 443, toPort: 9043, sourceSet: setChalV6, toAddr: net.ParseIP("::1")}
	exprs := dnatRuleExprs(spec)
	lookup, ok := exprs[1].(*expr.Lookup)
	if !ok || lookup.SetName != setChalV6 || lookup.SourceRegister != 1 || lookup.Invert {
		t.Fatalf("source lookup = %#v, want non-inverted @%s lookup from register 1", exprs[1], setChalV6)
	}
	var nat *expr.NAT
	for _, ex := range exprs {
		if n, ok := ex.(*expr.NAT); ok {
			nat = n
		}
	}
	if nat == nil || nat.Family != uint32(nftables.TableFamilyIPv6) || nat.RegAddrMin != 1 || nat.RegProtoMin != 2 {
		t.Fatalf("NAT expr = %#v, want IPv6 DNAT with address and port registers", nat)
	}
}

func TestDNATShowRuleLineOutput(t *testing.T) {
	tests := []struct {
		spec dnatRuleSpec
		want string
	}{
		{spec: dnatRuleSpec{family: nftables.TableFamilyIPv4, proto: 6, dport: 80, toPort: 9080, sourceSet: setChalV4, toAddr: net.ParseIP("127.0.0.1")}, want: "ip saddr @challenge_v4 tcp dport 80 dnat to 127.0.0.1:9080"},
		{spec: dnatRuleSpec{family: nftables.TableFamilyIPv4, proto: 6, dport: 443, toPort: 9043, sourceSet: "self_v4", toAddr: net.ParseIP("192.0.2.10")}, want: "ip saddr @self_v4 tcp dport 443 dnat to 192.0.2.10:9043"},
		{spec: dnatRuleSpec{family: nftables.TableFamilyIPv6, proto: 6, dport: 80, toPort: 9080, sourceSet: setChalV6, toAddr: net.ParseIP("::1")}, want: "ip6 saddr @challenge_v6 tcp dport 80 dnat to [::1]:9080"},
		{spec: dnatRuleSpec{family: nftables.TableFamilyIPv6, proto: 17, dport: 443, toPort: 9043, sourceSet: "self_v6", toAddr: net.ParseIP("2001:db8::10")}, want: "ip6 saddr @self_v6 udp dport 443 dnat to [2001:db8::10]:9043"},
		{spec: dnatRuleSpec{family: nftables.TableFamilyIPv4, proto: 6, dport: 80, toPort: 9080, sourceSet: setChalV4}, want: "ip saddr @challenge_v4 tcp dport 80 dnat to :9080"},
	}
	for _, tc := range tests {
		if got := dnatShowRuleLine(tc.spec); got != tc.want {
			t.Fatalf("dnatShowRuleLine() = %q, want %q", got, tc.want)
		}
	}
}

func TestDNATAcceptRuleExprUsesDNATMetadataAndTranslatedDestination(t *testing.T) {
	spec := dnatRuleSpec{family: nftables.TableFamilyIPv6, proto: 17, dport: 443, toPort: 9043, sourceSet: "self_v6", toAddr: net.ParseIP("2001:db8::10")}
	want := `add rule inet cfm input ct state new ct status dnat ct original proto-dst 443 ip6 daddr 2001:db8::10 udp dport 9043 accept comment "cfm_dnat_accept:web_https_ip6_udp:443:9043"`
	got := dnatAcceptRuleExpr(spec)
	if got != want {
		t.Fatalf("dnatAcceptRuleExpr() = %q, want %q", got, want)
	}
	if strings.Contains(got, " saddr @") {
		t.Fatalf("dnatAcceptRuleExpr() = %q, want no source-set membership requirement", got)
	}
}

func TestDNATAcceptRuleExprCanInsertBeforeDefaultDropHandle(t *testing.T) {
	spec := dnatRuleSpec{family: nftables.TableFamilyIPv4, proto: 6, dport: 80, toPort: 9080, sourceSet: setChalV4, toAddr: net.ParseIP("127.0.0.1")}
	chain := `table inet cfm {
		chain input {
			ct state new tcp dport 0-65535 drop # handle 31
			ct state new udp dport 0-65535 drop # handle 32
		}
	}`
	handle := firstInputDefaultDropHandle(chain)
	if handle != "31" {
		t.Fatalf("firstInputDefaultDropHandle() = %q, want 31", handle)
	}
	got := dnatAcceptRuleExpr(spec, handle)
	if !strings.HasPrefix(got, "insert rule inet cfm input position 31 ") {
		t.Fatalf("DNAT accept rule was not handle-inserted before default drops: %q", got)
	}
	if strings.HasPrefix(got, "add rule inet cfm input ") {
		t.Fatalf("DNAT accept rule used append syntax that can place it after default drops: %q", got)
	}
}
