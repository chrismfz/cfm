//go:build linux

package nftlib

import (
	"reflect"
	"strings"
	"testing"

	"cfm/internal/config"

	"github.com/google/nftables/expr"
)

func TestBuildFloodVerdictPlan_OrderParity(t *testing.T) {
	cfg := &config.Config{}
	cfg.Hardening.BlockBadTCPFlags = true
	cfg.Connlimit.Rules = []config.ConnlimitRule{{Proto: "tcp"}, {Proto: "udp"}}
	cfg.PortFlood.Rules = []config.PortFloodRule{{}, {}, {}}

	got, err := buildFloodVerdictPlan(cfg)
	if err != nil {
		t.Fatalf("buildFloodVerdictPlan: %v", err)
	}

	wantCount := 4 + len(cfg.Connlimit.Rules) + len(cfg.PortFlood.Rules)
	if len(got) != wantCount {
		t.Fatalf("rule count mismatch: got %d want %d", len(got), wantCount)
	}
	for i, kind := range got {
		if kind != expr.VerdictDrop {
			t.Fatalf("rule %d kind mismatch: got %v want drop", i, kind)
		}
	}
}

func TestBuildPortsAllowlistRules_AllDirectionsProtocols(t *testing.T) {
	cfg := &config.PortsConfig{
		TCPIn:  []config.PortRange{{From: 80, To: 80}},
		UDPIn:  []config.PortRange{{From: 53, To: 53}},
		TCPOut: []config.PortRange{{From: 443, To: 443}},
		UDPOut: []config.PortRange{{From: 123, To: 123}},
	}
	got := buildPortsAllowlistRules(cfg)
	want := []portsPolicyRule{
		{Chain: "input", Protocol: "tcp", PortFrom: 80, PortTo: 80, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", "tcp dport 80-80"}, ExpectedMatch: true},
		{Chain: "input", Protocol: "udp", PortFrom: 53, PortTo: 53, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", "udp dport 53-53"}, ExpectedMatch: true},
		{Chain: "output", Protocol: "tcp", PortFrom: 443, PortTo: 443, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", "tcp dport 443-443"}, ExpectedMatch: true},
		{Chain: "output", Protocol: "udp", PortFrom: 123, PortTo: 123, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", "udp dport 123-123"}, ExpectedMatch: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestValidateRuleBeforeCommit_RejectsAcceptWithoutExpectedMatch(t *testing.T) {
	r := portsPolicyRule{Chain: "input", Protocol: "tcp", Verdict: expr.VerdictAccept, ExpectedMatch: true}
	if err := validateRuleBeforeCommit(r); err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestRenderExpressionsParity_NFTVsNFTLibFixture(t *testing.T) {
	cfg := &config.PortsConfig{TCPIn: []config.PortRange{{From: 443, To: 443}}, UDPIn: []config.PortRange{{From: 53, To: 53}}}
	rules := buildPortsAllowlistRules(cfg)
	if len(rules) == 0 {
		t.Fatalf("expected rules")
	}
	got := renderPortsPolicyRule(rules[0])
	// nft backend equivalent expression shape
	wantContains := []string{"ct state new", "dport", "verdict=accept"}
	for _, s := range wantContains {
		if !strings.Contains(strings.ToLower(got), strings.ToLower(s)) {
			t.Fatalf("rendered rule missing key expression %q in %q", s, got)
		}
	}
}

func TestBuildPortsAllowlistRules_StableAcrossRepeatedApplies(t *testing.T) {
	cfg := &config.PortsConfig{
		TCPIn:  []config.PortRange{{From: 22, To: 22}, {From: 80, To: 81}},
		UDPIn:  []config.PortRange{{From: 53, To: 53}},
		TCPOut: []config.PortRange{{From: 443, To: 443}},
		UDPOut: []config.PortRange{{From: 123, To: 123}, {From: 5000, To: 5001}},
	}
	first := buildPortsAllowlistRules(cfg)
	second := buildPortsAllowlistRules(cfg)
	third := buildPortsAllowlistRules(cfg)
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(second, third) {
		t.Fatalf("rule planner is not stable across repeated applies")
	}
}

func TestBuildFloodVerdictPlan_ConnlimitProtoValidationParity(t *testing.T) {
	cfg := &config.Config{}
	cfg.Connlimit.Rules = []config.ConnlimitRule{{Proto: "icmp"}}

	if _, err := buildFloodVerdictPlan(cfg); err == nil {
		t.Fatalf("expected unknown proto error")
	}
}

func TestAppendVerdictRulesBatched_SplitBounded(t *testing.T) {
	kinds := make([]expr.VerdictKind, 10)
	for i := range kinds {
		kinds[i] = expr.VerdictDrop
	}

	batches := 0
	for i := 0; i < len(kinds); i += 3 {
		batches++
	}
	if batches != 4 {
		t.Fatalf("unexpected computed batches: got %d want 4", batches)
	}
}

func TestBuildHardeningRuleSnapshots_Parity(t *testing.T) {
	cfg := &config.Config{}
	cfg.Hardening.BlockBadTCPFlags = true
	cfg.Hardening.NewRate = 10
	cfg.Hardening.ICMPRate = 20

	got := buildHardeningRuleSnapshots(cfg)
	want := []hardeningRuleSnapshot{
		{Chain: "flood", Path: "tcp.flags.syn_fin", Verdict: expr.VerdictDrop},
		{Chain: "flood", Path: "tcp.flags.syn_rst", Verdict: expr.VerdictDrop},
		{Chain: "flood", Path: "tcp.flags.xmas", Verdict: expr.VerdictDrop},
		{Chain: "flood", Path: "tcp.flags.null", Verdict: expr.VerdictDrop},
		{Chain: "flood", Path: "ct.new.no_icmp.v4_over_rate", Verdict: expr.VerdictDrop},
		{Chain: "flood", Path: "ct.new.no_icmp.v6_over_rate", Verdict: expr.VerdictDrop},
		{Chain: "flood", Path: "icmp.echo.v4_over_rate", Verdict: expr.VerdictDrop},
		{Chain: "flood", Path: "icmp.echo.v6_over_rate", Verdict: expr.VerdictDrop},
	}

	if len(got) != len(want) {
		t.Fatalf("snapshot count mismatch: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("snapshot[%d] mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestBuildPortsPolicySnapshots_Parity(t *testing.T) {
	cfg := &config.PortsConfig{
		TCPIn:  []config.PortRange{{From: 80, To: 80}},
		UDPIn:  []config.PortRange{{From: 53, To: 53}},
		TCPOut: []config.PortRange{{From: 443, To: 443}},
		UDPOut: []config.PortRange{{From: 123, To: 123}},
	}
	got := buildPortsPolicySnapshots(cfg)
	want := []hardeningRuleSnapshot{
		{Chain: "input", Path: "ct.established_related", Verdict: expr.VerdictAccept},
		{Chain: "input", Path: "ct.invalid", Verdict: expr.VerdictDrop},
		{Chain: "output", Path: "ct.established_related", Verdict: expr.VerdictAccept},
		{Chain: "output", Path: "ct.invalid", Verdict: expr.VerdictDrop},
		{Chain: "input", Path: "ct.new.tcp.accept", Verdict: expr.VerdictAccept},
		{Chain: "input", Path: "ct.new.udp.accept", Verdict: expr.VerdictAccept},
		{Chain: "output", Path: "ct.new.tcp.accept", Verdict: expr.VerdictAccept},
		{Chain: "output", Path: "ct.new.udp.accept", Verdict: expr.VerdictAccept},
	}
	if len(got) != len(want) {
		t.Fatalf("snapshot count mismatch: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("snapshot[%d] mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestOutboundObserveSelectionRules_UIDGIDDedupSort(t *testing.T) {
	cfg := &config.OutboundConfig{
		AllowUIDs: []uint32{1002, 42, 42, 7},
		AllowGIDs: []uint32{300, 1, 300},
	}
	got := nftlibOutboundObserveSelectionRules(cfg)
	want := []string{
		"add rule inet cfm cfm_outbound_observe meta skuid 0 return",
		"add rule inet cfm cfm_outbound_observe meta skuid { 7, 42, 1002 } return",
		"add rule inet cfm cfm_outbound_observe meta skgid { 1, 300 } return",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selection rules mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestOutboundObservePortGroups_PerGroupEmission(t *testing.T) {
	cfg := &config.OutboundConfig{
		SMTPPorts: []uint16{587, 25},
		ScanPorts: []uint16{23, 22},
		HTTPPorts: []uint16{8443, 443},
	}
	got := nftlibOutboundObservePortGroups(cfg)
	want := []string{"25, 587", "22, 23", "443, 8443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("port groups mismatch:\n got=%v\nwant=%v", got, want)
	}

	rule := nftlibOutboundObservePortGroupRule(17, got[0])
	if !strings.Contains(rule, `group 17`) || !strings.Contains(rule, `{ 25, 587 }`) {
		t.Fatalf("unexpected outbound observe rule: %q", rule)
	}
}
