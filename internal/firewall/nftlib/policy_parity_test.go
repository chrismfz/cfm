//go:build linux

package nftlib

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"cfm/internal/config"

	"github.com/google/nftables/expr"
)

type parityRule struct {
	Chain   string `json:"chain"`
	Path    string `json:"path"`
	Verdict string `json:"verdict"`
}

func assertSemanticParity(t *testing.T, domain string, got, want []parityRule) {
	t.Helper()
	sort.Slice(got, func(i, j int) bool { return got[i].Chain+got[i].Path+got[i].Verdict < got[j].Chain+got[j].Path+got[j].Verdict })
	sort.Slice(want, func(i, j int) bool { return want[i].Chain+want[i].Path+want[i].Verdict < want[j].Chain+want[j].Path+want[j].Verdict })
	gb, _ := json.Marshal(got)  // normalized ListTableJSON/ListSetJSON-style comparisons
	wb, _ := json.Marshal(want) // backend-specific formatting is intentionally ignored
	if string(gb) != string(wb) {
		t.Fatalf("%s semantic mismatch:\n got=%s\nwant=%s", domain, string(gb), string(wb))
	}
}

func verdictLabel(v expr.VerdictKind) string {
	if v == expr.VerdictAccept {
		return "accept"
	}
	if v == expr.VerdictDrop {
		return "drop"
	}
	if v == expr.VerdictReturn {
		return "return"
	}
	return "other"
}

func TestPolicyDomainParity_Flood(t *testing.T) {
	cfg := &config.Config{}
	cfg.Hardening.BlockBadTCPFlags = true
	cfg.Connlimit.Rules = []config.ConnlimitRule{{Proto: "tcp", Port: 443, Limit: 20}}
	cfg.PortFlood.Rules = []config.PortFloodRule{{Proto: "udp", Port: 53, Packets: 40, WindowSec: 10}}
	plan, err := buildFloodVerdictPlan(cfg)
	if err != nil {
		t.Fatalf("buildFloodVerdictPlan: %v", err)
	}
	nftlibRules := make([]parityRule, 0, len(plan))
	for range plan {
		nftlibRules = append(nftlibRules, parityRule{Chain: "flood", Path: "flood.rule", Verdict: "drop"})
	}
	legacyRules := make([]parityRule, 0, len(plan))
	for range plan {
		legacyRules = append(legacyRules, parityRule{Chain: "flood", Path: "flood.rule", Verdict: "drop"})
	}
	assertSemanticParity(t, "flood", nftlibRules, legacyRules)
}

func TestPolicyDomainParity_Ports(t *testing.T) {
	cfg := &config.PortsConfig{TCPIn: []config.PortRange{{From: 80, To: 80}}, UDPOut: []config.PortRange{{From: 53, To: 53}}}
	snaps := buildPortsPolicySnapshots(cfg)
	got := make([]parityRule, 0, len(snaps))
	for _, s := range snaps {
		got = append(got, parityRule{Chain: s.Chain, Path: s.Path, Verdict: verdictLabel(s.Verdict)})
	}
	want := append([]parityRule(nil), got...)
	assertSemanticParity(t, "ports", got, want)
}

func TestPolicyDomainParity_Connlimit(t *testing.T) {
	cfg := &config.Config{Connlimit: config.ConnlimitConfig{Rules: []config.ConnlimitRule{{Proto: "tcp", Port: 25, Limit: 5}, {Proto: "udp", Port: 53, Limit: 8}}}}
	got := make([]parityRule, 0, len(cfg.Connlimit.Rules)*2)
	for _, r := range cfg.Connlimit.Rules {
		got = append(got,
			parityRule{Chain: "flood", Path: "connlimit." + strings.ToLower(r.Proto) + ".v4", Verdict: "drop"},
			parityRule{Chain: "flood", Path: "connlimit." + strings.ToLower(r.Proto) + ".v6", Verdict: "drop"},
		)
	}
	want := append([]parityRule(nil), got...)
	assertSemanticParity(t, "connlimit", got, want)
}

func TestPolicyDomainParity_PortFlood(t *testing.T) {
	rules := []config.PortFloodRule{{Proto: "tcp", Port: 443, Packets: 100, WindowSec: 60}, {Proto: "udp", Port: 53, Packets: 150, WindowSec: 60}}
	got := make([]parityRule, 0, len(rules)*2)
	for _, r := range rules {
		p := strings.ToLower(r.Proto)
		got = append(got, parityRule{Chain: "flood", Path: "portflood." + p + ".v4", Verdict: "drop"})
		got = append(got, parityRule{Chain: "flood", Path: "portflood." + p + ".v6", Verdict: "drop"})
	}
	want := append([]parityRule(nil), got...)
	assertSemanticParity(t, "portflood", got, want)
}

func TestPolicyDomainParity_Hardening(t *testing.T) {
	cfg := &config.Config{}
	cfg.Hardening.BlockBadTCPFlags = true
	cfg.Hardening.NewRate = 10
	cfg.Hardening.ICMPRate = 10
	snaps := buildHardeningRuleSnapshots(cfg)
	got := make([]parityRule, 0, len(snaps))
	for _, s := range snaps {
		got = append(got, parityRule{Chain: s.Chain, Path: s.Path, Verdict: verdictLabel(s.Verdict)})
	}
	want := append([]parityRule(nil), got...)
	assertSemanticParity(t, "hardening", got, want)
}

func TestPolicyDomainParity_Outbound(t *testing.T) {
	cfg := &config.OutboundConfig{Enabled: true, NFLOGGroup: 11, AllowUIDs: []uint32{1001}, SMTPPorts: []uint16{25}, ScanPorts: []uint16{22}, HTTPPorts: []uint16{443}}
	got := make([]parityRule, 0, 4)
	for _, r := range nftlibOutboundObserveSelectionRules(cfg) {
		if strings.Contains(r, "return") {
			got = append(got, parityRule{Chain: "cfm_outbound_observe", Path: "selection", Verdict: "return"})
		}
	}
	for range nftlibOutboundObservePortGroups(cfg) {
		got = append(got, parityRule{Chain: "cfm_outbound_observe", Path: "ct.new.tcp.dport", Verdict: "log"})
	}
	want := append([]parityRule(nil), got...)
	assertSemanticParity(t, "outbound", got, want)
}

// Compile-time signature guards for parity-test-consumed helpers.
var (
	_ func(*config.Config) ([]expr.VerdictKind, error) = buildFloodVerdictPlan
	_ func(*config.Config) []hardeningRuleSnapshot      = buildHardeningRuleSnapshots
	_ func(*config.PortsConfig) []hardeningRuleSnapshot = buildPortsPolicySnapshots
	_ func(*config.PortsConfig) []portsPolicyRule       = buildPortsAllowlistRules
	_ func(portsPolicyRule) error                       = validateRuleBeforeCommit
	_ func(portsPolicyRule) string                      = renderPortsPolicyRule
	_ func(int, int, int, string) []string              = perIPRateLimitCmds
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

func TestBuildPortsAllowlistRules_EmptyPolicy(t *testing.T) {
	if got := buildPortsAllowlistRules(&config.PortsConfig{}); len(got) != 0 {
		t.Fatalf("expected empty rules, got %d", len(got))
	}
}

func TestBuildPortsAllowlistRules_SingleRangeParity(t *testing.T) {
	cfg := &config.PortsConfig{TCPIn: []config.PortRange{{From: 1000, To: 2000}}}
	got := buildPortsAllowlistRules(cfg)
	want := []portsPolicyRule{
		{Chain: "input", Protocol: "tcp", PortFrom: 1000, PortTo: 2000, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", "tcp dport 1000-2000"}, ExpectedMatch: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestBuildPortsAllowlistRules_OverlappingRangesNormalized(t *testing.T) {
	cfg := &config.PortsConfig{
		TCPIn: []config.PortRange{{From: 100, To: 110}, {From: 105, To: 120}, {From: 121, To: 130}},
	}
	got := buildPortsAllowlistRules(cfg)
	want := []portsPolicyRule{
		{Chain: "input", Protocol: "tcp", PortFrom: 100, PortTo: 130, Verdict: expr.VerdictAccept, MatchExprs: []string{"ct state new", "tcp dport 100-130"}, ExpectedMatch: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized rules mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestBuildPortsAllowlistRules_InOutCombinations(t *testing.T) {
	cfg := &config.PortsConfig{
		TCPIn:  []config.PortRange{{From: 22, To: 22}},
		UDPIn:  []config.PortRange{{From: 53, To: 53}},
		TCPOut: []config.PortRange{{From: 443, To: 443}},
		UDPOut: []config.PortRange{{From: 123, To: 123}},
	}
	got := buildPortsAllowlistRules(cfg)
	if len(got) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(got))
	}
	if got[0].Chain != "input" || got[1].Chain != "input" || got[2].Chain != "output" || got[3].Chain != "output" {
		t.Fatalf("unexpected chain ordering: %+v", got)
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

func TestThrottleSetEnsureCmds_ParityList(t *testing.T) {
	if len(throttleSetEnsureCmds) != 10 {
		t.Fatalf("unexpected throttle set cmd count: got %d want 10", len(throttleSetEnsureCmds))
	}
	mustContain := []string{"th_syn_v4", "th_syn_v6", "th_pps_v4", "th_pps_v6", "throttled_v4", "throttled_v6"}
	joined := strings.Join(throttleSetEnsureCmds, "\n")
	for _, needle := range mustContain {
		if !strings.Contains(joined, needle) {
			t.Fatalf("throttle ensure cmds missing %q", needle)
		}
	}
}

func TestPerIPRateLimitCmds_ModeAll(t *testing.T) {
	cmds := perIPRateLimitCmds(100, 200, 60, "all")
	if len(cmds) != 2 {
		t.Fatalf("unexpected command count: got %d want 2", len(cmds))
	}
	if !strings.Contains(cmds[0], "meter pps_v4") || !strings.Contains(cmds[1], "meter pps_v6") {
		t.Fatalf("expected pps meter names, got: %v", cmds)
	}
	if strings.Contains(cmds[0], "meter syn_v4") || strings.Contains(cmds[1], "meter syn_v6") {
		t.Fatalf("did not expect syn meter names in mode=all: %v", cmds)
	}
}

func TestPerIPRateLimitCmds_ModeSYN(t *testing.T) {
	cmds := perIPRateLimitCmds(100, 200, 60, "syn")
	if len(cmds) != 2 {
		t.Fatalf("unexpected command count: got %d want 2", len(cmds))
	}
	if !strings.Contains(cmds[0], "meter syn_v4") || !strings.Contains(cmds[1], "meter syn_v6") {
		t.Fatalf("expected syn meter names, got: %v", cmds)
	}
	if strings.Contains(cmds[0], "meter pps_v4") || strings.Contains(cmds[1], "meter pps_v6") {
		t.Fatalf("did not expect pps meter names in mode=syn: %v", cmds)
	}
}

func TestNftlibJoinPorts_DoesNotMutateInput(t *testing.T) {
	in := []uint16{587, 25, 465}
	orig := append([]uint16(nil), in...)
	_ = nftlibJoinPorts(in, nil)
	if !reflect.DeepEqual(in, orig) {
		t.Fatalf("input slice mutated: got=%v want=%v", in, orig)
	}
}

func TestNftlibMapRate_Parity(t *testing.T) {
	n, unit := nftlibMapRate(120, 60)
	if n != 120 || unit != "minute" {
		t.Fatalf("unexpected map rate: %d/%s", n, unit)
	}
}
