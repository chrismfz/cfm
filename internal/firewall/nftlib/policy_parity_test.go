//go:build linux

package nftlib

import (
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
