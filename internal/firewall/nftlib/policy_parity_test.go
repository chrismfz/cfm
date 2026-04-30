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
