package nft

import (
	"testing"

	"cfm/internal/config"
)

// The startup restore re-applies a changed NFT_DNAT_PRIORITY only when the
// priority came from an applied cfm.conf: before ApplyFloodRules (or when
// cfm.conf failed to parse) it is just the -99 / env fallback.
func TestConfiguredDNATPriorityReportsItsSource(t *testing.T) {
	t.Setenv("NFT_DNAT_PRIORITY", "")
	b := &Backend{}
	if p, ok := b.ConfiguredDNATPriority(); p != -99 || ok {
		t.Fatalf("no config: got (%d, %v), want (-99, false)", p, ok)
	}
	t.Setenv("NFT_DNAT_PRIORITY", "-120")
	if p, ok := b.ConfiguredDNATPriority(); p != -120 || ok {
		t.Fatalf("env only: got (%d, %v), want (-120, false)", p, ok)
	}
	b.cfg = &config.Config{}
	b.cfg.NFT.DNATPriority = -101
	if p, ok := b.ConfiguredDNATPriority(); p != -101 || !ok {
		t.Fatalf("cfm.conf -101: got (%d, %v), want (-101, true)", p, ok)
	}
	b.cfg.NFT.DNATPriority = -999
	if p, ok := b.ConfiguredDNATPriority(); p != -300 || !ok {
		t.Fatalf("out of range: got (%d, %v), want (-300, true)", p, ok)
	}
}
