package nflog

import (
	"math"
	"testing"

	"cfm/internal/config"
)

func TestFromConfig_ClampsInvalidNFLOGGroupToZero(t *testing.T) {
	tests := []struct {
		name  string
		group int
	}{
		{name: "negative", group: -1},
		{name: "above uint16 max", group: int(math.MaxUint16) + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.SMTPBlockConfig{LogNFLOG: tt.group, LogEnrich: true}
			sc := FromConfig(cfg)

			if sc.Group != 0 {
				t.Fatalf("Group=%d, want 0 for LogNFLOG=%d", sc.Group, tt.group)
			}
			if !sc.Enrich {
				t.Fatalf("Enrich=%v, want true", sc.Enrich)
			}
		})
	}
}

func TestFromConfig_PreservesValidNFLOGGroup(t *testing.T) {
	cfg := &config.SMTPBlockConfig{LogNFLOG: int(math.MaxUint16), LogEnrich: false}
	sc := FromConfig(cfg)

	if sc.Group != math.MaxUint16 {
		t.Fatalf("Group=%d, want %d", sc.Group, uint16(math.MaxUint16))
	}
	if sc.Enrich {
		t.Fatalf("Enrich=%v, want false", sc.Enrich)
	}
}
