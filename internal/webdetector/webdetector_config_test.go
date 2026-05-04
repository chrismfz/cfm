package webdetector

import (
	"testing"
	"time"
)

func TestConfigApplyDefaults_OpenRestyOkIPTTL_ClampsNegativeToZero(t *testing.T) {
	cfg := Config{OpenRestyOkIPTTL: -5 * time.Second}
	cfg.FillDefaults()
	if cfg.OpenRestyOkIPTTL != 0 {
		t.Fatalf("OpenRestyOkIPTTL=%v, want 0", cfg.OpenRestyOkIPTTL)
	}
}

func TestConfigApplyDefaults_OpenRestyOkIPTTL_KeepsExplicitZero(t *testing.T) {
	cfg := Config{OpenRestyOkIPTTL: 0}
	cfg.FillDefaults()
	if cfg.OpenRestyOkIPTTL != 0 {
		t.Fatalf("OpenRestyOkIPTTL=%v, want 0", cfg.OpenRestyOkIPTTL)
	}
}
