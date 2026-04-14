package apiserver

import (
	"strings"
	"testing"

	cfgpkg "cfm/internal/config"
)

func TestValidateStartupConfig_EnabledServerRequiresAuthToken(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.Debug.Port = 6060
	cfg.API.AuthToken = ""

	err := validateStartupConfig(cfg)
	if err == nil {
		t.Fatalf("expected startup validation error for empty AUTH_TOKEN")
	}
	if !strings.Contains(err.Error(), "AUTH_TOKEN") {
		t.Fatalf("expected AUTH_TOKEN in error, got: %v", err)
	}
}

func TestValidateStartupConfig_DisabledServerDoesNotRequireAuthToken(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.Debug.Port = 0
	cfg.Debug.TLSPort = 0
	cfg.API.AuthToken = ""

	if err := validateStartupConfig(cfg); err != nil {
		t.Fatalf("expected no validation error for disabled API server, got: %v", err)
	}
}
