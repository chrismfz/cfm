package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// OverlayAPIAuthToken returns the AUTH_TOKEN defined in the cfm.api.conf overlay
// located in cfgDir, or "" when the overlay file is absent, unreadable, or does
// not set AUTH_TOKEN.
//
// CFM stores AUTH_TOKEN in the cfm.api.conf overlay rather than the base
// cfm.conf; daemon and CLI config loading apply this overlay via
// cli.LoadConfigWithAPIOverride. Secret-derivation paths that re-read config
// from disk (plugin assertion key, embed cookie signing key) must mirror the
// same precedence, otherwise they derive keys from an empty token and reject
// otherwise-valid requests with secret_missing.
func OverlayAPIAuthToken(cfgDir string) string {
	if strings.TrimSpace(cfgDir) == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(cfgDir, "cfm.api.conf")) // #nosec G304 -- cfgDir resolved from trusted runtime config state
	if err != nil || len(b) == 0 {
		return ""
	}
	cfg, err := ParseCFMConf(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.API.AuthToken)
}
