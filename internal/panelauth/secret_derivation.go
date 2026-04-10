package panelauth

import (
	"bytes"
	cfgpkg "cfm/internal/config"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	pluginAssertionHKDFInfo = "cfm-plugin-cpanel-assertion-v1"
	// Static app salt: stable across hosts so the same AUTH_TOKEN yields
	// identical derived assertion keys in clustered deployments.
	pluginAssertionHKDFSalt = "cfm-plugin-cpanel-assertion-salt-v1"
	cfmConfigStatePath      = "/run/cfm/config.path"
)

var errAuthTokenMissing = errors.New("auth_token_missing")

// DerivePluginAssertionKey derives the 32-byte HS256 signing key for cPanel
// plugin assertions from AUTH_TOKEN in cfm.conf via HKDF-SHA256.
func DerivePluginAssertionKey() ([]byte, error) {
	authToken, err := loadAuthTokenFromRuntimeConfig()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(authToken) == "" {
		return nil, errAuthTokenMissing
	}

	key, err := hkdf.Key(sha256.New, []byte(authToken), []byte(pluginAssertionHKDFSalt), pluginAssertionHKDFInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive_plugin_assertion_key: %w", err)
	}
	return key, nil
}

func loadAuthTokenFromRuntimeConfig() (string, error) {
	cfgPath, err := resolveRuntimeCFMConfPath()
	if err != nil {
		return "", err
	}
	cfg, err := loadConfigFromPath(cfgPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(cfg.API.AuthToken), nil
}

func loadConfigFromPath(cfgPath string) (*cfgpkg.Config, error) {
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("auth_token_unavailable: %w", err)
	}
	cfg, err := cfgpkg.ParseCFMConf(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("auth_token_parse_error: %w", err)
	}
	return cfg, nil
}

func resolveRuntimeCFMConfPath() (string, error) {
	if envDir := strings.TrimSpace(os.Getenv("CFM_CONFIG_DIR")); envDir != "" {
		path := filepath.Join(envDir, "cfm.conf")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	if b, err := os.ReadFile(cfmConfigStatePath); err == nil {
		if dir := strings.TrimSpace(string(b)); dir != "" {
			path := filepath.Join(dir, "cfm.conf")
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
	}

	const fallbackPath = "/etc/cfm/cfm.conf"
	if _, err := os.Stat(fallbackPath); err == nil {
		return fallbackPath, nil
	}

	return "", errors.New("auth_token_config_not_found")
}
