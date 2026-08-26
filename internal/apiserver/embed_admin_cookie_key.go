package apiserver

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cfm/internal/logging"
)

// Signing key for the admin SSO cookie (cfm-embed-admin).
//
// Previously this key was HKDF-derived from AUTH_TOKEN. That made the cookie
// FORGEABLE from a cfm-web database leak: cfm-web holds every node's AUTH_TOKEN,
// so a leak let an attacker derive the (public-salt) HKDF key and mint a valid
// admin cookie, reaching full admin from any IP — bypassing the admin-token
// source-IP gate, which only covers the token branch.
//
// The key is now a RANDOM, per-node secret: generated on the node, persisted
// 0600 root-only, and NEVER derived from AUTH_TOKEN nor sent to cfm-web. A
// cfm-web DB leak therefore cannot forge an admin session cookie. Mirrors the
// loadOrCreateMCPToken / MFA-key persistence pattern.
//
// Rotation / recovery: delete the file and restart cfm. The key is cached in
// memory for the process, so a delete alone does not take effect until restart;
// a fresh key then invalidates open admin SSO sessions (a one-time re-login,
// bounded by the ~10-minute cookie TTL).
const embedAdminCookieKeyPath = "/var/lib/cfm/embed-admin-cookie.key"

// embedAdminCookieKeyLen is the HMAC-SHA256 signing-key length.
const embedAdminCookieKeyLen = 32

var (
	embedAdminCookieKeyOnce sync.Once
	embedAdminCookieKeyVal  []byte
	embedAdminCookieKeyErr  error
)

// loadOrCreateEmbedAdminCookieSigningKey returns the per-node signing key,
// loading (or creating) it once and caching it for the process. It is the
// default embedAdminCookieSigningKeyProvider.
func loadOrCreateEmbedAdminCookieSigningKey() ([]byte, error) {
	embedAdminCookieKeyOnce.Do(func() {
		embedAdminCookieKeyVal, embedAdminCookieKeyErr = loadOrCreateEmbedAdminCookieKeyFile(embedAdminCookieKeyPath)
	})
	return embedAdminCookieKeyVal, embedAdminCookieKeyErr
}

// loadOrCreateEmbedAdminCookieKeyFile reads the hex-encoded 32-byte key at path,
// or generates and persists a fresh one (0600 root-only) on first use / on a
// corrupt file. If persisting fails (e.g. read-only disk) it still returns the
// in-memory key so the process works; the next restart regenerates.
func loadOrCreateEmbedAdminCookieKeyFile(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("empty path")
	}
	// Reuse an existing key so cookies survive restarts.
	if raw, err := os.ReadFile(path); err == nil {
		if key, derr := hex.DecodeString(strings.TrimSpace(string(raw))); derr == nil && len(key) == embedAdminCookieKeyLen {
			return key, nil
		}
		// Corrupt / wrong-length file → fall through and regenerate.
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key := make([]byte, embedAdminCookieKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := writeEmbedAdminCookieKeyFile(path, key); err != nil {
		logging.LogfAPI("[apiserver] WARNING: could not persist embed-admin cookie key at %s: %v (using an ephemeral key this run; sessions won't survive restart)", path, err)
	}
	return key, nil
}

func writeEmbedAdminCookieKeyFile(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
