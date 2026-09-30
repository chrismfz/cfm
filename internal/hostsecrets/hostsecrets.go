// Package hostsecrets keeps CFM's per-host generated secrets out of the
// packaged conffiles.
//
// [webdetector] CHALLENGE_TOKEN (the browser-challenge HMAC key) and
// OPENRESTY_TOKEN (the edge↔daemon socket bearer) used to be generated INTO
// /etc/cfm/detectors.conf. That made the conffile "modified" on every node,
// so no upgrade could update it: every release left a .rpmnew / .dpkg-dist
// beside it and new stock knobs never arrived. They now live one file each
// under Dir, generated once per host and never shared across the fleet.
//
// A strong value still set in detectors.conf wins and is copied into the
// store. Emptying the line afterwards keeps the same secret, so no visitor's
// challenge cookie is invalidated by the migration.
package hostsecrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cfm/internal/sslcollector"
)

// Dir holds one file per secret, root-only (dir 0700, files 0600). A var so
// tests can point it at a temp dir: a test must never write the live path
// (CLAUDE.md §5).
var Dir = "/var/lib/cfm/secrets"

// The secrets this package manages, named after their legacy detectors.conf
// keys ([webdetector] section).
const (
	ChallengeToken = "CHALLENGE_TOKEN"
	BridgeToken    = "OPENRESTY_TOKEN"
)

// Sources Resolve reports.
const (
	SourceConf      = "detectors.conf"
	SourceStore     = "store"
	SourceGenerated = "generated"
)

// Path is the store file for key: Dir/<lowercased key>.
func Path(key string) string {
	return filepath.Join(Dir, strings.ToLower(key))
}

// Read returns the stored value for key, trimmed. ok is false when the file
// is absent, unreadable or empty. It does not judge strength.
func Read(key string) (string, bool) {
	b, err := os.ReadFile(Path(key)) // #nosec G304 -- fixed daemon-internal path
	if err != nil {
		return "", false
	}
	v := strings.TrimSpace(string(b))
	return v, v != ""
}

// Effective is the value the daemon runs with for key, for read-only probes
// (cfm status, cfm health): a strong legacy detectors.conf value, else the
// stored value, else the legacy value as given (so a probe can still report
// a weak one). It never generates or writes.
func Effective(key, legacy string) string {
	legacy = strings.TrimSpace(legacy)
	if sslcollector.IsStrongToken(legacy) {
		return legacy
	}
	if v, ok := Read(key); ok {
		return v
	}
	return legacy
}

// Resolve returns the secret the daemon runs with for key, and where it came
// from:
//
//  1. SourceConf: legacy, a strong value still set in detectors.conf. It is
//     copied into the store (when the store differs), so emptying the line
//     later keeps the same secret.
//  2. SourceStore: the stored value, when strong.
//  3. SourceGenerated: a new random 48-hex value, stored.
//
// A weak legacy value (a placeholder, too short, not Lua-safe) is ignored, as
// is a weak stored one. The secret is always returned. A non-nil error means
// storing it failed: the daemon still runs with it, but a restart that finds
// no strong value generates another one.
func Resolve(key, legacy string) (secret, source string, err error) {
	legacy = strings.TrimSpace(legacy)
	if sslcollector.IsStrongToken(legacy) {
		if cur, ok := Read(key); !ok || cur != legacy {
			err = write(key, legacy)
		} else {
			tighten(key)
		}
		return legacy, SourceConf, err
	}
	if cur, ok := Read(key); ok && sslcollector.IsStrongToken(cur) {
		tighten(key)
		return cur, SourceStore, nil
	}
	gen, gerr := sslcollector.GenerateToken()
	if gerr != nil {
		return "", "", gerr
	}
	return gen, SourceGenerated, write(key, gen)
}

// tighten re-applies the store's modes (dir 0700, file 0600) when an existing
// store is only read: one restored from a backup or copied with a default
// umask would otherwise stay readable to every local user, who could then
// forge challenge cookies or call the bridge socket API. Best effort: a
// failure here does not stop the daemon using the secret.
func tighten(key string) {
	for path, want := range map[string]os.FileMode{Dir: 0o700, Path(key): 0o600} {
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink == 0 && fi.Mode().Perm()&^want != 0 {
			_ = os.Chmod(path, want)
		}
	}
}

// write stores value atomically: a temp file in Dir (0600), then rename.
func write(key, value string) error {
	if err := os.MkdirAll(Dir, 0o700); err != nil {
		return fmt.Errorf("hostsecrets: mkdir %s: %w", Dir, err)
	}
	// MkdirAll leaves an existing dir's mode alone; tighten it.
	if err := os.Chmod(Dir, 0o700); err != nil {
		return fmt.Errorf("hostsecrets: chmod %s: %w", Dir, err)
	}
	f, err := os.CreateTemp(Dir, "."+strings.ToLower(key)+".tmp-*")
	if err != nil {
		return fmt.Errorf("hostsecrets: temp file: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("hostsecrets: chmod temp: %w", err)
	}
	if _, err := f.WriteString(value + "\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("hostsecrets: write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("hostsecrets: sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("hostsecrets: close temp: %w", err)
	}
	if err := os.Rename(tmp, Path(key)); err != nil {
		return fmt.Errorf("hostsecrets: rename into %s: %w", Path(key), err)
	}
	return nil
}
