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
// A usable value still set in detectors.conf wins and is copied into the
// store. Setting the line back to a placeholder afterwards keeps the same
// secret, so no visitor's challenge cookie is invalidated by the migration.
// The package snapshots detectors.conf into Dir before it can replace the
// conffile (PreUpgradePath; the token-seed block of the Debian preinst and the
// RPM pre scriptlet), and the daemon reads the tokens from that snapshot with
// the real parser.
package hostsecrets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"cfm/internal/detconf"
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
	// SourceRunning: the store could not be read, so the process keeps the
	// value it already runs rather than generating a new one.
	SourceRunning = "running"
)

// ErrStoreUnreadable wraps a store read error other than "absent". Resolve
// then never writes the store: it may hold a good secret.
var ErrStoreUnreadable = errors.New("hostsecrets: store unreadable")

// Path is the store file for key: Dir/<lowercased key>.
func Path(key string) string {
	return filepath.Join(Dir, strings.ToLower(key))
}

// PreUpgradePath is the copy of /etc/cfm/detectors.conf the package's
// pre-install scriptlet takes before it can replace the conffile. The daemon
// reads the tokens from it once (the detectors manager), then removes it.
func PreUpgradePath() string {
	return filepath.Join(Dir, "detectors.conf.pre-upgrade")
}

// readStore returns the stored value for key, trimmed; "" with a nil error
// when the file is absent or empty, a non-nil error for anything else (EACCES,
// EIO, EMFILE, a directory in its place).
func readStore(key string) (string, error) {
	b, err := os.ReadFile(Path(key)) // #nosec G304 -- fixed daemon-internal path
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Read returns the stored value for key, trimmed. ok is false when the file
// is absent, unreadable or empty. It does not judge strength.
func Read(key string) (string, bool) {
	v, err := readStore(key)
	return v, err == nil && v != ""
}

// Usable reports whether v can be a token: strong (sslcollector.IsStrongToken)
// and unchanged by the detectors.conf value cleaner (detconf.CleanValue:
// inline comments, surrounding quotes). The daemon re-reads the resolved
// value through that cleaner, so a value it would change would run as a
// DIFFERENT secret than the one mirrored to the edge (cfm_bridge_token.lua),
// or as none at all. Every value the old binary could run end to end passes.
func Usable(v string) bool {
	return sslcollector.IsStrongToken(v) && detconf.CleanValue(v) == v
}

var (
	// unstored holds, per key, a token this process generated but could not
	// store. Without it an unwritable store would yield a new token on every
	// Resolve, i.e. on every reload (each config save, each tailed-log
	// rotation), invalidating every challenge cookie each time. It is dropped
	// once a value is stored, so it can never bring back a replaced token.
	unstored sync.Map
	// running holds, per key, the value Resolve last returned: what this
	// process runs while the store cannot be read.
	running sync.Map
)

// choose is the one precedence rule, shared by Resolve and Effective so the
// probes can never drift from the daemon: a usable legacy detectors.conf
// value, else a usable stored value, else (store unreadable) the value this
// process already runs, else a token this process generated but could not
// store. ok is false when none applies.
func choose(key, legacy, cur string, readErr error) (value, source string, ok bool) {
	if Usable(legacy) {
		return legacy, SourceConf, true
	}
	if readErr == nil && Usable(cur) {
		return cur, SourceStore, true
	}
	if readErr != nil {
		if v, found := running.Load(key); found {
			return v.(string), SourceRunning, true
		}
	}
	if v, found := unstored.Load(key); found {
		return v.(string), SourceGenerated, true
	}
	return "", "", false
}

// Effective is the value the daemon runs with for key, for read-only probes
// (cfm health), by the same precedence as Resolve. When nothing usable
// applies it returns the legacy value as given (possibly weak or empty), so a
// probe reports weak/missing. It never generates or writes.
func Effective(key, legacy string) string {
	legacy = strings.TrimSpace(legacy)
	cur, readErr := readStore(key)
	if v, _, ok := choose(key, legacy, cur, readErr); ok {
		return v
	}
	return legacy
}

// Resolve returns the secret the daemon runs with for key, and where it came
// from:
//
//  1. SourceConf: legacy, a usable value still set in detectors.conf (or in
//     the package's pre-upgrade snapshot of it). It is copied into the store
//     (when the store differs), so setting the line back to a placeholder
//     later keeps the same secret.
//  2. SourceStore: the stored value, when usable.
//  3. SourceRunning: the store cannot be read (ErrStoreUnreadable); the value
//     this process already runs is kept and the store is left alone.
//  4. SourceGenerated: a new random 48-hex value, stored. Until it is stored
//     it is kept for the rest of this process.
//
// A weak legacy value (a placeholder, too short, not Lua-safe, see Usable) is
// ignored, as is a weak stored one, which is replaced. The secret is always
// returned. A non-nil error means it was not stored: the daemon keeps running
// with it and retries on each reload.
func Resolve(key, legacy string) (secret, source string, err error) {
	legacy = strings.TrimSpace(legacy)
	cur, readErr := readStore(key)
	value, source, ok := choose(key, legacy, cur, readErr)
	if !ok {
		gen, gerr := sslcollector.GenerateToken()
		if gerr != nil {
			return "", "", gerr
		}
		actual, _ := unstored.LoadOrStore(key, gen)
		value, source = actual.(string), SourceGenerated
	}
	switch {
	case readErr != nil && source != SourceConf:
		// Never overwrite a store that may hold a good secret; a later
		// reload reads it again.
		err = fmt.Errorf("%w: %s: %v", ErrStoreUnreadable, Path(key), readErr)
	case readErr != nil || cur != value:
		err = write(key, value)
	default:
		tighten(key)
	}
	if err == nil {
		unstored.Delete(key)
	}
	running.Store(key, value)
	return value, source, err
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

// ensureDir creates Dir (0700). Its parent, /var/lib/cfm, is created 0755 if
// missing, never 0700: the edge workers (user cfm) must reach
// /var/lib/cfm/lua through it.
func ensureDir() error {
	if err := os.MkdirAll(filepath.Dir(Dir), 0o755); err != nil {
		return fmt.Errorf("hostsecrets: mkdir %s: %w", filepath.Dir(Dir), err)
	}
	if err := os.Mkdir(Dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("hostsecrets: mkdir %s: %w", Dir, err)
	}
	return nil
}

// RemovePreUpgrade removes the package's pre-upgrade snapshot once the
// daemon has taken the tokens from it. Absent is not an error.
func RemovePreUpgrade() error {
	if err := os.Remove(PreUpgradePath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// KeepPreUpgrade rewrites the pre-upgrade snapshot down to the tokens in vals
// (key → value, each Usable) that could not be stored yet, so a token already
// taken over can never be taken from it again, e.g. after a rotation. With
// vals empty it removes the snapshot.
func KeepPreUpgrade(vals map[string]string) error {
	if len(vals) == 0 {
		return RemovePreUpgrade()
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("[webdetector]\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, vals[k])
	}
	return writeFile(PreUpgradePath(), b.String())
}

// write stores value atomically: a temp file in Dir (0600), then rename.
func write(key, value string) error {
	return writeFile(Path(key), value+"\n")
}

// writeFile writes content to path (in Dir) atomically: a temp file in Dir
// (0600), then rename.
func writeFile(path, content string) error {
	if err := ensureDir(); err != nil {
		return err
	}
	// Mkdir leaves an existing dir's mode alone; tighten it.
	if err := os.Chmod(Dir, 0o700); err != nil {
		return fmt.Errorf("hostsecrets: chmod %s: %w", Dir, err)
	}
	f, err := os.CreateTemp(Dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("hostsecrets: temp file: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("hostsecrets: chmod temp: %w", err)
	}
	if _, err := f.WriteString(content); err != nil {
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
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("hostsecrets: rename into %s: %w", path, err)
	}
	return nil
}
