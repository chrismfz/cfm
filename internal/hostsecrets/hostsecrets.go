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
	"time"

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
	SourceConf = "detectors.conf"
	// SourceSnapshot: the package's pre-upgrade snapshot of detectors.conf
	// (PreUpgradePath), taken before it could replace the conffile.
	SourceSnapshot  = "pre-upgrade snapshot"
	SourceStore     = "store"
	SourceGenerated = "generated"
	// SourceRunning: the store could not be read, so the process keeps the
	// value it already runs rather than generating a new one.
	SourceRunning = "running"
)

// ErrStoreUnreadable wraps a store read error other than "absent". Resolve
// then never writes the store: it may hold a good secret.
var ErrStoreUnreadable = errors.New("hostsecrets: store unreadable")

// ErrSnapshotNotUpdated: the token was stored, but it could not be dropped
// from the pre-upgrade snapshot.
var ErrSnapshotNotUpdated = errors.New("hostsecrets: pre-upgrade snapshot not updated")

// Path is the store file for key: Dir/<lowercased key>.
func Path(key string) string {
	return filepath.Join(Dir, strings.ToLower(key))
}

// PreUpgradePath is the copy of /etc/cfm/detectors.conf the package's
// pre-install scriptlet takes before it can replace the conffile. Resolve
// takes each token from it at most once: a token is dropped from it as soon
// as the key is stored, and the file goes when no usable token is left.
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

// Usable reports whether v can be a token: strong (sslcollector.IsStrongToken)
// and unchanged by the detectors.conf value cleaner (detconf.CleanValue:
// inline comments, surrounding quotes). The daemon re-reads the resolved
// value through that cleaner, so a value it would change would run as a
// DIFFERENT secret than the one mirrored to the edge (cfm_bridge_token.lua),
// or as none at all. Every value the old binary could run end to end passes.
func Usable(v string) bool {
	return sslcollector.IsStrongToken(v) && detconf.CleanValue(v) == v
}

// readRetryDelay spaces the retries of a failed first store read. A var so
// tests can shorten it.
var readRetryDelay = 200 * time.Millisecond

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

// snapshotKV returns the [webdetector] section of the pre-upgrade snapshot,
// read with the daemon's own parser; ok is false when there is none.
func snapshotKV() (kv map[string]string, ok bool) {
	s, err := detconf.ReadSectionsFile(PreUpgradePath())
	if err != nil {
		return nil, false
	}
	return s.ByName["webdetector"], true
}

// snapshotValue is the usable value for key in the pre-upgrade snapshot, or "".
func snapshotValue(key string) string {
	kv, _ := snapshotKV()
	if v := detconf.CleanValue(kv[strings.ToUpper(key)]); Usable(v) {
		return v
	}
	return ""
}

// consumeSnapshot drops key from the pre-upgrade snapshot once the key is
// stored, so a later rotation can never take the old value from it again.
// The file goes when no usable token is left in it.
func consumeSnapshot(key string) error {
	kv, ok := snapshotKV()
	if !ok {
		return nil
	}
	left := map[string]string{}
	for _, k := range []string{ChallengeToken, BridgeToken} {
		if v := detconf.CleanValue(kv[k]); k != strings.ToUpper(key) && Usable(v) {
			left[k] = v
		}
	}
	if len(left) == 0 {
		return RemovePreUpgrade()
	}
	if len(left) == len(kv) {
		return nil // nothing to drop
	}
	return keepPreUpgrade(left)
}

// choose is the one precedence rule, shared by Resolve and Effective so the
// probes can never drift from the daemon: a usable legacy detectors.conf
// value, else a usable value from the pre-upgrade snapshot, else a usable
// stored value, else (store unreadable) the value this process already
// runs, else a token this process generated but could not store. ok is
// false when none applies.
func choose(key, legacy, snap, cur string, readErr error) (value, source string, ok bool) {
	if Usable(legacy) {
		return legacy, SourceConf, true
	}
	if snap != "" {
		return snap, SourceSnapshot, true
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
	if v, _, ok := choose(key, legacy, snapshotValue(key), cur, readErr); ok {
		return v
	}
	return legacy
}

// Resolve returns the secret the daemon runs with for key, and where it came
// from:
//
//  1. SourceConf: legacy, a usable value still set in detectors.conf. It is
//     copied into the store (when the store differs), so setting the line
//     back to a placeholder later keeps the same secret.
//  2. SourceSnapshot: a usable value in the package's pre-upgrade snapshot
//     of detectors.conf (the file as it was before the package could replace
//     it), stored the same way.
//  3. SourceStore: the stored value, when usable.
//  4. SourceRunning: the store cannot be read (ErrStoreUnreadable); the value
//     this process already runs is kept and the store is left alone.
//  5. SourceGenerated: a new random 48-hex value, stored. Until it is stored
//     it is kept for the rest of this process.
//
// A weak legacy value (a placeholder, too short, not Lua-safe, see Usable) is
// ignored, as is a weak stored one, which is replaced. Once key is stored it
// is dropped from the snapshot. The secret is always returned. A non-nil
// error is something to log: ErrSnapshotNotUpdated means the secret was
// stored; any other means it was not, and the daemon keeps running with it
// and retries on each reload.
func Resolve(key, legacy string) (secret, source string, err error) {
	legacy = strings.TrimSpace(legacy)
	cur, readErr := readStore(key)
	if _, runs := running.Load(key); readErr != nil && !runs {
		// Nothing running yet (daemon start): a transient error (EMFILE,
		// EIO) would make this process run a throwaway token, then switch
		// back to the stored one on the next reload. Retry briefly first.
		for i := 0; i < 3 && readErr != nil; i++ {
			time.Sleep(readRetryDelay)
			cur, readErr = readStore(key)
		}
	}
	value, source, ok := choose(key, legacy, snapshotValue(key), cur, readErr)
	if !ok {
		gen, gerr := sslcollector.GenerateToken()
		if gerr != nil {
			return "", "", gerr
		}
		actual, _ := unstored.LoadOrStore(key, gen)
		value, source = actual.(string), SourceGenerated
	}
	switch {
	case readErr != nil && source != SourceConf && source != SourceSnapshot:
		// Never overwrite a store that may hold a good secret; a later
		// reload reads it again.
		err = fmt.Errorf("%w: %s: %v", ErrStoreUnreadable, Path(key), readErr)
	case readErr != nil || cur != value:
		err = write(key, value)
	default:
		tighten(key)
	}
	running.Store(key, value)
	if err != nil {
		return value, source, err
	}
	unstored.Delete(key)
	if cerr := consumeSnapshot(key); cerr != nil {
		return value, source, fmt.Errorf("%w: %s: %v", ErrSnapshotNotUpdated, PreUpgradePath(), cerr)
	}
	return value, source, nil
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

// RemovePreUpgrade removes the package's pre-upgrade snapshot (consumeSnapshot
// when no usable token is left in it; the detectors manager when the config
// has no [webdetector] to use it). Absent is not an error.
func RemovePreUpgrade() error {
	if err := os.Remove(PreUpgradePath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// keepPreUpgrade rewrites the pre-upgrade snapshot down to the tokens in vals
// (key → value, each Usable) not stored yet.
func keepPreUpgrade(vals map[string]string) error {
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
