// Package hostsecrets keeps CFM's per-host generated secrets out of the
// packaged conffiles.
//
// [webdetector] CHALLENGE_TOKEN (the browser-challenge HMAC key) and
// OPENRESTY_TOKEN (the edge↔daemon socket bearer) used to be generated INTO
// /etc/cfm/detectors.conf. That made the conffile "modified" on every node,
// so no upgrade could update it: every release left a .rpmnew / .dpkg-dist
// beside it and new stock knobs never arrived. They now live one file each
// under Dir.
//
// The store is the source of truth. A token is created only when its file is
// missing (or holds no usable token): copied from detectors.conf when that
// still carries a usable one, so a migrating node keeps its token and no
// visitor's challenge cookie is invalidated, else generated. After that
// detectors.conf is never consulted for it again. To rotate, delete the file
// and restart.
package hostsecrets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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
	SourceStore     = "store"
	SourceConf      = "detectors.conf" // copied into an empty store
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
// and unchanged by the detectors.conf value cleaner (detconf.CleanValue). The
// daemon re-reads the resolved value through that cleaner, so a value it would
// change would run as a DIFFERENT secret than the one mirrored to the edge
// (cfm_bridge_token.lua), or as none at all.
func Usable(v string) bool {
	return sslcollector.IsStrongToken(v) && detconf.CleanValue(v) == v
}

// ConfSection is where the detectors.conf token value is read, as the old
// binary read it: the BASE [webdetector] section when the base has one (an
// overlay token is ignored), the merged section only when the base has none
// (the old binary ran an overlay token as-is), nil when the base cannot be
// read (an overlay token must never stand in for it). One rule for the daemon
// (the detectors manager) and the probes. The value matters only while the
// store has no token: the migration.
func ConfSection(base detconf.Sections, baseErr error, merged map[string]string) map[string]string {
	if baseErr != nil {
		return nil
	}
	if b, ok := base.ByName["webdetector"]; ok {
		return b
	}
	return merged
}

// readRetryDelay spaces the retries of a failed first store read. A var so
// tests can shorten it.
var readRetryDelay = 50 * time.Millisecond

var (
	// unstored holds, per key, a token this process generated but could not
	// store, so an unwritable store does not yield a new token on every
	// reload. Dropped once a value is stored.
	unstored sync.Map
	// running holds, per key, the value Resolve last returned: what this
	// process keeps while the store cannot be read.
	running sync.Map
)

// choose is the one precedence rule, shared by Resolve and Effective: a
// usable stored value; else, when the store cannot be read, the value this
// process already runs; else a usable detectors.conf value (the node's token
// before the migration); else a token this process generated but could not
// store. ok is false when none applies.
func choose(key, legacy, cur string, readErr error) (value, source string, ok bool) {
	if readErr == nil && Usable(cur) {
		return cur, SourceStore, true
	}
	if readErr != nil {
		if v, found := running.Load(key); found {
			return v.(string), SourceRunning, true
		}
	}
	if Usable(legacy) {
		return legacy, SourceConf, true
	}
	if v, found := unstored.Load(key); found {
		return v.(string), SourceGenerated, true
	}
	return "", "", false
}

// Effective is the value the daemon runs with for key, for read-only probes
// (cfm health), by the same precedence as Resolve. A probe runs in its own
// process, so it cannot see a token the daemon holds only in memory (a store
// it could not write, or a file deleted to rotate, before the restart). When
// nothing usable applies it returns the legacy value as given (possibly weak
// or empty), so a probe reports weak/missing. It never generates or writes.
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
//  1. SourceStore: the stored value, when usable. detectors.conf is ignored.
//  2. SourceRunning: the store cannot be read (ErrStoreUnreadable); the value
//     this process already runs is kept and the store is left alone.
//  3. SourceConf: the store is empty and legacy, the detectors.conf value, is
//     usable: it is copied into the store (the migration). When the store
//     cannot be read it is run without being stored.
//  4. SourceGenerated: a new random 48-hex value, stored. Until it is stored
//     it is kept for the rest of this process.
//
// A stored value that is not usable is replaced like an empty store. The
// secret is always returned. A non-nil error means it was not stored: the
// daemon keeps running with it and retries on each reload.
func Resolve(key, legacy string) (secret, source string, err error) {
	legacy = strings.TrimSpace(legacy)
	cur, readErr := readStore(key)
	if _, runs := running.Load(key); readErr != nil && !runs {
		// Nothing running yet (daemon start): a transient error (EMFILE,
		// EIO) would make this process run a throwaway token, then switch to
		// the stored one on the next reload. Retry briefly first.
		for i := 0; i < 3 && readErr != nil; i++ {
			time.Sleep(readRetryDelay)
			cur, readErr = readStore(key)
		}
	}
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
	case readErr != nil:
		// Never overwrite a store that may hold a good secret; a later
		// reload reads it again.
		err = fmt.Errorf("%w: %s: %v", ErrStoreUnreadable, Path(key), readErr)
	case source != SourceStore:
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

// tighten re-applies the store's modes (dir 0700, file 0600) and root
// ownership when an existing store is only read: one restored from a backup or copied with a default
// umask would otherwise stay readable to every local user, who could then
// forge challenge cookies or call the bridge socket API. Best effort: a
// failure here does not stop the daemon using the secret.
func tighten(key string) {
	for path, want := range map[string]os.FileMode{Dir: 0o700, Path(key): 0o600} {
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if fi.Mode().Perm()&^want != 0 {
			_ = os.Chmod(path, want)
		}
		// Owned by another user (a restore as uid cfm), the mode alone
		// protects nothing: the owner can read or replace the secret.
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && (st.Uid != 0 || st.Gid != 0) {
			_ = os.Lchown(path, 0, 0)
		}
	}
}

// ensureDir creates Dir (0700). A missing parent (/var/lib/cfm) is created
// 0701, the daemon's own mode for it (cmd/cfm/main.go): the edge workers
// (user cfm) must traverse it to /var/lib/cfm/lua.
func ensureDir() error {
	parent := filepath.Dir(Dir)
	if _, err := os.Stat(parent); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(parent, 0o701); err != nil {
			return fmt.Errorf("hostsecrets: mkdir %s: %w", parent, err)
		}
		if err := os.Chmod(parent, 0o701); err != nil {
			return fmt.Errorf("hostsecrets: chmod %s: %w", parent, err)
		}
	}
	if err := os.Mkdir(Dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("hostsecrets: mkdir %s: %w", Dir, err)
	}
	// Mkdir leaves an existing dir's mode alone; tighten it.
	if err := os.Chmod(Dir, 0o700); err != nil {
		return fmt.Errorf("hostsecrets: chmod %s: %w", Dir, err)
	}
	return nil
}

// write stores value atomically: a temp file in Dir (0600), then rename.
func write(key, value string) error {
	if err := ensureDir(); err != nil {
		return err
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
	// Make the new directory entry durable too: a migrated token lost to a
	// power cut would be regenerated once the conf line is a placeholder.
	if d, err := os.Open(Dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
