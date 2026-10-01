// Package hostsecrets keeps CFM's per-host generated secrets out of the
// packaged conffiles.
//
// [webdetector] CHALLENGE_TOKEN (the browser-challenge HMAC key) and
// OPENRESTY_TOKEN (the edge↔daemon socket bearer) used to be generated INTO
// /etc/cfm/detectors.conf, and SSLCOLLECTOR_SOCK_TOKEN (the edge↔sslcollector
// socket bearer) into /etc/cfm/cfm.conf. That made those conffiles "modified"
// on every node, so no upgrade could update them: every release left a
// .rpmnew / .dpkg-dist beside them and new stock knobs never arrived. They
// now live one file each under Dir.
//
// The store is the source of truth. A token is created only when its file is
// missing: copied from its config file (the legacy value) when that still
// carries a usable one, so a migrating node keeps its token (no visitor's
// challenge cookie is invalidated, no edge loses socket auth), else
// generated. After that the config file is never consulted for it again. A
// file that exists but holds no usable token is never overwritten
// (ErrStoreUnusable), except an empty one, which is treated as absent
// (errEmpty). To rotate, set the config line to placeholder (a token still
// there would be copied back), delete the file and restart.
package hostsecrets

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"cfm/internal/detconf"
)

// Dir holds one file per secret, root-only (dir 0700, files 0600). A var so
// tests can point it at a temp dir: a test must never write the live path
// (CLAUDE.md §5).
var Dir = "/var/lib/cfm/secrets"

// SetDirForTest points Dir at dir and forgets this process's token caches,
// for tests in other packages (from a TestMain, or per test); it returns a
// restore func. A test must never touch the live store (CLAUDE.md §5), and a
// cached token from an earlier test would otherwise leak into the next one.
func SetDirForTest(dir string) (restore func()) {
	old := Dir
	Dir = dir
	forget()
	return func() { Dir = old; forget() }
}

// forget drops the per-process token caches.
func forget() {
	for _, m := range []*sync.Map{&unstored, &running} {
		m.Range(func(k, _ any) bool { m.Delete(k); return true })
	}
}

// The secrets this package manages, named after their legacy config keys
// (the file is the lower-cased key).
const (
	ChallengeToken    = "CHALLENGE_TOKEN"         // detectors.conf [webdetector]
	BridgeToken       = "OPENRESTY_TOKEN"         // detectors.conf [webdetector]
	SSLCollectorToken = "SSLCOLLECTOR_SOCK_TOKEN" // cfm.conf
)

// Sources Resolve reports.
const (
	SourceStore     = "store"
	SourceConf      = "config" // the legacy config-file value, copied into an empty store
	SourceGenerated = "generated"
	// SourceRunning: the store could not be read, so the process keeps the
	// value it already runs rather than generating a new one.
	SourceRunning = "running"
)

// ErrStoreUnreadable wraps a store read error other than "absent". Resolve
// then never writes the store: it may hold a good secret.
var ErrStoreUnreadable = errors.New("hostsecrets: store unreadable")

// ErrStoreUnusable: the token file exists but holds no usable token (weak, too
// long, or not a regular file). It is never overwritten: it may be an
// operator's token to fix. The process runs another token, unstored, until the
// file is fixed or deleted. An empty file is the exception (errEmpty, which
// wraps this error): after a short mid-write retry it is treated as absent
// and replaced.
var ErrStoreUnusable = errors.New("hostsecrets: token file holds no usable token")

// ErrStoreChanged: a token file appeared while a new one was being stored
// (an operator writing one); it is left alone and read on the next reload.
var ErrStoreChanged = errors.New("hostsecrets: a token file appeared meanwhile; left alone, read on the next reload")

// ErrConfUnknown: the store is empty and the config file could not be read
// (ResolveConfUnknown), so a generated token is run but not stored: the
// node's config-file token may still be copied on a later reload.
var ErrConfUnknown = errors.New("hostsecrets: config file unreadable, generated token not stored")

// Path is the store file for key: Dir/<lowercased key>.
func Path(key string) string {
	return filepath.Join(Dir, strings.ToLower(key))
}

// maxTokenFile caps a token file: a longer one is unusable, never truncated.
const maxTokenFile = 4096

// readStore returns the stored token for key; ("", nil) when the file is
// absent. An error means a file is there but gives no usable token, and
// Resolve never overwrites it: unreadable (EACCES, EIO, a directory in its
// place), or ErrStoreUnusable: weak, too long, or not a regular file. An
// empty file is errEmpty (see there). A symlink is never followed (the root
// daemon would read, and mirror to the edge, whatever it points at) and a
// FIFO or device is never opened.
func readStore(key string) (string, error) {
	// Type first, without opening: opening a device node can have side
	// effects, a FIFO blocks, a symlink would be followed.
	fi, err := os.Lstat(Path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return "", fmt.Errorf("%w: a symlink, never followed", ErrStoreUnusable)
	case fi.IsDir():
		return "", fmt.Errorf("%s is a directory", Path(key))
	case !fi.Mode().IsRegular():
		return "", fmt.Errorf("%w: not a regular file (%v)", ErrStoreUnusable, fi.Mode().Type())
	}
	// O_NOFOLLOW / O_NONBLOCK and the fstat below cover a swap after the
	// Lstat.
	f, err := os.OpenFile(Path(key), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- fixed daemon-internal path
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if errors.Is(err, syscall.ELOOP) {
		return "", fmt.Errorf("%w: a symlink, never followed", ErrStoreUnusable)
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%w: not a regular file (%v)", ErrStoreUnusable, fi.Mode().Type())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxTokenFile {
		return "", fmt.Errorf("%w: over %d bytes", ErrStoreUnusable, maxTokenFile)
	}
	if v := strings.TrimSpace(string(b)); Usable(v) {
		return v, nil
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", errEmpty
	}
	return "", ErrStoreUnusable
}

// errEmpty is ErrStoreUnusable for an empty file, which may be mid-write.
// Once a short retry has passed it is treated as absent (and replaced): an
// empty file can hold no one's token, and keeping it would make every
// restart run a new unstored token.
var errEmpty = fmt.Errorf("%w: empty", ErrStoreUnusable)

// Usable reports whether v can be a token: strong (IsStrongToken)
// and unchanged by the detectors.conf value cleaner (detconf.CleanValue). The
// daemon re-reads the resolved value through that cleaner, so a value it would
// change would run as a DIFFERENT secret than the one mirrored to the edge
// (cfm_bridge_token.lua), or as none at all.
func Usable(v string) bool {
	return IsStrongToken(v) && detconf.CleanValue(v) == v
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

// transient reports whether a store read error may clear by itself (fd
// exhaustion, I/O, an empty file caught mid-write), so a retry is worth it. A
// weak or special file, or a permission error, does not.
func transient(err error) bool {
	if errors.Is(err, errEmpty) { // an empty file may be mid-write
		return true
	}
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.EIO, syscall.EINTR, syscall.EAGAIN} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
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

// choose is Resolve's precedence rule: the stored token; else, when the store cannot be used, the value this
// process already runs; else a usable legacy config value (the node's token
// before the migration); else a token this process generated but could not
// store. ok is false when none applies.
func choose(key, legacy, cur string, readErr error) (value, source string, ok bool) {
	if readErr == nil && cur != "" {
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

// Effective is the token for key that read-only probes (cfm health) report:
//
//   - "" when the token file exists but holds no usable token
//     (ErrStoreUnusable; an empty file is treated as absent, as by Resolve):
//     the probe flags it, even while the daemon runs
//     another token, because a restart would not keep that one (the daemon
//     logs why);
//   - in the daemon, the token this process runs (the last Resolve), also
//     while its file is unreadable (EMFILE, EIO: the daemon logs it) or
//     deleted for a rotation not yet reloaded; "" for an unreadable file
//     when no token runs here (a separate probe process);
//   - else the stored token; else a usable legacy (config-file) value,
//     the token the daemon would copy; else legacy as given (possibly weak or
//     empty), so a probe reports weak/missing.
//
// It is written out rather than routed through choose (Resolve's rule): it
// never generates, never writes, and reports an unusable file instead of
// masking it. A probe in its own process cannot see a token the daemon holds
// only in memory.
func Effective(key, legacy string) string {
	cur, readErr := readStore(key)
	if errors.Is(readErr, errEmpty) {
		readErr = nil // treated as absent, as by Resolve
	}
	v, runs := running.Load(key)
	switch {
	case errors.Is(readErr, ErrStoreUnusable):
		return ""
	case readErr != nil && runs:
		// Unreadable (possibly transient: EMFILE, EIO): the daemon keeps
		// the token it runs, and logs the error.
		return v.(string)
	case readErr != nil:
		return ""
	case runs:
		return v.(string)
	}
	if cur != "" {
		return cur
	}
	return strings.TrimSpace(legacy)
}

// ForgetRunning drops this process's running tokens (not a generated token
// it could not store, which stays for the life of the process): the
// detectors manager calls it when the config no longer has [webdetector], so
// no probe reports a token nothing runs any more.
func ForgetRunning() {
	running.Range(func(k, _ any) bool { running.Delete(k); return true })
}

// Running returns the token for key this process runs (the last Resolve), if
// any: in the daemon, what the edge and the challenge server use right now.
func Running(key string) (string, bool) {
	v, found := running.Load(key)
	if !found {
		return "", false
	}
	return v.(string), true
}

// Resolve returns the secret the daemon runs with for key, and where it came
// from:
//
//  1. SourceStore: the stored value, when usable. The config file is ignored.
//  2. SourceRunning: the store cannot be read (ErrStoreUnreadable); the value
//     this process already runs is kept and the store is left alone.
//  3. SourceConf: the store is empty and legacy, the config-file value, is
//     usable: it is copied into the store (the migration). When the store
//     cannot be read it is run without being stored.
//  4. SourceGenerated: a new random 48-hex value, stored. Until it is stored
//     it is kept for the rest of this process.
//
// A token file that exists but holds no usable token (ErrStoreUnusable, a
// symlink or FIFO included) is never overwritten: the process runs a token as
// for an unreadable store. An empty file is treated as absent and replaced
// (with the running token, if any; see errEmpty). The secret is always
// returned. A non-nil error means it was not stored: the
// daemon keeps running with it and retries on each reload.
func Resolve(key, legacy string) (secret, source string, err error) {
	return resolve(key, strings.TrimSpace(legacy), true)
}

// ResolveConfUnknown is Resolve when the config file could not be read: the
// stored token is used as usual, but a token generated for an empty store is
// not stored (ErrConfUnknown), so a later reload that reads the config file can
// still copy the node's token into the store.
func ResolveConfUnknown(key string) (secret, source string, err error) {
	return resolve(key, "", false)
}

func resolve(key, legacy string, confKnown bool) (secret, source string, err error) {
	cur, readErr := readStore(key)
	if _, runs := running.Load(key); transient(readErr) && (!runs || errors.Is(readErr, errEmpty)) {
		// Nothing running yet (daemon start): a transient error (EMFILE,
		// EIO) would make this process run a throwaway token, then switch to
		// the stored one on the next reload. An empty file may be an
		// operator's token being written. Retry briefly first.
		for i := 0; i < 3 && transient(readErr); i++ {
			time.Sleep(readRetryDelay)
			cur, readErr = readStore(key)
		}
	}
	replace := errors.Is(readErr, errEmpty) // still empty: treat as absent
	if replace {
		readErr = nil
	}
	value, source, ok := choose(key, legacy, cur, readErr)
	if v, runs := running.Load(key); replace && runs {
		// Emptied under a running daemon (a truncating write gone wrong, a
		// restore): put back the token it runs, rather than rotate.
		value, source, ok = v.(string), SourceRunning, true
	}
	if !ok {
		gen, gerr := GenerateToken()
		if gerr != nil {
			return "", "", gerr
		}
		actual, _ := unstored.LoadOrStore(key, gen)
		value, source = actual.(string), SourceGenerated
	}
	switch {
	case errors.Is(readErr, ErrStoreUnusable):
		// Never overwrite it: an operator's token being written, or one to
		// fix. A later reload reads it again.
		err = fmt.Errorf("%s: %w (fix it, or delete it to have one created)", Path(key), readErr)
	case readErr != nil:
		// Never overwrite a store that may hold a good secret; a later
		// reload reads it again.
		err = fmt.Errorf("%w: %s: %v", ErrStoreUnreadable, Path(key), readErr)
	case source == SourceGenerated && !confKnown:
		err = ErrConfUnknown
	case source != SourceStore:
		err = write(key, value, replace)
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
	_ = rootOnly(Dir, 0o700, true)
	_ = rootOnly(Path(key), 0o600, false)
}

// rootOnly takes path to mode at most and, when running as root, to root
// ownership: owned by another user (a restore as uid cfm), the mode alone
// protects nothing, the owner can read or replace the secret. follow: the
// store dir may be a symlink (moved to another volume), and it is its target
// that holds the tokens; a token file is never a symlink worth following.
func rootOnly(path string, mode os.FileMode, follow bool) error {
	stat := os.Lstat
	if follow {
		stat = os.Stat
	}
	fi, err := stat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return err
	}
	if fi.Mode().Perm()&^mode != 0 {
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("hostsecrets: chmod %s: %w", path, err)
		}
	}
	chown := os.Lchown
	if follow {
		chown = os.Chown
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && (st.Uid != 0 || st.Gid != 0) {
		if err := chown(path, 0, 0); err != nil {
			return fmt.Errorf("hostsecrets: chown %s: %w", path, err)
		}
	}
	return nil
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
	// Mkdir leaves an existing dir's mode and owner alone; tighten them, best
	// effort as in tighten (a root_squash mount cannot be chowned, and must
	// still hold the token).
	_ = rootOnly(Dir, 0o700, true)
	return nil
}

// bare drops the path from a file-operation error: write's temp file has a
// random name, and an error that differs on every reload defeats the
// log-once guard of a store that keeps failing.
func bare(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}

// write stores value atomically: a temp file in Dir (0600), then into place.
// Unless replace (an empty file there), the file is created with a hard link,
// which never replaces one that appeared meanwhile (ErrStoreChanged): an
// existing token file is never overwritten.
func write(key, value string, replace bool) error {
	if err := ensureDir(); err != nil {
		return err
	}
	f, err := os.CreateTemp(Dir, "."+strings.ToLower(key)+".tmp-*")
	if err != nil {
		return fmt.Errorf("hostsecrets: temp file in %s: %w", Dir, bare(err))
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("hostsecrets: chmod temp: %w", bare(err))
	}
	if _, err := f.WriteString(value + "\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("hostsecrets: write temp: %w", bare(err))
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("hostsecrets: sync temp: %w", bare(err))
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("hostsecrets: close temp: %w", bare(err))
	}
	place := func(oldpath, newpath string) error {
		// Replacing an empty file: unless it got content meanwhile.
		if fi, err := os.Lstat(newpath); err == nil && (fi.Size() != 0 || !fi.Mode().IsRegular()) {
			return ErrStoreChanged
		}
		return os.Rename(oldpath, newpath)
	}
	if !replace {
		place = func(oldpath, newpath string) error {
			err := os.Link(oldpath, newpath)
			if errors.Is(err, fs.ErrExist) {
				return ErrStoreChanged
			}
			if err != nil { // a filesystem without hard links
				if _, lerr := os.Lstat(newpath); lerr == nil {
					return ErrStoreChanged
				}
				return os.Rename(oldpath, newpath)
			}
			return nil
		}
	}
	if err := place(tmp, Path(key)); errors.Is(err, ErrStoreChanged) {
		return err
	} else if err != nil {
		return fmt.Errorf("hostsecrets: rename into %s: %w", Path(key), bare(err))
	}
	// Make the new directory entry durable too: a migrated token lost to a
	// power cut would be regenerated once the conf line is a placeholder.
	if d, err := os.Open(Dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
