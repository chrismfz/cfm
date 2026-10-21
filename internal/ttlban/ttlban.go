// Package ttlban keeps the node's TTL host bans across a restart.
//
// A TTL ban (an autoblock, a WAF autoblock, `cfm block --ttl`, a fleet
// blocklist delta) lives only as a timed element of inet cfm block_v4 /
// block_v6. cfm.deny holds the permanent ones, and must not hold these: it
// has no expiry, so they would become permanent. Anything that empties the
// table therefore freed every such ban, while the notifier had already
// reported "Blocked: Yes": the rpm %post ran `cfm disable` on every upgrade
// (2026-10-21, 49 of 50 bans gone on one node), and a reboot, `cfm reset` or
// `cfm disable` still do.
//
// The store is a snapshot of those elements, refreshed from nft (the edge
// ban reconcile's read, and once more on SIGTERM), and restored after
// EnsureBase with the time each ban has left. It is not a second source of
// bans: a snapshot replaces the store with what nft holds, so an element
// that expired, was unblocked or flushed leaves it at the next read. Between
// two reads an unblock inside the daemon calls Forget, which drops the entry
// at once and keeps a stale read (one begun before the unblock) from putting
// it back. Restore adds or extends only (AddBlockBatch never shortens a ban
// or turns a permanent one temporary), skips what has expired, and drops
// what the caller says must not be blocked (an allow, cfm.ignore,
// IGNORE_IPS).
//
// Host bans only: TTL'd CIDR blocks come from cfm.deny (re-read at start)
// or a manual `cfm block <cidr> --ttl`, and are not persisted.
package ttlban

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/firewall"
)

// DefaultPath is where the daemon persists the store. A var so tests point it
// at a temp dir (CLAUDE.md §5: tests never touch CFM's live paths).
var DefaultPath = "/var/lib/cfm/ttlbans.json"

// SetPathForTest points DefaultPath at path and returns a restore func.
func SetPathForTest(path string) (restore func()) {
	old := DefaultPath
	DefaultPath = path
	return func() { DefaultPath = old }
}

// Sets are the block sets the store mirrors.
var Sets = []string{"block_v4", "block_v6"}

// minRemaining is the least time left worth restoring: nft reports whole
// seconds, and a ban in its last second is as good as expired.
const minRemaining = time.Second

// expiryTolerance is how far a snapshot's expiry may drift from the stored
// one before the file is rewritten: nft reports the remaining time in whole
// seconds, so every read moves each expiry by up to a second.
const expiryTolerance = 5 * time.Second

// Entry is one persisted ban.
type Entry struct {
	Set     string    `json:"set"`
	Expires time.Time `json:"expires"`
}

type fileFormat struct {
	Version int              `json:"version"`
	SavedAt time.Time        `json:"saved_at"`
	Bans    map[string]Entry `json:"bans"`
}

// Store is the persisted set of TTL host bans.
type Store struct {
	mu     sync.Mutex
	path   string
	bans   map[string]Entry
	forgot map[string]time.Time // unblocked at; a read begun before it is stale for that address
	// armed: Restore ran. A snapshot before it would save the empty sets of a
	// fresh table over the bans still waiting to be restored.
	armed bool
	// carry: bans a failed restore may not have written. Every snapshot keeps
	// them until they expire or are forgotten, so the next start retries them
	// instead of the first snapshot dropping them for good.
	carry    map[string]Entry
	savedAt  time.Time // the loaded file's saved_at
	lastRead time.Time // readAt of the last applied snapshot
	now      func() time.Time
	sleep    func(time.Duration)
	saveMu   sync.Mutex
}

// restoreAttempts is how many times Restore tries the batch (an nft busy at
// boot); restoreBackoff is the wait before the second, doubled after.
const (
	restoreAttempts = 3
	restoreBackoff  = time.Second
)

// New returns an empty store persisted at path ("" keeps it in memory only).
func New(path string) *Store {
	return &Store{path: path, bans: map[string]Entry{}, forgot: map[string]time.Time{}, carry: map[string]Entry{}, now: time.Now, sleep: time.Sleep}
}

var def atomic.Pointer[Store]

// SetDefault installs the daemon's store (nil removes it). Forget and the
// snapshot helpers act on it; outside the daemon there is none and they do
// nothing.
func SetDefault(s *Store) { def.Store(s) }

// Default is the daemon's store, or nil.
func Default() *Store { return def.Load() }

// Load reads the file. A missing file is an empty store; an unreadable or
// corrupt one is an empty store and an error, and the next snapshot rewrites
// it.
func (s *Store) Load() error {
	if s.path == "" {
		return nil
	}
	raw, err := os.ReadFile(s.path) // #nosec G304 -- daemon-owned state file
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("ttlban: %s: %w", s.path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bans = map[string]Entry{}
	s.savedAt = f.SavedAt
	for k, e := range f.Bans {
		ip := net.ParseIP(k)
		if ip == nil || e.Expires.IsZero() {
			continue
		}
		s.bans[ip.String()] = Entry{Set: setFor(ip), Expires: e.Expires}
	}
	return nil
}

// Len is the number of stored bans.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bans)
}

// Entries returns a copy of the stored bans.
func (s *Store) Entries() map[string]Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Entry, len(s.bans))
	for k, e := range s.bans {
		out[k] = e
	}
	return out
}

// RestoreResult counts what Restore did.
type RestoreResult struct {
	Stored   int // entries in the store before the restore
	Expired  int // their time ran out while the daemon was down: dropped
	Excluded int // an allow / ignore covers them: dropped, never re-added
	Batch    firewall.BlockBatchResult
}

// Restore re-adds the stored bans that still have time left, each for the
// time it has left, and then arms the snapshots: one taken while the batch
// is still writing would save a half-restored table over the file. exclude
// reports an address that must not be blocked (its entry is dropped). The
// block sets must exist (EnsureBase). A failing batch is retried; if it
// still fails the store arms all the same (one that never armed would never
// persist a ban again) and carries the bans in the file, so the next start
// retries them.
//
// The time left is capped at what the ban had when the file was saved: a
// clock behind at boot (no RTC sync yet) must not stretch a 6h ban into days.
// A clock AHEAD reads as a long downtime and expires bans early; nothing in
// the file can tell the two apart.
func (s *Store) Restore(be firewall.Backend, exclude func(net.IP) bool) (RestoreResult, error) {
	s.mu.Lock()
	now := s.now()
	res := RestoreResult{Stored: len(s.bans)}
	var entries []firewall.BlockEntry
	keep := map[string]Entry{}
	for k, e := range s.bans {
		ip := net.ParseIP(k)
		left := e.Expires.Sub(now)
		if !s.savedAt.IsZero() {
			if atSave := e.Expires.Sub(s.savedAt); left > atSave {
				left = atSave
			}
		}
		left = left.Truncate(time.Second)
		switch {
		case ip == nil, left < minRemaining:
			res.Expired++
		case exclude != nil && exclude(ip):
			res.Excluded++
		default:
			keep[k] = e
			entries = append(entries, firewall.BlockEntry{IP: ip, TTL: left})
		}
	}
	s.bans = keep
	s.mu.Unlock()

	var err error
	if len(entries) > 0 && be != nil {
		sort.Slice(entries, func(i, j int) bool { return entries[i].IP.String() < entries[j].IP.String() })
		wait := restoreBackoff
		for attempt := 1; ; attempt++ {
			res.Batch, err = be.AddBlockBatch(entries) // adds or extends: safe to repeat
			if err == nil || attempt == restoreAttempts {
				break
			}
			s.sleep(wait)
			wait *= 2
		}
	}
	// An unblock that landed while the batch was writing may have removed
	// the element before the batch re-added it: take those out again.
	s.mu.Lock()
	var undo []net.IP
	for _, e := range entries {
		if be == nil {
			break
		}
		if t, ok := s.forgot[e.IP.String()]; ok && !t.Before(now) {
			undo = append(undo, e.IP)
		}
	}
	if err != nil {
		for k, e := range s.bans {
			s.carry[k] = e
		}
	}
	s.armed = true
	s.mu.Unlock()
	for _, ip := range undo {
		if rerr := be.RemoveBlock(ip); rerr != nil && err == nil {
			err = fmt.Errorf("ttlban: undo restore of unblocked %s: %w", ip, rerr)
		}
	}
	if res.Expired > 0 || res.Excluded > 0 {
		if serr := s.save(); serr != nil && err == nil {
			err = serr
		}
	}
	return res, err
}

// Snapshot replaces the store with the timed host elements of a complete
// read of the block sets begun at readAt (the caller reads every set in Sets
// or does not call). Permanent elements are not kept: cfm.deny re-applies
// those. An address Forget dropped at or after readAt is left out (the read
// predates the unblock). It does nothing before Restore ran, and ignores a
// read older than one already applied (a slow periodic read finishing after
// the shutdown one).
func (s *Store) Snapshot(readAt time.Time, elems []firewall.SetElementTimed) error {
	s.mu.Lock()
	if !s.armed || readAt.Before(s.lastRead) {
		s.mu.Unlock()
		return nil
	}
	s.lastRead = readAt
	next := make(map[string]Entry, len(elems))
	for _, el := range elems {
		if el.Expires <= 0 {
			continue
		}
		ip := net.ParseIP(el.Elem)
		if ip == nil {
			continue
		}
		k := ip.String()
		if t, ok := s.forgot[k]; ok && !t.Before(readAt) {
			continue
		}
		next[k] = Entry{Set: setFor(ip), Expires: readAt.Add(el.Expires)}
	}
	for k, e := range s.carry {
		if _, inNft := next[k]; inNft || !e.Expires.After(readAt) {
			delete(s.carry, k) // nft holds it after all, or it expired
			continue
		}
		next[k] = e
	}
	for k, t := range s.forgot {
		if t.Before(readAt) {
			delete(s.forgot, k) // this read already reflects that unblock
		}
	}
	changed := !sameBans(s.bans, next)
	s.bans = next
	s.mu.Unlock()
	if !changed {
		return nil
	}
	return s.save()
}

// Forget drops ips from the store (an unblock). It also keeps a snapshot
// whose read began before now from adding them back.
func (s *Store) Forget(ips ...string) error {
	s.mu.Lock()
	now := s.now()
	changed := false
	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		k := ip.String()
		s.forgot[k] = now
		delete(s.carry, k)
		if _, ok := s.bans[k]; ok {
			delete(s.bans, k)
			changed = true
		}
	}
	s.mu.Unlock()
	if !changed {
		return nil
	}
	return s.save()
}

// Forget drops ips from the daemon's store; a no-op outside the daemon.
func Forget(ips ...string) {
	if s := Default(); s != nil {
		_ = s.Forget(ips...)
	}
}

// save writes the store atomically: a temp file in the same dir, then rename.
func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	f := fileFormat{Version: 1, SavedAt: s.now().UTC(), Bans: make(map[string]Entry, len(s.bans))}
	for k, e := range s.bans {
		f.Bans[k] = Entry{Set: e.Set, Expires: e.Expires.UTC()}
	}
	s.mu.Unlock()
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ttlbans-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after the rename
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

func setFor(ip net.IP) string {
	if ip.To4() != nil {
		return "block_v4"
	}
	return "block_v6"
}

func sameBans(a, b map[string]Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for k, ea := range a {
		eb, ok := b[k]
		if !ok {
			return false
		}
		d := ea.Expires.Sub(eb.Expires)
		if d > expiryTolerance || d < -expiryTolerance {
			return false
		}
	}
	return true
}
