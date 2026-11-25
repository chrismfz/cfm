package edgeban

import "sync"

// The change log tells the edge feed (internal/webdetector, /nginx/edgeban)
// WHICH keys changed, so it can bring its published list up to date by
// looking those keys up (Lookup) instead of rebuilding the whole list from
// List on every version change. With 7-day WAF bans a node held 58 000 of
// them (earth, 2026-11-25), and the rebuild ran after nearly every ban:
// 453 times in 3 hours, ~150 ms each, inside the edge's poll.
//
// A change to one key (a ban, an unban, a reconcile dropping or clamping an
// entry) is logged as that key. A change that can move many answers at once
// (the allow sets, the kill switch, the trusted proxies, readiness, a new
// Default store, a Load) starts a new generation instead: a reader of an
// older generation rebuilds. So does a reader the log has been trimmed past.
//
// A key is logged after the store holds its new state, so a reader that has
// seen the key's change can read that state (or a later one).

// changeLogMax bounds the log. A reader further behind rebuilds.
const changeLogMax = 16384

type keyChange struct {
	seq uint64
	key string
}

var changes struct {
	mu  sync.Mutex
	gen uint64
	seq uint64
	log []keyChange // ascending seq, the last changeLogMax
}

// markKeys logs a change of each key.
func markKeys(keys ...string) {
	if len(keys) == 0 {
		return
	}
	changes.mu.Lock()
	for _, k := range keys {
		changes.seq++
		changes.log = append(changes.log, keyChange{seq: changes.seq, key: k})
	}
	if n := len(changes.log) - changeLogMax; n > 0 {
		changes.log = append([]keyChange(nil), changes.log[n:]...)
	}
	changes.mu.Unlock()
}

// markAll starts a new generation: every reader rebuilds.
func markAll() {
	changes.mu.Lock()
	changes.gen++
	changes.log = nil
	changes.mu.Unlock()
}

// ChangePos is the change log's position. A reader that rebuilds from List
// reads it first, so that the changes landing during the rebuild are the
// ones it picks up next.
func ChangePos() (gen, seq uint64) {
	changes.mu.Lock()
	defer changes.mu.Unlock()
	return changes.gen, changes.seq
}

// ChangesSince returns the keys changed after (gen, seq), each once, and the
// position after them. ok is false when the reader must rebuild instead: a
// new generation began, or the log no longer reaches back to seq.
func ChangesSince(gen, seq uint64) (keys []string, ngen, nseq uint64, ok bool) {
	changes.mu.Lock()
	defer changes.mu.Unlock()
	if gen != changes.gen || seq > changes.seq {
		return nil, changes.gen, changes.seq, false
	}
	if seq < changes.seq && (len(changes.log) == 0 || changes.log[0].seq > seq+1) {
		return nil, changes.gen, changes.seq, false // trimmed past seq
	}
	seen := map[string]bool{}
	for _, c := range changes.log {
		if c.seq > seq && !seen[c.key] {
			seen[c.key] = true
			keys = append(keys, c.key)
		}
	}
	return keys, changes.gen, changes.seq, true
}

// Lookup answers one key (an address, or an IPv6 client's /64) as List
// does: the ban the edge must hold for it, if any.
func (s *Store) Lookup(k string) (Item, bool) {
	if s == nil || !enabled.Load() || !s.ready.Load() {
		return Item{}, false
	}
	s.mu.RLock()
	e, ok := s.m[k]
	s.mu.RUnlock()
	if !ok {
		return Item{}, false
	}
	if b, _ := s.answers(k, e, s.now()); !b {
		return Item{}, false
	}
	return Item{IP: k, Expires: e.Expires}, true
}

// Lookup is Store.Lookup on the Default store.
func Lookup(k string) (Item, bool) { return Default().Lookup(k) }
