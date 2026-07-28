package tlsfp

import "sync"

// Registry remembers which fingerprints have already been written out in full.
//
// The full tuple is a few hundred bytes and the id is eight. Logging the tuple
// on every solve would add tens of megabytes a day to cfm.challenges.log for
// information that repeats; logging only the id would leave the log
// un-interpretable. So the tuple is written once per distinct fingerprint as a
// dictionary line and every solve carries the id.
//
// It is deliberately not persisted: after a restart each fingerprint is
// re-announced once, which costs a handful of lines and keeps every log file
// self-contained.
type Registry struct {
	mu     sync.Mutex
	seen   map[string]struct{}
	max    int
	capped bool
}

// NewRegistry returns a registry bounded to max entries. The bound matters
// because the id is derived from client-controlled bytes: without it, a client
// varying its ClientHello per connection would grow this map without limit.
func NewRegistry(max int) *Registry {
	if max <= 0 {
		max = 5000
	}
	return &Registry{seen: make(map[string]struct{}), max: max}
}

// FirstSeen reports whether id has not been announced yet, recording it if so.
//
// Once the bound is reached it returns false for every unknown id: the choice is
// between losing new dictionary entries and letting a client drive unbounded
// memory, and the ids already recorded are the ones with traffic behind them.
// Capped reports when that has happened, so the gap is never silent.
func (r *Registry) FirstSeen(id string) bool {
	if r == nil || id == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[id]; ok {
		return false
	}
	if len(r.seen) >= r.max {
		r.capped = true
		return false
	}
	r.seen[id] = struct{}{}
	return true
}

// Capped reports whether the registry stopped admitting new fingerprints.
func (r *Registry) Capped() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.capped
}

// Len reports how many distinct fingerprints have been announced.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}
