// internal/webdetector/ua_emergency.go
//
// Box-wide UA emergency rule store. Operators apply throttle/block/allow
// to a normalized User-Agent (see ua_norm.go) for a bounded TTL. Rules are
// keyed by UA only — they apply across all vhosts on the box.
//
// Persistence: the in-process map is mirrored to a JSON file so the Lua
// side can pick it up (via init_worker_by_lua / periodic reload). The file
// is also re-read on Go process restart so an operator restart doesn't
// silently lose active rules mid-TTL.
//
// Audit: every create/expire/undo event is appended to a dedicated log so
// post-mortems can answer "what got applied at 02:14, by whom, against
// which UA, and for how long?". Per-request actions are NOT logged here —
// the lifecycle audit log stays tiny by design.
package webdetector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/logging"
)

// UA emergency action vocabulary.
const (
	UAActionThrottle = "throttle"
	UAActionBlock    = "block"
	UAActionAllow    = "allow"
)

// TTL bounds — server-side guards applied in the API layer.
const (
	UAEmergencyDefaultTTL = 30 * time.Minute
	UAEmergencyMaxTTL     = 60 * time.Minute
	UAEmergencyMinTTL     = 1 * time.Minute
)

// UAEmergencyRule is one active emergency rule.
type UAEmergencyRule struct {
	UA        string    `json:"ua"`         // normalized UA key
	Action    string    `json:"action"`     // throttle | block | allow
	CreatedAt time.Time `json:"created_at"` // wall clock
	ExpiresAt time.Time `json:"expires_at"` // wall clock
	CreatedBy string    `json:"created_by"` // token name / "admin" / "scoped:foo"
	Reason    string    `json:"reason,omitempty"`
	Hits      int64     `json:"hits"` // incremented by enforcement layer via IncHits
}

// UAEmergencyStore holds the active rules and writes them to disk so the
// Lua enforcement side can pick them up. It is safe for concurrent use.
type UAEmergencyStore struct {
	path       string
	auditPath  string
	mu         sync.RWMutex
	rules      map[string]*UAEmergencyRule // key: normalized UA
	saveSerial uint64                      // bumped on every disk write
}

// NewUAEmergencyStore loads any existing rules from `path` and returns a
// ready-to-use store. Missing file is not an error; corrupt file is logged
// and treated as empty.
func NewUAEmergencyStore(path, auditPath string) *UAEmergencyStore {
	s := &UAEmergencyStore{
		path:      path,
		auditPath: auditPath,
		rules:     make(map[string]*UAEmergencyRule),
	}
	s.load()
	// Drop anything already expired at startup so a long-stopped daemon
	// doesn't reincarnate stale rules.
	s.PruneExpired(time.Now())
	return s
}

// load reads the JSON snapshot from disk into memory. Errors are logged but
// non-fatal.
func (s *UAEmergencyStore) load() {
	if s.path == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logging.Logf("[ua_emergency] load %s failed: %v", s.path, err)
		}
		return
	}
	if len(data) == 0 {
		return
	}
	var rules []UAEmergencyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		logging.Logf("[ua_emergency] parse %s failed: %v (treating as empty)", s.path, err)
		return
	}
	s.mu.Lock()
	for i := range rules {
		r := rules[i]
		if r.UA == "" {
			continue
		}
		s.rules[r.UA] = &r
	}
	s.mu.Unlock()
}

// save writes the current rule set to disk atomically (write-temp + rename).
func (s *UAEmergencyStore) save() {
	if s.path == "" {
		return
	}
	s.mu.RLock()
	rules := make([]UAEmergencyRule, 0, len(s.rules))
	for _, r := range s.rules {
		rules = append(rules, *r)
	}
	s.mu.RUnlock()

	sort.Slice(rules, func(i, j int) bool { return rules[i].UA < rules[j].UA })

	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		logging.Logf("[ua_emergency] marshal failed: %v", err)
		return
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		logging.Logf("[ua_emergency] mkdir %s failed: %v", filepath.Dir(s.path), err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		logging.Logf("[ua_emergency] write %s failed: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		logging.Logf("[ua_emergency] rename %s failed: %v", s.path, err)
		_ = os.Remove(tmp)
		return
	}
	atomic.AddUint64(&s.saveSerial, 1)
}

// audit appends a single-line event to the lifecycle audit log. Format is
// stable across versions for easy grep/awk parsing.
func (s *UAEmergencyStore) audit(event string, r *UAEmergencyRule, extra string) {
	if s.auditPath == "" || r == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.auditPath), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(s.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	line := fmt.Sprintf(
		"ts=%s event=%s ua=%q action=%s ttl=%s expires=%s by=%q reason=%q hits=%d%s\n",
		time.Now().UTC().Format(time.RFC3339),
		event,
		r.UA,
		r.Action,
		r.ExpiresAt.Sub(r.CreatedAt).Round(time.Second),
		r.ExpiresAt.UTC().Format(time.RFC3339),
		r.CreatedBy,
		r.Reason,
		atomic.LoadInt64(&r.Hits),
		extra,
	)
	_, _ = f.WriteString(line)
}

// Set installs or replaces an emergency rule. The caller is responsible
// for normalizing the UA and enforcing TTL bounds / warn-list confirmation.
// Returns the stored rule (a copy).
func (s *UAEmergencyStore) Set(ua, action, createdBy, reason string, ttl time.Duration) (UAEmergencyRule, error) {
	if ua == "" || ua == "-" {
		return UAEmergencyRule{}, fmt.Errorf("ua is required")
	}
	switch action {
	case UAActionThrottle, UAActionBlock, UAActionAllow:
	default:
		return UAEmergencyRule{}, fmt.Errorf("invalid action %q", action)
	}
	if ttl < UAEmergencyMinTTL {
		ttl = UAEmergencyDefaultTTL
	}
	if ttl > UAEmergencyMaxTTL {
		ttl = UAEmergencyMaxTTL
	}

	now := time.Now()
	r := &UAEmergencyRule{
		UA:        ua,
		Action:    action,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		CreatedBy: createdBy,
		Reason:    reason,
	}

	s.mu.Lock()
	s.rules[ua] = r
	s.mu.Unlock()

	s.save()
	s.audit("create", r, "")
	return *r, nil
}

// Delete removes an emergency rule by normalized UA. Returns the removed
// rule (if any) and a bool indicating whether it existed.
func (s *UAEmergencyStore) Delete(ua, by string) (UAEmergencyRule, bool) {
	s.mu.Lock()
	r, ok := s.rules[ua]
	if ok {
		delete(s.rules, ua)
	}
	s.mu.Unlock()
	if !ok {
		return UAEmergencyRule{}, false
	}
	copy := *r
	s.save()
	s.audit("undo", &copy, fmt.Sprintf(" undo_by=%q", by))
	return copy, true
}

// Get returns the rule for the given normalized UA (copy + true) or
// (zero, false) if no rule is active.
func (s *UAEmergencyStore) Get(ua string) (UAEmergencyRule, bool) {
	s.mu.RLock()
	r, ok := s.rules[ua]
	s.mu.RUnlock()
	if !ok {
		return UAEmergencyRule{}, false
	}
	return *r, true
}

// List returns a snapshot of all active rules, sorted by expiry ascending
// (soonest-to-expire first). Expired rules are excluded.
func (s *UAEmergencyStore) List() []UAEmergencyRule {
	now := time.Now()
	s.mu.RLock()
	out := make([]UAEmergencyRule, 0, len(s.rules))
	for _, r := range s.rules {
		if r.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, *r)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

// IncHits bumps the hit counter for a rule. Intended for the enforcement
// layer to call once per (throttled/blocked) request. No-op if the rule no
// longer exists. Hot path: takes only an RLock + atomic increment.
func (s *UAEmergencyStore) IncHits(ua string, delta int64) {
	if delta <= 0 {
		return
	}
	s.mu.RLock()
	r, ok := s.rules[ua]
	s.mu.RUnlock()
	if !ok {
		return
	}
	atomic.AddInt64(&r.Hits, delta)
}

// PruneExpired removes rules whose ExpiresAt is before `now`. Returns the
// number of rules removed. Caller is responsible for scheduling.
func (s *UAEmergencyStore) PruneExpired(now time.Time) int {
	s.mu.Lock()
	expired := make([]*UAEmergencyRule, 0)
	for ua, r := range s.rules {
		if r.ExpiresAt.Before(now) {
			expired = append(expired, r)
			delete(s.rules, ua)
		}
	}
	s.mu.Unlock()
	if len(expired) == 0 {
		return 0
	}
	for _, r := range expired {
		s.audit("expire", r, "")
	}
	s.save()
	return len(expired)
}

// RunPruneLoop drives PruneExpired on a fixed interval until ctx is done.
// Designed to be launched as a goroutine from the engine bootstrap.
func (s *UAEmergencyStore) RunPruneLoop(stop <-chan struct{}, every time.Duration) {
	if every <= 0 {
		every = 10 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			s.PruneExpired(now)
		}
	}
}

// SaveSerial returns the monotonic counter of disk writes. Useful for
// tests / sanity checks.
func (s *UAEmergencyStore) SaveSerial() uint64 {
	return atomic.LoadUint64(&s.saveSerial)
}
