package webdetector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cfm/internal/clam"
)

// Per-signature ClamAV excludes ("sig-ignore"), the runtime complement of the
// CLAM_SIG_IGNORE config baseline: entries editable via API/CLI/UI with no
// config edit and no reload. An entry downgrades a matching infected verdict
// to log-only (see internal/clam/sigignore.go for the enforcement semantics).
//
// Host scoping: Host == "" is a GLOBAL entry (admin-only — it weakens
// detection for every tenant); a non-empty Host limits the entry to that
// exact vhost, which is what a scoped cPanel token may manage for itself.
// Pattern is a case-insensitive glob on the signature name, matched with
// clam.SigGlobMatch — the same matcher the scanner enforces with.

type clamSigIgnoreEntry struct {
	Host       string    `json:"host,omitempty"` // "" = global (admin-only)
	Pattern    string    `json:"pattern"`
	ScopeHosts []string  `json:"scope_hosts,omitempty"` // audit: the writing token's scope (nil = admin)
	CreatedAt  time.Time `json:"created_at"`
}

type clamSigIgnoreStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]clamSigIgnoreEntry // key = host + "\x00" + lower(pattern)
}

func newClamSigIgnoreStore(path string) *clamSigIgnoreStore {
	s := &clamSigIgnoreStore{
		path:    strings.TrimSpace(path),
		entries: make(map[string]clamSigIgnoreEntry),
	}
	s.load()
	return s
}

// normalizeClamSigIgnore validates and canonicalises an entry. The pattern
// must be a well-formed, printable glob (a malformed one would silently never
// match — reject it here, not in the scanner).
func normalizeClamSigIgnore(host, pattern string) (string, string, bool) {
	host = normalizeControlHost(host) // "" stays "" (global)
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || len(pattern) > 200 {
		return "", "", false
	}
	for _, r := range pattern {
		if r < 0x20 || r == 0x7f {
			return "", "", false
		}
	}
	if _, err := filepath.Match(strings.ToLower(pattern), "probe"); err != nil {
		return "", "", false
	}
	return host, pattern, true
}

func (s *clamSigIgnoreStore) key(host, pattern string) string {
	return host + "\x00" + strings.ToLower(pattern)
}

func (s *clamSigIgnoreStore) Add(host, pattern string, scopeHosts []string) bool {
	if s == nil {
		return false
	}
	h, p, ok := normalizeClamSigIgnore(host, pattern)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(h, p)
	if _, exists := s.entries[k]; exists {
		return false
	}
	s.entries[k] = clamSigIgnoreEntry{
		Host:       h,
		Pattern:    p,
		ScopeHosts: normalizeScopeHosts(scopeHosts),
		CreatedAt:  time.Now(),
	}
	return s.saveLocked() == nil
}

func (s *clamSigIgnoreStore) Remove(host, pattern string) bool {
	if s == nil {
		return false
	}
	h, p, ok := normalizeClamSigIgnore(host, pattern)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(h, p)
	if _, exists := s.entries[k]; !exists {
		return false
	}
	delete(s.entries, k)
	return s.saveLocked() == nil
}

// List returns entries sorted global-first then by host/pattern.
func (s *clamSigIgnoreStore) List() []clamSigIgnoreEntry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	out := make([]clamSigIgnoreEntry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Pattern < out[j].Pattern
	})
	return out
}

// Match reports whether an infected verdict (host, sig) is downgraded by a
// global or matching-host entry, and a label for the scanner's log line.
// Called from a scanner worker via clam.SetSigIgnoreLookup — keep it cheap
// and panic-free.
func (s *clamSigIgnoreStore) Match(host, sig string) (bool, string) {
	if s == nil || sig == "" {
		return false, ""
	}
	h := normalizeControlHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.Host != "" && e.Host != h {
			continue
		}
		if clam.SigGlobMatch(e.Pattern, sig) {
			scope := e.Host
			if scope == "" {
				scope = "global"
			}
			return true, "store:" + scope + ":" + e.Pattern
		}
	}
	return false, ""
}

func (s *clamSigIgnoreStore) load() {
	if s == nil || s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var arr []clamSigIgnoreEntry
	if err := json.Unmarshal(b, &arr); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range arr {
		h, p, ok := normalizeClamSigIgnore(e.Host, e.Pattern)
		if !ok {
			continue
		}
		if e.CreatedAt.IsZero() {
			e.CreatedAt = time.Now()
		}
		e.Host, e.Pattern = h, p
		e.ScopeHosts = normalizeScopeHosts(e.ScopeHosts)
		s.entries[s.key(h, p)] = e
	}
}

func (s *clamSigIgnoreStore) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	arr := make([]clamSigIgnoreEntry, 0, len(s.entries))
	for _, e := range s.entries {
		arr = append(arr, e)
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Host != arr[j].Host {
			return arr[i].Host < arr[j].Host
		}
		return arr[i].Pattern < arr[j].Pattern
	})
	b, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
