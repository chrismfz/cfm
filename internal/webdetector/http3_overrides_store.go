// internal/webdetector/http3_overrides_store.go
//
// HTTP/3 (QUIC) per-vhost opt-in store.
//
// Semantics — IMPORTANT, opposite of excludeStore:
//
//   * Global default for every vhost is "HTTP/3 DISABLED" — i.e. nginx does
//     NOT advertise the Alt-Svc header (so browsers stay on HTTP/2 over TCP).
//   * This store keeps the OPT-IN list. A host present here gets Alt-Svc.
//   * For excludeStore the convention is opposite: default ON, list is the
//     set of OFFs. Keep the difference in mind when reading this file.
//
// Why opt-in (not opt-out): HTTP/3 over UDP/443 has been observed to fail
// silently on mobile/CGNAT paths (server sees status=200 rt=0.003 while
// the client browser hangs for minutes on small assets). Until that path
// is reliable end-to-end for all customer profiles, the safe default is to
// stay on HTTP/2 and let owners opt-in per vhost.
//
// Storage format: JSON array of http3OverrideEntry objects on disk at
// /var/lib/cfm/webdetector_http3_overrides.json (configurable). Wildcard
// hosts (e.g. "*.cdn.example.com") match via filepath.Match the same way
// excludeStore's host matching works in the UI helpers.
//
// Scope model (matches exclude_api_handlers.go):
//   * admin tokens: can opt-in any vhost.
//   * scoped tokens: can only opt-in vhosts inside their token scope.
//   * ScopeHosts on each entry records WHO added it (audit trail). It does
//     not gate reads — gating happens at the API layer via
//     filterHTTP3ListForScope() + validateScopedHTTP3Write().
//
// Lua side reads the current opt-in set via the bridge endpoint
// /nginx/h3/config (see nginx_bridge.go). A per-worker TTL cache in
// configs/lua/cfm_h3_config.lua keeps the per-request cost at ~1µs.
// Changes propagate within ~60s by default (CFM_H3_REFRESH_SEC).

package webdetector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// http3OverrideEntry is one opt-in row. A host with a wildcard ("*",
// "?", "[abc]") is matched via path/filepath.Match in IsEnabled().
type http3OverrideEntry struct {
	Host       string    `json:"host"`
	ScopeHosts []string  `json:"scope_hosts,omitempty"` // who added it
	CreatedAt  time.Time `json:"created_at"`
}

type http3OverrideStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]http3OverrideEntry // key = host (already normalized)
}

func newHTTP3OverrideStore(path string) *http3OverrideStore {
	s := &http3OverrideStore{
		path:    strings.TrimSpace(path),
		entries: make(map[string]http3OverrideEntry),
	}
	s.load()
	return s
}

// normalize lowercases the host, strips trailing dot, rejects empties,
// and rejects glob patterns the Lua data path cannot match.
//
// Supported patterns: exact hosts (e.g. `example.com`) and `*.suffix`
// wildcards (e.g. `*.cdn.example.com`). Anything else — `?`, `[abc]`,
// mid-pattern `*` like `cdn.*.example.com` — is rejected here so the
// store can never hold a pattern that the Lua glob_match in
// cfm_h3_config.lua would silently skip. This guarantees UI / API /
// CLI / Lua all agree on which hosts get Alt-Svc.
//
// Keep these rules in step with is_supported_pattern() in
// configs/lua/cfm_h3_config.lua. If you lift the restriction (e.g. by
// adopting cfm.lua's glob_to_lua_pattern), update both ends together.
func (s *http3OverrideStore) normalize(host string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", false
	}
	// Reject unsupported pattern classes. Exact (no glob chars) and
	// `*.suffix` only.
	if strings.ContainsAny(h, "?[") {
		return "", false
	}
	if strings.Contains(h, "*") {
		// Must be exactly "*." followed by a literal suffix.
		if !strings.HasPrefix(h, "*.") || strings.Contains(h[2:], "*") {
			return "", false
		}
	}
	return h, true
}

// Add records an opt-in for host (admin or scoped). scope is the token's
// allowed-vhost set; nil/empty means admin. Returns true on a real insert,
// false if the host was already present.
//
// Persistence: if saveLocked fails (disk full, permission, read-only mount)
// the in-memory entry is rolled back so the daemon's view matches what's on
// disk — otherwise a restart would silently lose the opt-in while the API
// reported success. The error is also logged loudly via logging.Logf.
func (s *http3OverrideStore) Add(host string, scope map[string]struct{}) bool {
	h, ok := s.normalize(host)
	if !ok {
		return false
	}
	scopeHosts := scopeMapToHosts(scope)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[h]; exists {
		return false
	}
	s.entries[h] = http3OverrideEntry{
		Host:       h,
		ScopeHosts: scopeHosts,
		CreatedAt:  time.Now(),
	}
	if err := s.saveLocked(); err != nil {
		delete(s.entries, h)
		logging.Logf("[webdetector][http3] failed to persist opt-in for %q (rollback): %v (path=%s)", h, err, s.path)
		return false
	}
	return true
}

// Remove deletes an opt-in. Returns true if a row was actually removed.
// scope is enforced at the API layer (scoped tokens can only target hosts
// inside their scope); the store does not re-validate.
//
// Persistence: on save failure the in-memory entry is restored so the
// daemon's view matches disk. Error logged loudly via logging.Logf.
func (s *http3OverrideStore) Remove(host string, _ map[string]struct{}) bool {
	h, ok := s.normalize(host)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, exists := s.entries[h]
	if !exists {
		return false
	}
	delete(s.entries, h)
	if err := s.saveLocked(); err != nil {
		s.entries[h] = prev
		logging.Logf("[webdetector][http3] failed to persist removal of %q (rollback): %v (path=%s)", h, err, s.path)
		return false
	}
	return true
}

// List returns all opt-in rows, sorted by host. Caller MUST treat the
// returned slice as read-only.
func (s *http3OverrideStore) List() []http3OverrideEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]http3OverrideEntry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Hosts returns just the host strings (exact + wildcard) for cheap export
// to the Lua bridge. Sorted for stable JSON output.
func (s *http3OverrideStore) Hosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.entries))
	for h := range s.entries {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// IsEnabled reports whether HTTP/3 should be advertised for this host.
// Matches exact entries first, then wildcard entries via filepath.Match.
// Used only by Go-side callers (Lua does its own lookup against the
// cached config file).
func (s *http3OverrideStore) IsEnabled(host string) bool {
	matched, _, _ := s.MatchInfo(host)
	return matched
}

// MatchInfo returns the same decision as IsEnabled plus the matching
// pattern and whether it was an exact match (vs. wildcard). Used by the
// cfm-admin UI to render the toggle row correctly:
//
//   * exact match  → row is toggleable (operator can flip it off here)
//   * wildcard hit → row is enabled but NOT toggleable (the wildcard
//                    must be edited via CLI; flipping this single host
//                    would be confusing).
//
// CRITICAL: this is the ONLY function the UI should use for deciding
// "is this host opted in?". Earlier versions reused matchHostExclude
// which expanded `cdn.example.com` into a suffix match against every
// subdomain — the Lua data path never honored that, so the UI lied. The
// matching rules here (exact + filepath.Match wildcards) MUST stay in
// step with the Lua glob_match in cfm_h3_config.lua.
func (s *http3OverrideStore) MatchInfo(host string) (matched bool, pattern string, exact bool) {
	h, ok := s.normalize(host)
	if !ok {
		return false, "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ex := s.entries[h]; ex {
		return true, h, true
	}
	for p := range s.entries {
		if !strings.ContainsAny(p, "*?[") {
			continue
		}
		if m, err := filepath.Match(p, h); err == nil && m {
			return true, p, false
		}
	}
	return false, "", false
}

// HasAny is a fast "is any vhost opted in?" check the Lua side can use to
// skip its lookup entirely when the list is empty.
func (s *http3OverrideStore) HasAny() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries) > 0
}

func (s *http3OverrideStore) load() {
	if s == nil || s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var arr []http3OverrideEntry
	if err := json.Unmarshal(b, &arr); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range arr {
		h, ok := s.normalize(e.Host)
		if !ok {
			continue
		}
		if e.CreatedAt.IsZero() {
			e.CreatedAt = time.Now()
		}
		e.Host = h
		e.ScopeHosts = normalizeScopeHosts(e.ScopeHosts)
		s.entries[h] = e
	}
}

func (s *http3OverrideStore) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	arr := make([]http3OverrideEntry, 0, len(s.entries))
	for _, e := range s.entries {
		arr = append(arr, e)
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].Host < arr[j].Host })
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
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}
