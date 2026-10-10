// Package edgeban keeps the bans the edge must enforce itself.
//
// An nft ban (`inet cfm input`, ip saddr @block_v4 drop) never reaches a
// client that comes in through a trusted proxy: on the wire the source is
// the proxy (Cloudflare), and the edge learns the client address from
// CF-Connecting-IP. A scanner banned for 7 days kept hitting sites through
// Cloudflare for half an hour after each ban (2026-10-09). The store holds
// the web-related bans (the WAF / web detector / challenge sections, the
// challenge server's self-protection, manual bans) with their expiry, and
// the bridge's decision answers ip_action=block for them.
//
// It is NOT a mirror of the nft sets: those also hold fleet feeds, cfm.deny,
// port-scan and flood bans (thousands of entries, some of them proxy
// addresses), which the edge must not copy. It only ever narrows to what
// nft still blocks: Reconcile drops an entry nft no longer blocks (expired,
// unblocked from the CLI, flushed) or an allow set now lets through, and
// clamps an expiry to nft's. Unblocks inside the daemon remove the entry at
// once. Anything uncertain fails toward NOT blocking: the store answers
// nothing until its first reconcile, and a disabled store answers nothing.
package edgeban

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/firewall"
)

// DefaultPath is where the daemon persists the store (a restart keeps the
// bans the edge enforces; Reconcile re-checks them against nft before they
// count). A var so tests point it at a temp dir (CLAUDE.md §5: tests never
// touch CFM's live paths).
var DefaultPath = "/var/lib/cfm/edgeban.json"

// SetPathForTest points DefaultPath at path and returns a restore func.
func SetPathForTest(path string) (restore func()) {
	old := DefaultPath
	DefaultPath = path
	return func() { DefaultPath = old }
}

// Entry is one banned address. A zero Expires is permanent.
type Entry struct {
	Expires time.Time `json:"expires,omitempty"`
	Source  string    `json:"source,omitempty"`
}

// Store is the set of edge-enforced bans.
type Store struct {
	mu    sync.RWMutex
	m     map[string]Entry
	path  string
	ready atomic.Bool
	now   func() time.Time
}

var (
	enabled atomic.Bool
	def     atomic.Pointer[Store]
)

func init() { enabled.Store(true) }

// SetEnabled is the [webdetector] EDGE_BAN kill switch: off, Banned answers
// false for every address (the store keeps its entries).
func SetEnabled(on bool) { enabled.Store(on) }

// Enabled reports the kill switch.
func Enabled() bool { return enabled.Load() }

// SetDefault installs the daemon's store; nil uninstalls it.
func SetDefault(s *Store) { def.Store(s) }

// Default is the daemon's store, nil when none is installed (the one-shot
// CLI, tests). Every package-level helper below is a no-op then.
func Default() *Store { return def.Load() }

// New returns an empty store persisted at path ("" = memory only).
func New(path string) *Store {
	return &Store{m: map[string]Entry{}, path: path, now: time.Now}
}

// key normalises an address (IPv4-mapped IPv6 as IPv4); "" if not one.
func key(ip net.IP) string {
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// Add records a ban of ip for ttl (nil or <= 0: permanent). exact replaces
// the entry (a manual ban sets the operator's TTL, as AddBlock does);
// otherwise a longer or permanent entry is kept (as ExtendBlock does).
func (s *Store) Add(ip net.IP, ttl *time.Duration, source string, exact bool) {
	k := key(ip)
	if s == nil || k == "" {
		return
	}
	e := Entry{Source: source}
	if ttl != nil && *ttl > 0 {
		e.Expires = s.now().Add(*ttl)
	}
	s.mu.Lock()
	if old, ok := s.m[k]; ok && !exact && outlasts(old, e) {
		s.mu.Unlock()
		return
	}
	s.m[k] = e
	s.mu.Unlock()
	s.save()
}

// outlasts reports whether a ends no earlier than b.
func outlasts(a, b Entry) bool {
	if a.Expires.IsZero() {
		return true
	}
	if b.Expires.IsZero() {
		return false
	}
	return !a.Expires.Before(b.Expires)
}

// Remove drops ip (an unblock).
func (s *Store) Remove(ip string) {
	if s == nil {
		return
	}
	k := key(net.ParseIP(strings.TrimSpace(ip)))
	if k == "" {
		return
	}
	s.mu.Lock()
	_, had := s.m[k]
	delete(s.m, k)
	s.mu.Unlock()
	if had {
		s.save()
	}
}

// Banned reports whether the edge must block ip, and for how long (0 =
// permanent). False until the first Reconcile, and while switched off.
func (s *Store) Banned(ip string) (bool, time.Duration) {
	if s == nil || !enabled.Load() || !s.ready.Load() {
		return false, 0
	}
	k := key(net.ParseIP(strings.TrimSpace(ip)))
	if k == "" {
		return false, 0
	}
	s.mu.RLock()
	e, ok := s.m[k]
	s.mu.RUnlock()
	if !ok {
		return false, 0
	}
	if e.Expires.IsZero() {
		return true, 0
	}
	left := e.Expires.Sub(s.now())
	if left <= 0 {
		return false, 0
	}
	return true, left
}

// Len is the number of entries (expired ones included until Reconcile).
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// Ready reports whether a Reconcile has run.
func (s *Store) Ready() bool { return s != nil && s.ready.Load() }

// Reconcile narrows the store to what nft still enforces: blocks and allows
// are the block_v4/v6 and allow_v4/v6 host sets as ListBlocks / ListAllows
// return them. An entry nft no longer blocks, or that an allow lets through,
// is dropped; a later nft expiry never extends an entry, an earlier one
// clamps it. Expired entries go. The first call makes the store answer.
func (s *Store) Reconcile(blocks, allows []firewall.BlockedEntry) {
	if s == nil {
		return
	}
	now := s.now()
	inNft := make(map[string]time.Time, len(blocks)) // zero = permanent
	for _, b := range blocks {
		if k := key(b.IP); k != "" {
			var exp time.Time
			if b.Expires != nil {
				exp = *b.Expires
			}
			inNft[k] = exp
		}
	}
	allowed := make(map[string]bool, len(allows))
	for _, a := range allows {
		if k := key(a.IP); k != "" {
			allowed[k] = true
		}
	}
	changed := false
	s.mu.Lock()
	for k, e := range s.m {
		exp, blocked := inNft[k]
		switch {
		case !blocked, allowed[k], !e.Expires.IsZero() && !e.Expires.After(now):
			delete(s.m, k)
			changed = true
		case !exp.IsZero() && (e.Expires.IsZero() || exp.Before(e.Expires)):
			e.Expires = exp
			s.m[k] = e
			changed = true
		}
	}
	s.mu.Unlock()
	s.ready.Store(true)
	if changed {
		s.save()
	}
}

// Load reads the persisted store (missing or unreadable: empty). Entries
// count only after the next Reconcile.
func (s *Store) Load() {
	if s == nil || s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var m map[string]Entry
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	s.mu.Lock()
	for k, e := range m {
		if kk := key(net.ParseIP(k)); kk != "" {
			s.m[kk] = e
		}
	}
	s.mu.Unlock()
}

// save writes the store atomically (temp file + rename). Best effort: a
// failed write only costs the bans a restart would have kept.
func (s *Store) save() {
	if s.path == "" {
		return
	}
	s.mu.RLock()
	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]Entry, len(keys))
	for _, k := range keys {
		out[k] = s.m[k]
	}
	s.mu.RUnlock()
	raw, err := json.Marshal(out)
	if err != nil {
		return
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".edgeban-*")
	if err != nil {
		return
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return
	}
	tmp.Close()
	_ = os.Chmod(tmp.Name(), 0o600)
	if os.Rename(tmp.Name(), s.path) != nil {
		os.Remove(tmp.Name())
	}
}

// ── Package-level helpers on the Default store ────────────────────────────

// WebSection reports whether a detectors.conf section's bans are web
// bans the edge must enforce too (its WAF, web detector, challenge, ModSecurity,
// CFM endpoint and cPanel sections). Mail / SSH / FTP / database bans stay
// nft-only: a proxy relays only HTTP.
func WebSection(section string) bool {
	s := strings.ToLower(strings.TrimSpace(section))
	switch s {
	case "waf_security", "webdetector", "modsec", "cfm_endpoints", "cpanel":
		return true
	}
	return strings.HasPrefix(s, "challenge_") || strings.HasPrefix(s, "waf_security.")
}

// Ban records a ban in the Default store (no-op without one).
func Ban(ip net.IP, ttl *time.Duration, source string, exact bool) {
	Default().Add(ip, ttl, source, exact)
}

// Unban drops ip from the Default store (no-op without one).
func Unban(ip string) { Default().Remove(ip) }

// IsBanned asks the Default store (false without one).
func IsBanned(ip string) (bool, time.Duration) { return Default().Banned(ip) }
