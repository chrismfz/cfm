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
// unblocked from the CLI, flushed), and clamps an expiry to nft's. An
// address any nft allow set accepts (hosts, nets, the fleet whitelist) is
// never answered, as nft accepts it before any drop. Unblocks inside the
// daemon remove the entry at once. The bridge answers it only for a request
// that came through a trusted proxy: a direct client is nft's alone. Anything
// uncertain fails toward NOT blocking: the store answers nothing until its
// first reconcile, and a disabled store answers nothing.
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
	// Added is when the entry was last written: a reconcile never drops an
	// entry written after its nft read began (the read predates the ban).
	Added time.Time `json:"added,omitempty"`
}

// Store is the set of edge-enforced bans.
type Store struct {
	mu    sync.RWMutex
	m     map[string]Entry
	path  string
	ready atomic.Bool
	// cleared: Clear ran (nft unreadable, the table gone after `cfm
	// disable`) and no reconcile has worked since. Unlike a store that
	// never reconciled after a start, it knows its bans are not to be
	// enforced: the edge's copy is emptied, not kept.
	cleared atomic.Bool
	now     func() time.Time
	allow   atomic.Pointer[allowSet] // nft's allow sets at the last reconcile
	saveMu  sync.Mutex               // one save at a time: snapshot, write, rename
}

var (
	// version changes whenever what List could return may have changed: a
	// write to a store, a reconcile, the kill switch, the proxy ranges, the
	// Default store. The edge feed caches on it (internal/webdetector).
	version  atomic.Uint64
	enabled  atomic.Bool
	edgeMode atomic.Value // string, see EdgeMode
	def      atomic.Pointer[Store]
	proxies  atomic.Pointer[[]*net.IPNet] // the trusted proxies' own ranges
)

// SetTrustedProxies sets the ranges the edge trusts to name the client
// (trusted_proxies.conf). An address in them is never answered: realip
// leaves remote_addr at a proxy address when CF-Connecting-IP itself names
// one (a Cloudflare Worker's subrequest), so a ban of that address would
// 403 every visitor who arrives the same way.
func SetTrustedProxies(nets []*net.IPNet) {
	cp := append([]*net.IPNet(nil), nets...)
	proxies.Store(&cp)
	version.Add(1)
}

// Version changes whenever List's answer may have (expiry aside: an entry
// that expires drops out of List with no write).
func Version() uint64 { return version.Load() }

func isTrustedProxy(ip net.IP) bool {
	p := proxies.Load()
	if p == nil {
		return false
	}
	for _, n := range *p {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies reads `set_real_ip_from <cidr|ip>;` lines (the
// trusted_proxies.conf format); anything else is skipped.
func ParseTrustedProxies(text string) []*net.IPNet {
	var out []*net.IPNet
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || f[0] != "set_real_ip_from" {
			continue
		}
		v := strings.TrimSuffix(f[1], ";")
		if !strings.Contains(v, "/") {
			if ip := net.ParseIP(v); ip != nil {
				if ip.To4() != nil {
					v += "/32"
				} else {
					v += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(v); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func init() { enabled.Store(true) }

// SetEnabled is the [webdetector] EDGE_BAN kill switch: off, Banned answers
// false for every address (the store keeps its entries).
func SetEnabled(on bool) {
	if enabled.Swap(on) != on {
		version.Add(1)
	}
}

// EdgeMode is how the edge treats a banned proxied client at cfm.lua's top
// and on the static location ([webdetector] EDGE_BAN_MODE): "log" (count and
// log what it would block; the burn-in default) or "enforce" (403). The
// bridge decision path answers bans either way (EDGE_BAN alone gates it).
func EdgeMode() string {
	if m, _ := edgeMode.Load().(string); m == "enforce" {
		return m
	}
	return "log"
}

// SetEdgeMode sets EdgeMode; anything but "enforce" is "log".
func SetEdgeMode(m string) {
	if strings.EqualFold(strings.TrimSpace(m), "enforce") {
		edgeMode.Store("enforce")
		return
	}
	edgeMode.Store("log")
}

// Enabled reports the kill switch.
func Enabled() bool { return enabled.Load() }

// SetDefault installs the daemon's store; nil uninstalls it.
func SetDefault(s *Store) {
	def.Store(s)
	version.Add(1)
}

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
	e := Entry{Source: source, Added: s.now()}
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
	addr := net.ParseIP(strings.TrimSpace(ip))
	k := key(addr)
	if k == "" {
		return false, 0
	}
	s.mu.RLock()
	e, ok := s.m[k]
	s.mu.RUnlock()
	if !ok {
		return false, 0
	}
	return s.answers(addr, e, s.now())
}

// answers is Banned for an entry the store holds.
func (s *Store) answers(addr net.IP, e Entry, now time.Time) (bool, time.Duration) {
	// nft accepts an allowed address before any block drop: so does the edge.
	if a := s.allow.Load(); a != nil && a.contains(addr) {
		return false, 0
	}
	if isTrustedProxy(addr) {
		return false, 0
	}
	if e.Expires.IsZero() {
		return true, 0
	}
	left := e.Expires.Sub(now)
	if left <= 0 {
		return false, 0
	}
	return true, left
}

// Item is one address the edge must block (List). A zero Expires is
// permanent.
type Item struct {
	IP      string
	Expires time.Time
}

// List returns every address Banned answers true for now, sorted by
// address: the feed the edge pulls (/nginx/edgeban). Empty until the first
// Reconcile and while switched off, as Banned.
func (s *Store) List() []Item {
	if s == nil || !enabled.Load() || !s.ready.Load() {
		return nil
	}
	now := s.now()
	// Copy under the lock, check outside it: the allow sets are scanned per
	// entry, and a writer waiting on a long read lock would stall every
	// Banned() behind it (Go's writer preference) on the decision hot path.
	s.mu.RLock()
	all := make([]Item, 0, len(s.m))
	ents := make([]Entry, 0, len(s.m))
	for k, e := range s.m {
		all = append(all, Item{IP: k, Expires: e.Expires})
		ents = append(ents, e)
	}
	s.mu.RUnlock()
	out := all[:0]
	for i, it := range all {
		if ok, _ := s.answers(net.ParseIP(it.IP), ents[i], now); ok {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
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

// Cleared reports whether Clear ran with no reconcile working since.
func (s *Store) Cleared() bool { return s != nil && s.cleared.Load() }

// Ready reports whether a Reconcile has run.
func (s *Store) Ready() bool { return s != nil && s.ready.Load() }

// Snapshot is one read of nft for Reconcile: the block host sets
// (block_v4/v6, with remaining TTLs) and every allow set (hosts, nets and
// ranges, as ListSetElementsTimed prints them), read starting at ReadAt.
type Snapshot struct {
	Blocks []firewall.SetElementTimed
	Allows []string
	ReadAt time.Time
}

// Reconcile narrows the store to what nft still enforces, from a COMPLETE
// read (the caller skips it on any read error: an empty or partial read
// would drop real bans). An entry nft no longer blocks is dropped unless it
// was written after the read began (a ban landing mid-read); one an allow
// covers is dropped; a later nft expiry never extends an entry, an earlier
// one clamps it; expired entries go. The allow sets are kept for Banned, and
// the first call makes the store answer.
func (s *Store) Reconcile(snap Snapshot) {
	if s == nil {
		return
	}
	now := s.now()
	inNft := make(map[string]time.Time, len(snap.Blocks)) // zero = permanent
	for _, b := range snap.Blocks {
		if k := key(net.ParseIP(strings.TrimSpace(b.Elem))); k != "" {
			var exp time.Time
			if b.Expires > 0 {
				exp = now.Add(b.Expires)
			}
			inNft[k] = exp
		}
	}
	allow := parseAllowSet(snap.Allows)
	s.allow.Store(allow)
	changed := false
	s.mu.Lock()
	for k, e := range s.m {
		exp, blocked := inNft[k]
		fresh := !snap.ReadAt.IsZero() && !e.Added.Before(snap.ReadAt)
		switch {
		case !e.Expires.IsZero() && !e.Expires.After(now):
			delete(s.m, k)
			changed = true
		case allow.contains(net.ParseIP(k)):
			delete(s.m, k)
			changed = true
		case !blocked && !fresh:
			delete(s.m, k)
			changed = true
		case blocked && !exp.IsZero() && (e.Expires.IsZero() || e.Expires.Sub(exp) > time.Second):
			// nft ends earlier (more than a second: its own clock): clamp.
			e.Expires = exp
			s.m[k] = e
			changed = true
		}
	}
	s.mu.Unlock()
	s.ready.Store(true)
	s.cleared.Store(false)
	version.Add(1) // the allow sets and readiness, even with no entry changed
	if changed {
		s.save()
	}
}

// Clear empties the store and makes it answer nothing until the next
// Reconcile (the caller decided nft cannot be read).
func (s *Store) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	had := len(s.m) > 0
	s.m = map[string]Entry{}
	s.mu.Unlock()
	// Not ready again, and no allow snapshot: a ban added while nft cannot be
	// read is never answered unchecked.
	s.ready.Store(false)
	s.cleared.Store(true)
	version.Add(1)
	s.allow.Store(nil)
	if had {
		s.save()
	}
}

// allowSet matches the addresses nft's allow sets accept: hosts, CIDRs and
// first-last ranges.
type allowSet struct {
	hosts  map[string]bool
	nets   []*net.IPNet
	ranges [][2]net.IP
}

func parseAllowSet(elems []string) *allowSet {
	a := &allowSet{hosts: map[string]bool{}}
	for _, raw := range elems {
		e := strings.TrimSpace(raw)
		switch {
		case e == "":
		case strings.Contains(e, "/"):
			if _, n, err := net.ParseCIDR(e); err == nil {
				a.nets = append(a.nets, n)
			}
		case strings.Contains(e, "-"):
			parts := strings.SplitN(e, "-", 2)
			lo, hi := net.ParseIP(strings.TrimSpace(parts[0])), net.ParseIP(strings.TrimSpace(parts[1]))
			if lo != nil && hi != nil {
				a.ranges = append(a.ranges, [2]net.IP{norm(lo), norm(hi)})
			}
		default:
			if k := key(net.ParseIP(e)); k != "" {
				a.hosts[k] = true
			}
		}
	}
	return a
}

func norm(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

func (a *allowSet) contains(ip net.IP) bool {
	if a == nil || ip == nil {
		return false
	}
	if a.hosts[key(ip)] {
		return true
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	n := norm(ip)
	for _, r := range a.ranges {
		if len(r[0]) == len(n) && bytesCompare(r[0], n) <= 0 && bytesCompare(n, r[1]) <= 0 {
			return true
		}
	}
	return false
}

func bytesCompare(a, b net.IP) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
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
	version.Add(1)
}

// save writes the store atomically (temp file + rename), one save at a time
// so an older snapshot never lands after a newer one. Best effort: a failed
// write only costs the bans a restart would have kept.
func (s *Store) save() {
	version.Add(1)
	if s.path == "" {
		return
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.RLock()
	raw, err := json.Marshal(s.m)
	s.mu.RUnlock()
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".edgeban-*")
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
	return strings.HasPrefix(s, "challenge_")
}

// Ban records a ban in the Default store (no-op without one).
func Ban(ip net.IP, ttl *time.Duration, source string, exact bool) {
	Default().Add(ip, ttl, source, exact)
}

// Unban drops ip from the Default store (no-op without one).
func Unban(ip string) { Default().Remove(ip) }

// IsBanned asks the Default store (false without one).
func IsBanned(ip string) (bool, time.Duration) { return Default().Banned(ip) }

// List is the Default store's List (nil without one).
func List() []Item { return Default().List() }
