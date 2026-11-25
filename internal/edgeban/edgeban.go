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
//
// An entry is what nft blocks: an address, or the /64 an automatic ban of an
// IPv6 client takes (firewall.ExtendClientBlock; docs/edge-ipv6.md "IPv6 /64
// grouping"), keyed as ipkey prints it ("2001:db8:1:2::/64"). A /64 that an
// allow set or a trusted proxy range overlaps, even in part, is never
// answered: the edge cannot tell the allowed address from the rest of it.
package edgeban

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/ipkey"
	"cfm/internal/logging"
	"cfm/internal/proxyipfilter"
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
	// saveDelay > 0 (SetSaveDelay) coalesces the file writes: a change marks
	// the store dirty and one write follows saveDelay later; Flush writes
	// now. 0 writes on every change.
	saveDelay time.Duration
	dirty     atomic.Bool
}

var (
	// version changes whenever what List could return may have changed: a
	// write to a store, a reconcile, the kill switch, the proxy ranges, the
	// Default store. The edge feed caches on it (internal/webdetector).
	version  atomic.Uint64
	enabled  atomic.Bool
	edgeMode atomic.Value // string, see EdgeMode
	def      atomic.Pointer[Store]
	proxies  atomic.Pointer[allowSet] // the trusted proxies' own ranges, searched like the allow sets
)

// SetTrustedProxies sets the ranges the edge trusts to name the client
// (trusted_proxies.conf). An address in them is never answered: realip
// leaves remote_addr at a proxy address when CF-Connecting-IP itself names
// one (a Cloudflare Worker's subrequest), so a ban of that address would
// 403 every visitor who arrives the same way.
func SetTrustedProxies(nets []*net.IPNet) {
	a := &allowSet{}
	for _, n := range nets {
		a.addNet(n)
	}
	a.merge()
	proxies.Store(a)
	// Nor does nft ban a proxy's whole /64 (a detector that saw the proxy's
	// own address): firewall/client_block.go bans the address instead.
	firewall.SetClientNetExempt("trusted_proxies", func(p netip.Prefix) bool { return proxies.Load().overlaps(p) })
	markAll()
	version.Add(1)
}

// Version changes whenever List's answer may have (expiry aside: an entry
// that expires drops out of List with no write).
func Version() uint64 { return version.Load() }

// IsTrustedProxy reports whether ip is in the trusted proxies' own ranges
// (SetTrustedProxies): an address the edge only sees when the proxy named
// itself, which stands for every visitor who arrives the same way.
func IsTrustedProxy(ip net.IP) bool { return isTrustedProxy(ip) }

func isTrustedProxy(ip net.IP) bool {
	return proxies.Load().contains(ip)
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

// registerAllowExempt tells the firewall, once the Default store holds an
// allow snapshot, that a /64 the allow sets touch (the fleet whitelist
// included) is never banned as a whole: the edge would never answer it
// (answers) and the TTL restore drops it, so nft bans the address instead
// (firewall/client_block.go). Until then (and after Clear) the firewall reads
// the fleet whitelist sets itself.
func (s *Store) registerAllowExempt(on bool) {
	if s == nil || s != Default() {
		return
	}
	if !on {
		firewall.SetClientNetExempt("allow_sets", nil)
		return
	}
	firewall.SetClientNetExempt("allow_sets", func(p netip.Prefix) bool {
		d := Default()
		if d == nil {
			return false
		}
		a := d.allow.Load()
		return a != nil && a.overlaps(p)
	})
}

// SetEnabled is the [webdetector] EDGE_BAN kill switch: off, Banned answers
// false for every address (the store keeps its entries).
func SetEnabled(on bool) {
	if enabled.Swap(on) != on {
		markAll()
		version.Add(1)
	}
}

// EdgeMode is how the edge treats a banned proxied client at cfm.lua's top
// and on the static location ([webdetector] EDGE_BAN_MODE): "enforce" (403,
// the default since 2026-11-10) or "log" (count and log what it would block,
// as the burn-in ran). The bridge decision path answers bans either way
// (EDGE_BAN alone gates it).
func EdgeMode() string {
	if m, _ := edgeMode.Load().(string); m == "log" {
		return m
	}
	return "enforce"
}

// SetEdgeMode sets EdgeMode: "enforce", or empty (the key left out), is
// enforce; "log" is log. Any other value is a typo for something the
// operator meant (logonly, dryrun, off): it logs instead of enforcing, and
// says so, rather than start 403ing on a misspelt observe-only setting.
func SetEdgeMode(m string) {
	switch v := strings.ToLower(strings.TrimSpace(m)); v {
	case "", "enforce":
		edgeMode.Store("enforce")
	case "log":
		edgeMode.Store("log")
	default:
		logging.Logf("[edgeban] EDGE_BAN_MODE = %q is neither enforce nor log: logging only", m)
		edgeMode.Store("log")
	}
}

// Enabled reports the kill switch.
func Enabled() bool { return enabled.Load() }

// SetDefault installs the daemon's store; nil uninstalls it.
func SetDefault(s *Store) {
	def.Store(s)
	markAll()
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

// keyOf is the key of a ban element: an address (key), or an IPv6 client's
// /64 exactly as ipkey groups it, in its text. Any other CIDR is no
// edge ban ("").
func keyOf(elem string) string {
	elem = strings.TrimSpace(elem)
	if !strings.Contains(elem, "/") {
		return key(net.ParseIP(elem))
	}
	p, err := netip.ParsePrefix(elem)
	if err != nil {
		return ""
	}
	if g, ok := ipkey.Prefix(p.Addr()); !ok || g != p {
		return ""
	}
	return p.String()
}

// clientKey is the /64 key of addr when ipkey groups it, else "".
func clientKey(addr net.IP) string {
	a, ok := netip.AddrFromSlice(addr)
	if !ok {
		return ""
	}
	if p, grouped := ipkey.Prefix(a.Unmap()); grouped {
		return p.String()
	}
	return ""
}

// Add records a ban of ip for ttl (nil or <= 0: permanent). exact replaces
// the entry (a manual ban sets the operator's TTL, as AddBlock does);
// otherwise a longer or permanent entry is kept (as ExtendBlock does).
func (s *Store) Add(ip net.IP, ttl *time.Duration, source string, exact bool) {
	s.add(key(ip), ttl, source, exact)
}

// AddElem is Add for a ban element as firewall.ExtendClientBlock names it:
// an address or an IPv6 client's /64.
func (s *Store) AddElem(elem string, ttl *time.Duration, source string, exact bool) {
	s.add(keyOf(elem), ttl, source, exact)
}

func (s *Store) add(k string, ttl *time.Duration, source string, exact bool) {
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
	markKeys(k)
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

// Remove drops ip (an unblock): the address, and the /64 ban of its client
// (unblocking an IPv6 address frees its /64, which is the client). A /64
// key itself is accepted too.
func (s *Store) Remove(ip string) {
	if s == nil {
		return
	}
	keys := []string{keyOf(ip)}
	if addr := net.ParseIP(strings.TrimSpace(ip)); addr != nil {
		keys = append(keys, clientKey(addr))
	}
	var gone []string
	s.mu.Lock()
	for _, k := range keys {
		if k == "" {
			continue
		}
		if _, ok := s.m[k]; ok {
			gone = append(gone, k)
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
	if len(gone) > 0 {
		markKeys(gone...)
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
	ck := clientKey(addr)
	s.mu.RLock()
	e, ok := s.m[k]
	ce, cok := Entry{}, false
	if ck != "" {
		ce, cok = s.m[ck]
	}
	s.mu.RUnlock()
	now := s.now()
	if ok {
		if b, left := s.answers(k, e, now); b {
			return b, left
		}
	}
	if cok {
		return s.answers(ck, ce, now)
	}
	return false, 0
}

// answers is Banned for an entry the store holds under k (an address or a
// /64).
func (s *Store) answers(k string, e Entry, now time.Time) (bool, time.Duration) {
	if p, err := netip.ParsePrefix(k); err == nil {
		// A /64: never answered when an allow or a trusted proxy range
		// touches any of it (the edge cannot tell those addresses apart).
		if a := s.allow.Load(); a != nil && a.overlaps(p) {
			return false, 0
		}
		if proxies.Load().overlaps(p) {
			return false, 0
		}
	} else {
		addr := net.ParseIP(k)
		// nft accepts an allowed address before any block drop: so does the edge.
		if a := s.allow.Load(); a != nil && a.contains(addr) {
			return false, 0
		}
		if isTrustedProxy(addr) {
			return false, 0
		}
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

// List returns every address Banned answers true for now, in no particular
// order: the feed the edge pulls (/nginx/edgeban), which puts it in a map.
// Empty until the first Reconcile and while switched off, as Banned.
func (s *Store) List() []Item {
	if s == nil || !enabled.Load() || !s.ready.Load() {
		return nil
	}
	now := s.now()
	// Copy under the lock, check outside it: every entry is checked against
	// the allow sets and the trusted proxies, and a writer waiting on a long
	// read lock would stall every Banned() behind it (Go's writer
	// preference) on the decision hot path.
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
		if ok, _ := s.answers(it.IP, ents[i], now); ok {
			out = append(out, it)
		}
	}
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
		if k := keyOf(b.Elem); k != "" {
			var exp time.Time
			if b.Expires > 0 {
				exp = now.Add(b.Expires)
			}
			inNft[k] = exp
		}
	}
	allow := parseAllowSet(snap.Allows)
	old := s.allow.Swap(allow)
	s.registerAllowExempt(true)
	var changed []string
	s.mu.Lock()
	for k, e := range s.m {
		exp, blocked := inNft[k]
		fresh := !snap.ReadAt.IsZero() && !e.Added.Before(snap.ReadAt)
		switch {
		case !e.Expires.IsZero() && !e.Expires.After(now):
			delete(s.m, k)
			changed = append(changed, k)
		case allow.coversKey(k):
			delete(s.m, k)
			changed = append(changed, k)
		case !blocked && !fresh:
			delete(s.m, k)
			changed = append(changed, k)
		case blocked && !exp.IsZero() && (e.Expires.IsZero() || e.Expires.Sub(exp) > time.Second):
			// nft ends earlier (more than a second: its own clock): clamp.
			e.Expires = exp
			s.m[k] = e
			changed = append(changed, k)
		}
	}
	s.mu.Unlock()
	wasReady, wasCleared := s.ready.Swap(true), s.cleared.Swap(false)
	// The answers can move without an entry changing: readiness, or the
	// allow sets. Those move every answer at once (a new generation of the
	// change log); a reconcile that changed nothing leaves the version
	// alone, or every 2 minute reconcile rebuilt the edge's list.
	moved := !wasReady || wasCleared || !allow.equal(old)
	if moved {
		markAll()
	} else {
		markKeys(changed...)
	}
	if len(changed) > 0 {
		s.save() // bumps the version
	} else if moved {
		version.Add(1)
	}
}

// Clear makes the store answer nothing, to the edge too, until the next
// Reconcile (the caller decided nft cannot be read: three failed reads, the
// table gone after `cfm disable`). It keeps the entries: List and Banned
// answer nothing while not ready, and a reconcile that works again narrows
// them to what nft still blocks, so a transient read failure does not throw
// away bans nft still holds.
func (s *Store) Clear() {
	if s == nil {
		return
	}
	// Not ready again, and no allow snapshot: a ban added while nft cannot be
	// read is never answered unchecked.
	s.ready.Store(false)
	s.cleared.Store(true)
	s.allow.Store(nil)
	s.registerAllowExempt(false)
	markAll()
	version.Add(1)
}

// allowSet matches the addresses nft's allow sets accept: hosts, CIDRs and
// first-last ranges, all merged into sorted, non-overlapping intervals per
// family and looked up by binary search. The edge ban list checks every ban
// against them on each resync, and a linear scan of a few hundred allow nets
// over ~23 000 bans took 100+ ms (mars, 2026-11-10; BenchmarkList). The
// trusted proxies' ranges use it too.
type allowSet struct {
	v4 []span4
	v6 []span6
}

type span4 struct{ lo, hi uint32 }

type span6 struct{ lo, hi [16]byte }

func parseAllowSet(elems []string) *allowSet {
	a := &allowSet{}
	for _, raw := range elems {
		e := strings.TrimSpace(raw)
		switch {
		case e == "":
		case strings.Contains(e, "/"):
			if _, n, err := net.ParseCIDR(e); err == nil {
				a.addNet(n)
			}
		case strings.Contains(e, "-"):
			parts := strings.SplitN(e, "-", 2)
			lo, hi := net.ParseIP(strings.TrimSpace(parts[0])), net.ParseIP(strings.TrimSpace(parts[1]))
			if lo != nil && hi != nil {
				a.add(norm(lo), norm(hi))
			}
		default:
			// key() refuses the unspecified address, as the old host map did.
			if ip := net.ParseIP(e); ip != nil && !ip.IsUnspecified() {
				a.add(norm(ip), norm(ip))
			}
		}
	}
	a.merge()
	return a
}

// addNet records a CIDR as net.IPNet.Contains reads it: a v4-mapped v6 CIDR
// is a v4 one. A mask that is not a prefix (only an IPNet built by hand; a
// parsed CIDR always is one) is no single interval and is skipped.
func (a *allowSet) addNet(n *net.IPNet) {
	if n == nil {
		return
	}
	ip, m := n.IP.To4(), n.Mask
	if ip == nil {
		ip = n.IP
	}
	if len(m) == net.IPv6len && len(ip) == net.IPv4len {
		m = m[12:]
	}
	if len(m) != len(ip) {
		return
	}
	if ones, bits := m.Size(); ones == 0 && bits == 0 {
		return // not a prefix: no single interval
	}
	lo, hi := make(net.IP, len(ip)), make(net.IP, len(ip))
	for i := range ip {
		lo[i] = ip[i] & m[i]
		hi[i] = lo[i] | ^m[i]
	}
	a.add(lo, hi)
}

// equal reports whether a and b answer the same (nil is empty).
func (a *allowSet) equal(b *allowSet) bool {
	var av4, bv4 []span4
	var av6, bv6 []span6
	if a != nil {
		av4, av6 = a.v4, a.v6
	}
	if b != nil {
		bv4, bv6 = b.v4, b.v6
	}
	return slices.Equal(av4, bv4) && slices.Equal(av6, bv6)
}

// merge sorts and merges the spans (parseAllowSet, after the adds).
func (a *allowSet) merge() {
	a.v4 = mergeSpans(a.v4, func(x, y span4) bool { return x.lo < y.lo },
		func(cur *span4, next span4) bool {
			if cur.hi == ^uint32(0) || next.lo <= cur.hi+1 {
				if next.hi > cur.hi {
					cur.hi = next.hi
				}
				return true
			}
			return false
		})
	a.v6 = mergeSpans(a.v6, func(x, y span6) bool { return bytes.Compare(x.lo[:], y.lo[:]) < 0 },
		func(cur *span6, next span6) bool {
			if bytes.Compare(next.lo[:], cur.hi[:]) <= 0 || adjacent6(cur.hi, next.lo) {
				if bytes.Compare(next.hi[:], cur.hi[:]) > 0 {
					cur.hi = next.hi
				}
				return true
			}
			return false
		})
}

// add records the interval lo-hi of one family (4 or 16 bytes, as a v4 or
// v6 CIDR parses and as norm gives them). A range whose ends are of two
// families, or whose ends are reversed, matches nothing (the linear code
// before 2026-11-10 compared a mixed range's v4 probe with the first bytes of
// its v6 end).
func (a *allowSet) add(lo, hi net.IP) {
	switch {
	case len(lo) == 4 && len(hi) == 4:
		l, h := binary.BigEndian.Uint32(lo), binary.BigEndian.Uint32(hi)
		if l <= h {
			a.v4 = append(a.v4, span4{l, h})
		}
	case len(lo) == 16 && len(hi) == 16:
		var sp span6
		copy(sp.lo[:], lo)
		copy(sp.hi[:], hi)
		if bytes.Compare(sp.lo[:], sp.hi[:]) <= 0 {
			a.v6 = append(a.v6, sp)
		}
	}
}

// adjacent6 reports whether b is a+1.
func adjacent6(a, b [16]byte) bool {
	for i := 15; i >= 0; i-- {
		if a[i] != 0xff {
			a[i]++
			return a == b
		}
		a[i] = 0
	}
	return false // a was the last address
}

// mergeSpans sorts spans by start and merges overlapping or adjacent ones
// (join extends cur by next when they touch).
func mergeSpans[T any](spans []T, less func(x, y T) bool, join func(cur *T, next T) bool) []T {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool { return less(spans[i], spans[j]) })
	out := spans[:1]
	for _, sp := range spans[1:] {
		if !join(&out[len(out)-1], sp) {
			out = append(out, sp)
		}
	}
	return out
}

func norm(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// overlaps reports whether any address of p is in the set.
func (a *allowSet) overlaps(p netip.Prefix) bool {
	if a == nil || !p.IsValid() {
		return false
	}
	lo, hi, ok := firewall.ElemRange(p.String())
	if !ok {
		return false
	}
	if lo.Is4() {
		l, h := lo.As4(), hi.As4()
		ql, qh := binary.BigEndian.Uint32(l[:]), binary.BigEndian.Uint32(h[:])
		i := sort.Search(len(a.v4), func(i int) bool { return a.v4[i].lo > qh }) - 1
		return i >= 0 && a.v4[i].hi >= ql
	}
	ql, qh := lo.As16(), hi.As16()
	i := sort.Search(len(a.v6), func(i int) bool { return bytes.Compare(a.v6[i].lo[:], qh[:]) > 0 }) - 1
	return i >= 0 && bytes.Compare(a.v6[i].hi[:], ql[:]) >= 0
}

// coversKey: for an address key, the set holds it; for a /64 key, the set
// touches any of it (Reconcile drops such an entry, as answers never
// answers it).
func (a *allowSet) coversKey(k string) bool {
	if p, err := netip.ParsePrefix(k); err == nil {
		return a.overlaps(p)
	}
	return a.contains(net.ParseIP(k))
}

func (a *allowSet) contains(ip net.IP) bool {
	if a == nil || ip == nil {
		return false
	}
	n := norm(ip)
	if len(n) == 4 {
		v := binary.BigEndian.Uint32(n)
		i := sort.Search(len(a.v4), func(i int) bool { return a.v4[i].lo > v }) - 1
		return i >= 0 && v <= a.v4[i].hi
	}
	if len(n) != 16 {
		return false
	}
	var v [16]byte
	copy(v[:], n)
	i := sort.Search(len(a.v6), func(i int) bool { return bytes.Compare(a.v6[i].lo[:], v[:]) > 0 }) - 1
	return i >= 0 && bytes.Compare(v[:], a.v6[i].hi[:]) <= 0
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
		if kk := keyOf(k); kk != "" {
			s.m[kk] = e
		}
	}
	s.mu.Unlock()
	markAll()
	version.Add(1)
}

// SetSaveDelay makes the store coalesce its file writes (see save): at most
// one write per d, and Flush for the rest. Set it before the store is used.
func (s *Store) SetSaveDelay(d time.Duration) {
	if s != nil {
		s.saveDelay = d
	}
}

// save records a change: the version moves at once (the edge's next poll sees
// it), and the file is written now, or once saveDelay later when that is set.
// Every write marshals the whole store: with 50 000 bans that was 7 MB per
// automatic ban, a tenth of the daemon's CPU on the busiest nodes
// (2026-11-24). The file only matters to the next start, so the daemon
// coalesces the writes and flushes on a stop signal.
func (s *Store) save() {
	version.Add(1)
	if s.path == "" {
		return
	}
	if s.saveDelay > 0 {
		if s.dirty.CompareAndSwap(false, true) {
			time.AfterFunc(s.saveDelay, s.Flush)
		}
		return
	}
	s.write()
}

// Flush writes a change that save deferred; a no-op when nothing waits.
func (s *Store) Flush() {
	if s == nil || !s.dirty.CompareAndSwap(true, false) {
		return
	}
	s.write()
}

// write saves the store atomically (temp file + rename), one write at a time
// so an older snapshot never lands after a newer one. Best effort: a failed
// write only costs the bans a restart would have kept.
func (s *Store) write() {
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
// CFM endpoint, cPanel and login brute-force sections). Mail / SSH / FTP / database bans stay
// nft-only: a proxy relays only HTTP.
func WebSection(section string) bool {
	s := strings.ToLower(strings.TrimSpace(section))
	switch s {
	case "waf_security", "webdetector", "modsec", "cfm_endpoints", "cpanel", "login_bruteforce":
		return true
	}
	if strings.HasPrefix(s, "challenge_") {
		return true
	}
	// An instance of the type ("login_bruteforce:strict", or with a space).
	if typ, _, cut := strings.Cut(strings.NewReplacer("\t", " ", ":", " ").Replace(s), " "); cut {
		return typ == "login_bruteforce"
	}
	return false
}

// Ban records a ban in the Default store (no-op without one).
func Ban(ip net.IP, ttl *time.Duration, source string, exact bool) {
	Default().Add(ip, ttl, source, exact)
}

// BanElem records in the Default store (no-op without one) a ban of the
// element nft now blocks, as firewall.ExtendClientBlock / BlockClientPermanent
// return it: an address or an IPv6 client's /64.
func BanElem(elem string, ttl *time.Duration, source string) {
	Default().AddElem(elem, ttl, source, false)
}

// Unban drops ip from the Default store (no-op without one), and clears it
// from the proxied-client IP filter's lists until they are next read
// (internal/proxyipfilter): every unblock and allow path calls Unban, and the
// address must stop being blocked behind a trusted proxy as soon as nft stops
// dropping it.
func Unban(ip string) {
	Default().Remove(ip)
	// The address only: forgetting its whole /64 there would lift every
	// source (the fleet blacklist, other addresses' own bans) for the /64.
	// Other addresses of an unblocked /64 ban stay filtered until the
	// filter's next read of the sets (proxyipfilter.LocalRefreshEvery).
	proxyipfilter.Forget(ip)
}

// IsBanned asks the Default store (false without one).
func IsBanned(ip string) (bool, time.Duration) { return Default().Banned(ip) }

// List is the Default store's List (nil without one).
func List() []Item { return Default().List() }

// AddrOverlapMatcher is AddrMatcher for a network: it reports whether any
// address of the prefix is in the elements (the TTL ban restore's test for
// an IPv6 client /64).
func AddrOverlapMatcher(elems []string) func(netip.Prefix) bool {
	a := parseAllowSet(elems)
	return a.overlaps
}

// AddrMatcher returns a matcher for nft set elements as nft lists them
// (hosts, CIDRs, first-last ranges), the one edge ban reconcile uses for the
// allow sets. The daemon's TTL ban restore (internal/ttlban) shares it.
func AddrMatcher(elems []string) func(net.IP) bool {
	return parseAllowSet(elems).contains
}
