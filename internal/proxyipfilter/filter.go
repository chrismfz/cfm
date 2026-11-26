// Package proxyipfilter gives a client behind a trusted proxy (Cloudflare) the
// verdict CFM's nft IP filter would give it if it came direct.
//
// nft sees the proxy's address, never the visitor's, so the fleet blacklist
// (cfm-web's MYBLOCK feed, 267 782 addresses on earth), the node's own bans
// (block_v4: cfm.deny, detector TTL bans) and the allows never apply to a
// proxied visitor. The edge ban store (internal/edgeban) covers only the
// node's web-related bans, and by design holds no fleet feed: 268 k entries in
// the edge's Lua copy is the regression ruled out (its dict is sized for 20 k).
// On earth (2026-11-17) addresses another node had fleet-banned for WAF hits
// (orion: WAF/WEBSHELL, virgo: WAF/CVE-2025-11833) reached the origin through
// Cloudflare with 200/301/404 (docs/proxied-ipfilter.md).
//
// So the lists live here, in the daemon's memory, and the nginx bridge's
// decision for a proxied request (px=1) asks Decide: no list in Lua, no extra
// round trip (the edge asks the bridge for every request it has no cached
// clean allow for, and a block is never cached). The verdict follows the order
// of the `inet cfm input` chain: every allow set accepts before any block set
// drops, so an allow only cancels a block here. It never exempts the request
// from the WAF or a challenge, exactly as an nft allow does not for a direct
// client.
//
// Sources: feeds (blocklists.Manager hands each applied feed over, BLOCK and
// ALLOW; a CHALLENGE feed is kept apart, for every web client, direct or not:
// challenge.go) and the node's local sets, read from the kernel every minute
// (StartLocalRefresh). Each block source belongs to a group with its own mode,
// [webdetector] PROXIED_IPFILTER_FEED and PROXIED_IPFILTER_LOCAL: log (FEED's
// default: a line per client says which lists it is on and what would happen,
// nothing changes), enforce (the bridge answers ip_action=block), off.
package proxyipfilter

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/logging"
)

// Groups a block source belongs to, each with its own mode.
const (
	GroupFeed  = "feed"
	GroupLocal = "local"
)

// Modes.
const (
	ModeOff     = "off"
	ModeLog     = "log"
	ModeEnforce = "enforce"
)

type source struct {
	label string // what the log names: "feed:MYBLOCK", "block_v4", "allow_dyn_v4"
	group string // GroupFeed / GroupLocal for a block source; "" for an allow
	allow bool
	// challenge: a CHALLENGE feed (challenge.go), never a block source.
	challenge bool
	t         table
}

type snapshot struct {
	blocks, allows, challenges []*source
}

var (
	mu     sync.Mutex
	feeds  = map[string]*source{} // by feed name
	locals = map[string]*source{} // by set name
	cur    atomic.Pointer[snapshot]

	// forgotten: addresses an unblock or allow just cleared (Forget), each with
	// the time the override ends. Outside the snapshot, so a mass unblock (5 000
	// edgeban.Unban calls) is 5 000 map stores, not 5 000 snapshot copies;
	// nForgotten lets Check skip the map while it is empty.
	forgotten  sync.Map // netip.Addr -> time.Time
	nForgotten atomic.Int64
	// forgottenNets: the same for a network (`cfm allow 203.0.113.0/24`).
	// Rare, so a copy-on-write slice.
	forgottenNets atomic.Pointer[[]netForget]
	netsMu        sync.Mutex

	// clock is time.Now; tests swap it (an atomic: Check and the refresh
	// goroutine read it while a test may set it).
	clock atomic.Pointer[func() time.Time]

	modeFeed  atomic.Value // string
	modeLocal atomic.Value // string

	nChecks, nWould, nBlocked, nAllowed atomic.Int64
)

// The defaults, when detectors.conf names no mode. LOCAL (the node's own
// block sets) is enforce since 2026-11-26, after a week of log mode on eight
// nodes: scanners only (Censys, 45.138.12.x, Techoff, an Iranian address),
// no customer, no network that serves real users. FEED stays log: the fleet
// blacklist still holds permanent bans on shared mobile / CGNAT addresses.
const (
	DefaultModeFeed  = ModeLog
	DefaultModeLocal = ModeEnforce
)

func init() {
	modeFeed.Store(DefaultModeFeed)
	modeLocal.Store(DefaultModeLocal)
	modeChallenge.Store(DefaultModeChallenge)
	cur.Store(&snapshot{})
	setClock(time.Now)
}

func now() time.Time { return (*clock.Load())() }

func setClock(f func() time.Time) { clock.Store(&f) }

// SetModes sets the mode of each group; an empty or unknown value is "log",
// the safe default (logged, so a typo is visible).
func SetModes(feed, local string) {
	modeFeed.Store(normMode("PROXIED_IPFILTER_FEED", feed, DefaultModeFeed))
	modeLocal.Store(normMode("PROXIED_IPFILTER_LOCAL", local, DefaultModeLocal))
}

// normMode reads one knob: empty is the group's default, an unknown value is
// log (the safe side, logged).
func normMode(key, m, def string) string {
	switch m = strings.ToLower(strings.TrimSpace(m)); m {
	case "":
		return def
	case ModeOff, ModeLog, ModeEnforce:
		return m
	case "0":
		return ModeOff
	}
	logging.Logf("[proxied_ipfilter] %s = %q is none of off, log, enforce: logging only", key, m)
	return ModeLog
}

func groupMode(g string) string {
	if g == GroupLocal {
		return modeLocal.Load().(string)
	}
	return modeFeed.Load().(string)
}

// PreparedFeed is a feed's table, built and ready to publish. Building takes
// ~100 ms for the fleet list, so blocklists.Manager builds it outside its own
// lock and publishes under it, after checking that the feed is still
// configured: a fetch that finishes after Reload removed its feed must not
// bring it back.
type PreparedFeed struct {
	name string
	s    *source
}

// PrepareFeed builds one feed's table. allow: an ALLOW feed (MYALLOW), which
// cancels a block. A feed's per-element TTL (cfm.blocklists `|TTL=`) is not
// applied here, as it is not in nft's verdict: it times the per-feed set's
// elements, while the base rules drop on the union sets (block_ext_v4_hosts,
// allow_ext_*), which RebuildExternalUnions rebuilds without a TTL on both
// engines. A feed holds until its next apply, there as here.
func PrepareFeed(name string, allow bool, v4, v6 []string) PreparedFeed {
	// The name as written: two feeds whose names differ only in case
	// (MyList, MYLIST) are two lists, and the log must tell them apart.
	s := &source{label: "feed:" + name, allow: allow, t: buildTable(v4, v6)}
	if !allow {
		s.group = GroupFeed
	}
	return PreparedFeed{name: name, s: s}
}

// Publish replaces the feed's addresses with the prepared ones.
func (p PreparedFeed) Publish() {
	if p.s == nil {
		return
	}
	mu.Lock()
	feeds[p.name] = p.s
	publishLocked()
	mu.Unlock()
}

// SetFeed is PrepareFeed then Publish.
func SetFeed(name string, allow bool, v4, v6 []string) {
	PrepareFeed(name, allow, v4, v6).Publish()
}

// DropFeed forgets a feed the configuration no longer has.
func DropFeed(name string) {
	mu.Lock()
	if _, ok := feeds[name]; ok {
		delete(feeds, name)
		publishLocked()
	}
	mu.Unlock()
}

// setLocal replaces one local set's addresses.
func setLocal(set string, allow bool, elems []string) {
	s := &source{label: set, allow: allow, t: buildTable(elems)}
	if !allow {
		s.group = GroupLocal
	}
	mu.Lock()
	locals[set] = s
	publishLocked()
	mu.Unlock()
}

// forgetFor is how long Forget overrides the lists: two reads of the slowest
// source (the ban sets, BanFeedEvery), by when the sets read show the unblock
// (the block gone, or the allow an unblock adds for a feed-listed address).
const forgetFor = 2 * BanFeedEvery

type netForget struct {
	p   netip.Prefix
	exp time.Time
}

// Forget clears ip (an address, or a network as a CIDR) from every block
// source now, for forgetFor. Called from edgeban.Unban, which every unblock
// and allow path of an address calls (CLAUDE.md), and for a network allow:
// nft stops dropping it at once, and so must this filter, rather than at the
// next minute's refresh. A ban the address earns again within forgetFor
// reaches it after the override ends (nft's own drop is immediate).
func Forget(ip string) {
	ip = strings.TrimSpace(ip)
	if strings.Contains(ip, "/") {
		if p, err := netip.ParsePrefix(ip); err == nil {
			forgetNet(p.Masked())
		}
		return
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	if _, loaded := forgotten.Swap(a.Unmap(), now().Add(forgetFor)); !loaded {
		nForgotten.Add(1)
	}
}

// forgottenNow reports whether a is under a Forget override; an expired one is
// removed on the way.
func forgottenNow(a netip.Addr) bool {
	v, ok := forgotten.Load(a)
	if !ok {
		return false
	}
	if now().Before(v.(time.Time)) {
		return true
	}
	if forgotten.CompareAndDelete(a, v) {
		nForgotten.Add(-1)
	}
	return false
}

func forgetNet(p netip.Prefix) {
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	netsMu.Lock()
	defer netsMu.Unlock()
	t := now()
	var next []netForget
	if cur := forgottenNets.Load(); cur != nil {
		for _, f := range *cur {
			if t.Before(f.exp) && f.p != p {
				next = append(next, f)
			}
		}
	}
	next = append(next, netForget{p: p, exp: t.Add(forgetFor)})
	forgottenNets.Store(&next)
}

func forgottenNet(a netip.Addr) bool {
	l := forgottenNets.Load()
	if l == nil || len(*l) == 0 {
		return false
	}
	t := now()
	for _, f := range *l {
		if t.Before(f.exp) && f.p.Contains(a) {
			return true
		}
	}
	return false
}

// pruneForgotten drops the expired overrides of addresses no request asked
// about since (StartLocalRefresh, every minute).
func pruneForgotten() {
	netsMu.Lock()
	if cur := forgottenNets.Load(); cur != nil && len(*cur) > 0 {
		t := now()
		var next []netForget
		for _, f := range *cur {
			if t.Before(f.exp) {
				next = append(next, f)
			}
		}
		forgottenNets.Store(&next)
	}
	netsMu.Unlock()
	t := now()
	forgotten.Range(func(k, v any) bool {
		if !t.Before(v.(time.Time)) && forgotten.CompareAndDelete(k, v) {
			nForgotten.Add(-1)
		}
		return true
	})
}

func publishLocked() {
	snap := &snapshot{}
	add := func(s *source) {
		switch {
		case s.challenge:
			snap.challenges = append(snap.challenges, s)
		case s.allow:
			snap.allows = append(snap.allows, s)
		default:
			snap.blocks = append(snap.blocks, s)
		}
	}
	for _, s := range locals {
		add(s)
	}
	for _, s := range feeds {
		add(s)
	}
	byLabel := func(l []*source) {
		sort.Slice(l, func(i, j int) bool { return l[i].label < l[j].label })
	}
	byLabel(snap.blocks)
	byLabel(snap.allows)
	byLabel(snap.challenges)
	cur.Store(snap)
}

// Verdict is the nft IP filter's answer for one address.
type Verdict struct {
	Blocks  []string // the block sources it is on (off excluded)
	Allows  []string // the allow sources it is on, when it is on a block source
	Enforce bool     // a block in enforce mode, and no allow
}

// Listed reports whether the address is on a block source in log or enforce mode.
func (v Verdict) Listed() bool { return len(v.Blocks) > 0 }

// Check returns the verdict for ip, without logging.
func Check(ip string) Verdict {
	var v Verdict
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return v
	}
	a = a.Unmap()
	if nForgotten.Load() > 0 && forgottenNow(a) || forgottenNet(a) {
		return v
	}
	snap := cur.Load()
	for _, s := range snap.blocks {
		m := groupMode(s.group)
		if m == ModeOff || !s.t.contains(a) {
			continue
		}
		v.Blocks = append(v.Blocks, s.label)
		if m == ModeEnforce {
			v.Enforce = true
		}
	}
	if len(v.Blocks) == 0 {
		return v
	}
	for _, s := range snap.allows {
		if s.t.contains(a) {
			v.Allows = append(v.Allows, s.label)
		}
	}
	if len(v.Allows) > 0 {
		v.Enforce = false
	}
	return v
}

// Decide is the bridge's question for a proxied web request: should it answer
// block, and is the client on a block list with no allow cancelling it
// (listed: the bridge then keeps the edge from caching its allow, so every
// request a log-mode block stands for is decided and counted)? An address an
// allow cancels gets neither: its allow is final, and stays cacheable. It
// logs what it found, once per client and outcome per logEvery.
func Decide(ip, host string) (enforce, listed bool) {
	nChecks.Add(1)
	v := Check(ip)
	if !v.Listed() {
		return false, false
	}
	var what string
	switch {
	case len(v.Allows) > 0:
		nAllowed.Add(1)
		what = "allowed"
	case v.Enforce:
		nBlocked.Add(1)
		what = "block"
	default:
		nWould.Add(1)
		what = "would_block"
	}
	if n, ok := logDue(ip + "|" + what); ok {
		allow := "-"
		if len(v.Allows) > 0 {
			allow = strings.Join(v.Allows, ",")
		}
		logf("[proxied_ipfilter] %s ip=%s host=%s block=%s allow=%s mode=feed:%s,local:%s n=%d %s",
			what, ip, orDash(host), strings.Join(v.Blocks, ","), allow,
			modeFeed.Load().(string), modeLocal.Load().(string), n, geoFields(ip))
	}
	return v.Enforce, len(v.Allows) == 0
}

// GeoFunc answers an address's country (ISO-2) and network (ASN number and
// name) from the node's local GeoIP database: a memory read, no DNS.
type GeoFunc func(ip string) (cc string, asn uint, asnName string)

var geo atomic.Pointer[GeoFunc]

// logf writes a would_block / allowed / block line (a var for the tests).
var logf = logging.Logf

// SetGeo gives the log line its cc= / asn= / asn_name= fields (nil: none).
// The webdetector engine sets it with its enricher. A read for the weekly
// review: whether a would_block is a Greek visitor, and whether a foreign one
// is a network that serves real users (Google, Microsoft, Meta, a CDN), not
// a scanner's host. Called once per logged line (per client and outcome per
// logEvery), never per request.
func SetGeo(fn GeoFunc) {
	if fn == nil {
		geo.Store(nil)
		return
	}
	geo.Store(&fn)
}

// geoFields is the log line's tail: `cc=GR asn=6799 asn_name=OTEnet_S.A.`,
// "-" for what the database does not know.
func geoFields(ip string) string {
	cc, asnStr, name := "-", "-", "-"
	if p := geo.Load(); p != nil {
		c, a, n := (*p)(ip)
		cc, name = orDash(strings.ToUpper(c)), orDash(n)
		if a != 0 {
			asnStr = strconv.FormatUint(uint64(a), 10)
		}
	}
	return "cc=" + cc + " asn=" + asnStr + " asn_name=" + name
}

// orDash makes a value the edge passed safe for one log line: no whitespace,
// quote or control character (a forged one could fake another field), at most
// 253 bytes (a DNS name), "-" when empty.
func orDash(s string) string {
	if len(s) > 253 {
		s = s[:253]
	}
	s = strings.Map(func(r rune) rune {
		if r <= ' ' || r == '"' || r == 0x7f {
			return '_'
		}
		return r
	}, s)
	if s == "" {
		return "-"
	}
	return s
}

// Log de-duplication: a scanner sends thousands of requests, one line per
// client and outcome per logEvery is enough; n says how many it stands for.
const (
	logEvery   = 10 * time.Minute
	logMaxKeys = 20000
)

// seen is one log key's state, updated without a lock: a listed scanner's
// requests all come here, and one mutex for every decision would serialise
// the bridge on it (CLAUDE.md: a write lock on a hot path stalls everyone).
type seen struct {
	last atomic.Int64 // UnixNano of the last line
	n    atomic.Int64 // occurrences since it
}

var (
	logSeen  sync.Map // key -> *seen
	nLogKeys atomic.Int64
	logEvict sync.Mutex // only for evicting, never on the hot path
)

// logDue counts one occurrence of key and reports whether a line is due, with
// the occurrences since the last line.
func logDue(key string) (int, bool) {
	t := now().UnixNano()
	v, ok := logSeen.Load(key)
	if !ok {
		if nLogKeys.Load() >= logMaxKeys {
			evictLogKeys(t)
		}
		s := &seen{}
		s.last.Store(t)
		if v, ok = logSeen.LoadOrStore(key, s); !ok {
			nLogKeys.Add(1)
			return 1, true
		}
	}
	s := v.(*seen)
	s.n.Add(1)
	last := s.last.Load()
	if t-last < int64(logEvery) || !s.last.CompareAndSwap(last, t) {
		return 0, false
	}
	return int(s.n.Swap(0)), true
}

// evictLogKeys drops the keys idle for a window; if every key is fresh (a
// flood of distinct clients), it starts over.
func evictLogKeys(t int64) {
	logEvict.Lock()
	defer logEvict.Unlock()
	if nLogKeys.Load() < logMaxKeys {
		return
	}
	logSeen.Range(func(k, v any) bool {
		if t-v.(*seen).last.Load() >= int64(logEvery) {
			logSeen.Delete(k)
			nLogKeys.Add(-1)
		}
		return true
	})
	if nLogKeys.Load() >= logMaxKeys {
		logSeen.Range(func(k, _ any) bool { logSeen.Delete(k); return true })
		nLogKeys.Store(0)
	}
}

// Stats is what Decide has counted since the daemon started, and the size of
// each source.
func Stats() map[string]any {
	snap := cur.Load()
	srcs := map[string]any{}
	for _, l := range [][]*source{snap.blocks, snap.allows, snap.challenges} {
		for _, s := range l {
			srcs[s.label] = map[string]int{"entries": s.t.n, "unparsed": s.t.bad}
		}
	}
	return map[string]any{
		"mode_feed":   modeFeed.Load().(string),
		"mode_local":  modeLocal.Load().(string),
		"checks":      nChecks.Load(),
		"would_block": nWould.Load(),
		"blocked":     nBlocked.Load(),
		"allowed":     nAllowed.Load(),
		"forgotten":   nForgotten.Load(),
		"geo":         geo.Load() != nil, // the log line's cc= / asn= fields are filled
		"sources":     srcs,
		// CHALLENGE feeds (challenge.go): every web client, direct or not.
		"mode_challenge":   modeChallenge.Load().(string),
		"challenge_listed": nChalChecks.Load(),
		"would_challenge":  nChalWould.Load(),
		"challenged":       nChalEnforced.Load(),
		"challenge_allow":  nChalAllowed.Load(),
	}
}

// ResetForTest empties every source and the log de-duplication and restores
// the default modes. Tests only (other packages' tests seed the filter with
// SetFeed and must not leak it).
func ResetForTest() {
	mu.Lock()
	feeds, locals = map[string]*source{}, map[string]*source{}
	publishLocked()
	mu.Unlock()
	bansMu.Lock()
	bans = map[string][]timedElem{}
	bansMu.Unlock()
	logSeen.Range(func(k, _ any) bool { logSeen.Delete(k); return true })
	nLogKeys.Store(0)
	modeFeed.Store(DefaultModeFeed)
	modeLocal.Store(DefaultModeLocal)
	modeChallenge.Store(DefaultModeChallenge)
	nChalChecks.Store(0)
	nChalWould.Store(0)
	nChalEnforced.Store(0)
	nChalAllowed.Store(0)
	forgotten.Range(func(k, _ any) bool { forgotten.Delete(k); return true })
	nForgotten.Store(0)
	forgottenNets.Store(nil)
	nChecks.Store(0)
	nWould.Store(0)
	nBlocked.Store(0)
	nAllowed.Store(0)
	setClock(time.Now)
}
