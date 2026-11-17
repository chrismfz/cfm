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
// Cloudflare with 200/301/404 (docs/imunify-webshield-parity.md, P1).
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
// ALLOW) and the node's local sets, read from the kernel every minute
// (StartLocalRefresh). Each block source belongs to a group with its own mode,
// [webdetector] PROXIED_IPFILTER_FEED and PROXIED_IPFILTER_LOCAL: log (the
// default: a line per client says which lists it is on and what would happen,
// nothing changes), enforce (the bridge answers ip_action=block), off.
package proxyipfilter

import (
	"net/netip"
	"sort"
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
	label string // what the log names: "feed:myblock", "block_v4", "allow_dyn_v4"
	group string // GroupFeed / GroupLocal for a block source; "" for an allow
	allow bool
	t     table
}

type snapshot struct {
	blocks, allows []*source
}

var (
	mu     sync.Mutex
	feeds  = map[string]*source{} // by feed name
	locals = map[string]*source{} // by set name
	cur    atomic.Pointer[snapshot]

	modeFeed  atomic.Value // string
	modeLocal atomic.Value // string

	nChecks, nWould, nBlocked, nAllowed atomic.Int64
)

func init() {
	modeFeed.Store(ModeLog)
	modeLocal.Store(ModeLog)
	cur.Store(&snapshot{})
}

// SetModes sets the mode of each group; an empty or unknown value is "log",
// the safe default (logged, so a typo is visible).
func SetModes(feed, local string) {
	modeFeed.Store(normMode("PROXIED_IPFILTER_FEED", feed))
	modeLocal.Store(normMode("PROXIED_IPFILTER_LOCAL", local))
}

func normMode(key, m string) string {
	switch m = strings.ToLower(strings.TrimSpace(m)); m {
	case "":
		return ModeLog
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

// SetFeed replaces one feed's addresses (blocklists: after each successful
// apply). allow: an ALLOW feed (MYALLOW), which cancels a block.
func SetFeed(name string, allow bool, v4, v6 []string) {
	elems := make([]string, 0, len(v4)+len(v6))
	elems = append(append(elems, v4...), v6...)
	s := &source{label: "feed:" + strings.ToLower(name), allow: allow, t: buildTable(elems)}
	if !allow {
		s.group = GroupFeed
	}
	mu.Lock()
	feeds[name] = s
	publishLocked()
	mu.Unlock()
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

func publishLocked() {
	snap := &snapshot{}
	add := func(s *source) {
		if s.allow {
			snap.allows = append(snap.allows, s)
		} else {
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
	cur.Store(snap)
}

// Verdict is the nft IP filter's answer for one address.
type Verdict struct {
	Blocks  []string // the block sources it is on (whatever their mode, off excluded)
	Allows  []string // the allow sources it is on
	Enforce bool     // a block in enforce mode, and no allow
	Log     bool     // on a block source (in log or enforce mode)
}

// Check returns the verdict for ip, without logging.
func Check(ip string) Verdict {
	var v Verdict
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return v
	}
	snap := cur.Load()
	for _, s := range snap.blocks {
		m := groupMode(s.group)
		if m == ModeOff || !s.t.contains(a) {
			continue
		}
		v.Blocks = append(v.Blocks, s.label)
		v.Log = true
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
// block? It logs what it found, once per client and outcome per logEvery.
func Decide(ip, host string) bool {
	nChecks.Add(1)
	v := Check(ip)
	if !v.Log {
		return false
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
		logging.Logf("[proxied_ipfilter] %s ip=%s host=%s block=%s allow=%s mode=feed:%s,local:%s n=%d",
			what, ip, orDash(host), strings.Join(v.Blocks, ","), allow,
			modeFeed.Load().(string), modeLocal.Load().(string), n)
	}
	return v.Enforce
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

type seen struct {
	last time.Time
	n    int
}

var (
	logMu   sync.Mutex
	logSeen = map[string]*seen{}
	logNow  = time.Now
)

// logDue counts one occurrence of key and reports whether a line is due, with
// the occurrences since the last line.
func logDue(key string) (int, bool) {
	now := logNow()
	logMu.Lock()
	defer logMu.Unlock()
	s := logSeen[key]
	if s == nil {
		if len(logSeen) >= logMaxKeys {
			for k, e := range logSeen {
				if now.Sub(e.last) >= logEvery {
					delete(logSeen, k)
				}
			}
			if len(logSeen) >= logMaxKeys {
				logSeen = map[string]*seen{}
			}
		}
		logSeen[key] = &seen{last: now}
		return 1, true
	}
	s.n++
	if now.Sub(s.last) < logEvery {
		return 0, false
	}
	n := s.n
	s.last, s.n = now, 0
	return n, true
}

// Stats is what Decide has counted since the daemon started, and the size of
// each source.
func Stats() map[string]any {
	snap := cur.Load()
	srcs := map[string]any{}
	for _, l := range [][]*source{snap.blocks, snap.allows} {
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
		"sources":     srcs,
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
	logMu.Lock()
	logSeen = map[string]*seen{}
	logMu.Unlock()
	modeFeed.Store(ModeLog)
	modeLocal.Store(ModeLog)
}
