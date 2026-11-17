package firewall

import (
	"sync"
	"time"

	enrichpkg "cfm/internal/enrich"
	"cfm/internal/goodbot"
)

// Flood/portscan autoblock good-bot exemption, shared by both engines'
// autoBlockAction.
//
// The L4 flood heuristics (syn / portflood / pps / connlimit / new / icmp)
// count packets per source address, and a crawler or a link-preview proxy is
// a busy source: Meta's fwdproxy-*.fbsv.net addresses (Facebook link
// previews, facebookexternalhit, the in-app browser) tripped
// portflood_443_tcp and SYN flood and were banned PERMANENTLY in cfm.deny
// on two nodes (59 addresses, May-June 2026), breaking link previews and
// in-app visits for every site there. The meters still drop a good bot's
// excess packets; what it is spared is the ban, as in the web detector's own
// IP bans (webdetector goodBotForBan). The port scanner feeds the same
// autoBlockAction, so its bans follow the same rule and kill switch.
//
// The PTR comes from the enricher the autoblock already consults for its
// label (cached, or one bounded reverse lookup), so the only added DNS is one
// forward-confirm (2 s cap), and only for an address whose PTR claims a good
// bot. A source address can be spoofed in a SYN flood; exempting a verified
// crawler's address then spares the real crawler a ban an attacker earned
// for it. A PTR that does not forward-confirm (spoofed: NXDOMAIN or another
// address) is banned as before.
//
// A forward-confirm that does not complete skips that crossing (not cached;
// the next one re-checks): taking the ban instead would let one DNS blip ban
// a real crawler, permanently under THROTTLE_MODE = permanent, which is the
// incident this exists for. But the PTR of an address is its owner's to set,
// so a resolver that stays down must not hold a claimed-crawler address off
// the ban list for good: after autoblockGoodBotMaxInconclusive inconclusive
// crossings in a row the ban goes ahead. A definitive answer resets the run.
//
// It needs the enricher's PTR (PTR enrichment on); without one there is no
// claim to verify and the ban goes ahead.

var (
	autoblockGoodBotPTR = func(enr *enrichpkg.Enricher, ip string) string {
		if enr == nil {
			return ""
		}
		return enr.Lookup(ip).PTR
	}
	autoblockGoodBotVerify = goodbot.Verify
	autoblockGoodBotNow    = time.Now
)

// The verdict cache: a crawler crosses the threshold again every window or
// so, and each crossing runs under the engine's autoblock mutex. A positive
// is kept 30 min (crawler addresses are stable), a definitive negative 5 min
// (a spoofed suffix PTR is not re-resolved on every crossing). Inconclusive
// results are not cached as verdicts; their run is counted in inconclusive
// (an entry older than autoblockGoodBotInconclusiveTTL starts a new run).
const (
	autoblockGoodBotPosTTL          = 30 * time.Minute
	autoblockGoodBotNegTTL          = 5 * time.Minute
	autoblockGoodBotCap             = 4096
	autoblockGoodBotMaxInconclusive = 3
	autoblockGoodBotInconclusiveTTL = time.Hour
)

type autoblockGoodBotVerdict struct {
	name  string
	until time.Time
}

type autoblockGoodBotRun struct {
	n    int
	last time.Time
}

var (
	autoblockGoodBotMu           sync.Mutex
	autoblockGoodBotCache        = map[string]autoblockGoodBotVerdict{}
	autoblockGoodBotInconclusive = map[string]autoblockGoodBotRun{}
)

// AutoblockGoodBot reports whether the flood/portscan autoblock must skip ip,
// and why: an FCrDNS-verified good bot, or a good-bot PTR whose
// forward-confirm did not complete (at most autoblockGoodBotMaxInconclusive-1
// crossings in a row). off is THROTTLE_GOODBOT_EXEMPT = 0.
func AutoblockGoodBot(enr *enrichpkg.Enricher, ip string, off bool) (skip bool, why string) {
	if off || ip == "" {
		return false, ""
	}
	now := autoblockGoodBotNow()
	autoblockGoodBotMu.Lock()
	v, ok := autoblockGoodBotCache[ip]
	autoblockGoodBotMu.Unlock()
	if ok && now.Before(v.until) {
		if v.name != "" {
			return true, "FCrDNS-verified good bot " + v.name
		}
		return false, ""
	}
	ptr := autoblockGoodBotPTR(enr, ip)
	if ptr == "" {
		return false, "" // no PTR: not cached, an attacker's is the common case
	}
	if _, _, ok := goodbot.SuffixName(ptr); !ok {
		return false, ""
	}
	name, cacheable := autoblockGoodBotVerify(ptr, ip)

	autoblockGoodBotMu.Lock()
	defer autoblockGoodBotMu.Unlock()
	if !cacheable {
		r := autoblockGoodBotInconclusive[ip]
		if now.Sub(r.last) >= autoblockGoodBotInconclusiveTTL {
			r.n = 0
		}
		r.n++
		r.last = now
		if r.n >= autoblockGoodBotMaxInconclusive {
			delete(autoblockGoodBotInconclusive, ip)
			return false, ""
		}
		if len(autoblockGoodBotInconclusive) >= autoblockGoodBotCap {
			autoblockGoodBotInconclusive = map[string]autoblockGoodBotRun{}
		}
		autoblockGoodBotInconclusive[ip] = r
		return true, "good-bot PTR " + ptr + " not verified (lookup did not complete); this crossing skipped"
	}
	delete(autoblockGoodBotInconclusive, ip)
	ttl := autoblockGoodBotNegTTL
	if name != "" {
		ttl = autoblockGoodBotPosTTL
	}
	if len(autoblockGoodBotCache) >= autoblockGoodBotCap {
		for k, e := range autoblockGoodBotCache {
			if !now.Before(e.until) {
				delete(autoblockGoodBotCache, k)
			}
		}
		if len(autoblockGoodBotCache) >= autoblockGoodBotCap {
			autoblockGoodBotCache = map[string]autoblockGoodBotVerdict{}
		}
	}
	autoblockGoodBotCache[ip] = autoblockGoodBotVerdict{name: name, until: now.Add(ttl)}
	if name != "" {
		return true, "FCrDNS-verified good bot " + name
	}
	return false, ""
}

// PruneSeen bounds a per-address "last seen" map the autoblock keeps for log
// rate limiting (lastIgnoredAt): past seenCap entries it drops those older
// than maxAge, which can no longer suppress anything. Call it before an insert.
func PruneSeen(m map[string]time.Time, maxAge time.Duration) {
	if len(m) < seenCap {
		return
	}
	now := time.Now()
	for k, t := range m {
		if now.Sub(t) >= maxAge {
			delete(m, k)
		}
	}
}

const seenCap = 1024

// SetAutoblockGoodBotForTest replaces the PTR source and the verifier of
// AutoblockGoodBot and empties its caches; the returned func restores them.
func SetAutoblockGoodBotForTest(ptr func(ip string) string, verify func(ptr, ip string) (string, bool)) (restore func()) {
	resetAutoblockGoodBot()
	oldP, oldV := autoblockGoodBotPTR, autoblockGoodBotVerify
	if ptr != nil {
		autoblockGoodBotPTR = func(_ *enrichpkg.Enricher, ip string) string { return ptr(ip) }
	}
	if verify != nil {
		autoblockGoodBotVerify = verify
	}
	return func() {
		autoblockGoodBotPTR, autoblockGoodBotVerify = oldP, oldV
		resetAutoblockGoodBot()
	}
}

func resetAutoblockGoodBot() {
	autoblockGoodBotMu.Lock()
	autoblockGoodBotCache = map[string]autoblockGoodBotVerdict{}
	autoblockGoodBotInconclusive = map[string]autoblockGoodBotRun{}
	autoblockGoodBotMu.Unlock()
}
