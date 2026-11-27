package firewall

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	cfgpkg "cfm/internal/config"
	enrichpkg "cfm/internal/enrich"
	"cfm/internal/goodbot"
	"cfm/internal/logging"
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
// The forward-confirms run synchronously, under the engine's autoblock mutex,
// and an attacker can put a crawler PTR on as many of their own addresses as
// they like. So they spend a budget, autoblockGoodBotBudget of resolver time
// per autoblockGoodBotBudgetWindow (the web detector's ban check has the same
// rule, goodBotBanTickBudget): past it a candidate gets only its cached
// verdict, and an uncached one is banned as before, never exempted on a
// guess. A real crawler verified earlier keeps its cached verdict.
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
// (a spoofed suffix PTR is not re-resolved on every crossing). An expired
// positive is still honoured for autoblockGoodBotStaleGrace when it cannot be
// re-verified now (budget spent, or the lookup did not complete), as the web
// detector does (goodBotIPStaleGrace): otherwise an attacker keeping the
// budget spent would get every real crawler banned once its 30 min ran out.
// A completed re-verify replaces it either way. A full cache drops expired
// entries, then negatives, and never wipes positives. Inconclusive
// results are not cached as verdicts; their run is counted in inconclusive
// (an entry older than autoblockGoodBotInconclusiveTTL starts a new run).
const (
	autoblockGoodBotPosTTL          = 30 * time.Minute
	autoblockGoodBotNegTTL          = 5 * time.Minute
	autoblockGoodBotCap             = 4096
	autoblockGoodBotMaxInconclusive = 3
	autoblockGoodBotInconclusiveTTL = time.Hour
	autoblockGoodBotStaleGrace      = 24 * time.Hour
	autoblockGoodBotBudget          = 5 * time.Second
	autoblockGoodBotBudgetWindow    = time.Minute
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
	// The resolver-time budget: spent in the window that started at
	// autoblockGoodBotBudgetStart; overLogged keeps it to one log per window.
	autoblockGoodBotBudgetStart time.Time
	autoblockGoodBotBudgetSpent time.Duration
	autoblockGoodBotOverLogged  bool
)

// AutoblockGoodBot reports whether the flood/portscan autoblock must skip ip,
// and why: an FCrDNS-verified good bot, or a good-bot PTR whose
// forward-confirm did not complete (at most autoblockGoodBotMaxInconclusive-1
// crossings in a row). off is THROTTLE_GOODBOT_EXEMPT = 0.
func AutoblockGoodBot(enr *enrichpkg.Enricher, ip string, off bool) (skip bool, why string) {
	if ip == "" {
		return false, ""
	}
	// A trusted proxy's own address (a Cloudflare edge, trusted_proxies.conf,
	// registered by the edge ban store) is never banned, whatever
	// THROTTLE_GOODBOT_EXEMPT says: it stands for every visitor behind that
	// edge, and an edge that opens many connections to this node's addresses
	// reads as a port scan (ten permanent Cloudflare portscan bans in the
	// fleet blacklist, cleared 2026-11-27). nft's allow sets (MYALLOW) kept
	// accepting it, but the ban was reported fleet-wide.
	if a, err := netip.ParseAddr(ip); err == nil && clientNetExemptRegistered("trusted_proxies") {
		a = a.Unmap()
		if f := (*clientNetExempt.Load())["trusted_proxies"]; f != nil && f(netip.PrefixFrom(a, a.BitLen())) {
			return true, "a trusted proxy's address (trusted_proxies.conf)"
		}
	}
	if off {
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
	// An expired positive within the grace: what to fall back on when the
	// re-verify below cannot run or complete.
	stale := ""
	if ok && v.name != "" && now.Before(v.until.Add(autoblockGoodBotStaleGrace)) {
		stale = v.name
	}
	ptr := autoblockGoodBotPTR(enr, ip)
	if ptr == "" {
		return false, "" // no PTR: not cached, an attacker's is the common case
	}
	if _, _, ok := goodbot.SuffixName(ptr); !ok {
		return false, "" // the address no longer claims a crawler: no stale verdict
	}
	if !autoblockGoodBotTakeBudget(now, ptr, ip) {
		if stale != "" {
			return true, "FCrDNS-verified good bot " + stale + " (earlier verdict; re-verify budget spent)"
		}
		return false, "" // budget spent: banned as before
	}
	name, cacheable := autoblockGoodBotVerify(ptr, ip)
	done := autoblockGoodBotNow()

	autoblockGoodBotMu.Lock()
	defer autoblockGoodBotMu.Unlock()
	autoblockGoodBotBudgetSpent += done.Sub(now)
	if !cacheable {
		if stale != "" {
			return true, "FCrDNS-verified good bot " + stale + " (earlier verdict; re-verify did not complete)"
		}
		r, seen := autoblockGoodBotInconclusive[ip]
		if now.Sub(r.last) >= autoblockGoodBotInconclusiveTTL {
			r.n = 0
		}
		r.n++
		r.last = now
		if r.n >= autoblockGoodBotMaxInconclusive {
			delete(autoblockGoodBotInconclusive, ip)
			return false, ""
		}
		if !seen && len(autoblockGoodBotInconclusive) >= autoblockGoodBotCap {
			// Drop the stale runs first; never wipe live ones (that would
			// restart every address's count). Still full: no room to count
			// this address, so it is banned, not skipped uncounted.
			for k, e := range autoblockGoodBotInconclusive {
				if now.Sub(e.last) >= autoblockGoodBotInconclusiveTTL {
					delete(autoblockGoodBotInconclusive, k)
				}
			}
			if len(autoblockGoodBotInconclusive) >= autoblockGoodBotCap {
				return false, ""
			}
		}
		autoblockGoodBotInconclusive[ip] = r
		return true, "good-bot PTR " + ptr + " not verified (lookup did not complete); this crossing skipped"
	}
	delete(autoblockGoodBotInconclusive, ip)
	ttl := autoblockGoodBotNegTTL
	if name != "" {
		ttl = autoblockGoodBotPosTTL
	}
	if _, present := autoblockGoodBotCache[ip]; present || autoblockGoodBotMakeRoom(now, name != "") {
		autoblockGoodBotCache[ip] = autoblockGoodBotVerdict{name: name, until: now.Add(ttl)}
	}
	if name != "" {
		return true, "FCrDNS-verified good bot " + name
	}
	return false, ""
}

// autoblockGoodBotMakeRoom frees a slot in a full verdict cache and reports
// whether there is one. Caller holds autoblockGoodBotMu. Expired entries go
// first (a positive only past its stale grace), then negatives. A positive is
// never dropped for a negative: past that a new negative is simply not cached
// (it is re-verified on its next crossing, within the budget). A cache full of
// live positives makes room for a new positive by dropping one of them.
func autoblockGoodBotMakeRoom(now time.Time, positive bool) bool {
	if len(autoblockGoodBotCache) < autoblockGoodBotCap {
		return true
	}
	for k, e := range autoblockGoodBotCache {
		if e.name == "" && !now.Before(e.until) ||
			e.name != "" && !now.Before(e.until.Add(autoblockGoodBotStaleGrace)) {
			delete(autoblockGoodBotCache, k)
		}
	}
	if len(autoblockGoodBotCache) < autoblockGoodBotCap {
		return true
	}
	for k, e := range autoblockGoodBotCache {
		if e.name == "" {
			delete(autoblockGoodBotCache, k)
		}
	}
	if len(autoblockGoodBotCache) < autoblockGoodBotCap {
		return true
	}
	if !positive {
		return false
	}
	for k := range autoblockGoodBotCache {
		delete(autoblockGoodBotCache, k)
		break
	}
	return true
}

// autoblockGoodBotTakeBudget reports whether a forward-confirm may run now:
// the window's resolver time is not spent yet. The time is charged after the
// lookup, so one lookup can run past the budget (each has its own 2 s cap).
func autoblockGoodBotTakeBudget(now time.Time, ptr, ip string) bool {
	autoblockGoodBotMu.Lock()
	defer autoblockGoodBotMu.Unlock()
	if now.Sub(autoblockGoodBotBudgetStart) >= autoblockGoodBotBudgetWindow {
		autoblockGoodBotBudgetStart, autoblockGoodBotBudgetSpent, autoblockGoodBotOverLogged = now, 0, false
	}
	if autoblockGoodBotBudgetSpent < autoblockGoodBotBudget {
		return true
	}
	if !autoblockGoodBotOverLogged {
		autoblockGoodBotOverLogged = true
		logging.Logf("[autoblock][goodbot] forward-confirm budget (%s per %s) spent; unverified crawler-PTR addresses are blocked as before until the window ends (first: %s ptr=%s)",
			autoblockGoodBotBudget, autoblockGoodBotBudgetWindow, ip, ptr)
	}
	return false
}

// PortscanThrottleConfig is the ThrottleConfig the port scanner hands
// autoBlockAction (both engines): Hits=1, since PS_LIMIT is already the
// threshold, PS_INTERVAL as the window, PS_MODE/PS_TTL, and the good-bot
// kill switch from the throttle config, because the same autoBlockAction and
// its good-bot exemption run for portscan bans.
func PortscanThrottleConfig(cfg *cfgpkg.Config) cfgpkg.ThrottleConfig {
	ps := cfg.Portscan
	tc := cfgpkg.ThrottleConfig{
		WindowSec:        ps.Interval,
		Hits:             1,
		Mode:             "ttl",
		TTLSeconds:       ps.TTLSeconds,
		GoodBotExemptOff: cfg.Throttle.GoodBotExemptOff,
	}
	if strings.ToLower(ps.Mode) == "permanent" {
		tc.Mode = "permanent"
	}
	return tc
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
	autoblockGoodBotBudgetStart, autoblockGoodBotBudgetSpent, autoblockGoodBotOverLogged = time.Time{}, 0, false
	autoblockGoodBotMu.Unlock()
}
