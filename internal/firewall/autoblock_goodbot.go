package firewall

import (
	"sync"
	"time"

	enrichpkg "cfm/internal/enrich"
	"cfm/internal/goodbot"
)

// Flood-autoblock good-bot exemption, shared by both engines' autoBlockAction.
//
// The L4 flood heuristics (syn / portflood / pps / connlimit / new / icmp)
// count packets per source address, and a crawler or a link-preview proxy is
// a busy source: Meta's fwdproxy-*.fbsv.net addresses (Facebook link
// previews, facebookexternalhit, the in-app browser) tripped
// portflood_443_tcp and SYN flood and were banned PERMANENTLY in cfm.deny
// on two nodes (59 addresses, May-June 2026), breaking link previews and
// in-app visits for every site there. The meters still drop a good bot's
// excess packets; what it is spared is the ban, as in the web detector's own
// IP bans (webdetector goodBotForBan).
//
// The PTR comes from the enricher the autoblock already consults for its
// label (cached, or one bounded reverse lookup), so the only added DNS is one
// forward-confirm (2 s cap), and only for an address whose PTR claims a good
// bot. A source address can be spoofed in a SYN flood; exempting a verified
// crawler's address then spares the real crawler a ban an attacker earned
// for it. A PTR that does not forward-confirm (spoofed: NXDOMAIN or another
// address) is banned as before. A forward-confirm that does not complete
// skips only that crossing (not cached; the next one re-checks): taking the
// ban instead would let one DNS blip ban a real crawler, permanently under
// THROTTLE_MODE = permanent, which is the incident this exists for. A
// spoofer cannot cause that: the forward name is the crawler's own domain.
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
// results are not cached.
const (
	autoblockGoodBotPosTTL = 30 * time.Minute
	autoblockGoodBotNegTTL = 5 * time.Minute
	autoblockGoodBotCap    = 4096
)

type autoblockGoodBotVerdict struct {
	name  string
	until time.Time
}

var (
	autoblockGoodBotMu    sync.Mutex
	autoblockGoodBotCache = map[string]autoblockGoodBotVerdict{}
)

// AutoblockGoodBot reports whether the flood autoblock must skip ip, and
// why: an FCrDNS-verified good bot, or a good-bot PTR whose forward-confirm
// did not complete. off is THROTTLE_GOODBOT_EXEMPT = 0.
func AutoblockGoodBot(enr *enrichpkg.Enricher, ip string, off bool) (skip bool, why string) {
	if off || ip == "" {
		return false, ""
	}
	name, ptr, inconclusive := autoblockGoodBotName(enr, ip)
	switch {
	case name != "":
		return true, "FCrDNS-verified good bot " + name
	case inconclusive:
		return true, "good-bot PTR " + ptr + " not verified (lookup did not complete); this crossing skipped"
	}
	return false, ""
}

func autoblockGoodBotName(enr *enrichpkg.Enricher, ip string) (name, ptr string, inconclusive bool) {
	now := autoblockGoodBotNow()
	autoblockGoodBotMu.Lock()
	v, ok := autoblockGoodBotCache[ip]
	autoblockGoodBotMu.Unlock()
	if ok && now.Before(v.until) {
		return v.name, "", false
	}
	ptr = autoblockGoodBotPTR(enr, ip)
	if ptr == "" {
		return "", "", false // no PTR: not cached, an attacker's is the common case
	}
	if _, _, ok := goodbot.SuffixName(ptr); !ok {
		return "", ptr, false
	}
	name, cacheable := autoblockGoodBotVerify(ptr, ip)
	if !cacheable {
		return "", ptr, true
	}
	ttl := autoblockGoodBotNegTTL
	if name != "" {
		ttl = autoblockGoodBotPosTTL
	}
	autoblockGoodBotMu.Lock()
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
	autoblockGoodBotMu.Unlock()
	return name, ptr, false
}

// SetAutoblockGoodBotForTest replaces the PTR source and the verifier of
// AutoblockGoodBot and empties its verdict cache; the returned func restores
// them.
func SetAutoblockGoodBotForTest(ptr func(ip string) string, verify func(ptr, ip string) (string, bool)) (restore func()) {
	autoblockGoodBotMu.Lock()
	autoblockGoodBotCache = map[string]autoblockGoodBotVerdict{}
	autoblockGoodBotMu.Unlock()
	oldP, oldV := autoblockGoodBotPTR, autoblockGoodBotVerify
	if ptr != nil {
		autoblockGoodBotPTR = func(_ *enrichpkg.Enricher, ip string) string { return ptr(ip) }
	}
	if verify != nil {
		autoblockGoodBotVerify = verify
	}
	return func() {
		autoblockGoodBotPTR, autoblockGoodBotVerify = oldP, oldV
		autoblockGoodBotMu.Lock()
		autoblockGoodBotCache = map[string]autoblockGoodBotVerdict{}
		autoblockGoodBotMu.Unlock()
	}
}
