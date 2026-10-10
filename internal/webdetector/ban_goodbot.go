package webdetector

import (
	"context"
	"time"

	"cfm/internal/logging"
)

// goodBotBanTickBudget bounds the good-bot check's DNS across one
// emitIPBlocks tick (reverse lookups of the candidates plus forward-confirms).
// It is checked between candidates: one candidate's own lookups (each with
// its own timeout, ~2 s) can run past it. Past it a candidate gets whatever is
// cached — an unverified one is banned as before, never exempted on a guess.
const goodBotBanTickBudget = 5 * time.Second

// banGoodBot is the verdict cache of the IP-ban check when the engine has no
// nginx bridge (no edge). With a bridge, the bridge's cache is used instead, so
// a crawler the challenge exemption already verified costs no DNS here.
var banGoodBot = newBanGoodBot()

func newBanGoodBot() *bridgeGoodBotState {
	s := newBridgeGoodBotState()
	s.logVerified = func(name, ip string) {
		logging.Logf("[webdetector] FCrDNS-verified crawler %q (per-IP; e.g. ip=%s) — exempt from webdetector IP bans", name, ip)
	}
	return s
}

// goodBotForBan reports the verified good-bot name for ip ("" when not one),
// from the same two sources as the solver-farm finding's good_bots (parity):
//
//   - the canonical PTR-suffix list (goodBotPTRSuffixes: Googlebot, Bingbot,
//     Applebot, Yandex, Meta, …) forward-confirmed (FCrDNS), through the
//     bridge's verdict cache — inline here (verifiedSync), because emitIPBlocks
//     runs off the hot path and a crawler must not be banned while its first
//     verdict is still in flight;
//   - the operator exclude file's verify_fcrdns=1 PTR rules (chalGoodBotFunc),
//     for a PTR the canonical list does not claim, spending budget.
//
// The file's ua=/asn= rules are NOT consulted: a UA is a claim anyone sends,
// and an ASN like Google's 15169 is all of GCP — fine for skipping a
// challenge, not for exempting an address from a ban. A reverse lookup that
// does not complete, or no slot / no time left in ctx, yields "" (the ban
// stands, as before).
func (e *Engine) goodBotForBan(ctx context.Context, ip string, budget *int, now time.Time) string {
	if e == nil || ip == "" {
		return ""
	}
	gb := banGoodBot
	if e.nginxBridge != nil && e.nginxBridge.goodBot != nil {
		gb = e.nginxBridge.goodBot
	}
	// The PTR: the enrich cache when it has one (no DNS), else a bounded
	// direct lookup that tells "no PTR" from "the lookup failed". A failed
	// one must stay inconclusive (ok=false): taken as "no PTR", verifiedSync
	// would drop a crawler's stale-but-graced verdict from the shared cache
	// and the ban would go ahead on a DNS blip.
	var ptrFn func() (string, bool)
	switch {
	case e.banPTRFn != nil:
		ptrFn = func() (string, bool) { return e.banPTRFn(ip) }
	case e.enr != nil:
		direct := e.simulatePTRLookup(ip) // nil when PTR enrichment is off
		ptrFn = func() (string, bool) {
			if p := e.enr.LookupCachedOrAsync(ip).PTR; p != "" {
				return p, true
			}
			if direct == nil {
				return "", false
			}
			return direct()
		}
	}
	if ptrFn == nil || ctx.Err() != nil {
		return gb.verified(ip, nil, now) // no resolver / no time left: cache only
	}
	var ptr string
	var ptrOK, resolved bool
	memo := func() (string, bool) {
		if !resolved {
			ptr, ptrOK = ptrFn()
			resolved = true
		}
		return ptr, ptrOK
	}
	name, _ := gb.verifiedSync(ctx, ip, memo, now)
	if name == "" && e.chalGoodBotFunc != nil && budget != nil && ctx.Err() == nil {
		if p, ok := memo(); ok && p != "" && !looksLikeGoodBotPTR(p) {
			if n, ok := e.chalGoodBotFunc(ip, p, budget); ok {
				name = n
			}
		}
	}
	return name
}
