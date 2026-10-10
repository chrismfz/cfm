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

// banNotBotTTL / banNotBotCap: how long, and for how many IPs, a definitive
// "not a crawler" is remembered by the ban check (an IP that gains a crawler
// PTR is re-checked after the TTL). At the cap, expired entries are pruned
// first, then the map is reset — losing the memory costs only lookups.
const (
	banNotBotTTL = 10 * time.Minute
	banNotBotCap = 4096
)

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
	if ptrFn == nil || ctx.Err() != nil || e.knownNotBot(ip, now) {
		return gb.verified(ip, nil, now) // no resolver / no time left / known: cache only
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
	// Definitively not a crawler: the lookup completed and its PTR is empty or
	// claimed by no rule. A crawler-suffix PTR is left to the verdict cache
	// (it caches its own negatives), and anything inconclusive — a failed
	// lookup, no time or budget left for the file rules — is not remembered.
	if name == "" && resolved && ptrOK && !looksLikeGoodBotPTR(ptr) &&
		ctx.Err() == nil && (e.chalGoodBotFunc == nil || ptr == "" || (budget != nil && *budget > 0)) {
		e.rememberNotBot(ip, now)
	}
	return name
}

func (e *Engine) knownNotBot(ip string, now time.Time) bool {
	e.banNotBotMu.Lock()
	defer e.banNotBotMu.Unlock()
	t, ok := e.banNotBot[ip]
	return ok && now.Sub(t) < banNotBotTTL
}

func (e *Engine) rememberNotBot(ip string, now time.Time) {
	e.banNotBotMu.Lock()
	defer e.banNotBotMu.Unlock()
	if e.banNotBot == nil {
		e.banNotBot = make(map[string]time.Time)
	}
	if len(e.banNotBot) >= banNotBotCap {
		for k, t := range e.banNotBot {
			if now.Sub(t) >= banNotBotTTL {
				delete(e.banNotBot, k)
			}
		}
		if len(e.banNotBot) >= banNotBotCap {
			e.banNotBot = make(map[string]time.Time)
		}
	}
	e.banNotBot[ip] = now
}
