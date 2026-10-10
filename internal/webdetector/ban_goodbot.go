package webdetector

import (
	"context"
	"time"

	"cfm/internal/logging"
)

// goodBotBanTickBudget bounds the good-bot check's DNS across one
// emitIPBlocks tick (reverse lookups of the candidates plus forward-confirms).
// Past it a candidate gets whatever is cached — an unverified one is banned as
// before, never exempted on a guess.
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
func (e *Engine) goodBotForBan(ctx context.Context, ip string, budget *int) string {
	if e == nil || ip == "" {
		return ""
	}
	gb := banGoodBot
	if e.nginxBridge != nil && e.nginxBridge.goodBot != nil {
		gb = e.nginxBridge.goodBot
	}
	var ptr string
	var resolved bool
	ptrFn := func() (string, bool) {
		if !resolved {
			resolved = true
			switch {
			case e.banPTRFn != nil:
				ptr = e.banPTRFn(ip)
			case e.enr != nil:
				ptr = e.enr.Lookup(ip).PTR
			}
		}
		return ptr, true
	}
	if (e.banPTRFn == nil && e.enr == nil) || ctx.Err() != nil {
		return gb.verified(ip, nil, time.Now()) // no resolver / no time left: cache only
	}
	name, _ := gb.verifiedSync(ctx, ip, ptrFn, time.Now())
	if name == "" && e.chalGoodBotFunc != nil && budget != nil && ctx.Err() == nil {
		if p, _ := ptrFn(); p != "" && !looksLikeGoodBotPTR(p) {
			if n, ok := e.chalGoodBotFunc(ip, p, budget); ok {
				name = n
			}
		}
	}
	return name
}
