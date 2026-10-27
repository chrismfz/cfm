package webdetector

import (
	"fmt"
	"time"
)

// Vhost uniqIP count: who a vhost-wide challenge cannot reach.
//
// The suspicious-vhost trip (tripReasonBase) arms a vhost-wide challenge once
// UniqueIPs crosses CHALLENGE_SUSPICIOUS_VHOST_UNIQIP_ON / _MAX. That count
// used to include every client, the ones the edge then waves through the
// challenge as well. On qualityweb (2026-10-27) Applebot alone brought ~1 300
// distinct IPs to one shop in 10 minutes: the vhost went CHALLENGED, Applebot
// (on the bypass list) kept crawling, and only the shop's human visitors saw
// the challenge it had set off. Counting a client the challenge cannot stop
// buys no protection; it only lowers the threshold for everyone else.
//
// vhostChallengeExemptClient is the count-side mirror of what lifts a
// vhost-wide challenge for one request at the edge, so "passes the vhost
// challenge" and "is not counted" are the same set of clients:
//   - the bypass list (challenge_waf_bypass.conf, cfm.lua Step 0), which the
//     edge reports per request (log-cfm.lua column 13, LogRec.Bypass); the
//     daemon never loads that file itself;
//   - an FCrDNS-verified good bot, under CHALLENGE_GOODBOT_EXEMPT
//     (handleDecision's goodBotDowngrade), from the same cache;
//   - the operator exclude file (webdetector_challenge_exclude.txt) through
//     the same DNS-free matcher the edge uses (ChalExcludeHot, MatchNoDNS),
//     skip and skip_vhost_only alike.
//
// So the operator file stays the switch: drop a crawler from the file (and
// from the bypass list / good-bot exemption it is also on) and it is both
// challenged and counted again. Challenge Access-Control entries are not
// mirrored: they exempt by path, country or method as well as by client, and
// a client exempt on one path is still challenged on the others.
//
// Cost: it runs once per ingested request, outside the engine lock. A bypass
// flag answers at once; the good-bot check is a read-locked cache hit, and
// only a crawler-looking UA (isBotUA) may start the bounded async verify (the
// edge only starts one for a challenged client, which before a challenge is
// nobody); the exclude matcher decides most rules on host / UA, reads the ASN
// from the local mmdb, and the PTR from the enrich cache, never DNS.
func (b *NginxBridge) vhostChallengeExemptClient(ip, host, ua string, bypass bool, now time.Time) bool {
	if bypass {
		return true
	}
	if b == nil || ip == "" {
		return false
	}
	ptrFn := func() string {
		if b.enr == nil {
			return ""
		}
		return b.enr.LookupCachedOrAsync(ip).PTR
	}
	if b.goodBotExempt && b.goodBot != nil && b.enr != nil {
		if isBotUA(ua) {
			if b.goodBot.verified(ip, ptrFn, now) != "" {
				return true
			}
		} else if l, fresh := b.goodBot.cached(ip, now); (fresh && l.name != "") || l.stale != "" {
			return true
		}
	}
	if b.ChalExcludeHot != nil {
		asnFn := func() string {
			if n := b.chalExcludeASN(ip); n > 0 {
				return fmt.Sprintf("AS%d", n)
			}
			return ""
		}
		if _, _, ok := b.ChalExcludeHot(host, ua, asnFn, ptrFn, "CHALLENGE_VHOST"); ok {
			return true
		}
	}
	return false
}

// countedUniqueIPs is the vhost uniqIP count: the distinct IPs in counts that
// sent at least one request vhostChallengeExemptClient did not exempt. An IP
// counts as soon as one of its requests could be challenged (a crawler IP that
// also sends a browser UA a ua= rule does not cover).
func countedUniqueIPs(counts, exempt map[string]int) int {
	if len(exempt) == 0 {
		return len(counts)
	}
	n := 0
	for ip, c := range counts {
		if c > exempt[ip] {
			n++
		}
	}
	return n
}
