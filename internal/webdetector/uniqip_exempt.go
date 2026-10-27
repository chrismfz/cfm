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
// The filtered number IS the vhost's UniqueIPs wherever that is read: the
// uniqIP trip, the score (uniqNorm, the many_unique_ips reason) and its
// MIN_UNIQIP gate, the longwin suspicion floor, Under-Attack leg 3, and the
// uniqIP= of the auto_on / auto_off lines and history rows. All of them ask
// "how many clients could a vhost challenge act on". HotIPs, the median
// per-IP rate and the top-IP lists still see every client, so a drilldown can
// list exempt crawler IPs beside a lower uniqIP.
//
// vhostChallengeExemptClient is the count-side mirror of what lifts a
// vhost-wide challenge for one request at the edge (handleDecision), so a
// client that passes the vhost challenge is not counted:
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
// challenged and counted again.
//
// It errs toward COUNTING wherever it cannot match the edge cheaply, never
// the other way, so a client the edge would challenge is always counted:
//   - the good-bot check reads the cache only and never starts a verify: the
//     edge verifies a crawler once a challenge is on (and Google, Bing and
//     Apple are on the bypass list anyway), so an unverified crawler is
//     counted until then. Every ingested request runs this, so a spoofed
//     crawler UA must not buy a reverse lookup. A stale positive (expired,
//     within goodBotIPStaleGrace) still exempts, as the edge serves it: the
//     edge refreshes verdicts only while it serves a challenge, so a
//     fresh-only check would count a verified crawler again ~30 min after
//     the challenge it caused went off, re-arm it, and flap;
//   - the exclude matcher gets the ASN from the local mmdb and NO PTR: the
//     enricher has no cache-only PTR read (a miss starts a reverse lookup),
//     so a ptr= rule never exempts here;
//   - not mirrored at all: Challenge Access-Control entries and the
//     challenge-exempt endpoints, which exempt by path, country or method as
//     well as by client (a client exempt on one path is challenged on others);
//   - only the socket carries the bypass flag: when the arbiter falls back
//     to a file tailer, bypass-listed clients count again (the pre-2026-10-27
//     count), until the socket is back.
//
// InjectObserved (a WAF hit re-fed to the engine) applies the same check, so
// an exempt client stays exempt when it trips the WAF.
//
// A third mirror of handleDecision's client exemptions, beside
// challengePageExempt: a change to the good-bot or exclude-file blocks there
// changes this too.
//
// Cost: once per ingested request, outside the engine lock: a bool, one
// read-locked map hit, then the exclude rules (host / UA first, an mmdb read
// only for a rule they leave undecided). No DNS, no async work.
//
// A vhost LOCKDOWN (vhost_lockdown.go) does not change the count, on purpose:
// the vhost is already under its manual challenge, and counting the crawlers
// it holds would arm an automatic challenge (at v2 by default) that outlives
// the lockdown and keeps the humans challenged after the crawlers are exempt
// again.
func (b *NginxBridge) vhostChallengeExemptClient(ip, host, ua string, bypass bool, now time.Time) bool {
	if bypass {
		return true
	}
	if b == nil || ip == "" {
		return false
	}
	if b.goodBotExempt && b.goodBot != nil && b.enr != nil {
		if l, fresh := b.goodBot.cached(ip, now); (fresh && l.name != "") || l.stale != "" {
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
		noPTR := func() string { return "" }
		if _, _, ok := b.ChalExcludeHot(host, ua, asnFn, noPTR, "CHALLENGE_VHOST"); ok {
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
