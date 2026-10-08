package webdetector

import (
	"strings"
	"time"

	"cfm/internal/logging"
)

// abuse_shadow_origin403.go — Signal O, LOG-ONLY: an IP that sends a burst of
// POSTs to one vhost which the ORIGIN answers 403 (an origin WAF such as
// Wordfence or ModSecurity refusing them) while CFM let every one through.
//
// The case (titan, 2026-10-08): 172.81.132.89 sent 115 POSTs to
// villadimitramykonos.com/wp-admin/admin-ajax.php in about a minute, the
// CVE-2026-19632 TranslatePress exploit. Wordfence answered each with its
// 403 block page; CFM logged nothing. A fleet read of the edge logs (retained
// 09-15..10-08) found the same shape almost only from scanner swarms on
// speedhost (POSTs to /wp-json/batch/v1, /wp/, /blog/ from a few /24s): at
// >= 30/min, 668 bursts from 45 IPs in ~3 weeks.
//
// Two classes are NOT this signal and are excluded at ingest:
//   - WordPress's own refusal of an admin-ajax/admin-post call with a stale or
//     missing nonce: 403 with a body of "-1" or "0". A cached page with an
//     expired nonce makes REAL visitors send bursts of these (liloteddykidsworld.gr,
//     rigel: 3 378 of them at 6 bytes from Greek mobile IPs, and Googlebot did
//     the same on vani-atelier.gr). Only the tiny body tells them apart from a
//     WAF block page (Wordfence's is ~7 KB; speedhost's origin WAF sends 0 or
//     107 bytes on other paths, so a minimum size cannot be the test).
//   - CFM's own endpoints (/__cfm_*): the daemon is their upstream, so its
//     verify refusals look like an origin 403.
// "The origin answered" is LogRec.Upstream: the edge logged an upstream time.
// The Apache origin log carries none, so on a node without the edge this
// signal stays silent.
//
// Runs on the per-tick emitIPChallenges under ABUSE_SHADOW; nothing here
// challenges or blocks. A line with verdict=would_ban is what a soft-TTL ban
// would have hit; a verified good bot logs exempt_goodbot instead.

const (
	// origin403PathCap bounds the distinct-path set kept per IP per bucket.
	origin403PathCap = 64
	// wpAjaxDenialMaxBytes: WordPress answers a refused admin-ajax/admin-post
	// call with "-1" or "0" (wp_die), which the edge logs at a handful of bytes
	// (6-10 with headers trimmed, gzip framing included). A WAF block page is
	// never this small on these paths.
	wpAjaxDenialMaxBytes = 16
	// maxOrigin403EnrichPerTick bounds the per-tick enrichment/log work.
	maxOrigin403EnrichPerTick = 50
)

// origin403Window is the per-minute window the burst is counted over.
const origin403Window = time.Minute

func (e *Engine) origin403PerMin() int {
	if n := e.cfg.AbuseShadowOrigin403PerMin; n > 0 {
		return n
	}
	return 30
}

// isOrigin403POST reports whether a request counts toward Signal O: a POST the
// origin answered 403, not WordPress's nonce refusal and not a CFM endpoint.
// p is the path without the query string.
func isOrigin403POST(rec LogRec, p string) bool {
	if rec.Method != "post" || rec.Status != 403 || !rec.Upstream {
		return false
	}
	if strings.HasPrefix(p, "/__cfm") {
		return false
	}
	return !isWPAjaxDenial(p, rec.Bytes)
}

// isWPAjaxDenial is WordPress's own "-1"/"0" refusal on its AJAX endpoints.
func isWPAjaxDenial(p string, bytes int64) bool {
	if bytes > wpAjaxDenialMaxBytes {
		return false
	}
	return strings.HasSuffix(p, "/admin-ajax.php") || strings.HasSuffix(p, "/admin-post.php")
}

// origin403GoodBot is Signal O's own FCrDNS verdict cache (async on a miss, so
// the emit never blocks on DNS); same machinery as the bridge and Signal H.
var origin403GoodBot = newOrigin403GoodBot()

func newOrigin403GoodBot() *bridgeGoodBotState {
	s := newBridgeGoodBotState()
	s.logVerified = func(name, ip string) {
		logging.LogfABUSESHADOW("[abuse-shadow] signal=origin_403_burst verified_crawler=%q exempt (per-IP FCrDNS; e.g. ip=%s)", name, ip)
	}
	return s
}

// origin403Burst is one (host, ip) over the window.
type origin403Burst struct {
	host, ip string
	post403  int // origin-403 POSTs in the window
	paths    int // distinct paths among them (capped per bucket)
	reqs     int // every request from the IP to the host in the window
}

// origin403Bursts snapshots the (host, ip) pairs at or over perMin in the last
// minute. Pure over the engine state (read lock only), so it is testable
// without the enricher.
func (e *Engine) origin403Bursts(now time.Time, perMin int) []origin403Burst {
	from := now.Add(-origin403Window)
	var out []origin403Burst
	e.mu.RLock()
	defer e.mu.RUnlock()
	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		var counts map[string]int
		for i := range hs.buckets {
			b := &hs.buckets[i]
			if b.to.Before(from) || len(b.ipsOrigin403POST) == 0 {
				continue
			}
			if counts == nil {
				counts = make(map[string]int)
			}
			for ip, n := range b.ipsOrigin403POST {
				counts[ip] += n
			}
		}
		for ip, n := range counts {
			if n < perMin {
				continue
			}
			paths := make(map[uint64]struct{})
			reqs := 0
			for i := range hs.buckets {
				b := &hs.buckets[i]
				if b.to.Before(from) {
					continue
				}
				for h := range b.ipOrigin403Paths[ip] {
					paths[h] = struct{}{}
				}
				reqs += b.ips[ip]
			}
			out = append(out, origin403Burst{host: host, ip: ip, post403: n, paths: len(paths), reqs: reqs})
		}
	}
	return out
}

// emitAbuseShadowOrigin403 logs Signal O. Called from the per-tick
// emitIPChallenges inside the ABUSE_SHADOW block.
func (e *Engine) emitAbuseShadowOrigin403(now time.Time) {
	if !e.cfg.AbuseShadow || !e.cfg.AbuseShadowOrigin403 {
		return
	}
	enriched := 0
	for _, b := range e.origin403Bursts(now, e.origin403PerMin()) {
		if e.isBypassed(b.ip) {
			continue
		}
		if enriched >= maxOrigin403EnrichPerTick {
			break
		}
		// One line per (host, ip) per holddown, so a persistent burst does not
		// log every tick.
		if !e.shouldLogVhostSuppress("abuseshadow:o403:"+b.host+"|"+b.ip, now) {
			continue
		}
		enriched++
		var asn uint
		var cc, ptr, goodBot string
		if e.enr != nil {
			r := e.enr.LookupCachedOrAsync(b.ip)
			asn, cc, ptr = r.ASN, r.CountryISO, r.PTR
			if e.cfg.AbuseShadowGoodbotExempt {
				goodBot = origin403GoodBot.verified(b.ip, func() string { return ptr }, now)
			}
		}
		verdict := "would_ban"
		if goodBot != "" {
			verdict = "exempt_goodbot"
		}
		logging.LogfABUSESHADOW(
			"[abuse-shadow] signal=origin_403_burst host=%s ip=%s post403=%d paths=%d reqs=%d window=60s asn=%d cc=%s good_bot=%s verdict=%s",
			b.host, b.ip, b.post403, b.paths, b.reqs, asn, orDash(cc), orDash(goodBot), verdict,
		)
	}
}
