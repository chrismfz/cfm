package webdetector

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"cfm/internal/goodbot"
	"cfm/internal/logging"
)

// abuse_shadow.go — LOG-ONLY entity-level abuse signals (docs/webdetector-
// refactor.md). Runs on the per-tick challenge eval (emitIPChallenges), never
// per-request. NOTHING here challenges or blocks — it writes structured lines to
// /var/log/cfm/cfm.abuse_shadow.log so the thresholds can be tuned from real
// fleet data before we promote any of it to a real per-IP challenge.
//
// Signal C (rate outlier) is first: an IP whose request rate is a large multiple
// of its vhost's own median per-IP rate — the CONCENTRATED shape (e.g. the two
// AS25472 residential IPs doing ~62× median on www.e-vafeiadis.gr). It is
// ASN-agnostic on purpose (residential abuse is the fleet's norm); the
// datacenter-ASN tag is only an ADDITIVE logged feature (§4a — origin is never
// innocence). By construction the K×median rule ignores the DISTRIBUTED shape
// (e-athlos: many IPs ≈ median, none exceeds K×median), which the uniqIP path
// already handles.

// shadowRateCfg is the resolved Signal-C threshold set (with defaults applied).
type shadowRateCfg struct {
	K       float64 // per-IP rps must be ≥ K × vhost median
	Floor   float64 // …and ≥ this absolute rps (guards tiny/idle vhosts)
	SkewMin float64 // …on a vhost whose max/median ≥ this (real concentration)
	MinReq  int     // …from an IP with ≥ this many requests (kills tiny samples)
	// Cost is the cost tier's bar: an outlier that fetched no static asset in
	// the window and kept the origin busy ≥ Cost on average (its origin
	// seconds / window seconds; 0.5 = 60 s of origin time in a 2-minute window).
	Cost float64
}

func (e *Engine) shadowRateCfg() shadowRateCfg {
	c := shadowRateCfg{
		K:       e.cfg.AbuseShadowRateK,
		Floor:   e.cfg.AbuseShadowRateFloor,
		SkewMin: e.cfg.AbuseShadowRateSkewMin,
		MinReq:  e.cfg.AbuseShadowRateMinReq,
		Cost:    e.cfg.AbuseShadowRateCost,
	}
	if c.K <= 0 {
		c.K = 20
	}
	if c.Floor <= 0 {
		c.Floor = 0.2
	}
	if c.SkewMin <= 0 {
		c.SkewMin = 5
	}
	if c.MinReq <= 0 {
		c.MinReq = 20
	}
	if c.Cost <= 0 {
		c.Cost = 0.5
	}
	return c
}

// rateCostTier reports whether a rate outlier also clears the cost tier: no
// static asset fetched in the window (a browser loads a page's css/js/images,
// a client fetching HTML only does not) and an origin share ≥ c.Cost. The
// 2026-11-24 read: on the morning a scraper drove titan and orion past load
// 100, the outliers that passed both were 30-50 % of the fleet's origin time
// and near none of it at normal hours, with 5 IPs carrying human solve
// evidence among them fleet-wide, against 275 of titan's 469 plain outliers
// that day looking like browsers. Static is the client's own to send, so a
// scraper that also fetches one asset per window leaves the tier: it is a
// measurement, never a reason to clear anyone.
func rateCostTier(static int, originShare float64, c shadowRateCfg) bool {
	return static == 0 && originShare >= c.Cost
}

// rateIP is one IP's Signal C counts on one vhost over the window.
type rateIP struct {
	dyn    int     // dynamic requests (ipsDyn)
	static int     // static-asset requests (ipsStatic)
	origin float64 // origin seconds of the dynamic requests (ipsDynOrigin)
}

// medianInt returns the median of a slice of counts (0 if empty). Sorts a copy.
func medianInt(vals []int) float64 {
	n := len(vals)
	if n == 0 {
		return 0
	}
	cp := make([]int, n)
	copy(cp, vals)
	sort.Ints(cp)
	if n%2 == 1 {
		return float64(cp[n/2])
	}
	return float64(cp[n/2-1]+cp[n/2]) / 2
}

// ipSkew is max/median of per-IP counts (0 when median is 0). A concentrated
// vhost has a high skew; a flat/distributed one sits near 1.
func ipSkew(vals []int) float64 {
	med := medianInt(vals)
	if med <= 0 {
		return 0
	}
	max := 0
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	return float64(max) / med
}

// rateOutlier is the Signal-C verdict for one IP: enough requests, on a
// concentrated-enough vhost, at a rate that dwarfs the vhost median AND clears
// the absolute floor. The K×median term is what makes it ignore the distributed
// shape (there every IP ≈ median, so K×median is never reached).
func rateOutlier(ipTotal int, ipRPS, medianRPS, skew float64, c shadowRateCfg) bool {
	if ipTotal < c.MinReq || skew < c.SkewMin {
		return false
	}
	thr := c.Floor
	if km := c.K * medianRPS; km > thr {
		thr = km
	}
	return ipRPS >= thr
}

// emitAbuseShadowRateOutliers runs Signal C in log-only mode over every vhost.
// Called from the per-tick emitIPChallenges. Snapshots per-vhost per-IP totals
// under the read lock, computes the vhost median + skew, and logs each per-IP
// rate outlier with the (additive) datacenter tag and good-bot verdict.
func (e *Engine) emitAbuseShadowRateOutliers(now time.Time) {
	if !e.cfg.AbuseShadow || !e.cfg.AbuseShadowRateOutlier {
		return
	}
	winSec := e.cfg.Window.Seconds()
	if winSec <= 0 {
		winSec = 60
	}
	cfg := e.shadowRateCfg()

	// Snapshot per-vhost per-IP request totals (mirrors the §2 aggregation, but
	// kept per-host so the median/skew are per-vhost), plus the node-wide origin
	// seconds of the window for origin_busy. Only buckets still in the window
	// count; the tick's pruneShort already drops older ones, so this only
	// keeps the figures right for a caller that runs without it.
	snap := make(map[string]map[string]*rateIP)
	hostStatic := make(map[string][2]int) // host -> {static, dynamic} requests
	hostMeasured := make(map[string]bool) // host -> a request reported its upstream
	var originSec float64
	upstreamSeen := false
	winStart := now.Add(-time.Duration(winSec * float64(time.Second)))
	e.mu.RLock()
	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		m := make(map[string]*rateIP)
		var hst, hdyn int
		for i := range hs.buckets {
			b := &hs.buckets[i]
			if !b.to.After(winStart) {
				continue
			}
			originSec += b.originSec
			hst += b.staticTotal
			if b.upstreamSeen {
				upstreamSeen = true
				hostMeasured[host] = true
			}
			// ipsDyn = dynamic requests only (static assets excluded), so a
			// human's per-pageview asset fan-out doesn't read as a rate outlier.
			for ip, n := range b.ipsDyn {
				r := m[ip]
				if r == nil {
					r = &rateIP{}
					m[ip] = r
				}
				r.dyn += n
				r.origin += b.ipsDynOrigin[ip]
				hdyn += n
			}
		}
		hostStatic[host] = [2]int{hst, hdyn}
		// Static counts only for the IPs that sent a dynamic request: an
		// assets-only IP is never a candidate.
		for i := range hs.buckets {
			if !hs.buckets[i].to.After(winStart) {
				continue
			}
			for ip, n := range hs.buckets[i].ipsStatic {
				if r := m[ip]; r != nil {
					r.static += n
				}
			}
		}
		if len(m) > 0 {
			snap[host] = m
		}
	}
	e.mu.RUnlock()
	originBusy := originSec / winSec
	// "-" when no request in the window said where the edge sent it (a
	// combined/Apache log): origin time is then unmeasured, never 0.
	busyStr := "-"
	if upstreamSeen {
		busyStr = strconv.FormatFloat(originBusy, 'f', 1, 64)
	}

	// Bound the enrichment/DNS work per tick. Each new outlier that clears the
	// throttle does a cold reverse-DNS (and, for good-bot-looking PTRs, a 2s
	// forward-confirm) synchronously in the ingest goroutine. Signal C's target
	// shape is a botnet spraying MANY distinct outlier IPs, so without a cap that
	// serial DNS could stall ingest past the run watchdog. Leftover outliers are
	// picked up on later ticks (the per-(host,ip) throttle window is generous).
	const maxShadowEnrichPerTick = 50
	enriched := 0

	// Per-vhost live outlier count for the UI badge / API field (abuse_shadow_marks.go).
	// Counted from the cheap rateOutlier check (no DNS), so it is COMPLETE even when
	// the enrich/log budget below throttles the detailed lines.
	marks := make(map[string]int)

	for host, perIP := range snap {
		if len(perIP) < 2 { // need a baseline population to be an "outlier"
			continue
		}
		totals := make([]int, 0, len(perIP))
		for _, r := range perIP {
			totals = append(totals, r.dyn)
		}
		medianRPS := medianInt(totals) / winSec
		skew := ipSkew(totals)
		if skew < cfg.SkewMin {
			continue // flat/distributed vhost — Signal C is not the tool (uniqIP is)
		}
		for ip, r := range perIP {
			tot := r.dyn
			ipRPS := float64(tot) / winSec
			if !rateOutlier(tot, ipRPS, medianRPS, skew, cfg) {
				continue
			}
			// Don't shadow what we'd never act on anyway.
			if e.isBypassed(ip) {
				continue
			}
			// Count every non-bypassed outlier for the badge (cheap, uncapped) —
			// BEFORE the enrich cap, so the count is complete even under a large
			// distributed burst that exhausts the per-tick DNS budget.
			marks[host]++
			// The cost tier is judged on EVERY tick (no DNS), not only when the
			// line's throttle opens: an IP first crosses the rate bar with
			// ~MinReq requests in the window, which says little of what it costs
			// once it runs at full rate. Its first tier=cost tick logs under its
			// own throttle key, so the tier isn't held back by a tier=- line the
			// same IP logged when it first crossed.
			originShare := r.origin / winSec
			// Measured per vhost: at a log-source handover the node can hold
			// both kinds of line inside one window.
			measured := hostMeasured[host]
			costTier := measured && rateCostTier(r.static, originShare, cfg)
			// Per-tick enrich cap — checked BEFORE the throttle so hitting the cap
			// doesn't consume a throttle token (the IP logs on a later tick).
			// `continue` (not `return`): the detailed line is skipped past the cap,
			// but the cheap counting above must keep visiting the remaining vhosts.
			if enriched >= maxShadowEnrichPerTick {
				continue
			}
			// Throttle BEFORE the (potentially DNS-bound) enrichment, so a
			// persistent outlier doesn't do a good-bot forward-confirm every tick.
			// ONE key gates each tick: the tier's while the IP is in it (and a
			// line under it stamps the plain key too), the plain key otherwise.
			// So an IP in the tier logs once per holddown, like any outlier,
			// and its entry into the tier is not held back by the tier=- line
			// it logged when it first crossed the rate bar.
			baseKey := "abuseshadow:" + host + "|" + ip
			if costTier {
				if !e.shouldLogVhostSuppress("abuseshadow:cost:"+host+"|"+ip, now) {
					continue
				}
				e.stampVhostSuppress(baseKey, now)
			} else if !e.shouldLogVhostSuppress(baseKey, now) {
				continue
			}
			enriched++
			var asn uint
			var provider, goodBot, cc string
			if e.enr != nil {
				r := e.enr.Lookup(ip)
				asn = r.ASN
				// Unconditional (no ABUSE_SHADOW_* gate, unlike provider/good_bot below):
				// CountryISO is free from the Lookup already done for the ASN, and it is the
				// primary FP-triage signal (domestic residential burst = likely FP). ISO-2
				// is space-free, which the abuse_shadow parser (splits on spaces) requires.
				cc = r.CountryISO
				if e.cfg.AbuseShadowDatacenter {
					provider = DatacenterClass(r.ASN, r.ASNName)
				}
				if e.cfg.AbuseShadowGoodbotExempt {
					goodBot = verifiedGoodBot(r.PTR, ip)
				}
			}
			verdict := "would_challenge"
			if goodBot != "" {
				verdict = "exempt_goodbot"
			}
			ratio := 0.0
			if medianRPS > 0 {
				ratio = ipRPS / medianRPS
			}
			// The cost tier rides on its own key, so verdict keeps its meaning
			// for every reader: tier=cost marks a would_challenge (never an
			// exempt good bot) that also clears rateCostTier.
			tier := "-"
			if verdict == "would_challenge" && costTier {
				tier = "cost"
			}
			originStr := "-"
			if measured {
				originStr = strconv.FormatFloat(originShare, 'f', 2, 64)
			}
			// host_static = the vhost's own static share of its requests in the
			// window: near 0 on a vhost behind a CDN or with its assets on
			// another host, where every visitor reads static=0.
			hostShare := 0.0
			if hs := hostStatic[host]; hs[0]+hs[1] > 0 {
				hostShare = float64(hs[0]) / float64(hs[0]+hs[1])
			}
			abuseShadowRateLogf(
				"[abuse-shadow] signal=rate_outlier host=%s ip=%s rps=%.3f median_rps=%.4f ratio=%.1f skew=%.1f reqs=%d asn=%d cc=%s provider=%s good_bot=%s verdict=%s static=%d host_static=%.2f origin=%s origin_busy=%s tier=%s",
				host, ip, ipRPS, medianRPS, ratio, skew, tot, asn, orDash(cc), orDash(provider), orDash(goodBot), verdict, r.static, hostShare, originStr, busyStr, tier,
			)
		}
	}

	// Stamp the per-vhost live outlier count for the badge / API field, in one
	// batch (a single prune pass regardless of how many vhosts are flagged). TTL
	// is a small multiple of the traffic window so the mark survives eval jitter
	// and clears on its own within one TTL once the burst stops (no un-mark path);
	// the 90s floor also covers a zero/unset window.
	if len(marks) > 0 {
		ttl := 3 * e.cfg.Window
		if ttl < 90*time.Second {
			ttl = 90 * time.Second
		}
		MarkAbuseShadowBulk(marks, ttl)
	}
}

// abuseShadowRateLogf writes Signal C's lines (a var so a test can read them).
var abuseShadowRateLogf = logging.LogfABUSESHADOW

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// goodBotPTRSuffixes is a read-only copy of the FCrDNS good-bot registry
// (internal/goodbot, the one list shared with the L4 flood autoblock), taken
// at init, for the code that lists it. Matching goes through goodbot itself
// (goodBotSuffixName). Membership alone is NOT trust: the PTR is
// forward-confirmed (FCrDNS) before a bot is treated as good.
var goodBotPTRSuffixes = goodbot.Suffixes()

// verifiedGoodBot returns a good-bot name when ptr is a known good-bot host AND
// forward-confirms back to ip (FCrDNS); "" otherwise. A PTR that claims a good
// bot but fails forward-confirm returns "" (spoofed → not exempt).
func verifiedGoodBot(ptr, ip string) string {
	name, host, ok := goodBotSuffixName(ptr)
	if !ok {
		return ""
	}
	if forwardConfirms(host, ip) {
		return name
	}
	return ""
}

// goodBotSuffixName reports the good-bot name whose canonical PTR suffix matches
// ptr, plus the normalised host to forward-confirm (goodbot.SuffixName). This
// is the MATCH only — membership is never trust; a caller that needs trust
// must forward-confirm (verifiedGoodBot).
func goodBotSuffixName(ptr string) (name, host string, ok bool) {
	return goodbot.SuffixName(ptr)
}

// forwardConfirms resolves host and reports whether any A/AAAA equals ip (FCrDNS).
func forwardConfirms(host, ip string) bool {
	ok, _ := forwardConfirmsE(host, ip)
	return ok
}

// forwardConfirmsE is forwardConfirms with the resolver error exposed, so a
// caller can tell a definitive non-match (spoofed / wrong IP) from a transient
// lookup failure (err != nil → inconclusive).
func forwardConfirmsE(host, ip string) (matched bool, err error) {
	return goodbot.ForwardConfirms(host, ip)
}

// forwardConfirmsWith is forwardConfirmsE over an injectable lookup (tests).
func forwardConfirmsWith(ctx context.Context, lookup func(context.Context, string) ([]string, error), host, ip string) (matched bool, err error) {
	return goodbot.ForwardConfirmsWith(ctx, lookup, host, ip)
}

// countsTowardRateOutlier reports whether a request feeds Signal C's per-IP
// dynamic counter (bucketSW.ipsDyn): not a static asset (a pageview's asset
// fan-out), and not a server-to-server endpoint (isChallengeExemptEndpoint:
// WooCommerce REST, payment webhooks, courier tracking), whose integrations
// poll a quiet shop far above its visitors' rate on purpose. That is the
// NARROW list on purpose: Signal C is a would-be enforcement signal, and the
// broad isMachineStyleEndpointGo (/api, /rest/, /wp-json/, /upload…) would
// hide a scraper on any of them. Both are read on the PATH only: the query is
// the client's to write, and with it "/shop/?x=/a.css" would hide every page
// a scraper fetches.
func countsTowardRateOutlier(uri string) bool {
	path, _, _ := strings.Cut(uri, "?")
	return !isStaticAssetPath(path) && !isChallengeExemptEndpoint(path)
}
