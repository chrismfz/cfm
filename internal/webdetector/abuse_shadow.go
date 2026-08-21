package webdetector

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

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
}

func (e *Engine) shadowRateCfg() shadowRateCfg {
	c := shadowRateCfg{
		K:       e.cfg.AbuseShadowRateK,
		Floor:   e.cfg.AbuseShadowRateFloor,
		SkewMin: e.cfg.AbuseShadowRateSkewMin,
		MinReq:  e.cfg.AbuseShadowRateMinReq,
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
	return c
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
	// kept per-host so the median/skew are per-vhost).
	snap := make(map[string]map[string]int)
	e.mu.RLock()
	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		m := make(map[string]int)
		for i := range hs.buckets {
			// ipsDyn = dynamic requests only (static assets excluded), so a
			// human's per-pageview asset fan-out doesn't read as a rate outlier.
			for ip, n := range hs.buckets[i].ipsDyn {
				m[ip] += n
			}
		}
		if len(m) > 0 {
			snap[host] = m
		}
	}
	e.mu.RUnlock()

	// Bound the enrichment/DNS work per tick. Each new outlier that clears the
	// throttle does a cold reverse-DNS (and, for good-bot-looking PTRs, a 2s
	// forward-confirm) synchronously in the ingest goroutine. Signal C's target
	// shape is a botnet spraying MANY distinct outlier IPs, so without a cap that
	// serial DNS could stall ingest past the run watchdog. Leftover outliers are
	// picked up on later ticks (the per-(host,ip) throttle window is generous).
	const maxShadowEnrichPerTick = 50
	enriched := 0

	for host, perIP := range snap {
		if len(perIP) < 2 { // need a baseline population to be an "outlier"
			continue
		}
		totals := make([]int, 0, len(perIP))
		for _, n := range perIP {
			totals = append(totals, n)
		}
		medianRPS := medianInt(totals) / winSec
		skew := ipSkew(totals)
		if skew < cfg.SkewMin {
			continue // flat/distributed vhost — Signal C is not the tool (uniqIP is)
		}
		for ip, tot := range perIP {
			ipRPS := float64(tot) / winSec
			if !rateOutlier(tot, ipRPS, medianRPS, skew, cfg) {
				continue
			}
			// Don't shadow what we'd never act on anyway.
			if e.isBypassed(ip) {
				continue
			}
			// Per-tick enrich cap — checked BEFORE the throttle so hitting the cap
			// doesn't consume a throttle token (the IP logs on a later tick).
			if enriched >= maxShadowEnrichPerTick {
				return
			}
			// Throttle BEFORE the (potentially DNS-bound) enrichment, so a
			// persistent outlier doesn't do a good-bot forward-confirm every tick.
			if !e.shouldLogVhostSuppress("abuseshadow:"+host+"|"+ip, now) {
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
			logging.LogfABUSESHADOW(
				"[abuse-shadow] signal=rate_outlier host=%s ip=%s rps=%.3f median_rps=%.4f ratio=%.1f skew=%.1f reqs=%d asn=%d cc=%s provider=%s good_bot=%s verdict=%s",
				host, ip, ipRPS, medianRPS, ratio, skew, tot, asn, orDash(cc), orDash(provider), orDash(goodBot), verdict,
			)
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// goodBotPTRSuffixes maps a good-bot's canonical PTR domain suffix to its name.
// Membership alone is NOT trust — the PTR is forward-confirmed (FCrDNS) before a
// bot is treated as good, so a spoofed UA/PTR can't earn an exemption.
var goodBotPTRSuffixes = map[string]string{
	".googlebot.com":      "googlebot",
	".google.com":         "google",
	".search.msn.com":     "bingbot",
	".crawl.yahoo.net":    "yahoo",
	".applebot.apple.com": "applebot",
	".yandex.com":         "yandex",
	".yandex.net":         "yandex",
	".yandex.ru":          "yandex",
	// Meta's crawler fleet (facebookexternalhit / meta-externalagent /
	// meta-externalads) reverses to *.fbsv.net and forward-confirms. Added
	// 2026-08-21 after CHALLENGE_SUBNET live-FP'd Meta's 57.141.20.0/24 on a
	// shop vhost (60+ crawler IPs in one /24 tripped SUBNET_MIN_IPS).
	".fbsv.net": "meta",
}

// verifiedGoodBot returns a good-bot name when ptr is a known good-bot host AND
// forward-confirms back to ip (FCrDNS); "" otherwise. A PTR that claims a good
// bot but fails forward-confirm returns "" (spoofed → not exempt).
func verifiedGoodBot(ptr, ip string) string {
	p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ptr), "."))
	if p == "" {
		return ""
	}
	for suf, name := range goodBotPTRSuffixes {
		if strings.HasSuffix(p, suf) {
			if forwardConfirms(p, ip) {
				return name
			}
			return ""
		}
	}
	return ""
}

// forwardConfirms resolves host and reports whether any A/AAAA equals ip (FCrDNS).
func forwardConfirms(host, ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return false
	}
	want := net.ParseIP(ip)
	for _, a := range addrs {
		// Compare as parsed IPs so a non-canonical IPv6 spelling still matches
		// (raw string compare would false-negative a legit AAAA good bot).
		if ap := net.ParseIP(a); ap != nil && want != nil && ap.Equal(want) {
			return true
		}
		if a == ip {
			return true
		}
	}
	return false
}
