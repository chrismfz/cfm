// internal/webdetector/challenge_rules.go
package webdetector

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
	"strconv"
        "cfm/internal/logging"
	core "cfm/internal/detectors/core"

)

// chalRule supports "N:substring" overrides like MALPATH.
type chalRule struct {
	sub   string // lowercased
	count int
}

type chalCtx struct {
    Host   string
    URI    string
    Method string
    Status int
    UA     string
    Sub    string // matched substring (rule)
    TS     float64
}


// hostMatch returns true if host matches pattern using one of:
//   - exact host: "example.com"
//   - suffix-domain wildcard: "*.example.com"
//   - prefix-label wildcard: "cpanel.*"
func hostMatch(host, pattern string) bool {
    host = strings.ToLower(strings.TrimSpace(host))
    pattern = strings.ToLower(strings.TrimSpace(pattern))
    if host == "" || pattern == "" {
        return false
    }
    if strings.HasPrefix(pattern, "*.") {
        pattern = strings.TrimPrefix(pattern, "*.")
    }
    if strings.HasSuffix(pattern, ".*") {
        base := strings.TrimSuffix(pattern, ".*")
        if base == "" {
            return false
        }
        return strings.HasPrefix(host, base+".")
    }
    if host == pattern {
        return true
    }
    return strings.HasSuffix(host, "."+pattern)
}

func hostMatchAny(host string, patterns []string) bool {
    for _, p := range patterns {
        if hostMatch(host, p) {
            return true
        }
    }
    return false
}


func isMachineStyleEndpointGo(uri string) bool {
	u := strings.ToLower(strings.TrimSpace(uri))
	if u == "" {
		return false
	}

	// Magento token endpoints
	if strings.Contains(u, "/rest/v1/integration/admin/token") { return true}
	if strings.Contains(u, "/rest/v1/integration/customer/token") {return true}
	// WooCommerce / WP API
	if strings.Contains(u, "/wp-json/wc/") {return true}
	if strings.Contains(u, "/wp-json/wc-") {return true}
	if strings.Contains(u, "/wp-json/wc_") {return true}

	// Known app-to-app/payment style routes
	if strings.Contains(u, "/shop-api/") {return true}
	if strings.Contains(u, "/transaction-payment-created") {return true}
	if strings.Contains(u, "/payments_methods_endpoint") {return true}
	// Generic machine endpoints
	if strings.Contains(u, "/webhook") {return true}
	if strings.Contains(u, "/callback") {return true}
	if strings.Contains(u, "/oauth") {return true}
	if strings.Contains(u, "/auth/token") {return true}
	if strings.Contains(u, "/api") {return true}
	if strings.Contains(u, "/auth/realms/") { return true }       // Keycloak
	if strings.Contains(u, "/realms/") { return true }
	if strings.Contains(u, "/protocol/openid-connect/") { return true }
	if strings.Contains(u, "/.well-known/openid-configuration") { return true }
	if strings.Contains(u, "/.well-known/jwks.json") { return true }
	if strings.Contains(u, "/sso/") { return true }
	if strings.Contains(u, "/stripe/webhook") { return true }
	if strings.Contains(u, "/paypal/ipn") { return true }
	if strings.Contains(u, "/adyen/") { return true }
	if strings.Contains(u, "/checkout/webhook") { return true }
	if strings.Contains(u, "/payment/callback") { return true }
	if strings.Contains(u, "/github/webhook") { return true }
	if strings.Contains(u, "/gitlab/webhook") { return true }
	if strings.Contains(u, "/bitbucket-hook") { return true }
	if strings.Contains(u, "/slack/webhook") { return true }
	if strings.Contains(u, "/telegram/webhook") { return true }
	if strings.Contains(u, "/rest/") { return true }              // BUT consider scoping tighter
	if strings.Contains(u, "/graphql") { return true }
	if strings.Contains(u, "/wp-json/") { return true }           // broader but common
	if strings.Contains(u, "/wc-api/") { return true }            // legacy Woo
	if strings.Contains(u, "/?wc-api=") { return true }           // PayPal/Stripe callbacks
	if strings.Contains(u, "/mobile-api/") { return true }
	if strings.Contains(u, "/client-api/") { return true }
	if strings.Contains(u, "/public-api/") { return true }
	if strings.Contains(u, "/upload") { return true }
	if strings.Contains(u, "/queue") { return true }
	if strings.Contains(u, "/jobs") { return true }


	return false
}

// isChallengeExemptEndpoint reports whether uri is a machine-to-machine API
// endpoint that must NOT receive an interactive JS challenge even when its
// vhost is under a *vhost-wide* challenge (auto-suspicious score / CHALLENGE_VHOST).
//
// This is a DELIBERATELY NARROW, high-confidence subset of
// isMachineStyleEndpointGo — the two lists serve different purposes and must
// not be merged. isMachineStyleEndpointGo only stops these paths from
// *inflating* the suspicious-vhost score (broad is harmless there); this list
// *suppresses enforcement*, so a too-broad entry (/api, /rest/, /upload, …)
// would be a challenge-bypass hole during a real attack. Keep it tight: only
// endpoints consumed by non-browser server-to-server clients that cannot solve
// a challenge and that are low-value as browser-scanner crawl targets.
//
// Enforcement stays in force elsewhere: the caller applies this only to the
// vhost-wide challenge and only for IPs not individually challenged/blocked;
// the WAF rule engine and per-IP autoblock still inspect these paths.
//
// uri is the path only (the caller has already stripped the query string), so
// query-arg APIs (OpenCart index.php?route=api/…, ?wc-api=) are intentionally
// not matched — add them via their path form, not by widening this set.
//
// Matching is substring (Contains), not prefix — deliberately, so it tolerates
// WordPress/Woo installed under a path prefix (/shop/wp-json/wc/…) and the
// double-slash form the edge sometimes forwards. The residual is that a token
// can appear mid-path (/wp-login.php/stripe/webhook on PATH_INFO apps); that is
// an accepted, low-value tradeoff since this only relaxes the challenge (WAF and
// per-IP autoblock still apply). The high-value vector — decorating a token to
// reach a *different* origin target via dot-segments — is closed by the
// traversal guard below (uri is NOT dot-normalised here: Lua forwards
// request_uri verbatim, '//' is preserved in our logs).
func isChallengeExemptEndpoint(uri string) bool {
	u := strings.ToLower(strings.TrimSpace(uri))
	if u == "" {
		return false
	}
	// Fail closed on anything that smells of path traversal (raw or
	// percent-encoded): a magic token must not be usable to slip a request that
	// resolves elsewhere at the origin past the vhost-wide challenge.
	if strings.Contains(u, "..") || strings.Contains(u, "%2e") {
		return false
	}
	switch {
	// WooCommerce REST — server-to-server order/stock sync (e.g. v-track).
	case strings.Contains(u, "/wp-json/wc/"),
		strings.Contains(u, "/wp-json/wc-"),
		strings.Contains(u, "/wp-json/wc_"),
		strings.Contains(u, "/wc-api/"): // legacy WooCommerce API
		return true
	// Payment-gateway webhooks / IPN — non-browser callbacks.
	case strings.Contains(u, "/stripe/webhook"),
		strings.Contains(u, "/paypal/ipn"),
		strings.Contains(u, "/adyen/"),
		strings.Contains(u, "/checkout/webhook"),
		strings.Contains(u, "/payment/callback"):
		return true
	// Known non-browser plugin integrations (fixed vendor paths). Narrow and
	// explicit on purpose; add new entries only for verified machine clients.
	case strings.Contains(u, "/ws_vtrack/"): // v-track.gr courier/tracking plugin
		return true
	}
	return false
}

func (e *Engine) hostBypassed(host string) bool {
    if host == "" {
        return false
    }
    if len(e.cfg.ChallengeHostBypass) == 0 {
        return false
    }
    return hostMatchAny(host, e.cfg.ChallengeHostBypass)
}

// hostChallengeExcluded reports whether host matches the dynamic "Challenge
// excludes" store (the runtime, UI/CLI/API-managed list — MatchChallenge, incl.
// its glob/subdomain patterns). Distinct from hostBypassed (static
// CHALLENGE_HOST_BYPASS config). Until this was wired, the vhost-wide challenge
// paths (auto-suspicious + the CHALLENGE_VHOST list) only consulted
// hostBypassed, never the dynamic excludes — so a host an operator explicitly
// excluded still got vhost-challenged when its suspicious score tripped. The
// dynamic excludes were honoured ONLY per-IP (isExcluded), not at the vhost
// decision. This closes that gap.
func (e *Engine) hostChallengeExcluded(host string) bool {
    // MatchChallenge already rejects the empty host (and short-circuits when no
    // challenge excludes are configured), so no host!="" guard is needed here.
    return e.challengeExcludes != nil && e.challengeExcludes.MatchChallenge(host)
}

// tripReason is the SINGLE source of the auto-suspicious-vhost trip decision:
// the reason the long-window scorer would flag this host now
// ("uniqip_max"/"uniqip_on"/"score_on"), or "" if it would not. It is used by
// BOTH the scorer's `if !cur` branch (which applies + logs the challenge) AND
// the suppressed_by_exclude audit path (which reports the protection an exclude
// declined). One copy — so the audit line can never disagree with the real
// decision (CLAUDE.md §5: never keep a second copy of a matcher that can drift).
// The conditions here MUST equal the scorer's; callers pass e.cfg fields, which
// FillDefaults has already normalised (ScoreOn=0.70/MinUniqIP=80 when enabled).
func (e *Engine) tripReason(row SuspiciousRow) string {
    if e.cfg.ChallengeSuspiciousUniqIP {
        if e.cfg.ChallengeSuspiciousUniqIPMax > 0 && row.UniqueIPs >= e.cfg.ChallengeSuspiciousUniqIPMax {
            return "uniqip_max"
        }
        if e.cfg.ChallengeSuspiciousUniqIPOn > 0 && row.UniqueIPs >= e.cfg.ChallengeSuspiciousUniqIPOn {
            return "uniqip_on"
        }
    }
    if row.Score >= e.cfg.ChallengeSuspiciousScoreOn && row.UniqueIPs >= e.cfg.ChallengeSuspiciousMinUniqIP {
        return "score_on"
    }
    return ""
}

// shouldLogVhostSuppress throttles the suppressed_by_exclude audit line to at
// most once per holddown window per host.
func (e *Engine) shouldLogVhostSuppress(host string, now time.Time) bool {
    win := e.cfg.ChallengeSuspiciousHolddown
    if win <= 0 {
        win = 15 * time.Minute
    }
    e.vhostMu.Lock()
    defer e.vhostMu.Unlock()
    if e.vhostSuppressLoggedAt == nil {
        e.vhostSuppressLoggedAt = make(map[string]time.Time)
    }
    if last, ok := e.vhostSuppressLoggedAt[host]; ok && now.Sub(last) < win {
        return false
    }
    e.vhostSuppressLoggedAt[host] = now
    return true
}


func compileChalRules(list []string, defCount int) []chalRule {
	if defCount <= 0 {
		defCount = 1
	}
	out := make([]chalRule, 0, len(list))
	for _, raw := range list {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		// optional "N:pattern"
		n := defCount
		if i := strings.IndexByte(s, ':'); i > 0 {
			// try parse prefix as count
			// (ignore errors; fall back to defCount)
			var parsed int
			_, _ = fmt.Sscanf(s[:i], "%d", &parsed)
			if parsed > 0 {
				n = parsed
				s = strings.TrimSpace(s[i+1:])
			}
		}
		if s == "" {
			continue
		}
		out = append(out, chalRule{sub: s, count: n})
	}
	return out
}

// boolFlag encodes a bool as "1" or "0" for transport via Alert.Extra.
// The sink reads this to decide whether to log/notify, since it has no direct
// access to webdetector.Config.
func boolFlag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// trackChallengePaths increments per-IP counters if path matches any challenge rule.
// Called from ingest() while engine lock is already held.
func (e *Engine) trackChallengePaths(rec LogRec, path string, b *bucketSW) {
	if !e.cfg.ChallengePathsEnabled {
		return
	}
	if rec.IP == "" || len(e.chalRules) == 0 {
		return
	}

	pl := strings.ToLower(path)

	for ridx, r := range e.chalRules {
		if r.sub == "" {
			continue
		}
		if !strings.Contains(pl, r.sub) {
			continue
		}

		// total challenge-path hits
		if b.ipsChalPath == nil {
			b.ipsChalPath = make(map[string]int)
		}
		b.ipsChalPath[rec.IP]++

		// per-rule counters
		if b.ipsChalRule == nil {
			b.ipsChalRule = make(map[string]map[int]int)
		}
		m := b.ipsChalRule[rec.IP]
		if m == nil {
			m = make(map[int]int)
			b.ipsChalRule[rec.IP] = m
		}
		m[ridx]++

		// store last context so we can include host/uri in alert extra
		e.chalLast[rec.IP] = chalCtx{
            Host:   rec.Host,
            URI:    path,
            Method: rec.Method,
            Status: rec.Status,
            Sub:    r.sub,
            TS:     rec.TS,
            UA:     rec.UA,
		}

		// count only first matching rule per request (avoid inflation)
		return
	}
}

func (e *Engine) emitIPChallenges(now time.Time, out chan<- core.Alert) {
	if out == nil {
		return
	}

        // NOTE: We may emit challenges from CHALLENGE_PATHS and/or from threshold rules.
        havePaths := e.cfg.ChallengePathsEnabled && len(e.chalRules) > 0
        haveThr := e.cfg.ChallengeIPRPSMin > 0 ||
        e.cfg.ChallengeIP4xxRPSMin > 0 || e.cfg.ChallengeIP5xxRPSMin > 0 ||
        e.cfg.ChallengeIPErrRatioMin > 0 || e.cfg.ChallengeIPPostRatioMin > 0 ||
        e.cfg.ChallengeIPNoUAMin > 0 || e.cfg.ChallengeIPHTTP10Min > 0

        haveMalformed := e.cfg.ChallengeIPMalformedMin > 0
        haveUniqUA    := e.cfg.ChallengeIPUniqUAMin > 0


        haveUniqPathsIP := e.cfg.ChallengeIPUniqPathsEnabled && e.cfg.ChallengeIPUniqPathsMin > 0
        haveUniqHostsIP := e.cfg.ChallengeIPUniqHostsEnabled && e.cfg.ChallengeIPUniqHostsMin > 0
        haveUniqPathsVhost := e.cfg.ChallengeVhostUniqPathsEnabled && e.cfg.ChallengeVhostUniqPathsMin > 0
        haveSubnet := e.cfg.ChallengeSubnetEnabled


        haveVhostManual := len(e.cfg.ChallengeVHost) > 0
        haveVhostAuto   := e.cfg.ChallengeSuspiciousVHost
        if !havePaths && !haveThr && !haveMalformed && !haveUniqUA && !haveUniqPathsIP && !haveUniqHostsIP && !haveUniqPathsVhost && !haveSubnet && !haveVhostManual && !haveVhostAuto { return }

	const (
		topN       = 50
		// Burst safety only. Real gating is "new hit since last emit".
		cooldown   = 5 * time.Second
		maxSamples = 8
	)

	tsToTime := func(ts float64) time.Time {
		return time.Unix(0, int64(ts*1e9))
	}


        var lastCtx map[string]chalCtx


    // ---- 0) Unique-based per-IP challenges (phase 1: challenge-only) ----
    if haveUniqPathsIP || haveUniqHostsIP {
        // aggregate sets across all hosts/buckets in short window
        // (cap union to "min" so we don't blow memory)
        type uAgg struct {
            paths map[uint64]struct{}
            hosts map[uint64]struct{}
        }
        agg := make(map[string]*uAgg)

        func() {
            e.mu.RLock()
            defer e.mu.RUnlock()

            for _, hs := range e.hosts {
                if hs == nil {
                    continue
                }
                for i := range hs.buckets {
                    b := &hs.buckets[i]
                    if haveUniqPathsIP && b.ipUniqPaths != nil {
                        for ip, set := range b.ipUniqPaths {
                            a := agg[ip]
                            if a == nil {
                                a = &uAgg{}
                                agg[ip] = a
                            }
                            if a.paths == nil {
                                a.paths = make(map[uint64]struct{}, 16)
                            }
                            // union with early stop at min
                            if len(a.paths) < e.cfg.ChallengeIPUniqPathsMin {
                                for h := range set {
                                    a.paths[h] = struct{}{}
                                    if len(a.paths) >= e.cfg.ChallengeIPUniqPathsMin {
                                        break
                                    }
                                }
                            }
                        }
                    }
                    if haveUniqHostsIP && b.ipUniqHosts != nil {
                        for ip, set := range b.ipUniqHosts {
                            a := agg[ip]
                            if a == nil {
                                a = &uAgg{}
                                agg[ip] = a
                            }
                            if a.hosts == nil {
                                a.hosts = make(map[uint64]struct{}, 8)
                            }
                            if len(a.hosts) < e.cfg.ChallengeIPUniqHostsMin {
                                for h := range set {
                                    a.hosts[h] = struct{}{}
                                    if len(a.hosts) >= e.cfg.ChallengeIPUniqHostsMin {
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // snapshot last ctx too (under same lock)
            lastCtx = make(map[string]chalCtx, len(e.chalLast))
            for ip, ctx := range e.chalLast {
                lastCtx[ip] = ctx
            }
        }()

        if len(agg) > 0 {
            for ipStr, a := range agg {
                if a == nil {
                    continue
                }

                // decide which unique rule triggers first (paths > hosts)
                rule := ""
                limit := ""
                ttl := time.Duration(0)

                if haveUniqPathsIP && a.paths != nil && len(a.paths) >= e.cfg.ChallengeIPUniqPathsMin {
                    rule = "CHALLENGE_UNIQPATHS_IP"
                    limit = fmt.Sprintf("uniq_paths(%d/%d)", len(a.paths), e.cfg.ChallengeIPUniqPathsMin)
                    ttl = e.cfg.ChallengeIPUniqPathsTTL
                } else if haveUniqHostsIP && a.hosts != nil && len(a.hosts) >= e.cfg.ChallengeIPUniqHostsMin {
                    rule = "CHALLENGE_UNIQHOSTS_IP"
                    limit = fmt.Sprintf("uniq_hosts(%d/%d)", len(a.hosts), e.cfg.ChallengeIPUniqHostsMin)
                    ttl = e.cfg.ChallengeIPUniqHostsTTL
                }

                if rule == "" {
                    continue
                }

                ip := net.ParseIP(ipStr)
                if ip == nil {
                    continue
                }
                if isLocalInterfaceIP(ip) || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
                    continue
                }

                // burst cooldown (reuse the same map)
                skip := func() bool {
                    e.emitMu.Lock()
                    defer e.emitMu.Unlock()
                    last, ok := e.ipLastChalEmit[ipStr]
                    if ok && now.Sub(last) < 5*time.Second {
                        return true
                    }
                    e.ipLastChalEmit[ipStr] = now
                    return false
                }()
                if skip {
                    continue
                }

                ctx := lastCtx[ipStr]
                if e.hostBypassed(ctx.Host) {
                    if e.cfg.ChallengeLogSuppressed {
                        logging.Logf("[challenge_suppressed] ip=%s host=%s rule=%s reason=host_bypass", ipStr, ctx.Host, rule)
                    }
                    continue
                }

                if ttl <= 0 {
                    ttl = e.cfg.ChallengePathsTTL
                    if ttl <= 0 {
                        ttl = 30 * time.Minute
                    }
                }

                extra := map[string]string{
                    "detector":         "webdetector",
                    "ip":               ipStr,
                    "action":           "challenge",
                    "rule":             rule,
                    "limit":            limit,
                    "ttl":              ttl.String(),
                    "challenge_log":    boolFlag(e.cfg.ChallengeLog),
                    "challenge_notify": boolFlag(e.cfg.ChallengeNotify),
                    "challenge_log_suppressed": boolFlag(e.cfg.ChallengeLogSuppressed),
                    "challenge_log_expired":    boolFlag(e.cfg.ChallengeLogExpired),
                }
                if ctx.Host != "" { extra["host"] = ctx.Host }
                if ctx.URI != ""  { extra["uri"]  = ctx.URI }
                if ctx.Method != "" { extra["method"] = ctx.Method }
                if ctx.Status != 0  { extra["status"] = fmt.Sprintf("%d", ctx.Status) }

                alet := core.Alert{
                    When:    now,
                    Kind:    core.AlertKind("WEB/CHALLENGE"),
                    Key:     ipStr,
                    Count:   0,
                    Extra:   extra,
                }

                // Skip IPs in IGNORE_IPS/IGNORE_NETS or matching a chalExclude rule.
            if e.isBypassed(ipStr) || e.isExcluded(ipStr, ctx.Host, ctx.UA, rule) {
                    if e.cfg.ChallengeLogSuppressed {
                        logging.Logf("[challenge_suppressed] ip=%s host=%s rule=%s reason=bypass_or_exclude", ipStr, ctx.Host, rule)
                    }
                    continue
                }
                e.RecordIPChallenge(ipStr, ctx.Host, rule, ctx.URI, ctx.Method, ctx.Status, ttl)
                alet.Samples = e.ipSamples(ipStr, 8)
                select { case out <- alet: default: }
            }
        }
    }




    // ---- 1) CHALLENGE_PATHS (existing behavior) ----
    // Aggregate counts over current short window
	type cand struct {
		ip    string
		count int
		ridx  int
		sub   string
		thr   int
		host  string
		uri   string
	}

        if havePaths {
                // Aggregate counts over current short window
                agg := make(map[string]map[int]int) // ip -> ridx -> count

                func() {
                e.mu.RLock()
                        defer e.mu.RUnlock()
                        for _, hs := range e.hosts {
                                if hs == nil {
                                        continue
                                }
                                for i := range hs.buckets {
                                        b := &hs.buckets[i]
                                        if b.ipsChalRule == nil {
                                                continue
                                        }
                                        for ip, mm := range b.ipsChalRule {
                                                a := agg[ip]
                                                if a == nil {
                                                        a = make(map[int]int)
                                                        agg[ip] = a
                                                }
                                                for ridx, n := range mm {
                                                        a[ridx] += n
                                                }
                                        }
                                }
                        }
                        // snapshot last ctx too (under same lock)
                        lastCtx = make(map[string]chalCtx, len(e.chalLast))
                        for ip, ctx := range e.chalLast {
                                lastCtx[ip] = ctx
                        }
                }()

                if len(agg) > 0 {
                        // Build candidates (first rule that breaches threshold)
                        cands := make([]cand, 0, len(agg))
                        for ip, mm := range agg {
                                for ridx, n := range mm {
                                        if ridx < 0 || ridx >= len(e.chalRules) {
                                                continue
                                        }
                                        thr := e.chalRules[ridx].count
                                        if thr <= 0 {
                                                thr = 1
                                        }
                                        if n < thr {
                                                continue
                                        }
                                        ctx := lastCtx[ip]
                                        cands = append(cands, cand{
                                                ip:    ip,
                                                count: n,
                                                ridx:  ridx,
                                                sub:   e.chalRules[ridx].sub,
                                                thr:   thr,
                                                host:  ctx.Host,
                                                uri:   ctx.URI,
                                        })
                                        break
                                }
                        }

                        if len(cands) > 0 {
                                sort.Slice(cands, func(i, j int) bool { return cands[i].count > cands[j].count })
                                if len(cands) > topN {
                                        cands = cands[:topN]
                                }

                                for _, c := range cands {
                                        ip := net.ParseIP(c.ip)
                                        if ip == nil {
                                                continue
                                        }




                                        // don't challenge ourselves / private / loopback
                                        if isLocalInterfaceIP(ip) || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
                                                continue
                                        }

                                        // Emit only if there was a NEW matching request since last emit for this IP.
                                        ctx := lastCtx[c.ip]
                                        matchAt := tsToTime(ctx.TS)


                                        skip := func() bool {
                                                e.emitMu.Lock()
                                                defer e.emitMu.Unlock()
                                                last, ok := e.ipLastChalEmit[c.ip]
                                                if ok && !matchAt.After(last) {
                                                        return true
                                                }
                                                if ok && now.Sub(last) < cooldown {
                                                        return true
                                                }
                                                e.ipLastChalEmit[c.ip] = now
                                                return false
                                        }()
                                        if skip {
                                                continue
                                        }



        // Absolute host bypass wins over per-IP challenge.
        if e.hostBypassed(c.host) {
            if e.cfg.ChallengeLogSuppressed {
                logging.Logf("[challenge_suppressed] ip=%s host=%s rule=CHALLENGE_PATHS reason=host_bypass", c.ip, c.host)
            }
            continue
        }
 

                                        ttl := e.cfg.ChallengePathsTTL
                                        if ttl <= 0 {
                                                ttl = 30 * time.Minute
                                        }

                                        extra := map[string]string{
                                                "detector":         "webdetector",
                                                "ip":               c.ip,
                                                "action":           "challenge",
                                                "rule":             "CHALLENGE_PATHS",
                                                "match":            c.sub,
                                                "limit":            fmt.Sprintf("challenge_paths(%d/%d:%s)", c.count, c.thr, c.sub),
                                                "ttl":              ttl.String(),
                                                "challenge_log":    boolFlag(e.cfg.ChallengeLog),
                                                "challenge_notify": boolFlag(e.cfg.ChallengeNotify),
                                                "challenge_log_suppressed": boolFlag(e.cfg.ChallengeLogSuppressed),
                                                "challenge_log_expired":    boolFlag(e.cfg.ChallengeLogExpired),
                                        }
                                        if c.host != "" {
                                                extra["host"] = c.host
                                        }
                                        if c.uri != "" {
                                                extra["uri"] = c.uri
                                        }

                                        // NEW: sample method/status if known
                                        if ctx := lastCtx[c.ip]; ctx.Method != "" { extra["method"] = ctx.Method }
                                        if ctx := lastCtx[c.ip]; ctx.Status != 0 { extra["status"] = fmt.Sprintf("%d", ctx.Status) }

                                        a := core.Alert{
                                                When:    now,
                                                Kind:    core.AlertKind("WEB/CHALLENGE"),
                                                Key:     c.ip,
                                                Count:   c.count,
                                                Extra:   extra,
                                        }

            // record to challenge API store (best-effort)
e.RecordIPChallenge(c.ip, c.host, "CHALLENGE_PATHS", c.uri, ctx.Method, ctx.Status, ttl)

                                        // Skip IPs in IGNORE_IPS/IGNORE_NETS or matching a chalExclude rule.
                                        if e.isBypassed(c.ip) || e.isExcluded(c.ip, c.host, ctx.UA, "CHALLENGE_PATHS") {
                                            if e.cfg.ChallengeLogSuppressed {
                                                logging.Logf("[challenge_suppressed] ip=%s host=%s rule=CHALLENGE_PATHS reason=bypass_or_exclude", c.ip, c.host)
                                            }
                                            continue
                                        }

                                        a.Samples = e.ipSamples(c.ip, maxSamples)
                                        select {
                                        case out <- a:
                                        default:
                                        }

                                }
                        }
                }
        }


    // ---- 2) Threshold-based per-IP challenge triggers ----
    if haveThr {
        type agg2 struct {
            total int
            c4xx  int
            c5xx  int
            cPOST int
            cNoUA int
            cH10  int
        }
        st := make(map[string]*agg2)



        func() {
        e.mu.RLock()

            defer e.mu.RUnlock()
            for _, hs := range e.hosts {
                if hs == nil { continue }
                for i := range hs.buckets {
                    b := &hs.buckets[i]
                    for ip, n := range b.ips {
                        a := st[ip]
                        if a == nil { a = &agg2{}; st[ip] = a }
                        a.total += n
                    }
                    if b.ips4xx != nil {
                        for ip, n := range b.ips4xx {
                            a := st[ip]
                            if a == nil { a = &agg2{}; st[ip] = a }
                            a.c4xx += n
                        }
                    }
                    if b.ips5xx != nil {
                        for ip, n := range b.ips5xx {
                            a := st[ip]
                            if a == nil { a = &agg2{}; st[ip] = a }
                            a.c5xx += n
                        }
                    }
                    if b.ipsPOST != nil {
                        for ip, n := range b.ipsPOST {
                            a := st[ip]
                            if a == nil { a = &agg2{}; st[ip] = a }
                            a.cPOST += n
                        }
                    }
                    if b.ipsNoUA != nil {
                        for ip, n := range b.ipsNoUA {
                            a := st[ip]
                            if a == nil { a = &agg2{}; st[ip] = a }
                            a.cNoUA += n
                        }
                    }
                    if b.ipsHTTP10 != nil {
                        for ip, n := range b.ipsHTTP10 {
                            a := st[ip]
                            if a == nil { a = &agg2{}; st[ip] = a }
                            a.cH10 += n
                        }
                    }
                }
            }
            // snapshot last ctx under same lock
            lastCtx = make(map[string]chalCtx, len(e.chalLast))
            for ip, ctx := range e.chalLast {
                lastCtx[ip] = ctx
            }
        }()

        winSec := e.cfg.Window.Seconds()
        if winSec <= 0 { winSec = 60 }

        // floor to avoid silly ratios from tiny samples
        const minReqForRatio = 20

        for ipStr, a := range st {
            if a == nil || a.total <= 0 { continue }

            rps := float64(a.total) / winSec
            rps4 := float64(a.c4xx) / winSec
            rps5 := float64(a.c5xx) / winSec
            errRatio := float64(a.c4xx+a.c5xx) / float64(a.total)
            postRatio := float64(a.cPOST) / float64(a.total)

            // Decide first matching threshold (ordered by "signal strength")
            rule := ""
            limit := ""
            if e.cfg.ChallengeIPHTTP10Min > 0 && a.cH10 >= e.cfg.ChallengeIPHTTP10Min {
                rule = "CHALLENGE_HTTP10"
                limit = fmt.Sprintf("http10(%d/%d)", a.cH10, e.cfg.ChallengeIPHTTP10Min)
            } else if e.cfg.ChallengeIPNoUAMin > 0 && a.cNoUA >= e.cfg.ChallengeIPNoUAMin {
                rule = "CHALLENGE_NO_UA"
                limit = fmt.Sprintf("no_ua(%d/%d)", a.cNoUA, e.cfg.ChallengeIPNoUAMin)
            } else if e.cfg.ChallengeIP5xxRPSMin > 0 && rps5 >= e.cfg.ChallengeIP5xxRPSMin {
                rule = "CHALLENGE_RPS_5XX"
                limit = fmt.Sprintf("rps_5xx(%.3f/%.3f)", rps5, e.cfg.ChallengeIP5xxRPSMin)
            } else if e.cfg.ChallengeIP4xxRPSMin > 0 && rps4 >= e.cfg.ChallengeIP4xxRPSMin {
                rule = "CHALLENGE_RPS_4XX"
                limit = fmt.Sprintf("rps_4xx(%.3f/%.3f)", rps4, e.cfg.ChallengeIP4xxRPSMin)
            } else if e.cfg.ChallengeIPErrRatioMin > 0 && a.total >= minReqForRatio && errRatio >= e.cfg.ChallengeIPErrRatioMin {
                rule = "CHALLENGE_ERR_RATIO"
                limit = fmt.Sprintf("err_ratio(%.3f/%.3f req=%d)", errRatio, e.cfg.ChallengeIPErrRatioMin, a.total)
            } else if e.cfg.ChallengeIPPostRatioMin > 0 && a.total >= minReqForRatio && postRatio >= e.cfg.ChallengeIPPostRatioMin {
                rule = "CHALLENGE_POST_RATIO"
                limit = fmt.Sprintf("post_ratio(%.3f/%.3f req=%d)", postRatio, e.cfg.ChallengeIPPostRatioMin, a.total)
            } else if e.cfg.ChallengeIPRPSMin > 0 && rps >= e.cfg.ChallengeIPRPSMin {
                rule = "CHALLENGE_RPS_TOTAL"
                limit = fmt.Sprintf("rps_total(%.3f/%.3f)", rps, e.cfg.ChallengeIPRPSMin)
            }

            if rule == "" { continue }

            ip := net.ParseIP(ipStr)
            if ip == nil { continue }
            if isLocalInterfaceIP(ip) || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
                continue
            }

            // cooldown gating (reuses the same per-IP chal emit map)

            skip := func() bool {
                e.emitMu.Lock()
                defer e.emitMu.Unlock()
                last, ok := e.ipLastChalEmit[ipStr]
                if ok && now.Sub(last) < cooldown {
                    return true
                }
                e.ipLastChalEmit[ipStr] = now
                return false
            }()
            if skip {
                continue
            }


            ctx := lastCtx[ipStr]

    // Absolute host bypass wins over per-IP challenge.
    if e.hostBypassed(ctx.Host) {
        if e.cfg.ChallengeLogSuppressed {
            logging.Logf("[challenge_suppressed] ip=%s host=%s rule=%s reason=host_bypass", ipStr, ctx.Host, rule)
        }
        continue
    }

            ttl := e.cfg.ChallengePathsTTL
            if ttl <= 0 { ttl = 30 * time.Minute }

            extra := map[string]string{
                "detector":         "webdetector",
                "ip":               ipStr,
                "action":           "challenge",
                "rule":             rule,
                "limit":            limit,
                "ttl":              ttl.String(),
                "challenge_log":    boolFlag(e.cfg.ChallengeLog),
                "challenge_notify": boolFlag(e.cfg.ChallengeNotify),
         "challenge_log_suppressed": boolFlag(e.cfg.ChallengeLogSuppressed),
         "challenge_log_expired":    boolFlag(e.cfg.ChallengeLogExpired),
            }
            if ctx.Host != "" { extra["host"] = ctx.Host }
            if ctx.URI != ""  { extra["uri"]  = ctx.URI }
            if ctx.Method != "" { extra["method"] = ctx.Method }
            if ctx.Status != 0  { extra["status"] = fmt.Sprintf("%d", ctx.Status) }

            alet := core.Alert{
                When:    now,
                Kind:    core.AlertKind("WEB/CHALLENGE"),
                Key:     ipStr,
                Count:   a.total,
                Extra:   extra,
            }
            e.RecordIPChallenge(ipStr, ctx.Host, rule, ctx.URI, ctx.Method, ctx.Status, ttl)
            // Skip IPs in IGNORE_IPS/IGNORE_NETS or matching a chalExclude rule.
                if e.isBypassed(ipStr) || e.isExcluded(ipStr, ctx.Host, ctx.UA, rule) {
                if e.cfg.ChallengeLogSuppressed {
                    logging.Logf("[challenge_suppressed] ip=%s host=%s rule=%s reason=bypass_or_exclude", ipStr, ctx.Host, rule)
                }
                continue
            }
            alet.Samples = e.ipSamples(ipStr, maxSamples)
            select { case out <- alet: default: }
        }
    }





    // ---- 2b) Malformed request burst (400 + 414 + 431) ----
    // Header/URI fuzzing and WAF-bypass tooling produce these in volume.
    if haveMalformed {
        stMalf := make(map[string]int)
        func() {
            e.mu.RLock()
            defer e.mu.RUnlock()
            for _, hs := range e.hosts {
                if hs == nil { continue }
                for i := range hs.buckets {
                    b := &hs.buckets[i]
                    for ip, n := range b.ipsMalformed {
                        stMalf[ip] += n
                    }
                }
            }
        }()

        for ipStr, cnt := range stMalf {
            if cnt < e.cfg.ChallengeIPMalformedMin { continue }
            ip := net.ParseIP(ipStr)
            if ip == nil { continue }
            if isLocalInterfaceIP(ip) || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() { continue }

            skip := func() bool {
                e.emitMu.Lock()
                defer e.emitMu.Unlock()
                last, ok := e.ipLastChalEmit[ipStr]
                if ok && now.Sub(last) < cooldown { return true }
                e.ipLastChalEmit[ipStr] = now
                return false
            }()
            if skip { continue }

            ctx := lastCtx[ipStr]
            if e.hostBypassed(ctx.Host) { continue }

            ttl := e.cfg.ChallengeIPMalformedTTL
            if ttl <= 0 { ttl = 30 * time.Minute }

            limit := fmt.Sprintf("malformed(%d/%d)", cnt, e.cfg.ChallengeIPMalformedMin)
            extra := map[string]string{
                "detector":         "webdetector",
                "ip":               ipStr,
                "action":           "challenge",
                "rule":             "CHALLENGE_MALFORMED",
                "limit":            limit,
                "ttl":              ttl.String(),
                "challenge_log":    boolFlag(e.cfg.ChallengeLog),
                "challenge_notify": boolFlag(e.cfg.ChallengeNotify),
                "challenge_log_suppressed": boolFlag(e.cfg.ChallengeLogSuppressed),
                "challenge_log_expired":    boolFlag(e.cfg.ChallengeLogExpired),
            }
            if ctx.Host != "" { extra["host"] = ctx.Host }
            if ctx.URI != ""  { extra["uri"]  = ctx.URI }
            if ctx.Status != 0 { extra["status"] = fmt.Sprintf("%d", ctx.Status) }

            alet := core.Alert{
                When:    now,
                Kind:    core.AlertKind("WEB/CHALLENGE"),
                Key:     ipStr,
                Count:   cnt,
                Extra:   extra,
            }
            e.RecordIPChallenge(ipStr, ctx.Host, "CHALLENGE_MALFORMED", ctx.URI, ctx.Method, ctx.Status, ttl)
            // Skip IPs in IGNORE_IPS/IGNORE_NETS or matching a chalExclude rule.
            if e.isBypassed(ipStr) || e.isExcluded(ipStr, ctx.Host, ctx.UA, "CHALLENGE_MALFORMED") {
                if e.cfg.ChallengeLogSuppressed {
                    logging.Logf("[challenge_suppressed] ip=%s host=%s rule=CHALLENGE_MALFORMED reason=bypass_or_exclude", ipStr, ctx.Host)
                }
                continue
            }
            alet.Samples = e.ipSamples(ipStr, maxSamples)
            select { case out <- alet: default: }
        }
    }


    // ---- 2c) UA churn (many distinct User-Agent strings from one IP) ----
    // Real browsers don't rotate UAs. Tooling does, to evade AGENT_LIST filters.
    if haveUniqUA {
        type uaAgg struct{ uniq map[uint64]struct{} }
        agg := make(map[string]*uaAgg)

        func() {
            e.mu.RLock()
            defer e.mu.RUnlock()
            for _, hs := range e.hosts {
                if hs == nil { continue }
                for i := range hs.buckets {
                    b := &hs.buckets[i]
                    for ip, set := range b.ipsUniqUA {
                        a := agg[ip]
                        if a == nil {
                            a = &uaAgg{uniq: make(map[uint64]struct{}, 8)}
                            agg[ip] = a
                        }
                        if len(a.uniq) < e.cfg.ChallengeIPUniqUAMin {
                            for h := range set {
                                a.uniq[h] = struct{}{}
                                if len(a.uniq) >= e.cfg.ChallengeIPUniqUAMin { break }
                            }
                        }
                    }
                }
            }
        }()

        for ipStr, a := range agg {
            if len(a.uniq) < e.cfg.ChallengeIPUniqUAMin { continue }
            ip := net.ParseIP(ipStr)
            if ip == nil { continue }
            if isLocalInterfaceIP(ip) || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() { continue }

            skip := func() bool {
                e.emitMu.Lock()
                defer e.emitMu.Unlock()
                last, ok := e.ipLastChalEmit[ipStr]
                if ok && now.Sub(last) < 5*time.Second { return true }
                e.ipLastChalEmit[ipStr] = now
                return false
            }()
            if skip { continue }

            ctx := lastCtx[ipStr]
            if e.hostBypassed(ctx.Host) { continue }

            ttl := e.cfg.ChallengeIPUniqUATTL
            if ttl <= 0 { ttl = 20 * time.Minute }

            limit := fmt.Sprintf("uniq_ua(%d/%d)", len(a.uniq), e.cfg.ChallengeIPUniqUAMin)
            extra := map[string]string{
                "detector":         "webdetector",
                "ip":               ipStr,
                "action":           "challenge",
                "rule":             "CHALLENGE_UNIQUA",
                "limit":            limit,
                "ttl":              ttl.String(),
                "challenge_log":    boolFlag(e.cfg.ChallengeLog),
                "challenge_notify": boolFlag(e.cfg.ChallengeNotify),
                "challenge_log_suppressed": boolFlag(e.cfg.ChallengeLogSuppressed),
                "challenge_log_expired":    boolFlag(e.cfg.ChallengeLogExpired),
            }
            if ctx.Host != "" { extra["host"] = ctx.Host }
            if ctx.URI != ""  { extra["uri"]  = ctx.URI }

            alet := core.Alert{
                When:    now,
                Kind:    core.AlertKind("WEB/CHALLENGE"),
                Key:     ipStr,
                Count:   len(a.uniq),
                Extra:   extra,
            }
            e.RecordIPChallenge(ipStr, ctx.Host, "CHALLENGE_UNIQUA", ctx.URI, ctx.Method, ctx.Status, ttl)
            // Skip IPs in IGNORE_IPS/IGNORE_NETS or matching a chalExclude rule.
            if e.isBypassed(ipStr) || e.isExcluded(ipStr, ctx.Host, ctx.UA, "CHALLENGE_UNIQUA") {
                if e.cfg.ChallengeLogSuppressed {
                    logging.Logf("[challenge_suppressed] ip=%s host=%s rule=CHALLENGE_UNIQUA reason=bypass_or_exclude", ipStr, ctx.Host)
                }
                continue
            }
            alet.Samples = e.ipSamples(ipStr, maxSamples)
            select { case out <- alet: default: }
        }
    }


     // ---- 3) VHOST-wide challenge (manual panic + auto suspicious) ----
    //
    // Manual panic:
    //   CHALLENGE_VHOST = victim.com, *.victim.com
    // Ignore (wins):
    //   CHALLENGE_VHOST_IGNORE = api.mybank.gr
    //
    // Auto suspicious:
    //   CHALLENGE_SUSPICIOUS_VHOST=1
    //   CHALLENGE_SUSPICIOUS_VHOST_SCORE_ON/OFF, MIN_UNIQIP, HOLDDOWN
    //
    // Emits:
    //   - Per-IP WEB/CHALLENGE (action=challenge) for affected IPs
    //   - WEB/VHOST_CHALLENGE_ON/OFF once per state change (auto only)
    if haveVhostManual || haveVhostAuto {

        // OpenResty mode: push manual panic vhosts unconditionally
        // so they work even before the host appears in short/long windows.
        if e.nginxBridge != nil && haveVhostManual {
            vttl := 60 * time.Minute
            for _, pat := range e.cfg.ChallengeVHost {
                if pat == "" {
                    continue
                }

        // Absolute bypass wins over everything.
        if e.hostBypassed(pat) {
            e.nginxBridge.ClearVhost(pat)
            continue
        }

                // ignore list wins (only meaningful for exact hosts)
                // If someone puts an exact host in IGNORE, don't push it.
                if len(e.cfg.ChallengeVHostIgnore) > 0 && hostMatchAny(pat, e.cfg.ChallengeVHostIgnore) {
                    e.nginxBridge.ClearVhost(pat)
                    continue
                }
                // Dynamic Challenge-exclude wins over the CHALLENGE_VHOST list too.
                if e.hostChallengeExcluded(pat) {
                    // Throttle key is prefixed "cfg:" so this low-detail line does
                    // NOT share a slot with — and starve — the richer auto-suspicious
                    // suppressed_by_exclude line (keyed by bare host) for a host that
                    // is both in CHALLENGE_VHOST and an auto candidate.
                    if e.cfg.ChallengeLog && e.shouldLogVhostSuppress("cfg:"+pat, now) {
                        logging.LogfCHALLENGES("[challenge][vhost] action=suppressed_by_exclude host=%s would_reason=vhost_config note=host_in_challenge_excludes", pat)
                    }
                    e.nginxBridge.ClearVhost(pat)
                    continue
                }
                // reason "vhost_config": pushed from the CHALLENGE_VHOST config
                // list every reconcile — NOT a human action. (Was mislabelled
                // "manual", which read as an operator having clicked it.)
                e.nginxBridge.ChallengeVhostWithReason(pat, vttl, "vhost_config")
            }
        }


        // 1) Build short-window host -> (ip -> count)
        type hostAgg struct {
            ips map[string]int
        }
        short := make(map[string]*hostAgg)

        func() {
        e.mu.RLock()
            defer e.mu.RUnlock()

            for host, hs := range e.hosts {
                if hs == nil {
                    continue
                }
                ha := short[host]
                if ha == nil {
                    ha = &hostAgg{ips: make(map[string]int)}
                    short[host] = ha
                }
                for i := range hs.buckets {
                    b := &hs.buckets[i]
                    for ip, n := range b.ips {
                        ha.ips[ip] += n
                    }
                }
            }
        }()

        // 2) Candidate hosts = union of:
        //    - hosts we saw recently (short window)
        //    - hosts currently in under-attack state
        //    - hosts present in long window (for auto off)
        candHosts := make(map[string]struct{}, len(short))
        for h := range short { candHosts[h] = struct{}{} }

        func() {
            e.vhostMu.Lock()
            defer e.vhostMu.Unlock()
            for h := range e.vhostUnderAttack { candHosts[h] = struct{}{} }
        }()

        if e.longwin != nil {
            for _, r := range e.longwin.All() {
                if r.Host != "" {
                    candHosts[r.Host] = struct{}{}
                }
            }
        }

        // 3) Evaluate each host.
        // Pre-compute the long-window sum ONCE here so the per-host
        // OneFromCache call below is O(1) instead of O(slots*hosts).
        var longSums map[string]bucket
        if haveVhostAuto && e.longwin != nil {
            longSums = e.longwin.SumAll()
        }

        for host := range candHosts {
            if host == "" {
                continue
            }


    // Absolute bypass wins over all vhost-wide challenge actions.
    if e.hostBypassed(host) {
        if haveVhostAuto {
            wasOn := false
            func() {
                e.vhostMu.Lock()
                defer e.vhostMu.Unlock()
                if e.vhostUnderAttack[host] {
                    wasOn = true
                    e.vhostUnderAttack[host] = false
                    e.vhostLastChange[host] = now
                }
            }()
            if wasOn {
                if e.cfg.ChallengeLog {
                    logging.LogfCHALLENGES("[challenge][vhost] action=auto_off host=%s reason=host_bypass", host)
                }
                if e.nginxBridge != nil {
                    e.nginxBridge.ClearVhost(host)
                }
                if e.cfg.ChallengeNotify {
                    a := core.Alert{
                        When:  now,
                        Kind:  core.AlertKind("WEB/VHOST_CHALLENGE_OFF"),
                        Key:   host,
                        Count: 0,
                        Extra: map[string]string{"host": host, "action": "auto_off", "reason": "host_bypass"},
                    }
                    select { case out <- a: default: }
                }
            }
        }
        if e.nginxBridge != nil {
            e.nginxBridge.ClearVhost(host)
        }
        continue
    }

    // Dynamic Challenge-exclude wins over vhost-wide challenge (auto-suspicious
    // AND the CHALLENGE_VHOST list). Unlike host_bypass/ignore, it leaves a
    // paper trail: if the suspicious scorer WOULD flag this host now, log
    // suppressed_by_exclude with the trigger + scale, so an operator who chose
    // to exclude a host has proof of exactly what protection they opted out of
    // ("we would have challenged N unique IPs on this vhost — you excluded it").
    if e.hostChallengeExcluded(host) {
        if haveVhostAuto {
            if e.cfg.ChallengeLog && e.longwin != nil {
                row := SuspiciousRow{Host: host}
                if r, ok := e.longwin.OneFromCache(longSums, host); ok {
                    row = r
                }
                if why := e.tripReason(row); why != "" && e.shouldLogVhostSuppress(host, now) {
                    logging.LogfCHALLENGES(
                        "[challenge][vhost] action=suppressed_by_exclude host=%s would_reason=%s score=%.2f uniqIP=%d rps=%.2f reasons=%s note=host_in_challenge_excludes",
                        host, why, row.Score, row.UniqueIPs, row.RPS, strings.Join(row.Reasons, ","),
                    )
                }
            }
            // Turn off any active auto state so the display + bridge agree.
            wasOn := false
            func() {
                e.vhostMu.Lock()
                defer e.vhostMu.Unlock()
                if e.vhostUnderAttack[host] {
                    wasOn = true
                    e.vhostUnderAttack[host] = false
                    e.vhostLastChange[host] = now
                }
            }()
            if wasOn {
                if e.cfg.ChallengeLog {
                    logging.LogfCHALLENGES("[challenge][vhost] action=auto_off host=%s reason=excluded", host)
                }
                // Emit the OFF alert to the sink, same as the host_bypass/ignored
                // paths — otherwise excluding an active vhost silently drops the
                // notification that the challenge lifted.
                if e.cfg.ChallengeNotify {
                    a := core.Alert{
                        When:  now,
                        Kind:  core.AlertKind("WEB/VHOST_CHALLENGE_OFF"),
                        Key:   host,
                        Count: 0,
                        Extra: map[string]string{"host": host, "action": "auto_off", "reason": "excluded"},
                    }
                    select { case out <- a: default: }
                }
            }
        }
        if e.nginxBridge != nil {
            e.nginxBridge.ClearVhost(host)
        }
        continue
    }


            // Ignore list wins for vhost-wide actions
            if len(e.cfg.ChallengeVHostIgnore) > 0 && hostMatchAny(host, e.cfg.ChallengeVHostIgnore) {
                // If auto-state is currently ON, turn it off and emit OFF (reason=ignored).
                if haveVhostAuto {




                        wasOn := false
                        func() {
                            e.vhostMu.Lock()
                            defer e.vhostMu.Unlock()
                            if e.vhostUnderAttack[host] {
                                wasOn = true
                                e.vhostUnderAttack[host] = false
                                e.vhostLastChange[host] = now
                            }
                        }()

                        if wasOn {
                            if e.cfg.ChallengeLog {
                                logging.LogfCHALLENGES("[challenge][vhost] action=auto_off host=%s reason=ignored", host)
                            }


                            if e.nginxBridge != nil {
                                e.nginxBridge.ClearVhost(host)
                            }


                            if e.cfg.ChallengeNotify {
                                a := core.Alert{
                                    When:  now,
                                    Kind:  core.AlertKind("WEB/VHOST_CHALLENGE_OFF"),
                                    Key:   host,
                                    Count: 0,
                                    Extra: map[string]string{
                                        "host":   host,
                                        "action": "auto_off",
                                        "reason": "ignored",
                                    },
                                }
                                select { case out <- a: default: }

                           if e.nginxBridge != nil {
                               e.nginxBridge.ClearVhost(host)
                           }


                            }
                        }
		}

                continue
            }




            // ---- NEW: VHOST unique-paths trigger (bridge mode) ----
            // If enabled and nginxBridge is active, challenge the whole vhost when
            // unique paths in short window explode (crawl storm).
            if haveUniqPathsVhost && e.nginxBridge != nil {
                // compute unique paths for this vhost over short window (union of b.paths)
                uniq := 0
                capN := e.cfg.ChallengeVhostUniqPathsCap
                if capN <= 0 {
                    capN = 5000
                }
                seen := make(map[string]struct{}, 256)
                e.mu.RLock()
                hs := e.hosts[host]
                if hs != nil {
                    for i := range hs.buckets {
                        b := &hs.buckets[i]
                        for pth := range b.paths {
                            seen[pth] = struct{}{}
                            if len(seen) >= capN {
                                break
                            }
                        }
                        if len(seen) >= capN {
                            break
                        }
                    }
                }
                e.mu.RUnlock()
                uniq = len(seen)

                // hysteresis ON/OFF state to avoid log spam
                on := e.cfg.ChallengeVhostUniqPathsMin
                off := e.cfg.ChallengeVhostUniqPathsOff
                ttl := e.cfg.ChallengeVhostUniqPathsTTL
                if ttl <= 0 {
                    ttl = 20 * time.Minute
                }

                shouldOn := uniq >= on
                shouldOff := uniq <= off

                var doChallenge bool
                var doLogOn bool
                e.vhostMu.Lock()
                cur := e.vhostUniqPathsActive[host]
                if !cur && shouldOn {
                    e.vhostUniqPathsActive[host] = true
                    e.vhostUniqPathsLastChange[host] = now
                    doChallenge = true
                    doLogOn = true
                } else if cur && shouldOff {
                    e.vhostUniqPathsActive[host] = false
                    e.vhostUniqPathsLastChange[host] = now
                } else if cur {
                    doChallenge = true // keep refreshing TTL while active
                }
                e.vhostMu.Unlock()

if doChallenge {
    // Protect bypass/excluded IPs from the vhost-wide challenge.
    if ha := short[host]; ha != nil {
        bypTTL := ttl + 2*time.Minute
        for ipStr := range ha.ips {
            byp := e.isBypassed(ipStr)
            exc := e.isExcluded(ipStr, host, "", "CHALLENGE_VHOST_UNIQPATHS")

//            logging.Logf("[challenge][debug] uniqpaths_bypass_check host=%s ip=%s rule=%s bypass=%v excluded=%v",
  //              host, ipStr, "CHALLENGE_VHOST_UNIQPATHS", byp, exc)

            if byp || exc {
//                logging.Logf("[challenge][debug] uniqpaths_bypass_apply host=%s ip=%s ttl=%s",
//                    host, ipStr, bypTTL)
                e.nginxBridge.BypassIPTemp(ipStr, bypTTL)
            }
        }
    }
                    e.nginxBridge.ChallengeVhostWithReason(host, ttl, "uniqpaths_short")
                    if doLogOn && e.cfg.ChallengeLog {
                        logging.LogfCHALLENGES("[challenge][vhost] action=auto_on host=%s reason=uniqpaths_short uniqPaths=%d on=%d off=%d ttl=%s",
                            host, uniq, on, off, ttl.String())
                    }
                    // vhost-wide challenge overrides need for per-IP enumeration
                    continue
                }
            }









            // Manual panic applies immediately.
manual := (haveVhostManual && hostMatchAny(host, e.cfg.ChallengeVHost)) ||
func() bool { ok, _, _ := e.manualChallengeCovering(host); return ok }()

            // Auto suspicious: long-window score with hysteresis + holddown.
            autoActive := false
            var row SuspiciousRow
            if haveVhostAuto && e.longwin != nil {
                autoWhy := ""
                r, ok := e.longwin.OneFromCache(longSums, host)
                if ok {
                    row = r
                } else {
                    row = SuspiciousRow{Host: host}
                }

                on  := e.cfg.ChallengeSuspiciousScoreOn
                off := e.cfg.ChallengeSuspiciousScoreOff
                minUniq := e.cfg.ChallengeSuspiciousMinUniqIP
                hold := e.cfg.ChallengeSuspiciousHolddown

				// uniqIP-based auto mode (optional)
				uniqEn := e.cfg.ChallengeSuspiciousUniqIP
				uniqOn := e.cfg.ChallengeSuspiciousUniqIPOn
				uniqOff := e.cfg.ChallengeSuspiciousUniqIPOff
				uniqMax := e.cfg.ChallengeSuspiciousUniqIPMax




                // IMPORTANT: don't defer-unlock in the outer loop, or you'll hold the lock
                // for all hosts and deadlock. Scope it to this iteration.
                autoActive = func() bool {
                    e.vhostMu.Lock()
                    defer e.vhostMu.Unlock()

                    cur := e.vhostUnderAttack[host]
                    last := e.vhostLastChange[host]

                    // holddown keeps it ON for a minimum duration
                    if cur && hold > 0 && !last.IsZero() && now.Sub(last) < hold {
                        return true
                    }

                    if !cur {
			// Single-sourced trip decision: tripReason() is the SAME function the
			// suppressed_by_exclude audit path uses, so the audit log can never
			// disagree with the real decision (CLAUDE.md §5). The three branches
			// below just apply + log the outcome tripReason already chose.
			autoWhy = e.tripReason(row)
			// 1) hard cap (if set): challenge immediately
			if autoWhy == "uniqip_max" {
                            e.vhostUnderAttack[host] = true
                            e.vhostLastChange[host] = now

                            if e.cfg.ChallengeLog {
                                logging.LogfCHALLENGES(
				"[challenge][vhost] action=auto_on host=%s reason=%s score=%.2f on=%.2f off=%.2f uniqIP=%d uniq_on=%d uniq_off=%d uniq_max=%d rps=%.2f reasons=%s hold=%s",
				host, autoWhy, row.Score, on, off, row.UniqueIPs, uniqOn, uniqOff, uniqMax, row.RPS, strings.Join(row.Reasons, ","), hold.String(),
                                )
                            }

                            // record to challenge API store
                            e.RecordVhostAuto(host, true, row, on, off, hold)

                            if e.cfg.ChallengeNotify {
                                a := core.Alert{
                                    When:  now,
                                    Kind:  core.AlertKind("WEB/VHOST_CHALLENGE_ON"),
                                    Key:   host,
                                    Count: row.UniqueIPs,
                                    Extra: map[string]string{
                                        "host":      host,
                                        "action":    "auto_on",
					"reason":    autoWhy,
                                        "score":     fmt.Sprintf("%.2f", row.Score),
                                        "score_on":  fmt.Sprintf("%.2f", on),
                                        "score_off": fmt.Sprintf("%.2f", off),
                                        "uniqIP":    fmt.Sprintf("%d", row.UniqueIPs),
					"uniq_on":   fmt.Sprintf("%d", uniqOn),
					"uniq_off":  fmt.Sprintf("%d", uniqOff),
					"uniq_max":  fmt.Sprintf("%d", uniqMax),
                                        "rps":       fmt.Sprintf("%.2f", row.RPS),
                                        "reasons":   strings.Join(row.Reasons, ","),
                                        "holddown":  hold.String(),
                                    },
                                }
                                select { case out <- a: default: }
                            }
                            return true
                        }





                        // 2) uniqIP hysteresis ON threshold
                        if autoWhy == "uniqip_on" {
                            e.vhostUnderAttack[host] = true
                            e.vhostLastChange[host] = now

                            if e.cfg.ChallengeLog {
                                logging.LogfCHALLENGES(
                                    "[challenge][vhost] action=auto_on host=%s reason=%s score=%.2f on=%.2f off=%.2f uniqIP=%d uniq_on=%d uniq_off=%d uniq_max=%d rps=%.2f reasons=%s hold=%s",
                                    host, autoWhy, row.Score, on, off, row.UniqueIPs, uniqOn, uniqOff, uniqMax, row.RPS, strings.Join(row.Reasons, ","), hold.String(),
                                )
                            }

                            e.RecordVhostAuto(host, true, row, on, off, hold)

                            if e.cfg.ChallengeNotify {
                                a := core.Alert{
                                    When:  now,
                                    Kind:  core.AlertKind("WEB/VHOST_CHALLENGE_ON"),
                                    Key:   host,
                                    Count: row.UniqueIPs,
                                    Extra: map[string]string{
                                        "host":      host,
                                        "action":    "auto_on",
                                        "reason":    autoWhy,
                                        "score":     fmt.Sprintf("%.2f", row.Score),
                                        "score_on":  fmt.Sprintf("%.2f", on),
                                        "score_off": fmt.Sprintf("%.2f", off),
                                        "uniqIP":    fmt.Sprintf("%d", row.UniqueIPs),
                                        "uniq_on":   fmt.Sprintf("%d", uniqOn),
                                        "uniq_off":  fmt.Sprintf("%d", uniqOff),
                                        "uniq_max":  fmt.Sprintf("%d", uniqMax),
                                        "rps":       fmt.Sprintf("%.2f", row.RPS),
                                        "reasons":   strings.Join(row.Reasons, ","),
                                        "holddown":  hold.String(),
                                    },
                                }
                                select { case out <- a: default: }
                            }
                            return true
                        }

                        // 3) legacy score ON threshold (+ min uniq gate)
                        if autoWhy == "score_on" {
                            e.vhostUnderAttack[host] = true
                            e.vhostLastChange[host] = now

                            if e.cfg.ChallengeLog {
                                logging.LogfCHALLENGES(
                                    "[challenge][vhost] action=auto_on host=%s reason=%s score=%.2f on=%.2f off=%.2f uniqIP=%d min_uniq=%d uniq_on=%d uniq_off=%d uniq_max=%d rps=%.2f reasons=%s hold=%s",
                                    host, autoWhy, row.Score, on, off, row.UniqueIPs, minUniq, uniqOn, uniqOff, uniqMax, row.RPS, strings.Join(row.Reasons, ","), hold.String(),
                                )
                            }

                            e.RecordVhostAuto(host, true, row, on, off, hold)

                            if e.cfg.ChallengeNotify {
                                a := core.Alert{
                                    When:  now,
                                    Kind:  core.AlertKind("WEB/VHOST_CHALLENGE_ON"),
                                    Key:   host,
                                    Count: row.UniqueIPs,
                                    Extra: map[string]string{
                                        "host":      host,
                                        "action":    "auto_on",
                                        "reason":    autoWhy,
                                        "score":     fmt.Sprintf("%.2f", row.Score),
                                        "score_on":  fmt.Sprintf("%.2f", on),
                                        "score_off": fmt.Sprintf("%.2f", off),
                                        "uniqIP":    fmt.Sprintf("%d", row.UniqueIPs),
                                        "min_uniq":  fmt.Sprintf("%d", minUniq),
                                        "uniq_on":   fmt.Sprintf("%d", uniqOn),
                                        "uniq_off":  fmt.Sprintf("%d", uniqOff),
                                        "uniq_max":  fmt.Sprintf("%d", uniqMax),
                                        "rps":       fmt.Sprintf("%.2f", row.RPS),
                                        "reasons":   strings.Join(row.Reasons, ","),
                                        "holddown":  hold.String(),
                                    },
                                }
                                select { case out <- a: default: }
                            }
                            return true
                        }

                        return false



                    }











                    // currently ON: keep ON while uniqIP hard cap exceeded
                    if uniqEn && uniqMax > 0 && row.UniqueIPs >= uniqMax {
                        return true
                    }

                    // currently ON: turn OFF when cooled down
                    // - legacy: score <= off
                    // - uniqIP mode: require BOTH score <= off AND uniqIP <= uniqOff
                    offOK := (row.Score <= off)
                    if uniqEn && uniqOff > 0 {
                        offOK = offOK && (row.UniqueIPs <= uniqOff)
                    }

                    if offOK {
                        e.vhostUnderAttack[host] = false
                        e.vhostLastChange[host] = now

                        // Auto cool-down must not tear down an operator manual
                        // challenge: ClearVhost deletes the bridge entry no
                        // matter who installed it, and the manual re-push later
                        // this tick would recreate it with the tick TTL —
                        // silently shortening e.g. a 24h manual challenge to 1h
                        // (and losing it entirely once the vhost drops out of
                        // the candidate set). Keep the bridge entry while a
                        // manual challenge covers this host; only the auto
                        // flag turns off.
                        if covered, mexp, _ := e.manualChallengeCovering(host); covered {
                            if e.cfg.ChallengeLog {
                                logging.LogfCHALLENGES(
                                    "[challenge][vhost] action=auto_off_keep_manual host=%s manual_expires_in=%s",
                                    host, time.Until(mexp).Round(time.Second),
                                )
                            }
                        } else if e.nginxBridge != nil {
                            e.nginxBridge.ClearVhost(host)
                        }


                        if e.cfg.ChallengeLog {
                            logging.LogfCHALLENGES(
                                "[challenge][vhost] action=auto_off host=%s score=%.2f off=%.2f uniqIP=%d rps=%.2f reasons=%s",
                                host, row.Score, off, row.UniqueIPs, row.RPS, strings.Join(row.Reasons, ","),
                            )
                        }

                        // record to challenge API store
                        e.RecordVhostAuto(host, false, row, on, off, hold)

                        if e.cfg.ChallengeNotify {
                            a := core.Alert{
                                When:  now,
                                Kind:  core.AlertKind("WEB/VHOST_CHALLENGE_OFF"),
                                Key:   host,
                                Count: 0,
                                Extra: map[string]string{
                                    "host":      host,
                                    "action":    "auto_off",
                                    "score":     fmt.Sprintf("%.2f", row.Score),
                                    "score_off": fmt.Sprintf("%.2f", off),
                                    "uniqIP":    fmt.Sprintf("%d", row.UniqueIPs),
                                    "rps":       fmt.Sprintf("%.2f", row.RPS),
                                    "reasons":   strings.Join(row.Reasons, ","),
                                },
                            }
                            select { case out <- a: default: }
                        }
                        return false
                    }
                    return true
                }()



            }

            effective := manual || autoActive
            if !effective {
                continue
            }

            // OpenResty mode: push vhost-wide challenge to the bridge.
            // No per-IP enumeration needed — the bridge challenges the whole vhost.
            // Exception: protect IPs that are in IGNORE_IPS/IGNORE_NETS or match a
            // chalExclude rule — extend their okState so handleDecision returns "allow"
            // for them even while the vhost is in challenge mode.
            if e.nginxBridge != nil {
                vttl := 60 * time.Minute
                if manualOn, mexp, _ := e.manualChallengeCovering(host); manualOn {
                    // An operator manual challenge carries its own expiry —
                    // push the REMAINING window, not the tick default. The
                    // tick default silently rewrote a 24h manual challenge to
                    // 1h whenever the bridge entry had to be recreated (e.g.
                    // after an auto cool-down cleared it), and the challenge
                    // then vanished ~1h later if the vhost fell out of the
                    // candidate set before the next refresh.
                    if rem := time.Until(mexp); rem > 0 {
                        vttl = rem
                    }
                } else if !manual && e.cfg.ChallengeSuspiciousHolddown > 0 {
                    // keep it at least holddown (+small cushion), refreshed each cycle
                    vttl = e.cfg.ChallengeSuspiciousHolddown + (2 * time.Minute)
                }

                // Determine rule name for isExcluded (skip_vhost_only semantics).
                exRule := "CHALLENGE_VHOST"
                if !manual {
                    exRule = "CHALLENGE_SUSPICIOUS_VHOST_SCORE"
                }

// Walk IPs seen for this vhost in the short window.
// BypassIPTemp writes into okState (checked in handleDecision before vhState).
if ha := short[host]; ha != nil {
    bypTTL := vttl + 2*time.Minute // slightly longer than vhost TTL
    for ipStr := range ha.ips {
        byp := e.isBypassed(ipStr)
        exc := e.isExcluded(ipStr, host, "", exRule)

//        logging.Logf("[challenge][debug] vhost_bypass_check host=%s ip=%s rule=%s bypass=%v excluded=%v",
//            host, ipStr, exRule, byp, exc)

        if byp || exc {
//            logging.Logf("[challenge][debug] vhost_bypass_apply host=%s ip=%s ttl=%s",
//                host, ipStr, bypTTL)
            e.nginxBridge.BypassIPTemp(ipStr, bypTTL)
        }
    }
}


                // `manual` (defined above) is TRUE for a CHALLENGE_VHOST config-list
                // match OR a genuine operator/API manual challenge (manualChal).
                // Label them distinctly: only the config list is "not a human
                // action" — a real manual challenge must stay reason=manual.
                vReason := "suspicious_vhost"
                if manual {
                    if ok, _, _ := e.manualChallengeCovering(host); ok {
                        vReason = "manual"
                    } else {
                        vReason = "vhost_config"
                    }
                }
                e.nginxBridge.ChallengeVhostWithReason(host, vttl, vReason)
                continue
            }


            // Challenge all IPs seen for this host in short window.
            ha := short[host]
            if ha == nil || len(ha.ips) == 0 {
                continue
            }

            rule := "CHALLENGE_VHOST"
            if manual {
                rule = "CHALLENGE_VHOST"
            } else {
                if e.cfg.ChallengeSuspiciousUniqIP && ((e.cfg.ChallengeSuspiciousUniqIPMax > 0 && row.UniqueIPs >= e.cfg.ChallengeSuspiciousUniqIPMax) || (e.cfg.ChallengeSuspiciousUniqIPOn > 0 && row.UniqueIPs >= e.cfg.ChallengeSuspiciousUniqIPOn)) {
                    rule = "CHALLENGE_SUSPICIOUS_VHOST_UNIQIP"
                } else {
                    rule = "CHALLENGE_SUSPICIOUS_VHOST_SCORE"
                }
            }

            for ipStr, reqN := range ha.ips {
                ip := net.ParseIP(ipStr)
                if ip == nil {
                    continue
                }
                if isLocalInterfaceIP(ip) || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
                    continue
                }

                // Burst safety (IP-level) — sink enforces real global cooldown
                e.emitMu.Lock()
                last, ok := e.ipLastChalEmit[ipStr]
                if ok && now.Sub(last) < cooldown {
                    e.emitMu.Unlock()
                    continue
                }
                e.ipLastChalEmit[ipStr] = now
                e.emitMu.Unlock()

                ttl := e.cfg.ChallengePathsTTL
                if ttl <= 0 {
                    ttl = 30 * time.Minute
                }

                extra := map[string]string{
                    "detector":         "webdetector",
                    "ip":               ipStr,
                    "action":           "challenge",
                    "rule":             rule,
                    "ttl":              ttl.String(),
                    "host":             host,
                    "challenge_log":    boolFlag(e.cfg.ChallengeLog),
                    "challenge_notify": boolFlag(e.cfg.ChallengeNotify),
	            "challenge_log_suppressed": boolFlag(e.cfg.ChallengeLogSuppressed),
                    "challenge_log_expired":    boolFlag(e.cfg.ChallengeLogExpired),
                }
                if !manual {
                    extra["score"]   = fmt.Sprintf("%.2f", row.Score)
                    extra["reasons"] = strings.Join(row.Reasons, ",")
                    extra["uniqIP"]  = fmt.Sprintf("%d", row.UniqueIPs)
                    extra["rps"]     = fmt.Sprintf("%.2f", row.RPS)
                }

                a := core.Alert{
                    When:    now,
                    Kind:    core.AlertKind("WEB/CHALLENGE"),
                    Key:     ipStr,
                    Count:   reqN,
                    Extra:   extra,
                }

               // DNAT mode: emit per-IP alert so nft sink can DNAT only those IPs.
               // Skip IPs in IGNORE_IPS/IGNORE_NETS or matching a chalExclude rule.
               if e.isBypassed(ipStr) || e.isExcluded(ipStr, host, "", rule) {
                   if e.cfg.ChallengeLogSuppressed {
                       logging.Logf("[challenge_suppressed] ip=%s host=%s rule=%s reason=bypass_or_exclude", ipStr, host, rule)
                   }
                   continue
               }
               a.Samples = e.ipSamples(ipStr, maxSamples)
               select { case out <- a: default: }
            }
        }



    }



 // ---- subnet-based behavioral challenges ----
    if e.cfg.ChallengeSubnetEnabled {
        e.emitSubnetChallenges(now, out)
    }


}




func (e *Engine) emitSubnetChallenges(now time.Time, out chan<- core.Alert) {

	if out == nil || !e.cfg.ChallengeSubnetEnabled {
		return
	}

	type pairAgg struct {
		sub  string
		host string
		reqs int
	}
	type subnetAgg struct {
		ips   map[string]struct{}
		paths map[uint64]struct{}
	}

	pairs := make(map[string]*pairAgg)
	subnets := make(map[string]*subnetAgg)
	capN := e.cfg.ChallengeSubnetCap
	if capN <= 0 {
		capN = 1
	}

	e.mu.RLock()
	for _, hs := range e.hosts {
		if hs == nil {
			continue
		}
		for i := range hs.buckets {
			b := &hs.buckets[i]
			for sub, hm := range b.subnetHostReqs {
				if sub == "" || len(hm) == 0 {
					continue
				}

				ips := b.subnetIPs[sub]
				paths := b.subnetUniqPaths[sub]

				sa := subnets[sub]
				if sa == nil {
					sa = &subnetAgg{}
					if len(ips) > 0 {
						sa.ips = make(map[string]struct{}, minInt(capN, len(ips)))
					}
					if len(paths) > 0 {
						sa.paths = make(map[uint64]struct{}, minInt(capN, len(paths)))
					}
					subnets[sub] = sa
				}

				if len(sa.ips) < capN {
					if sa.ips == nil {
						sa.ips = make(map[string]struct{}, minInt(capN, len(ips)))
					}
					for ip := range ips {
						sa.ips[ip] = struct{}{}
						if len(sa.ips) >= capN {
							break
						}
					}
				}
				if len(sa.paths) < capN {
					if sa.paths == nil {
						sa.paths = make(map[uint64]struct{}, minInt(capN, len(paths)))
					}
					for h := range paths {
						sa.paths[h] = struct{}{}
						if len(sa.paths) >= capN {
							break
						}
					}
				}

				for host, n := range hm {
					if n <= 0 || host == "" {
						continue
					}
					key := sub + "|" + host
					a := pairs[key]
					if a == nil {
						a = &pairAgg{sub: sub, host: host}
						pairs[key] = a
					}
					a.reqs += n
				}
			}
		}
	}
	e.mu.RUnlock()

	const cooldown = 10 * time.Second

	for pairKey, a := range pairs {
		if a == nil || a.host == "" {
			continue
		}

		sa := subnets[a.sub]
		if sa == nil {
			continue
		}
		ipN := len(sa.ips)
		pathN := len(sa.paths)

		if ipN < e.cfg.ChallengeSubnetMinIPs {
			continue
		}
		if a.reqs < e.cfg.ChallengeSubnetMinReq {
			continue
		}
		if pathN < e.cfg.ChallengeSubnetMinUniqPath {
			continue
		}
		if e.hostBypassed(a.host) {
			continue
		}

		e.emitMu.Lock()
		last, ok := e.subnetLastChalEmit[pairKey]
		if ok && now.Sub(last) < cooldown {
			e.emitMu.Unlock()
			continue
		}
		e.subnetLastChalEmit[pairKey] = now
		e.emitMu.Unlock()

		ttl := e.cfg.ChallengeSubnetTTL
		if ttl <= 0 {
			ttl = 30 * time.Minute
		}

		rule := "CHALLENGE_SUBNET"

		for ip := range sa.ips {
			if e.isBypassed(ip) || e.isExcluded(ip, a.host, "", rule) {
				if e.cfg.ChallengeLogSuppressed {
					logging.Logf("[challenge_suppressed] ip=%s host=%s rule=%s reason=bypass_or_exclude", ip, a.host, rule)
				}
				continue
			}

			samples := e.ipSamples(ip, 8)

			extra := map[string]string{
				"detector":         "webdetector",
				"ip":               ip,
				"action":           "challenge",
				"rule":             rule,
				"ttl":              ttl.String(),
				"host":             a.host,
				"subnet":           a.sub,
				"subnet_ips":       strconv.Itoa(ipN),
				"subnet_reqs":      strconv.Itoa(a.reqs),
				"subnet_uniqpaths": strconv.Itoa(pathN),
				"subnet_uniqhosts": "1",
				"challenge_log":    boolFlag(e.cfg.ChallengeLog),
				"challenge_notify": boolFlag(e.cfg.ChallengeNotify),
				"challenge_log_suppressed": boolFlag(e.cfg.ChallengeLogSuppressed),
				"challenge_log_expired":    boolFlag(e.cfg.ChallengeLogExpired),
			}

			e.RecordIPChallenge(ip, a.host, rule, "", "", 0, ttl)

			select {
			case out <- core.Alert{
				When:    now,
				Kind:    core.AlertKind("WEB/CHALLENGE"),
				Key:     ip,
				Count:   a.reqs,
				Samples: samples,
				Extra:   extra,
			}:
			default:
			}
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
