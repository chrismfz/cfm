// internal/webdetector/challenge_rules.go
package webdetector

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
        "cfm/internal/logging"
	core "cfm/internal/detectors/core"

)

// chalRule supports "N:substring" overrides like MALPATH.
type chalRule struct {
	sub   string // lowercased
	count int
}

type chalCtx struct {
	Host string
	URI  string
	Sub  string // matched substring (rule)
	TS   float64
}


// hostMatch returns true if host matches pattern exactly or as a subdomain.
// Supports patterns like "example.com" or "*.example.com".
func hostMatch(host, pattern string) bool {
    host = strings.ToLower(strings.TrimSpace(host))
    pattern = strings.ToLower(strings.TrimSpace(pattern))
    if host == "" || pattern == "" {
        return false
    }
    if strings.HasPrefix(pattern, "*.") {
        pattern = strings.TrimPrefix(pattern, "*.")
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
			Host: rec.Host,
			URI:  path,
			Sub:  r.sub,
			TS:   rec.TS,
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
        haveVhostManual := len(e.cfg.ChallengeVHost) > 0
        haveVhostAuto   := e.cfg.ChallengeSuspiciousVHost
        if !havePaths && !haveThr && !haveVhostManual && !haveVhostAuto { return }

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



                                        samples := e.ipSamples(c.ip, maxSamples)

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
                                        }
                                        if c.host != "" {
                                                extra["host"] = c.host
                                        }
                                        if c.uri != "" {
                                                extra["uri"] = c.uri
                                        }

                                        a := core.Alert{
                                                When:    now,
                                                Kind:    core.AlertKind("WEB/CHALLENGE"),
                                                Key:     c.ip,
                                                Count:   c.count,
                                                Samples: samples,
                                                Extra:   extra,
                                        }

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
            samples := e.ipSamples(ipStr, maxSamples)

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
            }
            if ctx.Host != "" { extra["host"] = ctx.Host }
            if ctx.URI != ""  { extra["uri"]  = ctx.URI }

            alet := core.Alert{
                When:    now,
                Kind:    core.AlertKind("WEB/CHALLENGE"),
                Key:     ipStr,
                Count:   a.total,
                Samples: samples,
                Extra:   extra,
            }
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

        // 3) Evaluate each host
        for host := range candHosts {
            if host == "" {
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
                            }
                        }
		}

                continue
            }

            // Manual panic applies immediately.
            manual := haveVhostManual && hostMatchAny(host, e.cfg.ChallengeVHost)

            // Auto suspicious: long-window score with hysteresis + holddown.
            autoActive := false
            var row SuspiciousRow
            if haveVhostAuto && e.longwin != nil {
                r, ok := e.longwin.One(host)
                if ok {
                    row = r
                } else {
                    row = SuspiciousRow{Host: host}
                }

                on  := e.cfg.ChallengeSuspiciousScoreOn
                off := e.cfg.ChallengeSuspiciousScoreOff
                minUniq := e.cfg.ChallengeSuspiciousMinUniqIP
                hold := e.cfg.ChallengeSuspiciousHolddown











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
                        if row.Score >= on && row.UniqueIPs >= minUniq {
                            e.vhostUnderAttack[host] = true
                            e.vhostLastChange[host] = now

                            if e.cfg.ChallengeLog {
                                logging.LogfCHALLENGES(
                                    "[challenge][vhost] action=auto_on host=%s score=%.2f on=%.2f off=%.2f uniqIP=%d rps=%.2f reasons=%s hold=%s",
                                    host, row.Score, on, off, row.UniqueIPs, row.RPS, strings.Join(row.Reasons, ","), hold.String(),
                                )
                            }
                            if e.cfg.ChallengeNotify {
                                a := core.Alert{
                                    When:  now,
                                    Kind:  core.AlertKind("WEB/VHOST_CHALLENGE_ON"),
                                    Key:   host,
                                    Count: row.UniqueIPs,
                                    Extra: map[string]string{
                                        "host":      host,
                                        "action":    "auto_on",
                                        "score":     fmt.Sprintf("%.2f", row.Score),
                                        "score_on":  fmt.Sprintf("%.2f", on),
                                        "score_off": fmt.Sprintf("%.2f", off),
                                        "uniqIP":    fmt.Sprintf("%d", row.UniqueIPs),
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

                    // currently ON: turn OFF when score <= off (and holddown already passed above)
                    if row.Score <= off {
                        e.vhostUnderAttack[host] = false
                        e.vhostLastChange[host] = now

                        if e.cfg.ChallengeLog {
                            logging.LogfCHALLENGES(
                                "[challenge][vhost] action=auto_off host=%s score=%.2f off=%.2f uniqIP=%d rps=%.2f reasons=%s",
                                host, row.Score, off, row.UniqueIPs, row.RPS, strings.Join(row.Reasons, ","),
                            )
                        }
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

            // Challenge all IPs seen for this host in short window.
            ha := short[host]
            if ha == nil || len(ha.ips) == 0 {
                continue
            }

            rule := "CHALLENGE_VHOST"
            if manual {
                rule = "CHALLENGE_VHOST"
            } else {
                rule = "CHALLENGE_SUSPICIOUS_VHOST_SCORE"
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

                samples := e.ipSamples(ipStr, maxSamples)
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
                    Samples: samples,
                    Extra:   extra,
                }
                select { case out <- a: default: }
            }
        }
    }




}
