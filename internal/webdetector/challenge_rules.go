// internal/webdetector/challenge_rules.go
package webdetector

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

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
        if !havePaths && !haveThr { return }

	const (
		topN       = 50
		// Burst safety only. Real gating is "new hit since last emit".
		cooldown   = 5 * time.Second
		maxSamples = 8
	)

	tsToTime := func(ts float64) time.Time {
		return time.Unix(0, int64(ts*1e9))
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

                e.mu.RLock()
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
                lastCtx := make(map[string]chalCtx, len(e.chalLast))
                for ip, ctx := range e.chalLast {
                        lastCtx[ip] = ctx
                }
                e.mu.RUnlock()

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

                                        e.emitMu.Lock()
                                        last, ok := e.ipLastChalEmit[c.ip]
                                        if ok && !matchAt.After(last) {
                                                e.emitMu.Unlock()
                                                continue
                                        }
                                        if ok && now.Sub(last) < cooldown {
                                                e.emitMu.Unlock()
                                                continue
                                        }
                                        e.ipLastChalEmit[c.ip] = now
                                        e.emitMu.Unlock()

                                        samples := e.ipSamples(c.ip, maxSamples)

                                        ttl := e.cfg.ChallengePathsTTL
                                        if ttl <= 0 {
                                                ttl = 30 * time.Minute
                                        }

                                        extra := map[string]string{
                                                "detector": "webdetector",
                                                "ip":       c.ip,
                                                "action":   "challenge",
                                                "rule":     "CHALLENGE_PATHS",
                                                "match":    c.sub,
                                                "limit":    fmt.Sprintf("challenge_paths(%d/%d:%s)", c.count, c.thr, c.sub),
                                                "ttl":      ttl.String(),
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

        e.mu.RLock()
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
        lastCtx := make(map[string]chalCtx, len(e.chalLast))
        for ip, ctx := range e.chalLast { lastCtx[ip] = ctx }
        e.mu.RUnlock()

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
            e.emitMu.Lock()
            last, ok := e.ipLastChalEmit[ipStr]
            if ok && now.Sub(last) < cooldown {
                e.emitMu.Unlock()
                continue
            }
            e.ipLastChalEmit[ipStr] = now
            e.emitMu.Unlock()

            ctx := lastCtx[ipStr]
            samples := e.ipSamples(ipStr, maxSamples)

            ttl := e.cfg.ChallengePathsTTL
            if ttl <= 0 { ttl = 30 * time.Minute }

            extra := map[string]string{
                "detector": "webdetector",
                "ip":       ipStr,
                "action":   "challenge",
                "rule":     rule,
                "limit":    limit,
                "ttl":      ttl.String(),
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
}
