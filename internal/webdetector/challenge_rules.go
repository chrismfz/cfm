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
		}

		// count only first matching rule per request (avoid inflation)
		return
	}
}

func (e *Engine) emitIPChallenges(now time.Time, out chan<- core.Alert) {
	if out == nil {
		return
	}
	if !e.cfg.ChallengePathsEnabled || len(e.chalRules) == 0 {
		return
	}

	const (
		topN       = 50
		cooldown   = 30 * time.Second
		maxSamples = 8
	)

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

	if len(agg) == 0 {
		return
	}

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

	if len(cands) == 0 {
		return
	}

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

		// cooldown check (separate from block cooldown)
		e.emitMu.Lock()
		last, ok := e.ipLastChalEmit[c.ip]
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
