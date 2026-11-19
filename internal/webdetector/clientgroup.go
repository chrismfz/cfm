package webdetector

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/firewall"
	"cfm/internal/logging"
)

// maxClientAddrs caps the addresses a grouped row lists (and a challenge
// fans out to): a client spraying its /64 is challenged on its busiest ones,
// and banned as the /64 anyway.
const maxClientAddrs = 16

// clientGroup is one grouped row's client: its /64 ("" when the row is a
// single address) and its addresses, busiest first.
type clientGroup struct {
	client string
	addrs  []string
}

// groupIPAggs folds per-address aggregates into per-client ones: an IPv6
// client is its /64 (firewall.CountKey: per address where a ban would not
// take the /64; IPv4 is always the address). The result is keyed by each
// client's busiest address (weight; ties: the lowest), so a caller keeps
// treating the key as an address (bans, challenges, allow and good-bot
// checks, samples, history); groups maps that key to the client and its
// addresses. merge adds src into dst; fresh makes an empty aggregate.
func groupIPAggs[T any](perIP map[string]*T, merge func(dst, src *T), weight func(*T) int, fresh func() *T) (map[string]*T, map[string]clientGroup) {
	type member struct {
		ip string
		w  int
	}
	byClient := map[string][]member{}
	for ip, a := range perIP {
		if a == nil {
			continue
		}
		k := firewall.CountKey(ip)
		byClient[k] = append(byClient[k], member{ip, weight(a)})
	}
	out := make(map[string]*T, len(byClient))
	groups := make(map[string]clientGroup)
	for k, ms := range byClient {
		if len(ms) == 1 && !strings.Contains(k, "/") {
			out[ms[0].ip] = perIP[ms[0].ip] // an address on its own: as before
			continue
		}
		sort.Slice(ms, func(i, j int) bool {
			if ms[i].w != ms[j].w {
				return ms[i].w > ms[j].w
			}
			return ms[i].ip < ms[j].ip
		})
		sum := fresh()
		addrs := make([]string, 0, min(len(ms), maxClientAddrs))
		for i, m := range ms {
			merge(sum, perIP[m.ip])
			if i < maxClientAddrs {
				addrs = append(addrs, m.ip)
			}
		}
		top := ms[0].ip
		out[top] = sum
		if strings.Contains(k, "/") {
			groups[top] = clientGroup{client: k, addrs: addrs}
		}
	}
	return out, groups
}

// fanOutChallenge sends a, a per-IP challenge alert for a grouped client's
// busiest address, to the client's other addresses in the window: the edge
// challenges an address, and the client is all of them. Each goes through the
// same per-address gates as the busiest one (a new matching hit since its last
// emit, the burst cooldown, the host bypass, IGNORE_IPS / chalExclude) and is
// recorded on its own; only the busiest one notifies. a gets the client tag.
func (e *Engine) fanOutChallenge(now time.Time, a core.Alert, g clientGroup, lastCtx map[string]chalCtx, rule string, ttl time.Duration, out chan<- core.Alert) {
	if g.client == "" || a.Extra == nil {
		return
	}
	a.Extra["client"] = g.client
	const cooldown = 5 * time.Second
	for _, other := range g.addrs {
		if other == a.Key {
			continue
		}
		ip := net.ParseIP(other)
		if ip == nil || isLocalInterfaceIP(ip) || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		ctx := lastCtx[other]
		matchAt := time.Unix(0, int64(ctx.TS*1e9))
		skip := func() bool {
			e.emitMu.Lock()
			defer e.emitMu.Unlock()
			last, ok := e.ipLastChalEmit[other]
			// A new matching hit since its last emit (when the hit is known),
			// and the burst cooldown, as the busiest address's own emit.
			if ok && ((ctx.TS != 0 && !matchAt.After(last)) || now.Sub(last) < cooldown) {
				return true
			}
			e.ipLastChalEmit[other] = now
			return false
		}()
		if skip || e.hostBypassed(ctx.Host) {
			continue
		}
		if e.isBypassed(other) || e.isExcluded(other, ctx.Host, ctx.UA, rule) {
			if e.cfg.ChallengeLogSuppressed {
				logging.Logf("[challenge_suppressed] ip=%s host=%s rule=%s reason=bypass_or_exclude", other, ctx.Host, rule)
			}
			continue
		}
		e.RecordIPChallenge(other, ctx.Host, rule, ctx.URI, ctx.Method, ctx.Status, ttl)
		extra := make(map[string]string, len(a.Extra))
		for k, v := range a.Extra {
			extra[k] = v
		}
		extra["ip"] = other
		extra["challenge_notify"] = "0" // the busiest address's alert notifies
		for k, v := range map[string]string{"host": ctx.Host, "uri": ctx.URI, "method": ctx.Method} {
			if v != "" {
				extra[k] = v
			} else {
				delete(extra, k)
			}
		}
		if ctx.Status != 0 {
			extra["status"] = strconv.Itoa(ctx.Status)
		} else {
			delete(extra, "status")
		}
		b := core.Alert{When: now, Kind: a.Kind, Key: other, Count: a.Count, Extra: extra, Samples: e.ipSamples(other, 4)}
		select {
		case out <- b:
		default:
		}
	}
}
