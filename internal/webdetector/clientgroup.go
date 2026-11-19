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

// maxFanOutPerTick bounds the fan-out alerts one emitIPChallenges tick sends
// in all (each costs the sink an exclude check, maybe a PTR lookup): a spray
// of fresh addresses must not crowd the busiest addresses' own alerts, nor a
// ban's, out of the shared channel.
const maxFanOutPerTick = 64

// clientTag tags a, the challenge alert of a grouped client's busiest
// address, with the client and returns a copy of its Extra for
// fanOutChallenge (taken before a is sent: the sink writes into a.Extra).
// nil for an ungrouped row.
func clientTag(a *core.Alert, g clientGroup) map[string]string {
	if g.client == "" || a.Extra == nil {
		return nil
	}
	a.Extra["client"] = g.client
	base := make(map[string]string, len(a.Extra))
	for k, v := range a.Extra {
		base[k] = v
	}
	return base
}

// fanOutChallenge sends a grouped client's challenge to its other addresses
// in the window: the edge challenges an address, and the client is all of
// them. Called only after the busiest address's own alert went out (so its
// exclude and bypass decide for the client: an excluded busiest address
// fans out nothing). Each address goes through the same per-address gates
// (a new matching hit since its last fan-out for this rule, the burst
// cooldown, the host bypass, IGNORE_IPS / chalExclude) and is recorded on
// its own; it never notifies (the busiest address's alert does). Its gate
// key is its own per rule, so it never pre-empts the address's own emit of
// another rule (CHALLENGE_PATHS and its v2 mark).
func (e *Engine) fanOutChallenge(now time.Time, top string, kind core.AlertKind, count int, base map[string]string, g clientGroup, lastCtx map[string]chalCtx, rule string, ttl time.Duration, out chan<- core.Alert) {
	if base == nil {
		return
	}
	const cooldown = 5 * time.Second
	for _, other := range g.addrs {
		if other == top {
			continue
		}
		if e.fanOutLeft <= 0 {
			return
		}
		ip := net.ParseIP(other)
		if ip == nil || isLocalInterfaceIP(ip) || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		ctx := lastCtx[other]
		matchAt := time.Unix(0, int64(ctx.TS*1e9))
		gate := "fan|" + rule + "|" + other
		skip := func() bool {
			e.emitMu.Lock()
			defer e.emitMu.Unlock()
			last, ok := e.ipLastChalEmit[gate]
			// A new matching hit since its last fan-out (when the hit is
			// known), and the burst cooldown.
			if ok && ((ctx.TS != 0 && !matchAt.After(last)) || now.Sub(last) < cooldown) {
				return true
			}
			e.ipLastChalEmit[gate] = now
			return false
		}()
		if skip || e.hostBypassed(ctx.Host) {
			continue
		}
		e.fanOutLeft--
		if e.isBypassed(other) || e.isExcluded(other, ctx.Host, ctx.UA, rule) {
			if e.cfg.ChallengeLogSuppressed {
				logging.Logf("[challenge_suppressed] ip=%s host=%s rule=%s reason=bypass_or_exclude", other, ctx.Host, rule)
			}
			continue
		}
		e.RecordIPChallenge(other, ctx.Host, rule, ctx.URI, ctx.Method, ctx.Status, ttl)
		extra := make(map[string]string, len(base))
		for k, v := range base {
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
		b := core.Alert{When: now, Kind: kind, Key: other, Count: count, Extra: extra, Samples: e.ipSamples(other, 4)}
		select {
		case out <- b:
		default:
		}
	}
}
