package webdetector

import (
	"sort"
	"strings"

	core "cfm/internal/detectors/core"
	"cfm/internal/firewall"
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

// maxExtraMembersPerTick bounds, per challenge section and tick, the members
// of grouped clients challenged beyond each client's first: each costs an
// exclude check (maybe a PTR lookup) here and in the sink, so a spray of
// fresh addresses must not stall the tick nor crowd the alert channel.
const maxExtraMembersPerTick = 32

// expandClients maps each address of a grouped client back to the client's
// summed aggregate: a per-IP challenge rule then judges every member on the
// client's counts while each member keeps its own per-address gates (a new
// matching hit, the burst cooldown, its host bypass and excludes, its
// context): no address decides for another. clientOf names each member's
// client (/64).
func expandClients[T any](grouped map[string]*T, groups map[string]clientGroup) (map[string]*T, map[string]string) {
	out := make(map[string]*T, len(grouped))
	clientOf := make(map[string]string)
	for top, a := range grouped {
		g, ok := groups[top]
		if !ok {
			out[top] = a
			continue
		}
		for _, m := range g.addrs {
			out[m] = a
			clientOf[m] = g.client
		}
	}
	return out, clientOf
}

// clientTick is one per-IP challenge section's state for grouped clients
// (each section of emitIPChallenges has its own: one rule's members never
// spend another's budget or notification).
type clientTick struct {
	extraLeft int
	seen      map[string]bool // client -> a member reached the checks
	notified  map[string]bool // client -> a member's alert notified
}

func newClientTick() *clientTick {
	return &clientTick{extraLeft: maxExtraMembersPerTick, seen: map[string]bool{}, notified: map[string]bool{}}
}

// can says whether a grouped client's member may still be judged in this
// section: its client's first always, the others while the budget lasts. It
// takes nothing: the caller writes the member's emit gate only after it, so a
// member past the budget keeps its hit for the next tick. An ungrouped
// address (client "") always may.
func (t *clientTick) can(client string) bool {
	return client == "" || !t.seen[client] || t.extraLeft > 0
}

// take counts a member that passed its gate against the section's budget.
func (t *clientTick) take(client string) {
	if client == "" {
		return
	}
	if !t.seen[client] {
		t.seen[client] = true
		return
	}
	t.extraLeft--
}

// notify tags a, about to be sent, with its client; only the client's first
// alert this tick notifies (the others carry challenge_notify=0).
func (t *clientTick) notify(a *core.Alert, client string) {
	if client == "" || a.Extra == nil {
		return
	}
	a.Extra["client"] = client
	if t.notified[client] {
		a.Extra["challenge_notify"] = "0"
		return
	}
	t.notified[client] = true
}

// chalLastSnapshot copies chalLast (each address's last challenge-matching
// request): a per-IP challenge section reads its host / URI / UA for the
// excludes and the alert.
func (e *Engine) chalLastSnapshot() map[string]chalCtx {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]chalCtx, len(e.chalLast))
	for ip, ctx := range e.chalLast {
		out[ip] = ctx
	}
	return out
}
