// Package solverfarm is the challenge_solver_farm detector: it spots a
// distributed solver farm — bots that legitimately complete the cookie + JS +
// PoW challenge, but from a residential-proxy pool so wide that no single IP
// ever repeats.
//
// Why a new detector rather than a threshold on the existing per-IP machinery:
// measured over 23h on a production edge, one such farm produced 101,880 solves
// on a single vhost from 95,281 distinct IPs — 1.07 solves per IP, spread over
// 77,792 distinct /24s. Every per-IP counter sees a first-and-only request and
// stays silent by construction. The population is only visible in aggregate.
//
// The signal is the *spread of solvers per vhost per minute*, deliberately NOT
// keyed on User-Agent: the UA is attacker-controlled, so keying detection on it
// would be evaded by randomising a header. Measured on the same data, distinct
// /24s solving one vhost in one minute was 73 (median) for the farm versus a
// maximum of 22 across every other vhost — a clean separation that survives UA
// randomisation. The UA breakdown is carried on the alert as *evidence* for
// attribution, not as the detection key.
//
// This detector is alert-only by design: at ~1 solve per IP a per-IP nft ban is
// useless (the address is never seen again) and actively risky (the pool is
// residential, so it may belong to a real customer by the time it is banned).
// Acting on the finding — raising difficulty for the vhost, rate-limiting
// issuance, blocking a cluster — is a separate, deliberate decision.
//
// Two Extra keys enforce that, and they do different jobs:
//
//   - ip_scope=host (core.ExtraIPScope) tells the sink this finding is about a
//     vhost, so it must not resolve a source IP for it. Without it the sink
//     falls back to scanning Samples for anything IP-shaped — and Samples quote
//     the User-Agents observed, so a client could name its own "source" address.
//   - enforcement=observe stops the sink short of any block if an operator does
//     configure a BLOCK policy on the section.
//
// With no BLOCK key in the section (the shipped config), the sink takes its
// "no policy" path and notifies from there; enforcement=observe is the guard
// for when that is not true. Note the consequence: SETTING a BLOCK value on
// this section does not block, but it does move the alert onto the observe
// path, which logs to the detector log without raising a notification. Leave
// BLOCK unset.
package solverfarm

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	core "cfm/internal/detectors/core"
)

type Config struct {
	Every  time.Duration
	Window time.Duration

	// MinSubnets is the number of DISTINCT client subnets that must solve the
	// same vhost within Window to raise the alert.
	MinSubnets int
	// MinSolves guards against a trickle of one-solve-per-subnet clients looking
	// like a farm on a very quiet vhost.
	MinSolves int

	// PrefixV4/PrefixV6 set the aggregation prefix length. /24 matches how
	// residential pools are allocated; a farm that spreads within a single /24
	// is a per-IP problem, not this one. IPv6 defaults to /48 because a single
	// residential customer routinely holds many /64s.
	PrefixV4 int
	PrefixV6 int

	// Cooldown is the minimum gap between alerts for the same vhost, so a farm
	// that runs for hours does not emit one alert per scan.
	Cooldown time.Duration

	// MaxTrackedPerHost bounds retained solve records per vhost. Hitting it is
	// reported on the alert rather than silently truncating the evidence.
	MaxTrackedPerHost int

	SampleLimit int

	AllowHosts      []string
	AllowIPs        []string
	AllowNets       []string
	AllowUAContains []string
}

type solveRec struct {
	when   time.Time
	subnet string
	ip     string
	ua     string
	// uaBad is the UA-plausibility verdict carried on the event (empty when the
	// UA is coherent). Reported as corroborating evidence only — the detection
	// threshold never depends on it, because a farm can trivially send a
	// well-formed UA.
	uaBad string
}

type hostState struct {
	recs      []solveRec
	lastAlert time.Time
	truncated int
}

type Detector struct {
	cfg  Config
	name string

	mu     sync.Mutex
	events []core.InputEvent
	hosts  map[string]*hostState

	// nowFn is the detector's clock. Injectable so tests can replay a recorded
	// traffic window at its original timestamps instead of wall-clock.
	nowFn func() time.Time

	allowHosts map[string]struct{}
	allowIPs   map[string]struct{}
	allowNets  []*net.IPNet
}

func New(cfg Config) *Detector {
	if cfg.Every <= 0 {
		cfg.Every = 30 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.MinSubnets <= 0 {
		cfg.MinSubnets = 40
	}
	if cfg.MinSolves <= 0 {
		cfg.MinSolves = 40
	}
	if cfg.PrefixV4 <= 0 || cfg.PrefixV4 > 32 {
		cfg.PrefixV4 = 24
	}
	if cfg.PrefixV6 <= 0 || cfg.PrefixV6 > 128 {
		cfg.PrefixV6 = 48
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Minute
	}
	if cfg.MaxTrackedPerHost <= 0 {
		cfg.MaxTrackedPerHost = 20000
	}
	if cfg.SampleLimit <= 0 {
		cfg.SampleLimit = 10
	}

	d := &Detector{
		cfg:        cfg,
		nowFn:      time.Now,
		hosts:      make(map[string]*hostState),
		allowHosts: make(map[string]struct{}),
		allowIPs:   make(map[string]struct{}),
	}
	for _, h := range cfg.AllowHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			d.allowHosts[h] = struct{}{}
		}
	}
	for _, ip := range cfg.AllowIPs {
		if ip = strings.TrimSpace(ip); ip != "" {
			d.allowIPs[ip] = struct{}{}
		}
	}
	for _, cidr := range cfg.AllowNets {
		if cidr = strings.TrimSpace(cidr); cidr == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			d.allowNets = append(d.allowNets, n)
		}
	}
	return d
}

func (d *Detector) SetName(name string) { d.name = name }
func (d *Detector) Name() string {
	if d.name != "" {
		return d.name
	}
	return "challenge_solver_farm"
}
func (d *Detector) Every() time.Duration { return d.cfg.Every }

func (d *Detector) Enqueue(ev core.InputEvent) {
	if ev.When.IsZero() {
		ev.When = d.nowFn()
	}
	if ev.Scope == "" || ev.SrcIP == "" || d.allowed(ev) {
		return
	}
	d.mu.Lock()
	d.events = append(d.events, ev)
	d.mu.Unlock()
}

func (d *Detector) allowed(ev core.InputEvent) bool {
	if _, ok := d.allowHosts[strings.ToLower(strings.TrimSpace(ev.Scope))]; ok {
		return true
	}
	if _, ok := d.allowIPs[ev.SrcIP]; ok {
		return true
	}
	if ip := net.ParseIP(ev.SrcIP); ip != nil {
		for _, n := range d.allowNets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	ua := strings.ToLower(ev.UserAgent)
	for _, token := range d.cfg.AllowUAContains {
		if token = strings.ToLower(strings.TrimSpace(token)); token != "" && strings.Contains(ua, token) {
			return true
		}
	}
	return false
}

// subnetOf aggregates a client address to its configured prefix. It is the unit
// the detector counts: a farm buys reach in subnets, not addresses.
func subnetOf(ipStr string, v4bits, v6bits int) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ""
	}
	bits := v6bits
	size := 128
	if v4 := ip.To4(); v4 != nil {
		ip, bits, size = v4, v4bits, 32
	}
	mask := net.CIDRMask(bits, size)
	return ip.Mask(mask).String() + "/" + fmt.Sprint(bits)
}

func (d *Detector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	d.mu.Lock()
	batch := d.events
	d.events = nil
	d.mu.Unlock()

	now := d.nowFn()

	for _, ev := range batch {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		sn := subnetOf(ev.SrcIP, d.cfg.PrefixV4, d.cfg.PrefixV6)
		if sn == "" {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(ev.Scope))
		st := d.hosts[host]
		if st == nil {
			st = &hostState{}
			d.hosts[host] = st
		}
		if len(st.recs) >= d.cfg.MaxTrackedPerHost {
			st.truncated++
			continue
		}
		st.recs = append(st.recs, solveRec{when: ev.When, subnet: sn, ip: ev.SrcIP, ua: ev.UserAgent, uaBad: ev.Signal})
	}

	cutoff := now.Add(-d.cfg.Window)
	for host, st := range d.hosts {
		kept := st.recs[:0]
		for _, r := range st.recs {
			if r.when.After(cutoff) {
				kept = append(kept, r)
			}
		}
		st.recs = kept

		// Drop vhosts that have gone quiet so state does not grow without bound.
		if len(st.recs) == 0 && now.Sub(st.lastAlert) > d.cfg.Cooldown {
			delete(d.hosts, host)
			continue
		}
		if len(st.recs) < d.cfg.MinSolves {
			continue
		}

		subnets := make(map[string]struct{}, len(st.recs))
		ips := make(map[string]struct{}, len(st.recs))
		uas := make(map[string]int)
		impossibleUA := 0
		for _, r := range st.recs {
			subnets[r.subnet] = struct{}{}
			ips[r.ip] = struct{}{}
			uas[r.ua]++
			if r.uaBad != "" {
				impossibleUA++
			}
		}
		if len(subnets) < d.cfg.MinSubnets {
			continue
		}
		if !st.lastAlert.IsZero() && now.Sub(st.lastAlert) < d.cfg.Cooldown {
			continue
		}
		st.lastAlert = now

		out <- d.buildAlert(now, host, st, subnets, ips, uas, impossibleUA)
	}
	return nil
}

func (d *Detector) buildAlert(now time.Time, host string, st *hostState,
	subnets, ips map[string]struct{}, uas map[string]int, impossibleUA int) core.Alert {

	topUA, topUACount := "", 0
	for ua, n := range uas {
		if n > topUACount {
			topUA, topUACount = ua, n
		}
	}
	solves := len(st.recs)
	uaShare := 0
	if solves > 0 {
		uaShare = topUACount * 100 / solves
	}
	// Solves per IP is the tell that per-IP thresholds cannot fire: a farm burns
	// a fresh address per solve, so this sits at ~1.0 while a real repeat
	// visitor population sits well above it.
	solvesPerIP := float64(solves) / float64(len(ips))

	samples := []string{
		fmt.Sprintf("[challenge] host=%s solves=%d distinct_ips=%d distinct_subnets=%d solves_per_ip=%.2f window=%s",
			host, solves, len(ips), len(subnets), solvesPerIP, d.cfg.Window),
	}
	type uaCount struct {
		ua string
		n  int
	}
	ranked := make([]uaCount, 0, len(uas))
	for ua, n := range uas {
		ranked = append(ranked, uaCount{ua, n})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].n != ranked[j].n {
			return ranked[i].n > ranked[j].n
		}
		return ranked[i].ua < ranked[j].ua
	})
	for i, u := range ranked {
		if i >= d.cfg.SampleLimit-1 {
			break
		}
		samples = append(samples, fmt.Sprintf("[challenge] ua=%q solves=%d (%d%%)", u.ua, u.n, u.n*100/solves))
	}
	if impossibleUA > 0 {
		samples = append(samples, fmt.Sprintf("[challenge] self-contradictory User-Agents: %d of %d solves (%d%%)",
			impossibleUA, solves, impossibleUA*100/solves))
	}
	if st.truncated > 0 {
		samples = append(samples, fmt.Sprintf("[challenge] NOTE: %d further solves in this window were not tracked (MAX_TRACKED_PER_HOST=%d); counts above are a lower bound",
			st.truncated, d.cfg.MaxTrackedPerHost))
		st.truncated = 0
	}

	return core.Alert{
		When:    now,
		Kind:    core.AlertKind("Challenge/SolverFarm"),
		Key:     host,
		Count:   len(subnets),
		Samples: samples,
		Extra: map[string]string{
			// The Key is a vhost, not an address, and Samples quote observed
			// User-Agents — so the sink must not try to resolve a source IP for
			// this alert. See core.ExtraIPScope for why that fallback is unsafe
			// once a detector quotes client-controlled text.
			core.ExtraIPScope: core.IPScopeHost,
			// Alert-only: a per-IP ban is useless at ~1 solve per IP and risks
			// banning a real customer's residential address. See the package doc.
			"enforcement":   "observe",
			"reason":        "CHALLENGE_SOLVER_FARM",
			"host":          host,
			"solves":        fmt.Sprint(solves),
			"distinct_ips":  fmt.Sprint(len(ips)),
			"subnets":       fmt.Sprint(len(subnets)),
			"solves_per_ip": fmt.Sprintf("%.2f", solvesPerIP),
			"top_ua":        topUA,
			"top_ua_share":  fmt.Sprintf("%d%%", uaShare),
			"window":        d.cfg.Window.String(),
			// Corroboration only — never part of the threshold.
			"impossible_ua": fmt.Sprint(impossibleUA),
		},
	}
}
