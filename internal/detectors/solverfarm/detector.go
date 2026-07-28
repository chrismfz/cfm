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
// The signal is the *spread of solvers per vhost per window*, deliberately NOT
// keyed on User-Agent: the UA is attacker-controlled, so keying detection on it
// would be evaded by randomising a header. The UA breakdown is carried on the
// alert as *evidence* for attribution, not as the detection key.
//
// Calibration, measured the way this code measures — a SLIDING 60s window
// sampled every 30s, not disjoint one-minute buckets. That distinction matters:
// the maximum over sliding windows is always >= the maximum over fixed buckets,
// so calibrating on buckets would overstate the headroom. Over the same 23h
// capture, replayed at its original timestamps:
//
//	farm vhost   : median 73 distinct /24 per window, p01 49, max 122
//	every other  : max 27, across 3212 evaluations
//
// MinSubnets = 40 therefore flags 2758 of 2761 farm evaluations and 0 of 3212
// legitimate ones — a 1.5x margin over the busiest legitimate vhost observed.
// (Bucket-derived figures would have read "max 22" and implied 1.8x.)
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
	"cfm/internal/logging"
)

// Action is what the detector does with a flagged vhost, set by ACTION in
// detectors.conf. The full vocabulary is defined here even though only the first
// two are implemented, so the config surface is stable: detectors.conf is a
// packaged conffile, and growing its accepted values later costs an upgrade
// prompt on every host.
//
// Unset means ActionObserve, so a config written before this key existed keeps
// working unchanged.
type Action string

const (
	// ActionObserve raises the alert through the normal path: operator
	// notification (email, and Slack if routed) plus the detector log.
	ActionObserve Action = "observe"

	// ActionLogonly writes the detector-log record but suppresses the
	// notification. For a vhost already triaged and accepted as farmed, where the
	// finding stays true for hours and the mail is noise but the record is not.
	ActionLogonly Action = "logonly"

	// ActionDeny and ActionBlock are RESERVED, recognised but refused at load
	// with an explanation. They are not "not written yet" — each needs a design
	// decision this detector cannot make on its own:
	//
	//   deny  — 403 whom? The finding is about a vhost, so denying the vhost
	//           takes the customer's site down and the farm wins by proxy. The
	//           only subject narrow enough is the dominant UA cluster, which is
	//           a traffic rule — and one a farm evades by randomising a header,
	//           which is precisely what this detector is built to survive.
	//
	//   block — measured on the traffic this detector was written against, a farm
	//           solves 1.07 times per address. By the time an alert fires the
	//           address is gone, and the pool is residential, so the ban lands on
	//           whoever the ISP hands it to next. It is implementable and it does
	//           not work.
	//
	// The actuator that does fit is raising the vhost's PoW difficulty while
	// flagged: it costs a farm solving 100k times proportionally and a real
	// visitor once. That needs per-vhost difficulty (PowConfig is a process-wide
	// constant today) AND the faster browser solver, since at present raising
	// difficulty costs an honest client roughly 92x what it costs a native one.
	ActionDeny  Action = "deny"
	ActionBlock Action = "block"
)

// ParseAction resolves a configured ACTION value. It returns the action to use,
// and a non-empty note when the request could not be honoured — the caller logs
// that rather than letting an operator believe enforcement is on.
func ParseAction(raw string) (Action, string) {
	switch Action(strings.ToLower(strings.TrimSpace(raw))) {
	case "", ActionObserve:
		return ActionObserve, ""
	case ActionLogonly:
		return ActionLogonly, ""
	case ActionDeny:
		return ActionObserve, "ACTION=deny is reserved and not implemented (a vhost-wide 403 would take the site down; the narrow form is a traffic rule on the UA cluster, which a farm evades by randomising a header) — falling back to observe"
	case ActionBlock:
		return ActionObserve, "ACTION=block is reserved and not implemented (a farm solves ~1 time per address, so the address is gone before the alert fires, and the pool is residential — the ban would land on a real visitor) — falling back to observe"
	default:
		return ActionObserve, fmt.Sprintf("ACTION=%q is not a known value (observe, logonly) — falling back to observe", raw)
	}
}

type Config struct {
	Every  time.Duration
	Window time.Duration

	// Action selects what happens to a flagged vhost. Zero value = ActionObserve.
	Action Action

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

	// MaxQueue bounds the ingest buffer between ticks. Enqueue runs inline on
	// the verify path and RunOnce is the only drain, so an unbounded buffer turns
	// any stall of the detector loop into unbounded growth. Overflow is counted
	// and logged rather than dropped silently.
	MaxQueue int

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
	// subnets and ips are the authoritative in-window sets. They are kept
	// separate from recs and are NEVER dropped by the evidence cap: the subnet
	// count is what the threshold reads, so letting a cap suppress it would hand
	// an attacker a way to hide. A cheap flood from one subnet fills recs but
	// adds exactly one entry here, leaving a farm's spread fully visible.
	subnets map[string]time.Time // subnet -> newest solve seen from it
	ips     map[string]time.Time // client address -> newest solve seen from it

	// recs is the evidence buffer (UA histogram, sample lines) and is capped.
	// Losing records here costs detail, never detection.
	recs []solveRec

	// truncated counts records the evidence cap dropped SINCE THE LAST
	// EVALUATION. It is reset every pass, not only when an alert fires —
	// otherwise a vhost that truncates for an hour without ever crossing the
	// threshold would attribute an hour of drops to one 60s window the next time
	// it did.
	truncated int
	// setsCapped records that the subnet/IP sets themselves hit MaxTrackedPerHost
	// and stopped admitting new members, so their counts are lower bounds too.
	// Reaching this needs MaxTrackedPerHost DISTINCT subnets inside one window
	// (20000 by default, against a farm observed at ~110), but the alert must not
	// claim completeness it cannot verify.
	setsCapped bool

	lastAlert time.Time
}

func newHostState() *hostState {
	return &hostState{subnets: map[string]time.Time{}, ips: map[string]time.Time{}}
}

// prune drops everything that fell out of the window and returns whether the
// host still holds any in-window activity.
func (st *hostState) prune(cutoff time.Time) bool {
	for k, t := range st.subnets {
		if !t.After(cutoff) {
			delete(st.subnets, k)
		}
	}
	for k, t := range st.ips {
		if !t.After(cutoff) {
			delete(st.ips, k)
		}
	}
	kept := st.recs[:0]
	for _, r := range st.recs {
		if r.when.After(cutoff) {
			kept = append(kept, r)
		}
	}
	// Release the strings held by the pruned tail; the backing array itself is
	// reused, but a host that once peaked would otherwise pin every UA it saw.
	for i := len(kept); i < len(st.recs); i++ {
		st.recs[i] = solveRec{}
	}
	st.recs = kept
	return len(st.subnets) > 0 || len(st.recs) > 0
}

type Detector struct {
	cfg  Config
	name string

	mu      sync.Mutex
	events  []core.InputEvent
	dropped int
	// hosts is owned by RunOnce and is NOT guarded by mu: the framework runs
	// RunOnce serially per detector (run.go refuses to start a second pass while
	// one is in flight) and Enqueue never touches it. Take mu here too if that
	// ever stops being true.
	hosts map[string]*hostState

	// nowFn is the detector's clock. Injectable so tests can replay a recorded
	// traffic window at its original timestamps instead of wall-clock.
	nowFn func() time.Time

	allowHosts map[string]struct{}
	allowIPs   map[string]struct{}
	allowNets  []*net.IPNet

	// onFarm is called for every over-threshold evaluation, BEFORE the alert
	// cooldown is consulted. That distinction is the whole point: the alert is
	// rate-limited to one per COOLDOWN (30m by default) because a farm runs for
	// hours, so anything driven by alerts — a UI badge, a live status — would
	// blink off while the farm never stopped. See webdetector.MarkSolverFarm.
	onFarm func(host string, ttl time.Duration)
}

// SetFarmHook installs a callback invoked on every evaluation where a vhost is
// over threshold. It must be cheap and non-blocking; it runs inside RunOnce.
func (d *Detector) SetFarmHook(fn func(host string, ttl time.Duration)) { d.onFarm = fn }

// markTTL is how long a "farmed right now" mark should stay live. Three
// evaluation intervals, floored at the measurement window, so the mark survives
// normal jitter between passes and never expires faster than the window it was
// derived from. Expiry is the only way a mark clears — there is no unmark path
// to get wrong.
func (d *Detector) markTTL() time.Duration {
	ttl := 3 * d.cfg.Every
	if ttl < d.cfg.Window {
		ttl = d.cfg.Window
	}
	return ttl
}

func New(cfg Config) *Detector {
	if cfg.Every <= 0 {
		cfg.Every = 30 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	// An evaluation interval longer than the window leaves a blind gap: each pass
	// prunes everything older than Window, so solves that arrived more than
	// Window before the tick are ingested and immediately discarded, unexamined.
	// This is reachable without anyone choosing it — a section that omits EVERY
	// inherits [global] DEFAULT_EVERY, which ships at 60s.
	if cfg.Every > cfg.Window {
		cfg.Every = cfg.Window
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
	if cfg.Action == "" {
		cfg.Action = ActionObserve
	}
	if cfg.MaxQueue <= 0 {
		// ~15x the busiest window observed in production (110 solves/min), so a
		// healthy loop never reaches it.
		cfg.MaxQueue = 20000
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
	if len(d.events) >= d.cfg.MaxQueue {
		d.dropped++
		d.mu.Unlock()
		return
	}
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
	dropped := d.dropped
	d.events, d.dropped = nil, 0
	d.mu.Unlock()

	if dropped > 0 {
		logging.Logf("[challenge_solver_farm] ingest queue full: dropped %d solve events (MAX_QUEUE=%d)",
			dropped, d.cfg.MaxQueue)
	}

	now := d.nowFn()
	cutoff := now.Add(-d.cfg.Window)

	// Prune BEFORE ingesting, so the evidence cap is measured against what is
	// actually still in the window. Checking it against last pass's length let
	// up to Every seconds of already-expired records occupy the budget.
	for _, st := range d.hosts {
		st.prune(cutoff)
	}

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
			st = newHostState()
			d.hosts[host] = st
		}
		// The threshold input is recorded first, and is not subject to the
		// evidence cap — only to its own much larger cardinality bound.
		if _, seen := st.subnets[sn]; seen || len(st.subnets) < d.cfg.MaxTrackedPerHost {
			st.subnets[sn] = ev.When
		} else {
			st.setsCapped = true
		}
		if _, seen := st.ips[ev.SrcIP]; seen || len(st.ips) < d.cfg.MaxTrackedPerHost {
			st.ips[ev.SrcIP] = ev.When
		} else {
			st.setsCapped = true
		}
		if len(st.recs) >= d.cfg.MaxTrackedPerHost {
			st.truncated++
			continue
		}
		st.recs = append(st.recs, solveRec{when: ev.When, subnet: sn, ip: ev.SrcIP, ua: ev.UserAgent, uaBad: ev.Signal})
	}

	for host, st := range d.hosts {
		// Drop vhosts that have gone quiet so state does not grow without bound.
		// Guarded by the cooldown so state is never reclaimed while it still
		// suppresses a repeat alert.
		if len(st.subnets) == 0 && len(st.recs) == 0 && now.Sub(st.lastAlert) > d.cfg.Cooldown {
			delete(d.hosts, host)
			continue
		}

		solves := len(st.recs) + st.truncated
		truncated, setsCapped := st.truncated, st.setsCapped
		// Reset every pass, not only when an alert fires.
		st.truncated, st.setsCapped = 0, false

		if solves < d.cfg.MinSolves || len(st.subnets) < d.cfg.MinSubnets {
			continue
		}
		// Mark before the cooldown check, not after: the mark answers "is this
		// vhost being farmed right now", which stays true through the 30m the
		// alert is suppressed for.
		if d.onFarm != nil {
			d.onFarm(host, d.markTTL())
		}
		if !st.lastAlert.IsZero() && now.Sub(st.lastAlert) < d.cfg.Cooldown {
			continue
		}

		uas := make(map[string]int, len(st.recs))
		impossibleUA := 0
		for _, r := range st.recs {
			uas[r.ua]++
			if r.uaBad != "" {
				impossibleUA++
			}
		}

		alert := d.buildAlert(now, host, st, solves, truncated, setsCapped, uas, impossibleUA)
		select {
		case out <- alert:
			// Stamp the cooldown only once the alert is actually handed off, so a
			// shutdown mid-send does not silence the next window.
			st.lastAlert = now
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// buildAlert renders the finding. It reads state but does not mutate it — the
// caller owns the truncation counter and the cooldown stamp.
func (d *Detector) buildAlert(now time.Time, host string, st *hostState,
	solves, truncated int, setsCapped bool, uas map[string]int, impossibleUA int) core.Alert {

	topUA, topUACount := "", 0
	for ua, n := range uas {
		if n > topUACount {
			topUA, topUACount = ua, n
		}
	}
	// The UA histogram is built from the evidence buffer, which the cap may have
	// truncated, so percentages are of what was sampled rather than of `solves`.
	sampled := len(st.recs)
	uaShare := 0
	if sampled > 0 {
		uaShare = topUACount * 100 / sampled
	}
	// Solves per IP is the tell that per-IP thresholds cannot fire: a farm burns
	// a fresh address per solve, so this sits at ~1.0 while a real repeat
	// visitor population sits well above it.
	solvesPerIP := 0.0
	if len(st.ips) > 0 {
		solvesPerIP = float64(solves) / float64(len(st.ips))
	}

	samples := []string{
		fmt.Sprintf("[challenge] host=%s solves=%d distinct_ips=%d distinct_subnets=%d solves_per_ip=%.2f window=%s",
			host, solves, len(st.ips), len(st.subnets), solvesPerIP, d.cfg.Window),
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
		samples = append(samples, fmt.Sprintf("[challenge] ua=%q solves=%d (%d%%)", u.ua, u.n, u.n*100/sampled))
	}
	if impossibleUA > 0 {
		samples = append(samples, fmt.Sprintf("[challenge] self-contradictory User-Agents: %d of %d sampled solves (%d%%)",
			impossibleUA, sampled, impossibleUA*100/sampled))
	}
	// No silent caps: say which counts are lower bounds and which are not. The
	// subnet and IP sets are tracked separately from the evidence buffer
	// precisely so a flood from one subnet cannot mask a farm, so a truncated
	// buffer costs UA detail only — unless the sets hit their own bound too.
	if truncated > 0 {
		note := fmt.Sprintf("[challenge] NOTE: %d solves since the last evaluation were not sampled (MAX_TRACKED_PER_HOST=%d); the UA breakdown covers %d of %d solves",
			truncated, d.cfg.MaxTrackedPerHost, sampled, solves)
		if setsCapped {
			note += "; the subnet and IP counts also hit that bound and are lower bounds"
		} else {
			note += "; the subnet and IP counts are unaffected"
		}
		samples = append(samples, note)
	} else if setsCapped {
		samples = append(samples, fmt.Sprintf("[challenge] NOTE: the subnet/IP sets hit MAX_TRACKED_PER_HOST=%d; those counts are lower bounds",
			d.cfg.MaxTrackedPerHost))
	}

	alert := core.Alert{
		When:    now,
		Kind:    core.AlertKind("Challenge/SolverFarm"),
		Key:     host,
		Count:   len(st.subnets),
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
			"action":        string(d.cfg.Action),
			"reason":        "CHALLENGE_SOLVER_FARM",
			"host":          host,
			"solves":        fmt.Sprint(solves),
			"distinct_ips":  fmt.Sprint(len(st.ips)),
			"subnets":       fmt.Sprint(len(st.subnets)),
			"solves_per_ip": fmt.Sprintf("%.2f", solvesPerIP),
			"top_ua":        topUA,
			"top_ua_share":  fmt.Sprintf("%d%%", uaShare),
			"window":        d.cfg.Window.String(),
			// Corroboration only — never part of the threshold.
			"impossible_ua": fmt.Sprint(impossibleUA),
		},
	}
	// logonly keeps the detector-log record but drops the mail: the finding stays
	// true for hours on a vhost the operator has already triaged.
	if d.cfg.Action == ActionLogonly {
		alert.Extra[core.ExtraNotify] = core.NotifyNo
	}
	return alert
}
