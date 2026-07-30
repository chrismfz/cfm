// Package cookiediscard is the challenge_cookie_discard detector: it spots a
// client that solves the challenge over and over while it is still holding a
// perfectly valid clearance cookie for the same server.
//
// Why that is worth a detector of its own. A solved challenge mints a signed
// cfm_clearance cookie whose lifetime is CHALLENGE_COOKIE_LIFE (45m by default).
// A browser stores it and does not solve again until it expires. A client that
// re-solves minutes later is therefore telling you something specific: it never
// stored the cookie. That is not "aggressive crawling" — it is a request
// pipeline with no cookie jar, driving a headless browser per request. The
// challenge is doing its job perfectly and the client is paying it every time.
//
// It is the exact blind spot of challenge_solver_farm, and the mirror image of
// it. That detector keys on a vhost because the farm burns a fresh address per
// solve (~1.07 solves per IP), so no per-IP counter can ever see it. This one
// keys on the address, for the population that does the opposite: a handful of
// addresses solving dozens of times each. Neither sees the other's traffic.
//
// Calibration, measured against the same 23h production capture (111,537 solves
// from 97,556 distinct client addresses), replayed at its original timestamps
// through a SLIDING 10-minute window — the same shape this code uses, not
// disjoint buckets:
//
//	97,182 addresses (99.6%) never solved twice inside any 10-minute window
//	   248 addresses reached 3 or more
//	   244 of those 248 carried one identical desktop Chrome UA (the farm's)
//	     0 addresses peaked at exactly 5
//
// The four remaining repeaters are the plausibly-legitimate ones and they top
// out at 4: an iPhone and an iPad on small vhosts, one datacenter client, and a
// webmail address that sent three different User-Agents (a NAT or VPN exit with
// several real devices behind it). Legitimate traffic stops at 4 and the
// abusive population resumes at 6, so the gap in the distribution sits at 5.
//
// MinSolves therefore defaults to 8 — a 2x margin over the busiest legitimate
// repeater observed, still flagging 219 of the 248. The threshold is far above
// the "structurally impossible" line (which is 2) on purpose: a real browser
// CAN produce a small burst, because a user who opens several tabs at once gets
// challenged in each of them before any cookie is set. A burst of tabs is small
// and instantaneous; the traffic this detector is for sustained 30+ solves over
// minutes.
//
// Deliberately NOT part of the threshold: the User-Agent. It is
// attacker-controlled, so keying on it would be evaded by randomising a header —
// the same reasoning as challenge_solver_farm. The UA and vhost breakdowns ride
// on the alert as evidence for attribution only.
//
// Enforcement: unlike challenge_solver_farm, the subject here IS a single real
// address that is currently and repeatedly abusing the challenge, so an nft ban
// is a coherent action — this detector emits a normal per-IP alert and sets
// Extra["ip"] authoritatively, which is all the section sink needs to honour a
// BLOCK policy. The shipped config leaves BLOCK unset (alert-only) so the
// finding can be burned in first; enabling it is one line in detectors.conf and
// deliberately the operator's call, because the addresses observed here were
// residential proxy exits, which may belong to a real visitor later.
//
// apex↔www collapse. Almost every site canonicalises example.gr to
// www.example.gr (or the reverse) with a 301 from the origin, and CFM sits in
// front of that redirect. A visitor who lands on the non-canonical host solves
// there, is 301'd to the sibling — a different host, so a different host-only
// clearance cookie — and is challenged again: two genuine solves, seconds apart,
// for one gate. On a force-challenge endpoint under bot-registration attack this
// is routine, and behind a CGNAT/residential address carrying several real
// visitors the doubled count is exactly what crossed MIN_SOLVES and banned the
// shared address (observed 2026-07-29). So the threshold counts the busier host
// spelling per (apex-normalised host, path), not their sum: one journey is
// max(apex, www) == 1, while a cookie-less pipeline that repeats the whole
// redirect chain N times still scores N because both spellings climb together.
// The collapse can only ever LOWER the count — effectiveSolves <= raw — so it
// suppresses a canonical-inflated finding but can never manufacture one. The
// accepted cost: a client that DELIBERATELY alternates spellings halves its
// score, so the worst-case threshold for such a client is 2x MIN_SOLVES raw
// solves — 16 by default, still a fraction of the 30+/window the abusive
// population sustains.
package cookiediscard

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

type Config struct {
	Every  time.Duration
	Window time.Duration

	// MinSolves is how many times one address must complete the challenge
	// within Window before it is reported. See the package doc for how the
	// default was derived; the semantic bound is CHALLENGE_COOKIE_LIFE (any
	// repeat inside it is anomalous), and Window is a deliberately tighter and
	// cheaper proxy for it.
	MinSolves int

	// Cooldown is the minimum gap between alerts for the same address, so a
	// client that re-solves for hours does not emit one alert per scan.
	Cooldown time.Duration

	// MaxTrackedIPs bounds how many distinct addresses are kept in flight. The
	// map key is client-controlled, so this bound is not optional: at the
	// observed rate (~110 solves/min) roughly 1,100 addresses are live inside a
	// 10-minute window, and the default sits far above that. When it is reached
	// no NEW address is admitted — addresses already tracked keep counting, so
	// an in-progress finding is never lost to a flood of one-shot solvers.
	MaxTrackedIPs int

	// MaxTrackedPerIP bounds the evidence buffer for one address. Records lost
	// to it are still counted toward the solve total, so the cap costs UA/vhost
	// detail and never detection.
	MaxTrackedPerIP int

	SampleLimit int

	// MaxQueue bounds the ingest buffer between ticks. Enqueue runs inline on
	// the verify path and RunOnce is the only drain, so an unbounded buffer
	// turns any stall of the detector loop into unbounded growth. Overflow is
	// counted and logged rather than dropped silently.
	MaxQueue int

	AllowHosts      []string
	AllowIPs        []string
	AllowNets       []string
	AllowUAContains []string
}

type solveRec struct {
	when time.Time
	host string
	path string
	ua   string
	// uaBad is the UA-plausibility verdict carried on the event (empty when the
	// UA is coherent). Corroborating evidence only — never part of the
	// threshold, because a client can always send a well-formed UA.
	uaBad string
}

type ipState struct {
	recs []solveRec
	// truncated counts records the evidence cap dropped SINCE THE LAST
	// EVALUATION, and is added back into the solve total so the cap cannot hide
	// the very behaviour being counted. Reset every pass, not only when an
	// alert fires — otherwise an address that truncates for an hour without
	// crossing the threshold would attribute an hour of drops to one window.
	truncated int
	lastAlert time.Time
}

// prune drops everything that fell out of the window.
func (st *ipState) prune(cutoff time.Time) {
	kept := st.recs[:0]
	for _, r := range st.recs {
		if r.when.After(cutoff) {
			kept = append(kept, r)
		}
	}
	// Release the strings held by the pruned tail; the backing array is reused,
	// but an address that once peaked would otherwise pin every UA and URI it
	// ever sent.
	for i := len(kept); i < len(st.recs); i++ {
		st.recs[i] = solveRec{}
	}
	st.recs = kept
}

type Detector struct {
	cfg  Config
	name string

	mu      sync.Mutex
	events  []core.InputEvent
	dropped int

	// ips is owned by RunOnce and is NOT guarded by mu: the framework runs
	// RunOnce serially per detector (run.go refuses to start a second pass while
	// one is in flight) and Enqueue never touches it. Take mu here too if that
	// ever stops being true.
	ips map[string]*ipState
	// ipsCapped records that MaxTrackedIPs was reached during the last ingest,
	// so the pass can say so instead of quietly under-reporting.
	ipsCapped int

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
		cfg.Window = 10 * time.Minute
	}
	// An evaluation interval longer than the window leaves a blind gap: each
	// pass prunes everything older than Window, so solves that arrived more than
	// Window before the tick are ingested and immediately discarded, unexamined.
	// This is reachable without anyone choosing it — a section that omits EVERY
	// inherits [global] DEFAULT_EVERY.
	if cfg.Every > cfg.Window {
		cfg.Every = cfg.Window
	}
	if cfg.MinSolves <= 0 {
		cfg.MinSolves = 8
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Minute
	}
	if cfg.MaxTrackedIPs <= 0 {
		cfg.MaxTrackedIPs = 100000
	}
	if cfg.MaxTrackedPerIP <= 0 {
		cfg.MaxTrackedPerIP = 2000
	}
	if cfg.SampleLimit <= 0 {
		cfg.SampleLimit = 10
	}
	if cfg.MaxQueue <= 0 {
		// ~15x the busiest window observed in production, so a healthy loop
		// never reaches it.
		cfg.MaxQueue = 20000
	}

	d := &Detector{
		cfg:        cfg,
		nowFn:      time.Now,
		ips:        make(map[string]*ipState),
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
	return "challenge_cookie_discard"
}
func (d *Detector) Every() time.Duration { return d.cfg.Every }

func (d *Detector) Enqueue(ev core.InputEvent) {
	if ev.When.IsZero() {
		ev.When = d.nowFn()
	}
	if ev.SrcIP == "" || d.allowed(ev) {
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

func (d *Detector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	d.mu.Lock()
	batch := d.events
	dropped := d.dropped
	d.events, d.dropped = nil, 0
	d.mu.Unlock()

	if dropped > 0 {
		logging.Logf("[%s] ingest queue full: dropped %d solve events (MAX_QUEUE=%d)",
			d.Name(), dropped, d.cfg.MaxQueue)
	}

	now := d.nowFn()
	cutoff := now.Add(-d.cfg.Window)

	// Prune BEFORE ingesting, so the evidence cap is measured against what is
	// actually still in the window rather than against last pass's length.
	for _, st := range d.ips {
		st.prune(cutoff)
	}

	capped := 0
	for _, ev := range batch {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ip := strings.TrimSpace(ev.SrcIP)
		if net.ParseIP(ip) == nil {
			continue
		}
		st := d.ips[ip]
		if st == nil {
			// Admit new addresses only while there is room. Existing entries keep
			// counting either way, so a flood of one-shot solvers can delay a new
			// finding but cannot erase one already accumulating.
			if len(d.ips) >= d.cfg.MaxTrackedIPs {
				capped++
				continue
			}
			st = &ipState{}
			d.ips[ip] = st
		}
		if len(st.recs) >= d.cfg.MaxTrackedPerIP {
			st.truncated++
			continue
		}
		st.recs = append(st.recs, solveRec{
			when:  ev.When,
			host:  strings.ToLower(strings.TrimSpace(ev.Scope)),
			path:  ev.Path,
			ua:    ev.UserAgent,
			uaBad: ev.Signal,
		})
	}
	if capped > 0 && d.ipsCapped == 0 {
		logging.Logf("[%s] tracking %d addresses (MAX_TRACKED_IPS); %d solves from new addresses were not tracked this pass",
			d.Name(), len(d.ips), capped)
	}
	d.ipsCapped = capped

	for ip, st := range d.ips {
		// Drop addresses that have gone quiet so state does not grow without
		// bound. Guarded by the cooldown so state is never reclaimed while it
		// still suppresses a repeat alert.
		if len(st.recs) == 0 && now.Sub(st.lastAlert) > d.cfg.Cooldown {
			delete(d.ips, ip)
			continue
		}

		raw := len(st.recs) + st.truncated
		truncated := st.truncated
		st.truncated = 0

		// effectiveSolves can only lower a count (eff <= raw, by construction),
		// so an address whose raw total is already below threshold cannot cross
		// it — skip the per-group map for the ~99.6% of addresses with a single
		// solve. This matters under the exact flood MAX_TRACKED_IPS exists for:
		// up to 100k tracked addresses re-evaluated every EVERY tick.
		if raw < d.cfg.MinSolves {
			continue
		}
		solves := effectiveSolves(st.recs, truncated)
		if solves < d.cfg.MinSolves {
			continue
		}
		if !st.lastAlert.IsZero() && now.Sub(st.lastAlert) < d.cfg.Cooldown {
			continue
		}

		alert := d.buildAlert(now, ip, st, solves, raw, truncated)
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

// splitWWW reports the apex form of host and whether host carried a leading
// "www.". The strip applies only when something with a dot remains, so
// "www.example.gr" → ("example.gr", true) while "www.localhost" and a bare
// "webmail.example.gr" are returned unchanged with isWWW=false. This is the ONLY
// host relationship the collapse understands: the apex and its www, never a
// panel or mail label — the same narrow rule the clearance layer applies.
func splitWWW(host string) (apex string, isWWW bool) {
	if rest, ok := strings.CutPrefix(host, "www."); ok && strings.Contains(rest, ".") {
		return rest, true
	}
	return host, false
}

// effectiveSolves is the raw solve total with the apex↔www canonical
// double-solve collapsed out (see the package doc for why). For each
// (apex-normalised host, path) the logical count is the busier spelling rather
// than the sum, so a single visitor's apex-then-www journey counts once while a
// pipeline that solves N times still counts N. truncated records carry no host,
// so they are added back verbatim — truncation only happens far above threshold,
// on the abusive population this detector is for. The result is always <= raw.
func effectiveSolves(recs []solveRec, truncated int) int {
	type spellings struct{ apex, www int }
	groups := make(map[string]*spellings)
	for _, r := range recs {
		apex, isWWW := splitWWW(r.host)
		key := apex + "\x00" + r.path
		g := groups[key]
		if g == nil {
			g = &spellings{}
			groups[key] = g
		}
		if isWWW {
			g.www++
		} else {
			g.apex++
		}
	}
	total := truncated
	for _, g := range groups {
		if g.www > g.apex {
			total += g.www
		} else {
			total += g.apex
		}
	}
	return total
}

// buildAlert renders the finding. It reads state but does not mutate it — the
// caller owns the truncation counter and the cooldown stamp. solves is the
// threshold basis (apex↔www collapsed); raw is the uncollapsed total, reported
// so an operator can see how much the canonical redirect inflated it.
func (d *Detector) buildAlert(now time.Time, ip string, st *ipState, solves, raw, truncated int) core.Alert {
	hosts := map[string]int{}
	paths := map[string]int{}
	uas := map[string]int{}
	impossibleUA := 0
	for _, r := range st.recs {
		hosts[r.host]++
		paths[r.path]++
		uas[r.ua]++
		if r.uaBad != "" {
			impossibleUA++
		}
	}
	sampled := len(st.recs)

	topUA, topUACount := topOf(uas)
	uaShare := 0
	if sampled > 0 {
		uaShare = topUACount * 100 / sampled
	}
	topHost, _ := topOf(hosts)

	// The rate is what makes this unambiguous rather than merely odd: a browser
	// that kept its cookie would solve at most once per CHALLENGE_COOKIE_LIFE.
	perMinute := float64(solves) / d.cfg.Window.Minutes()

	samples := []string{
		fmt.Sprintf("[challenge] ip=%s solves=%d window=%s (%.1f/min) distinct_vhosts=%d distinct_uas=%d",
			ip, solves, d.cfg.Window, perMinute, len(hosts), len(uas)),
		"[challenge] a solved challenge grants clearance for CHALLENGE_COOKIE_LIFE; re-solving inside it means the client is discarding the cookie",
	}
	if raw != solves {
		samples = append(samples, fmt.Sprintf(
			"[challenge] apex↔www canonical collapse: %d raw solves scored as %d (a solve on a host and its www/apex sibling for the same path is one journey, not two)",
			raw, solves))
	}
	for _, s := range rank(hosts, sampled, "vhost") {
		if len(samples) >= d.cfg.SampleLimit {
			break
		}
		samples = append(samples, s)
	}
	for _, s := range rank(paths, sampled, "uri") {
		if len(samples) >= d.cfg.SampleLimit {
			break
		}
		samples = append(samples, s)
	}
	for _, s := range rank(uas, sampled, "ua") {
		if len(samples) >= d.cfg.SampleLimit {
			break
		}
		samples = append(samples, s)
	}
	if impossibleUA > 0 {
		samples = append(samples, fmt.Sprintf("[challenge] self-contradictory User-Agents: %d of %d sampled solves (%d%%)",
			impossibleUA, sampled, impossibleUA*100/sampled))
	}
	// No silent caps: say which counts are lower bounds. The solve total is not
	// one — truncated records are added back into it — but the breakdowns are.
	if truncated > 0 {
		samples = append(samples, fmt.Sprintf("[challenge] NOTE: %d solves since the last evaluation were not sampled (MAX_TRACKED_PER_IP=%d); the breakdowns above cover %d of %d solves",
			truncated, d.cfg.MaxTrackedPerIP, sampled, solves))
	}

	return core.Alert{
		When:    now,
		Kind:    core.AlertKind("Challenge/CookieDiscard"),
		Key:     ip,
		Count:   solves,
		Samples: samples,
		Extra: map[string]string{
			// Authoritative source address. Set explicitly so the sink never
			// reaches its Samples fallback, which takes the first IP-shaped
			// string it finds — and the samples below quote User-Agents and URIs,
			// which the reported client controls. See core.ExtraIPScope.
			"ip":              ip,
			"reason":          "CHALLENGE_COOKIE_DISCARD",
			"solves":          fmt.Sprint(solves),
			"raw_solves":      fmt.Sprint(raw),
			"window":          d.cfg.Window.String(),
			"solves_per_min":  fmt.Sprintf("%.1f", perMinute),
			"distinct_vhosts": fmt.Sprint(len(hosts)),
			"top_vhost":       topHost,
			"top_ua":          topUA,
			"top_ua_share":    fmt.Sprintf("%d%%", uaShare),
			// Corroboration only — never part of the threshold.
			"impossible_ua": fmt.Sprint(impossibleUA),
		},
	}
}

func topOf(m map[string]int) (string, int) {
	best, bestN := "", 0
	for k, n := range m {
		if n > bestN || (n == bestN && k < best) {
			best, bestN = k, n
		}
	}
	return best, bestN
}

// rank renders a histogram as sample lines, most frequent first, with ties
// broken by name so the output is stable across passes.
func rank(m map[string]int, sampled int, label string) []string {
	type kv struct {
		k string
		n int
	}
	items := make([]kv, 0, len(m))
	for k, n := range m {
		items = append(items, kv{k, n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].k < items[j].k
	})
	out := make([]string, 0, len(items))
	for _, it := range items {
		pct := 0
		if sampled > 0 {
			pct = it.n * 100 / sampled
		}
		out = append(out, fmt.Sprintf("[challenge] %s=%q solves=%d (%d%%)", label, it.k, it.n, pct))
	}
	return out
}
