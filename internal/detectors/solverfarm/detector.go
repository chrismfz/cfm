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
	enrich "cfm/internal/enrich"
	"cfm/internal/logging"
)

// State bounds for the fingerprint-concentration track. Generous: a farm uses one
// fingerprint, and there are ~249 countries, so these never bind in practice —
// they only stop a pathological host from growing state without bound.
const (
	maxFPsPerHost       = 4096
	maxCountriesTracked = 300
	// maxXHRecords bounds the node-level cross-host solve-record buffer. A safety
	// valve only: the buffer is pruned to XHWindow every pass, so it self-bounds to
	// XHWindow × fingerprinted-solve-rate; the cap stops a pathological burst from
	// growing it without bound. Overflow is counted and logged, not silently
	// dropped. A const (like the two above), not a config knob — an operator never
	// needs to tune it, and CLAUDE.md §5 keeps hidden config keys out of the tree.
	maxXHRecords = 100000
	// maxFindingIPs caps the fingerprint-accurate IP sample carried on an emitted
	// finding (for the fleet store's per-IP enrichment / block surface). A bounded
	// sample, not the full set: a residential-proxy pool rotates through thousands
	// of addresses over days, but the store dedups across findings and accumulates
	// the population over time, so a per-finding cap keeps the payload small without
	// losing coverage. Not a config knob (CLAUDE.md §5).
	maxFindingIPs = 128
)

// sampleKeys returns up to limit keys of m (map iteration order is random, so the
// sample is effectively arbitrary). nil for an empty map.
func sampleKeys[V any](m map[string]V, limit int) []string {
	n := len(m)
	if n == 0 {
		return nil
	}
	if n > limit {
		n = limit
	}
	out := make([]string, 0, n)
	for k := range m {
		out = append(out, k)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// fpSolveIPs returns a fingerprint's total solves and distinct addresses on a
// vhost. solves >= ips by construction (each address solved at least once), so a
// finding built from these is self-consistent.
func fpSolveIPs(m map[string]ipStat) (solves, ips int) {
	for _, s := range m {
		solves += s.solves
	}
	return solves, len(m)
}

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

	// FPTrack enables the fingerprint-concentration low-rate track: flag a vhost
	// whose solvers span many subnets AND many countries but collapse onto a
	// SINGLE client fingerprint — the low-and-slow farm the subnet-count rule
	// above (calibrated for a ~110/min farm) misses at ~8/min. The fingerprint is
	// a GROUP-BY key, never a matched value, so a new tool with a new fingerprint
	// trips the same shape. See docs/solver-farm-fingerprint-concentration.md.
	FPTrack bool
	// MinFPSubnets / MinFPCountries are the low-rate thresholds, AND'd. Country is
	// the load-bearing false-positive guard: a legit shared-fingerprint population
	// (corporate fleet, carrier CGNAT) is geographically clustered; a residential
	// farm is not. Calibrated on the 2026-09-08 fleet capture (farms 10–22
	// countries per window, every legitimate group ≤3). MinFPSubnets is only a
	// floor against a trickle — a legit group reached 17 /24s but 2 countries, so
	// the subnet count alone does not discriminate; the country guard does.
	MinFPSubnets   int
	MinFPCountries int
	// AllowFPs exempts known-legitimate shared fingerprints (e.g. a monitored
	// synthetic-checker fleet) from the concentration track. Applies to the
	// cross-host track too.
	AllowFPs []string

	// NotifyCooldown throttles NOTIFICATIONS (mail/Slack) for a farmed vhost to at
	// most one per this interval, independently of Cooldown. Cooldown (30m) still
	// governs how often the alert is emitted at all — i.e. the detector-log record
	// and the "farmed now" mark refresh — but a farm runs for hours, so mailing
	// every 30m is noise once the operator knows. Between Cooldown and
	// NotifyCooldown the alert is logged without a notification. Applies to every
	// track (subnet-spread included): the log stays live, the mail stays sparse.
	NotifyCooldown time.Duration

	// XHTrack enables the CROSS-HOST fingerprint-concentration track: a single
	// fingerprint that DOMINATES many vhosts (super-majority of each vhost's
	// solves) and spans many countries+subnets across the NODE, even when it stays
	// under the per-vhost 60s country bar on every individual host. This catches
	// the thin farm the per-host FPTrack misses (measured: 95070673 across 22
	// vhosts / 44 countries, ~1 solve/IP). Fingerprint is a GROUP-BY key, never a
	// matched value. See docs/solver-farm-cross-host-phase2.md.
	XHTrack bool
	// XHWindow is the (longer) aggregation window for the cross-host track — a thin
	// farm needs time to accumulate its spread. Independent of Window (60s).
	XHWindow time.Duration
	// MinXHHostShare is the PRIMARY cross-host guard: a (host, fp) pair is admitted
	// to the fingerprint's cross-host tally only when that fp is at least this
	// fraction of the vhost's fingerprinted solves in the window. A farm dominates
	// the vhosts it targets (0.85–1.0); a legitimate shared browser is a minority
	// (≤0.39 measured), so it never enters the pool and its spread never accrues.
	MinXHHostShare float64
	// MinXHHosts / MinXHCountries / MinXHSubnets are the spread FLOORS over the
	// pre-gated hosts. Countries is the secondary guard (raised to 12: the closest
	// legit fp reached 9 cross-host). solves_per_ip is deliberately NOT a gate —
	// the burn-in showed it does not separate farm from legit (farm at 1.11, legit
	// at 1.00–1.08) — it is carried on the alert as evidence only.
	MinXHHosts     int
	MinXHCountries int
	MinXHSubnets   int
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
	// lastNotify stamps the last time an alert for this vhost actually NOTIFIED
	// (not merely logged). Gated by Cfg.NotifyCooldown so a persistent farm mails
	// sparsely while still logging every Cooldown. Separate from lastAlert on
	// purpose: the log record and the mark stay live at the Cooldown cadence.
	lastNotify time.Time

	// fps is the per-fingerprint aggregation for the concentration track, nil
	// until the first usable-fingerprint solve. Every fp-tracked solve also feeds
	// the per-host subnets set above, so — below that set's own cap
	// (MaxTrackedPerHost distinct subnets in one window, unreachable in practice)
	// — fps never holds a subnet that set does not, and prune stays consistent
	// between them.
	fps map[string]*fpAgg
}

// fpAgg tracks, for one (host, fingerprint), the distinct subnets and countries
// solving under it in the window — the concentration track's threshold inputs.
// Both hold key -> newest solve time so prune drops what fell out of the window.
type fpAgg struct {
	subnets   map[string]time.Time
	countries map[string]time.Time
	// ips is the fingerprint's OWN client addresses on this vhost, each carrying
	// its solve count + newest-solve time. Keeping the per-address solve count
	// lets a per-host finding report the fp's solves/distinct_ips/solves_per_ip at
	// the SAME (fingerprint) scope as its subnets/countries — so the fleet-store
	// row is self-consistent (solves ≥ distinct_ips) instead of pairing an fp-scoped
	// subnet count with a vhost-wide IP/solve count.
	ips map[string]ipStat
}

// ipStat is one address's contribution to a fingerprint on a vhost.
type ipStat struct {
	solves int
	last   time.Time // newest solve, for windowing
}

// xhRec is one fingerprinted solve, retained node-wide for the cross-host track's
// XHWindow (longer than the per-host Window). The track re-aggregates the whole
// buffer each pass rather than maintaining incrementally-windowed counters —
// per-solve records are what a sliding window actually needs, and a flat slice
// pruned by time is far easier to reason about than decrementing counts on expiry.
// Only fingerprinted solves are stored (an empty fingerprint is never a group
// key), so the buffer self-bounds to the fingerprinted solve rate × XHWindow.
type xhRec struct {
	when    time.Time
	host    string
	fp      string
	subnet  string
	ip      string
	country string
}

// xhAgg is the per-fingerprint cross-host tally, folded from the pre-gated hosts
// (those where the fp is a super-majority). It is rebuilt each pass, never stored.
type xhAgg struct {
	hosts     map[string]struct{}
	countries map[string]struct{}
	subnets   map[string]struct{}
	ips       map[string]struct{}
	solves    int
}

func newHostState() *hostState {
	return &hostState{subnets: map[string]time.Time{}, ips: map[string]time.Time{}, fps: map[string]*fpAgg{}}
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
	for fp, a := range st.fps {
		for k, t := range a.subnets {
			if !t.After(cutoff) {
				delete(a.subnets, k)
			}
		}
		for k, t := range a.countries {
			if !t.After(cutoff) {
				delete(a.countries, k)
			}
		}
		// Prune the fp's address set to the window too, so a finding samples only
		// the CURRENTLY-active addresses — a stale residential IP that rotated away
		// must not linger in the block surface.
		for k, s := range a.ips {
			if !s.last.After(cutoff) {
				delete(a.ips, k)
			}
		}
		// Drop a fingerprint only when it has no live data of any kind. With the
		// lockstep ingest an empty a.ips already implies empty subnets/countries,
		// but check a.ips explicitly so a future change can't resurrect the
		// "fresh subnet, zero IPs" finding this guards against.
		if len(a.subnets) == 0 && len(a.countries) == 0 && len(a.ips) == 0 {
			delete(st.fps, fp)
		}
	}
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

	// xhRecs is the node-level cross-host solve-record buffer (XHWindow). Owned by
	// RunOnce, same as hosts. xhDropped counts records the cap refused since the
	// last pass. Both are unused when XHTrack is off.
	xhRecs    []xhRec
	xhDropped int

	// nowFn is the detector's clock. Injectable so tests can replay a recorded
	// traffic window at its original timestamps instead of wall-clock.
	nowFn func() time.Time

	allowHosts map[string]struct{}
	allowIPs   map[string]struct{}
	allowNets  []*net.IPNet
	allowFPs   map[string]struct{}

	// countryFn maps a client IP to its ISO-2 country ("" = unknown / no geodb).
	// Set from the injected Enricher (SetEnricher); nil disables the country
	// dimension, which FAIL-SAFE disables the concentration track — it can never
	// fire without confirming geographic spread. Injectable directly in tests.
	countryFn func(string) string

	// onFarm is called for every over-threshold evaluation, BEFORE the alert
	// cooldown is consulted. That distinction is the whole point: the alert is
	// rate-limited to one per COOLDOWN (30m by default) because a farm runs for
	// hours, so anything driven by alerts — a UI badge, a live status — would
	// blink off while the farm never stopped. See webdetector.MarkSolverFarm.
	onFarm func(host string, ttl time.Duration)

	// onFarmFP is the fingerprint-level twin of onFarm: called with the finding's
	// RESOLVED fingerprint (cross-host preferred over per-host) on the same
	// over-threshold evaluations, so a per-client consumer can mark "this
	// fingerprint is convicted" the way onFarm marks the vhost. Empty fingerprint
	// (subnet-spread-only finding, or no X-CFM-TLS) is never passed.
	onFarmFP func(fp string, ttl time.Duration)
}

// SetFarmHook installs a callback invoked on every evaluation where a vhost is
// over threshold. It must be cheap and non-blocking; it runs inside RunOnce.
func (d *Detector) SetFarmHook(fn func(host string, ttl time.Duration)) { d.onFarm = fn }

// SetFarmFPHook installs a callback invoked with the convicting fingerprint on
// every over-threshold evaluation that resolves one. Cheap and non-blocking; it
// runs inside RunOnce, alongside the vhost SetFarmHook.
func (d *Detector) SetFarmFPHook(fn func(fp string, ttl time.Duration)) { d.onFarmFP = fn }

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
	if cfg.MinFPSubnets <= 0 {
		cfg.MinFPSubnets = 8
	}
	if cfg.MinFPCountries <= 0 {
		cfg.MinFPCountries = 6
	}
	if cfg.NotifyCooldown <= 0 {
		cfg.NotifyCooldown = 6 * time.Hour
	}
	// The cross-host window must not be shorter than the per-host Window; a thin
	// farm is exactly what it exists to accumulate over time.
	if cfg.XHWindow < cfg.Window {
		cfg.XHWindow = 30 * time.Minute
	}
	if cfg.MinXHHostShare <= 0 || cfg.MinXHHostShare > 1 {
		cfg.MinXHHostShare = 0.50
	}
	if cfg.MinXHHosts <= 0 {
		cfg.MinXHHosts = 4
	}
	if cfg.MinXHCountries <= 0 {
		cfg.MinXHCountries = 12
	}
	if cfg.MinXHSubnets <= 0 {
		cfg.MinXHSubnets = 30
	}

	d := &Detector{
		cfg:        cfg,
		nowFn:      time.Now,
		hosts:      make(map[string]*hostState),
		allowHosts: make(map[string]struct{}),
		allowIPs:   make(map[string]struct{}),
		allowFPs:   make(map[string]struct{}),
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
	for _, fp := range cfg.AllowFPs {
		if fp = strings.ToLower(strings.TrimSpace(fp)); fp != "" {
			d.allowFPs[fp] = struct{}{}
		}
	}
	return d
}

// SetEnricher wires the country lookup the concentration track's false-positive
// guard needs. The detectors manager calls it via an interface assertion, so the
// register needs no change. LookupGeoFast reads Country/ASN only (no blocking PTR
// rDNS) and is called in RunOnce, off the hot Enqueue path. A nil enricher leaves
// countryFn nil, which fail-safe disables the concentration track; an enricher
// present but with no geo DB returns empty countries, so no fingerprint meets the
// country floor and the track cannot fire either — the same outcome, reached
// differently (it still builds per-fp state, harmlessly).
func (d *Detector) SetEnricher(e *enrich.Enricher) {
	if e == nil {
		return
	}
	d.countryFn = func(ip string) string {
		return strings.ToUpper(strings.TrimSpace(e.LookupGeoFast(ip).CountryISO))
	}
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
	// Same reasoning for the cross-host buffer: prune to XHWindow BEFORE ingest so
	// the maxXHRecords cap is measured against live records only. Pruning inside
	// evalCrossHost (after ingest) would let stale records hold cap budget and drop
	// live solves during a high-rate burst — the track would go blind exactly when
	// it matters. evalCrossHost then just aggregates the already-pruned buffer.
	if d.cfg.XHTrack {
		d.pruneXH(now.Add(-d.cfg.XHWindow))
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
		// Fingerprint tracks — per-host concentration (FPTrack) and cross-host
		// (XHTrack). Both group usable fingerprints and need the client's country,
		// so look it up HERE (RunOnce, off the hot Enqueue path) ONCE per fp-bearing
		// solve and feed both. Done before the evidence cap's continue below, so an
		// evidence flood cannot suppress either, exactly as the subnet/IP sets above
		// cannot. Empty fingerprint is never a group key (it pools unrelated
		// clients); allow-listed fingerprints are skipped from both tracks.
		if (d.cfg.FPTrack || d.cfg.XHTrack) && d.countryFn != nil {
			if fp := strings.ToLower(strings.TrimSpace(ev.Fingerprint)); fp != "" {
				if _, skip := d.allowFPs[fp]; !skip {
					cc := d.countryFn(ev.SrcIP)
					if d.cfg.FPTrack {
						a := st.fps[fp]
						if a == nil && len(st.fps) < maxFPsPerHost {
							a = &fpAgg{subnets: map[string]time.Time{}, countries: map[string]time.Time{}, ips: map[string]ipStat{}}
							st.fps[fp] = a
						}
						if a != nil {
							// Count subnets/countries ONLY for an address we actually
							// track in a.ips, so all three maps describe the SAME
							// population. This keeps the per-host finding self-consistent
							// (distinct_countries ≤ distinct_subnets ≤ distinct_ips ≤
							// solves) and prunes them in lockstep — a subnet can't outlive
							// the addresses that put it there. Otherwise a solve PAST the
							// a.ips cap still refreshed its subnet/country, so a subnet
							// could stay "fresh" via an untracked IP, survive prune after
							// its real IPs aged out, and emit a finding claiming
							// subnets > distinct_ips (== 0). The a.ips cap is a memory
							// bound, and distinct subnets ≤ distinct IPs always, so
							// gating never loses a subnet before the (equal) cap binds.
							if s, seen := a.ips[ev.SrcIP]; seen || len(a.ips) < d.cfg.MaxTrackedPerHost {
								s.solves++
								s.last = ev.When
								a.ips[ev.SrcIP] = s

								if _, sSeen := a.subnets[sn]; sSeen || len(a.subnets) < d.cfg.MaxTrackedPerHost {
									a.subnets[sn] = ev.When
								}
								if cc != "" {
									if _, cSeen := a.countries[cc]; cSeen || len(a.countries) < maxCountriesTracked {
										a.countries[cc] = ev.When
									}
								}
							}
						}
					}
					if d.cfg.XHTrack {
						if len(d.xhRecs) < maxXHRecords {
							d.xhRecs = append(d.xhRecs, xhRec{when: ev.When, host: host, fp: fp, subnet: sn, ip: ev.SrcIP, country: cc})
						} else {
							d.xhDropped++
						}
					}
				}
			}
		}
		if len(st.recs) >= d.cfg.MaxTrackedPerHost {
			st.truncated++
			continue
		}
		st.recs = append(st.recs, solveRec{when: ev.When, subnet: sn, ip: ev.SrcIP, ua: ev.UserAgent, uaBad: ev.Signal})
	}

	// Cross-host track: fold the node-level buffer once, up front, so the per-host
	// loop below can (a) not reclaim a vhost that is flagged cross-host this pass
	// and (b) attach the cross-host evidence to a combined finding.
	xhVerdicts := d.evalCrossHost(now)
	alerted := make(map[string]bool)

	for host, st := range d.hosts {
		// Drop vhosts that have gone quiet so state does not grow without bound.
		// Guarded so state is never reclaimed while it still suppresses something:
		// the alert cooldown, the NOTIFY cooldown (else a farm that idles past
		// Cooldown loses lastNotify and re-mails within NotifyCooldown — the pulsing
		// bypass), or a cross-host flag this pass (its per-host 60s state can be
		// empty while the fp is farming it thin).
		if len(st.subnets) == 0 && len(st.recs) == 0 &&
			now.Sub(st.lastAlert) > d.cfg.Cooldown &&
			(st.lastNotify.IsZero() || now.Sub(st.lastNotify) > d.cfg.NotifyCooldown) {
			if _, xh := xhVerdicts[host]; !xh {
				delete(d.hosts, host)
				continue
			}
		}

		solves := len(st.recs) + st.truncated
		truncated, setsCapped := st.truncated, st.setsCapped
		// Reset every pass, not only when an alert fires.
		st.truncated, st.setsCapped = 0, false

		// Three verdicts share one alert/mark/cooldown per vhost: the original
		// high-rate subnet spread, the per-host low-rate fingerprint concentration,
		// and (attached here when present) the cross-host concentration.
		hiRate := solves >= d.cfg.MinSolves && len(st.subnets) >= d.cfg.MinSubnets
		loFP, loFPSubs, loFPCcs := d.topConcentratedFP(st)
		xh, hasXH := xhVerdicts[host]
		if !hiRate && loFP == "" && !hasXH {
			continue
		}
		// Mark before the cooldown check, not after: the mark answers "is this
		// vhost being farmed right now", which stays true through the 30m the
		// alert is suppressed for.
		if d.onFarm != nil {
			d.onFarm(host, d.markTTL())
		}
		// Mark the convicting fingerprint too (cross-host preferred over the
		// per-host concentration fp, matching what the finding carries). Empty for
		// a subnet-spread-only flag — nothing to attribute.
		if d.onFarmFP != nil {
			fp := loFP
			if hasXH && xh.fp != "" {
				fp = xh.fp
			}
			if fp != "" {
				d.onFarmFP(fp, d.markTTL())
			}
		}
		alerted[host] = true
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

		// Notify decision. A vhost carried by a per-host or subnet-spread verdict
		// (or a combined finding that also includes cross-host) notifies per ACTION,
		// throttled by NotifyCooldown so a persistent farm logs every Cooldown but
		// mails sparsely. A finding that is CROSS-HOST ONLY (no per-host verdict this
		// pass, even though it has a hostState) stays log-only through the cross-host
		// burn-in — the same shadow-first discipline Phase-1's fp track shipped under.
		xhArg := &xh
		if !hasXH {
			xhArg = nil
		}
		xhOnly := hasXH && !hiRate && loFP == ""
		if d.emit(ctx, out, now, st, host, solves, truncated, setsCapped, uas, impossibleUA, hiRate, loFP, loFPSubs, loFPCcs, xhArg, xhOnly) != nil {
			return ctx.Err()
		}
	}

	// Cross-host-only vhosts: flagged solely by the cross-host track (no per-host
	// or subnet-spread verdict this pass). These are the thin-farm vhosts Phase-1
	// misses. Log-only through the cross-host burn-in.
	for host, xh := range xhVerdicts {
		if alerted[host] {
			continue
		}
		st := d.hosts[host]
		if st == nil {
			st = newHostState()
			d.hosts[host] = st
		}
		if d.onFarm != nil {
			d.onFarm(host, d.markTTL())
		}
		// Cross-host-only: the convicting fingerprint is the cross-host fp.
		if d.onFarmFP != nil && xh.fp != "" {
			d.onFarmFP(xh.fp, d.markTTL())
		}
		if !st.lastAlert.IsZero() && now.Sub(st.lastAlert) < d.cfg.Cooldown {
			continue
		}
		xh := xh
		if d.emit(ctx, out, now, st, host, 0, 0, false, nil, 0, false, "", 0, 0, &xh, true) != nil {
			return ctx.Err()
		}
	}
	return nil
}

// Finding is the durable, structured record of one EMITTED solver-farm alert —
// the evidence a fleet-central reputation store (cfm-web) ingests via the node's
// detection_history (event_type=solver_farm). It fires once per emitted alert
// (post-cooldown), regardless of whether the alert NOTIFIED: the durable memory
// must not be throttled by the mail cadence. Fingerprint is the GROUP-BY key that
// flagged the vhost (the cross-host fp when present, else the per-host
// concentration fp; empty for a subnet-spread-only finding) — never a matched
// signature. See docs/fleet-fingerprint-reputation.md §5 for the ingest contract.
type Finding struct {
	When        time.Time
	Host        string
	Fingerprint string
	Tracks      string // subnet_spread[+fp_concentration][+cross_host]
	Solves      int
	DistinctIPs int
	Subnets     int
	Countries   int
	HostShare   float64 // cross-host per-vhost dominance; 0 when not a cross-host finding
	SolvesPerIP float64
	Hosts       int // cross-host node-wide vhost count; 1 for a per-host-only finding
	// IPs is a bounded, FINGERPRINT-accurate sample of the client addresses behind
	// this finding (cross-host: the fp's node-wide set; per-host: the fp's own set
	// on the vhost). Empty for a subnet-spread-only finding (no fingerprint). The
	// fleet store enriches these (PTR/ASN/country/datacenter) so an operator can
	// tell a residential-proxy pool from a datacenter crawler and act accordingly.
	IPs []string
}

// findingSink, if set, receives every emitted Finding. Package-level and wired by
// webdetector_register to the Engine's durable history recorder — a plain
// callback, so this package takes no webdetector dependency (mirrors the ECC/clam
// sinks). Unset by default: findings then only alert/log, exactly as before.
// Guarded by a mutex like the sibling sinks: the setter is re-invoked on every
// config reload (the engine is rebuilt), so the write races the previous
// detector's RunOnce readers unless the reload's stop-join-rebuild-start ordering
// holds — the mutex makes correctness independent of that invariant.
var (
	findingSinkMu sync.RWMutex
	findingSink   func(Finding)
)

// SetFindingSink installs (replacing any prior) the durable-record sink for
// emitted findings. Pass nil to detach. Called at wiring time and on each reload;
// safe for concurrent use.
func SetFindingSink(fn func(Finding)) {
	findingSinkMu.Lock()
	findingSink = fn
	findingSinkMu.Unlock()
}

// publishFinding delivers f to the sink if one is set. A misbehaving sink must
// never take down the detector's evaluation pass: a panic here would unwind
// through emit → RunOnce and cost every other vhost this pass its mark refresh
// and alert (the current alert is already delivered and its clocks stamped), so
// panics are contained — mirrors clam.publishScanEvent.
func publishFinding(f Finding) {
	findingSinkMu.RLock()
	fn := findingSink
	findingSinkMu.RUnlock()
	if fn == nil {
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			logging.Logf("[challenge_solver_farm] finding sink panic host=%s fp=%s err=%v", f.Host, f.Fingerprint, rec)
		}
	}()
	fn(f)
}

// emit builds and sends one alert, applying the NotifyCooldown throttle and
// stamping the per-vhost cooldown/notify clocks on a successful hand-off. It
// returns a non-nil error only on context cancellation (mirrors the caller's
// `return ctx.Err()`). xhOnly forces the finding log-only (the cross-host
// burn-in); otherwise the NotifyCooldown + ACTION=logonly decide whether it
// notifies. On a successful hand-off it also fires the durable finding sink (if
// wired) — independent of the notify decision.
func (d *Detector) emit(ctx context.Context, out chan<- core.Alert, now time.Time, st *hostState,
	host string, solves, truncated int, setsCapped bool, uas map[string]int, impossibleUA int,
	hiRate bool, loFP string, loFPSubs, loFPCcs int, xh *xhVerdict, xhOnly bool) error {

	suppressNotify := xhOnly || d.cfg.Action == ActionLogonly
	if !suppressNotify && !st.lastNotify.IsZero() && now.Sub(st.lastNotify) < d.cfg.NotifyCooldown {
		suppressNotify = true
	}
	alert, finding := d.buildAlert(now, host, st, solves, truncated, setsCapped, uas, impossibleUA, hiRate, loFP, loFPSubs, loFPCcs, xh, suppressNotify)
	select {
	case out <- alert:
		// Stamp the clocks only once the alert is actually handed off, so a
		// shutdown mid-send does not silence the next window.
		st.lastAlert = now
		if !suppressNotify {
			st.lastNotify = now
		}
		publishFinding(finding)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// topConcentratedFP returns the fingerprint on this host whose in-window solves
// span the most subnets while meeting BOTH low-rate thresholds (subnets AND
// countries), or "" when none does. It is fingerprint-VALUE-blind: it ranks by
// spread, never by which fingerprint, so a new tool's new fingerprint is treated
// identically. With no countryFn (no geodb) the fps carry no countries, nothing
// meets the country threshold, and the track is off — fail-safe.
func (d *Detector) topConcentratedFP(st *hostState) (fp string, subnets, countries int) {
	if !d.cfg.FPTrack {
		return "", 0, 0
	}
	for k, a := range st.fps {
		ns, nc := len(a.subnets), len(a.countries)
		if ns < d.cfg.MinFPSubnets || nc < d.cfg.MinFPCountries {
			continue
		}
		// Deterministic pick so the reported top_fp/fp_* evidence is stable across
		// passes when two fingerprints tie: most subnets, then most countries, then
		// the lexicographically smaller fingerprint. (map iteration order is random.)
		if ns > subnets || (ns == subnets && (nc > countries || (nc == countries && k < fp))) {
			fp, subnets, countries = k, ns, nc
		}
	}
	return fp, subnets, countries
}

// xhVerdict is a cross-host finding for ONE vhost: the fingerprint that flagged
// it, that fingerprint's node-wide tally (over the pre-gated hosts), the
// aggregate solves-per-IP (evidence only), and THIS vhost's share of the fp. The
// host* fields are this vhost's own counts over XHWindow, used to render an honest
// headline when the per-host 60s state has already been reclaimed (a thin farm can
// flag cross-host with no solve in the last 60s).
type xhVerdict struct {
	fp          string
	hosts       int
	countries   int
	subnets     int
	ips         int      // node-wide distinct fp IPs across the dominated vhosts
	ipSample    []string // bounded sample of those node-wide fp IPs (for the fleet store)
	solves      int      // node-wide fp solves across the dominated vhosts (pairs with ips)
	solvesPerIP float64
	hostShare   float64
	hostSolves  int
	hostSubnets int
	hostIPs     int
}

// hostFPCell is per-(host, fp) accumulation while folding the cross-host buffer.
type hostFPCell struct {
	solves    int
	subnets   map[string]struct{}
	countries map[string]struct{}
	ips       map[string]struct{}
}

// pruneXH drops cross-host records older than the cutoff. Called BEFORE ingest so
// the maxXHRecords cap is measured against live records only (see the call site).
func (d *Detector) pruneXH(cutoff time.Time) {
	kept := d.xhRecs[:0]
	for _, r := range d.xhRecs {
		if r.when.After(cutoff) {
			kept = append(kept, r)
		}
	}
	// Release the strings held by the pruned tail; the backing array is reused.
	for i := len(kept); i < len(d.xhRecs); i++ {
		d.xhRecs[i] = xhRec{}
	}
	d.xhRecs = kept
}

// evalCrossHost folds the node-level solve-record buffer (XHWindow) into a
// per-vhost verdict for the cross-host track. A (host, fp) pair is admitted to a
// fingerprint's tally ONLY when the fp is a super-majority of that vhost's
// fingerprinted solves (MinXHHostShare) — the primary guard: a legit minority
// browser never enters the pool, so its country/subnet spread never accrues. A
// fingerprint whose pre-gated hosts clear the host/country/subnet floors flags,
// and every one of those hosts is returned. solves_per_ip is computed for
// evidence only — the burn-in showed it does not separate farm from legit, so it
// is NOT a gate. Fingerprint is a GROUP-BY key throughout, never a matched value.
// Returns nil when the track is off or nothing flags.
func (d *Detector) evalCrossHost(now time.Time) map[string]xhVerdict {
	if !d.cfg.XHTrack || d.countryFn == nil {
		return nil
	}
	// The buffer is already pruned to XHWindow by pruneXH (before ingest); here we
	// only report/clear the overflow counter and fold what remains.
	if d.xhDropped > 0 {
		logging.Logf("[challenge_solver_farm] cross-host record buffer full: dropped %d solves (cap=%d)",
			d.xhDropped, maxXHRecords)
		d.xhDropped = 0
	}
	if len(d.xhRecs) == 0 {
		return nil
	}

	// hostTotal: fingerprinted solves per vhost in the window (the share
	// denominator). fh: per-(fp, host) accumulation.
	hostTotal := make(map[string]int)
	fh := make(map[string]map[string]*hostFPCell)
	for _, r := range d.xhRecs {
		hostTotal[r.host]++
		hosts := fh[r.fp]
		if hosts == nil {
			hosts = make(map[string]*hostFPCell)
			fh[r.fp] = hosts
		}
		c := hosts[r.host]
		if c == nil {
			c = &hostFPCell{subnets: map[string]struct{}{}, countries: map[string]struct{}{}, ips: map[string]struct{}{}}
			hosts[r.host] = c
		}
		c.solves++
		c.subnets[r.subnet] = struct{}{}
		if r.country != "" {
			c.countries[r.country] = struct{}{}
		}
		c.ips[r.ip] = struct{}{}
	}

	out := map[string]xhVerdict{}
	for fp, hosts := range fh {
		agg := xhAgg{
			hosts:     map[string]struct{}{},
			countries: map[string]struct{}{},
			subnets:   map[string]struct{}{},
			ips:       map[string]struct{}{},
		}
		// share pre-gate: keep only vhosts this fp dominates.
		qualHosts := make(map[string]float64) // host -> share
		for host, c := range hosts {
			tot := hostTotal[host]
			if tot <= 0 {
				continue
			}
			share := float64(c.solves) / float64(tot)
			if share < d.cfg.MinXHHostShare {
				continue
			}
			qualHosts[host] = share
			agg.hosts[host] = struct{}{}
			agg.solves += c.solves
			for k := range c.subnets {
				agg.subnets[k] = struct{}{}
			}
			for k := range c.countries {
				agg.countries[k] = struct{}{}
			}
			for k := range c.ips {
				agg.ips[k] = struct{}{}
			}
		}
		if len(agg.hosts) < d.cfg.MinXHHosts ||
			len(agg.countries) < d.cfg.MinXHCountries ||
			len(agg.subnets) < d.cfg.MinXHSubnets {
			continue
		}
		spi := 0.0
		if len(agg.ips) > 0 {
			spi = float64(agg.solves) / float64(len(agg.ips))
		}
		nh, nc, ns, ni := len(agg.hosts), len(agg.countries), len(agg.subnets), len(agg.ips)
		ipSample := sampleKeys(agg.ips, maxFindingIPs) // the fp's node-wide addresses, bounded
		for host, share := range qualHosts {
			// A vhost dominated by two flagging fingerprints keeps the one with the
			// wider subnet spread (deterministic: then more countries, then the
			// smaller fp string) so the reported evidence is stable across passes.
			if prev, ok := out[host]; ok {
				if !(ns > prev.subnets ||
					(ns == prev.subnets && (nc > prev.countries ||
						(nc == prev.countries && fp < prev.fp)))) {
					continue
				}
			}
			c := hosts[host]
			out[host] = xhVerdict{
				fp: fp, hosts: nh, countries: nc, subnets: ns, ips: ni, ipSample: ipSample,
				solves: agg.solves, solvesPerIP: spi, hostShare: share,
				hostSolves: c.solves, hostSubnets: len(c.subnets), hostIPs: len(c.ips),
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildAlert renders the finding. It reads state but does not mutate it — the
// caller owns the truncation counter and the cooldown stamp.
func (d *Detector) buildAlert(now time.Time, host string, st *hostState,
	solves, truncated int, setsCapped bool, uas map[string]int, impossibleUA int,
	hiRate bool, loFP string, loFPSubs, loFPCcs int, xh *xhVerdict, suppressNotify bool) (core.Alert, Finding) {

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
	// Display counts. Normally the per-host 60s window; but a cross-host-only
	// finding on a vhost whose 60s state was already reclaimed (a thin farm can
	// flag with no solve in the last minute) would otherwise render solves=0 —
	// misleading. In that one case, report this vhost's own counts over XHWindow,
	// which the cross-host verdict carries. Combined findings keep the 60s counts.
	dispSolves, dispIPs, dispSubnets := solves, len(st.ips), len(st.subnets)
	dispWindow := d.cfg.Window
	if xh != nil && solves == 0 && dispSubnets == 0 {
		dispSolves, dispIPs, dispSubnets = xh.hostSolves, xh.hostIPs, xh.hostSubnets
		dispWindow = d.cfg.XHWindow
	}
	// Solves per IP is the tell that per-IP thresholds cannot fire: a farm burns
	// a fresh address per solve, so this sits at ~1.0 while a real repeat
	// visitor population sits well above it.
	solvesPerIP := 0.0
	if dispIPs > 0 {
		solvesPerIP = float64(dispSolves) / float64(dispIPs)
	}

	samples := []string{
		fmt.Sprintf("[challenge] host=%s solves=%d distinct_ips=%d distinct_subnets=%d solves_per_ip=%.2f window=%s",
			host, dispSolves, dispIPs, dispSubnets, solvesPerIP, dispWindow),
	}
	if loFP != "" {
		samples = append(samples, fmt.Sprintf(
			"[challenge] fingerprint concentration: one fingerprint %s solving from distinct_subnets=%d distinct_countries=%d (single-fingerprint low-and-slow farm)",
			loFP, loFPSubs, loFPCcs))
	}
	if xh != nil {
		samples = append(samples, fmt.Sprintf(
			"[challenge] cross-host concentration: fingerprint %s dominates this vhost (share=%.0f%%) and spans hosts=%d countries=%d subnets=%d node-wide (solves_per_ip=%.2f, evidence only) — thin cross-host farm",
			xh.fp, xh.hostShare*100, xh.hosts, xh.countries, xh.subnets, xh.solvesPerIP))
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
		Count:   dispSubnets,
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
			"solves":        fmt.Sprint(dispSolves),
			"distinct_ips":  fmt.Sprint(dispIPs),
			"subnets":       fmt.Sprint(dispSubnets),
			"solves_per_ip": fmt.Sprintf("%.2f", solvesPerIP),
			"top_ua":        topUA,
			"top_ua_share":  fmt.Sprintf("%d%%", uaShare),
			// dispWindow matches the counts: normally the 60s Window, but XHWindow
			// for a reclaimed-vhost cross-host-only finding whose solves/ips/subnets
			// were switched above — so a consumer computing solves/window gets the
			// right rate, not a ~30x over-read.
			"window": dispWindow.String(),
			// Corroboration only — never part of the threshold.
			"impossible_ua": fmt.Sprint(impossibleUA),
		},
	}
	// Which track(s) fired. The low-rate fingerprint-concentration evidence is
	// attached only when that track flagged, so an operator can tell a subnet-spread
	// farm from a single-fingerprint low-and-slow one.
	tracks := ""
	if hiRate {
		tracks = "subnet_spread"
	}
	alert.Extra["fp_track"] = "0"
	if loFP != "" {
		if tracks != "" {
			tracks += "+"
		}
		tracks += "fp_concentration"
		alert.Extra["fp_track"] = "1"
		alert.Extra["top_fp"] = loFP
		alert.Extra["fp_subnets"] = fmt.Sprint(loFPSubs)
		alert.Extra["fp_countries"] = fmt.Sprint(loFPCcs)
	}
	// Cross-host concentration evidence, attached only when that track flagged this
	// vhost. xh_solves_per_ip is EVIDENCE ONLY (the burn-in showed it does not
	// separate farm from legit) — never a threshold input.
	alert.Extra["xh_track"] = "0"
	if xh != nil {
		if tracks != "" {
			tracks += "+"
		}
		tracks += "cross_host"
		alert.Extra["xh_track"] = "1"
		alert.Extra["xh_fp"] = xh.fp
		alert.Extra["xh_hosts"] = fmt.Sprint(xh.hosts)
		alert.Extra["xh_countries"] = fmt.Sprint(xh.countries)
		alert.Extra["xh_subnets"] = fmt.Sprint(xh.subnets)
		alert.Extra["xh_host_share"] = fmt.Sprintf("%.0f%%", xh.hostShare*100)
		alert.Extra["xh_solves_per_ip"] = fmt.Sprintf("%.2f", xh.solvesPerIP)
	}
	alert.Extra["tracks"] = tracks
	// The caller decides notification and passes the verdict here: ACTION=logonly
	// mutes the section; the NotifyCooldown throttles a persistent farm's mail; a
	// CROSS-HOST-ONLY finding stays log-only through its burn-in. In every case the
	// detector-log record and the "farmed now" mark are unaffected — only the mail
	// is gated. (Per-host fp-concentration findings NOTIFY as of the 2026-09-11
	// promotion, subject only to the throttle.)
	if suppressNotify {
		alert.Extra[core.ExtraNotify] = core.NotifyNo
	}

	// The durable finding mirrors the alert's headline evidence, resolved to a
	// single fingerprint + spread (cross-host takes precedence over the per-host
	// concentration fp; a subnet-spread-only finding carries no fingerprint). This
	// is the structured record the fleet reputation store ingests.
	//
	// EVERY population field (solves, distinct_ips, subnets, countries, ips[]) must
	// describe the SAME set — the resolved fingerprint's solvers — or the row is
	// self-contradictory (distinct_subnets < distinct_countries, or distinct_ips >
	// solves, both impossible for one set of solvers). So each track overwrites the
	// vhost-wide defaults (dispSolves/dispIPs/dispSubnets) with the fp's own counts
	// at its own scope:
	//   - cross-host: the fp's NODE-WIDE counts (xh.solves/ips/subnets/countries) —
	//     the farm's true footprint across the dominated vhosts.
	//   - fp-concentration: the fp's counts ON THIS VHOST (fpSolveIPs(a.ips) for
	//     solves/distinct_ips, loFPSubs/loFPCcs for subnets/countries) — the fp's
	//     addresses only, never the vhost's whole solver set.
	// Both satisfy countries ≤ subnets ≤ distinct_ips ≤ solves, so the persisted row
	// is always self-consistent. A subnet-spread-only finding keeps the vhost counts
	// and carries no fingerprint (the fleet store skips it), so its scope is moot.
	finding := Finding{
		When: now, Host: host, Tracks: tracks,
		Solves: dispSolves, DistinctIPs: dispIPs, Subnets: dispSubnets,
		SolvesPerIP: solvesPerIP, Hosts: 1,
	}
	switch {
	case xh != nil:
		// Cross-host: every population field is the fp's NODE-WIDE value, so
		// solves ≥ distinct_ips and solves_per_ip describes the same set as the ips.
		finding.Fingerprint, finding.Countries = xh.fp, xh.countries
		finding.Solves, finding.DistinctIPs, finding.Subnets = xh.solves, xh.ips, xh.subnets
		finding.SolvesPerIP = xh.solvesPerIP
		finding.HostShare, finding.Hosts = xh.hostShare, xh.hosts
		finding.IPs = xh.ipSample // the fp's node-wide addresses
	case loFP != "":
		// Per-host: every population field is the fp's OWN value on this vhost (not
		// the vhost-wide totals), so the row is self-consistent and a block acts on
		// the fingerprint's addresses only.
		finding.Fingerprint, finding.Countries = loFP, loFPCcs
		finding.Subnets = loFPSubs
		if a := st.fps[loFP]; a != nil {
			fpSolves, fpIPs := fpSolveIPs(a.ips)
			finding.Solves, finding.DistinctIPs = fpSolves, fpIPs
			finding.SolvesPerIP = 0
			if fpIPs > 0 {
				finding.SolvesPerIP = float64(fpSolves) / float64(fpIPs)
			}
			finding.IPs = sampleKeys(a.ips, maxFindingIPs) // the fp's own addresses on this vhost
		}
	}
	// (A subnet-spread-only finding carries no fingerprint and leaves IPs empty —
	// the fleet store skips it, so there is nothing to attribute addresses to.)
	return alert, finding
}
