package webdetector

// Unsolved-challenge hold: a per-IP challenge that its client keeps loading
// and never solves does not run out.
//
// Why (titan, 2026-11-24): a scraper on Greek residential and academic IPs
// (one Chrome/152 UA, WooCommerce facet URLs) tripped the per-IP
// CHALLENGE_UNIQPATHS_IP challenge on a few of its addresses. While it lived,
// the address reached the origin with 0 pages; it fetched the challenge page
// ~80 times a minute and solved none. Then the 20m TTL ran out, and
// CHALLENGE_COOLDOWN (45m) kept the rules from challenging it again: one
// address went back to ~700 pages per 5 minutes for over an hour. A person
// solves a challenge in a second or two; a client that loads it again and
// again without solving is not one, and there is nothing to wait out for it.
//
// What: each challenge PAGE served (web scope) to an IP that holds a live
// per-IP challenge counts as an unsolved view. CHALLENGE_UNSOLVED_HOLD_VIEWS
// views within CHALLENGE_UNSOLVED_HOLD_WINDOW, with no solve in between, hold
// that challenge for CHALLENGE_UNSOLVED_HOLD_TTL from now (renewed each time
// the views come in again, never shortened, never over a block), for at most
// CHALLENGE_UNSOLVED_HOLD_MAX from the hold's first renewal. The hold rides on
// the entry's HoldUntil floor (withMalpathHoldLocked), so a detector's
// shorter re-challenge over it cannot cut it short. It keeps the entry's
// reason and WAF rule id; it adds no v2 mark and revokes no clearance (that is
// the malpath hold's job, challenge_v2_paths_ban.go).
//
// What it never does: start a challenge. It only extends a per-IP challenge
// that is already live; a client under a vhost challenge alone (no per-IP
// entry) is not counted, nor is a cleared or exempt client (they are sent to
// next before the page). Anyone on the address who can solve gets through:
// a solve (ClearIPScoped, any scope) ends the hold and the count, as does a
// manual clear. KNOWN LIMIT: a solve deletes the address's per-IP challenge
// for every client on it (pre-existing ClearIP behaviour), so on a shared
// address (a university or CGNAT egress) one person solving also releases a
// scraper there; the exit contract counts those solves. The cost of a wrong hold is the challenge the address already had,
// for longer, until someone there solves it.
//
// CHALLENGE_UNSOLVED_HOLD = log (default) writes `[challenge] unsolved_hold
// verdict=would_hold` and extends nothing; enforce holds; off counts nothing.
// The holds survive a config reload (unsolvedHolds, restored by
// RestoreUnsolvedHolds), not a daemon restart.

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/logging"
)

const (
	unsolvedHoldOff = iota
	unsolvedHoldLog
	unsolvedHoldEnforce
)

type unsolvedHoldConfig struct {
	Mode   int
	Views  int
	Window time.Duration
	TTL    time.Duration
	Max    time.Duration
}

// Defaults, and the bounds ConfigureChallengeUnsolvedHold clamps to.
const (
	unsolvedHoldDefaultViews  = 20
	unsolvedHoldDefaultWindow = 10 * time.Minute
	unsolvedHoldDefaultTTL    = time.Hour
	unsolvedHoldDefaultMax    = 24 * time.Hour

	unsolvedHoldMaxIPs     = 8192            // counted IPs; at the cap a new IP is not counted
	unsolvedHoldLogEvery   = 5 * time.Minute // one log line per IP per this, plus the first
	unsolvedHoldMinViews   = 5               // below this a person reloading could reach it
	unsolvedHoldMaxViewCfg = 10000
)

var unsolvedHoldCfg atomic.Pointer[unsolvedHoldConfig]

func init() {
	unsolvedHoldCfg.Store(&unsolvedHoldConfig{
		Mode:   unsolvedHoldLog,
		Views:  unsolvedHoldDefaultViews,
		Window: unsolvedHoldDefaultWindow,
		TTL:    unsolvedHoldDefaultTTL,
		Max:    unsolvedHoldDefaultMax,
	})
}

// ConfigureChallengeUnsolvedHold applies [webdetector] CHALLENGE_UNSOLVED_HOLD
// (off | log | enforce; anything else is log) and its _VIEWS / _WINDOW / _TTL
// / _MAX knobs (every reload). Out-of-range values are clamped: VIEWS to
// [5, 10000], WINDOW to [1m, 1h], TTL to [5m, 24h], MAX to [TTL, 7d].
func ConfigureChallengeUnsolvedHold(mode string, views int, window, ttl, max time.Duration) {
	c := unsolvedHoldConfig{Mode: unsolvedHoldLog, Views: views, Window: window, TTL: ttl, Max: max}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "off", "0", "no", "false":
		c.Mode = unsolvedHoldOff
	case "enforce", "on", "1", "yes", "true":
		c.Mode = unsolvedHoldEnforce
	}
	if c.Views < unsolvedHoldMinViews {
		c.Views = unsolvedHoldMinViews
	}
	if c.Views > unsolvedHoldMaxViewCfg {
		c.Views = unsolvedHoldMaxViewCfg
	}
	c.Window = clampDur(c.Window, time.Minute, time.Hour)
	c.TTL = clampDur(c.TTL, 5*time.Minute, 24*time.Hour)
	c.Max = clampDur(c.Max, c.TTL, 7*24*time.Hour)
	unsolvedHoldCfg.Store(&c)
}

func clampDur(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

func unsolvedHoldModeName(m int) string {
	switch m {
	case unsolvedHoldOff:
		return "off"
	case unsolvedHoldEnforce:
		return "enforce"
	}
	return "log"
}

type unsolvedViewState struct {
	winStart  time.Time // the current count's first view
	views     int       // views since winStart
	holdStart time.Time // the current hold episode's first renewal (zero: none)
	holdUntil time.Time // the hold's end (enforce) or what it would be (log)
	lastLog   time.Time
}

// unsolvedViews counts per firewall.CountKey (an IPv6 client is its /64, so
// rotating the address does not reset the count; CLAUDE.md §5). The hold
// itself extends ONLY the ipState entry of the address that crossed: a
// sibling address of the /64 with its own live per-IP challenge keeps that
// challenge's TTL (it is held when it crosses in turn; the per-IP challenges
// are per address to begin with). A solve or clear on any address of the /64
// starts its count over.
var unsolvedViews = struct {
	mu        sync.Mutex
	m         map[string]*unsolvedViewState
	lastPrune time.Time
}{m: make(map[string]*unsolvedViewState)}

const unsolvedHoldPruneEvery = 30 * time.Second

// unsolvedHoldEntry is what a stored hold restores: the entry's reason and
// WAF rule id (the solved hook and the history read both).
type unsolvedHoldEntry struct {
	Reason    string
	WAFRuleID int
}

// unsolvedHolds remembers the live holds by IP (value: the entry's reason and
// rule id),
// outside any one bridge: a config reload builds a new bridge with an empty
// ipState, and the hold must not be waited out through one.
var unsolvedHolds = pairTTLStore[unsolvedHoldEntry]{
	m:       map[string]time.Time{},
	vals:    map[string]unsolvedHoldEntry{},
	ttl:     time.Minute,
	maxKeys: unsolvedHoldMaxIPs,
	fullMsg: "[challenge] unsolved hold store full (%d) — new holds do not survive a config reload",
}

// UnsolvedHold is NoteUnsolvedChallengeView's answer (for tests and callers
// that log).
type UnsolvedHold struct {
	Counted bool      // the view was counted (a live per-IP challenge, mode not off)
	Views   int       // views in the current count, this one included
	Hold    bool      // this view reached the threshold (held, or would have)
	Until   time.Time // the hold's end
	Held    bool      // the hold is on the bridge entry (enforce)
	Capped  bool      // held, but MAX left nothing to extend
}

// NoteUnsolvedChallengeView counts one challenge page served to ip (web
// scope) and, at the threshold, holds its per-IP challenge (enforce) or logs
// that it would (log). host is for the log line only.
func (b *NginxBridge) NoteUnsolvedChallengeView(ip, host string, now time.Time) UnsolvedHold {
	cfg := unsolvedHoldCfg.Load()
	ip = strings.TrimSpace(ip)
	if b == nil || !b.cfg.Enabled || cfg == nil || cfg.Mode == unsolvedHoldOff || ip == "" {
		return UnsolvedHold{}
	}
	if b.bypassed(ip) {
		return UnsolvedHold{}
	}
	b.mu.RLock()
	cur, ok := b.ipState[ip]
	b.mu.RUnlock()
	if !ok || cur.Action != "challenge" || !cur.Expires.After(now) {
		return UnsolvedHold{}
	}

	key := firewall.CountKey(ip)
	unsolvedViews.mu.Lock()
	st := unsolvedViews.m[key]
	if st == nil {
		if len(unsolvedViews.m) >= unsolvedHoldMaxIPs {
			// At most one sweep per unsolvedHoldPruneEvery: a full map that
			// frees nothing must not cost every new IP a full scan.
			if now.Sub(unsolvedViews.lastPrune) >= unsolvedHoldPruneEvery {
				unsolvedViews.lastPrune = now
				pruneUnsolvedViewsLocked(now, cfg)
			}
			if len(unsolvedViews.m) >= unsolvedHoldMaxIPs {
				unsolvedViews.mu.Unlock()
				return UnsolvedHold{}
			}
		}
		st = &unsolvedViewState{winStart: now}
		unsolvedViews.m[key] = st
	}
	if now.Sub(st.winStart) > cfg.Window {
		st.winStart, st.views = now, 0
	}
	st.views++
	out := UnsolvedHold{Counted: true, Views: st.views}
	if st.views < cfg.Views {
		unsolvedViews.mu.Unlock()
		return out
	}
	// The threshold: renew the hold and start the next count, so a client that
	// keeps loading the page renews it every cfg.Views views.
	st.winStart, st.views = now, 0
	if st.holdStart.IsZero() || !st.holdUntil.After(now) {
		st.holdStart = now // a new episode (none yet, or the last one ran out)
	}
	until := now.Add(cfg.TTL)
	if capAt := st.holdStart.Add(cfg.Max); until.After(capAt) {
		until = capAt
	}
	// Nothing left to extend: MAX clamped this renewal to an end the episode
	// already had. Known here in log mode too, so the burn-in shows the cap.
	capped := !until.After(st.holdUntil)
	if until.After(st.holdUntil) {
		st.holdUntil = until
	}
	logIt := st.lastLog.IsZero() || now.Sub(st.lastLog) >= unsolvedHoldLogEvery
	if logIt {
		st.lastLog = now
	}
	holdStart := st.holdStart
	unsolvedViews.mu.Unlock()

	out.Hold, out.Until = true, until
	if cfg.Mode == unsolvedHoldEnforce {
		var extended bool
		out.Held, extended = b.holdUnsolvedIPChallenge(ip, until, now)
		out.Capped = out.Held && !extended
	} else {
		out.Capped = capped
	}
	if logIt {
		verdict := "would_hold"
		if out.Capped && cfg.Mode != unsolvedHoldEnforce {
			verdict = "would_hold_capped"
		} else if out.Capped {
			verdict = "hold_capped" // MAX reached: the hold ends at until
		} else if out.Held {
			verdict = "hold"
		} else if cfg.Mode == unsolvedHoldEnforce {
			verdict = "not_held" // the entry changed under us (a solve, a block)
		}
		logging.LogfCHALLENGES("[challenge] unsolved_hold verdict=%s mode=%s ip=%s host=%s views=%d window=%s until=%s hold_since=%s reason=%q note=challenge_loaded_not_solved",
			verdict, unsolvedHoldModeName(cfg.Mode), ip, truncateForLog(host, 120), cfg.Views, cfg.Window,
			until.Format(time.RFC3339), holdStart.Format(time.RFC3339), truncateForLog(cur.Reason, 120))
	}
	return out
}

// holdUnsolvedIPChallenge extends ip's live per-IP challenge to at least
// until (Expires and the HoldUntil floor). It never starts a challenge and
// never touches a block. It answers whether the entry is held, and whether
// this call moved its end (false once MAX caps the hold).
func (b *NginxBridge) holdUnsolvedIPChallenge(ip string, until, now time.Time) (held, extended bool) {
	b.mu.Lock()
	cur, ok := b.ipState[ip]
	if !ok || cur.Action != "challenge" || !cur.Expires.After(now) {
		b.mu.Unlock()
		return false, false
	}
	before := cur.Expires
	if until.After(cur.HoldUntil) {
		cur.HoldUntil = until
	}
	cur = b.withMalpathHoldLocked(ip, cur, now) // floors Expires on HoldUntil
	b.ipState[ip] = cur
	saved := unsolvedHoldEntry{Reason: cur.Reason, WAFRuleID: cur.WAFRuleID}
	b.mu.Unlock()
	unsolvedHolds.putFor(ip, saved, now, until.Sub(now))
	return true, cur.Expires.After(before)
}

// pruneUnsolvedViewsLocked drops counts that can no longer reach the
// threshold and whose hold has ended. Caller holds unsolvedViews.mu.
func pruneUnsolvedViewsLocked(now time.Time, cfg *unsolvedHoldConfig) {
	for k, v := range unsolvedViews.m {
		if now.Sub(v.winStart) > cfg.Window && !v.holdUntil.After(now) {
			delete(unsolvedViews.m, k)
		}
	}
}

// endUnsolvedHold ends ip's count and hold outside the bridge entry (a web
// solve, a manual clear: the entry itself is deleted by the caller).
func endUnsolvedHold(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	key := firewall.CountKey(ip)
	unsolvedViews.mu.Lock()
	delete(unsolvedViews.m, key)
	unsolvedViews.mu.Unlock()
	unsolvedHolds.delete(ip)
}

// RestoreUnsolvedHolds re-imposes the live unsolved-challenge holds on this
// bridge after a config reload (the detectors' webdetector wiring, after the
// IGNORE bypass is set). An IP the bridge now bypasses is forgotten. Only in
// enforce mode: a hold written under enforce and then switched to log or off
// is dropped. It answers how many it restored.
func (b *NginxBridge) RestoreUnsolvedHolds() int {
	if b == nil || !b.cfg.Enabled {
		return 0
	}
	cfg := unsolvedHoldCfg.Load()
	now := time.Now()
	live := unsolvedHolds.live(now)
	if cfg == nil || cfg.Mode != unsolvedHoldEnforce {
		for ip := range live {
			endUnsolvedHold(ip)
		}
		return 0
	}
	n := 0
	for ip, until := range live {
		if b.bypassed(ip) {
			endUnsolvedHold(ip)
			continue
		}
		saved, _ := unsolvedHolds.get(ip, now)
		b.mu.Lock()
		cur, ok := b.ipState[ip]
		if ok && cur.Expires.After(now) && cur.Action != "challenge" {
			b.mu.Unlock() // a block (or other action) owns the IP now
			continue
		}
		e := bridgeIPEntry{Action: "challenge", Expires: until, Reason: saved.Reason, WAFRuleID: saved.WAFRuleID, HoldUntil: until}
		if ok && cur.Action == "challenge" && cur.Expires.After(now) {
			if cur.Reason != "" || cur.WAFRuleID != 0 {
				e.Reason, e.WAFRuleID = cur.Reason, cur.WAFRuleID
			}
			// Never shorten a live challenge the fresh bridge already has (a
			// malpath hold restored just before, or a longer challenge).
			if cur.Expires.After(e.Expires) {
				e.Expires = cur.Expires
			}
		}
		b.ipState[ip] = b.withMalpathHoldLocked(ip, e, now)
		b.mu.Unlock()
		n++
	}
	return n
}
