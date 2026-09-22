package webdetector

// Under-Attack Mode — per-vhost challenge-efficacy detector (increment I1).
//
// The challenge engine arms a vhost and considers the job done; nobody closes
// the loop "did pressure actually drop?". When a solver farm defeats the
// challenge (real headless browsers + one-solve-per-exit proxies solving at tens
// of IPs/min), the flood continues *through* the challenge and the operator only
// finds out by reading logs. Under-Attack Mode is the missing state above
// CHALLENGED plus that feedback loop.
//
// I1 is DETECT-ONLY (ships behind UNDER_ATTACK, DRYRUN=1): it runs the state
// machine and emits a WEB/VHOST_UNDER_ATTACK_ON|OFF history + notification with
// an evidence one-liner, so the operator learns from an alert, not from logs.
// No enforcement — the in-state action ladder (harden / fingerprint / draft
// rule / nft) lands in later increments. See docs/under-attack-mode.md.
//
// Entry (§3), all true for CONFIRM_TICKS consecutive ticks, and only for a vhost
// the challenge layer already armed (UNDER_ATTACK is reachable ONLY from
// CHALLENGED — it never challenges a vhost the existing paths left alone):
//
//  1. challenge armed on the vhost (auto or manual)     — `challenged` arg
//  2. the challenge is being defeated: distinct solving  — solvesPerMin >= SolvesMin
//     IPs/min >= SOLVES_MIN (self-declared bots excluded)
//  3. pressure is sustained: uniqIP >= the arm threshold — row.UniqueIPs / ErrRatio
//     AND err_ratio >= ERR_FLOOR
//  4. the population claims to be human: bot_ratio ~= 0   — row.BotRatio <= BotCeil
//     while uniqIP is exploding (the inversion tell)
//
// Exit: leg 3 (pressure) false for HOLDDOWN -> back to CHALLENGED; the challenge
// itself clears (leg 1 false) -> immediate exit; or the operator fully suppresses
// the vhost (bypass/exclude/ignore) -> deescalateUnderAttack from the suppress
// site clears it.
//
// NOTE (leg 3, backend RT): the design's leg-3 clause is `err_ratio >= 0.5 OR
// backend RT >= 3x baseline`. No per-vhost backend-RT baseline is retained
// anywhere today (sumRT is dropped before the long window — engine.go, the
// procAvg comment), so I1 ships the err_ratio clause only. The reference
// incident (e-athlos) erred ~100%, and a melting backend almost always errors
// (timeouts -> 502/504/499), so err_ratio covers the common case; the RT clause
// (which additionally catches a slow-but-non-erroring backend) is a scoped
// follow-up that needs new RT-baseline plumbing. Tracked in docs/under-attack-mode.md.

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
)

const (
	// underAttackSolveWindow is the sliding window over which distinct solving
	// IPs are counted; 60s makes "distinct IPs in window" equal "distinct IPs/min".
	underAttackSolveWindow = 60 * time.Second
	// underAttackSolveIPCap bounds the distinct IPs held per vhost, so a
	// residential-rotation farm (thousands of one-solve IPs) can't grow the map
	// without bound between the periodic prunes. Far above any SOLVES_MIN, so the
	// leg-2 verdict is unaffected.
	underAttackSolveIPCap = 4096
	// underAttackConfirmResetGap: if a vhost is not evaluated for longer than
	// this, its pending confirm streak is stale (it fell out of the candidate set
	// and came back) and is reset, so entry always needs CONFIRM_TICKS *fresh*
	// consecutive ticks rather than resuming an old partial streak.
	underAttackConfirmResetGap = 5 * time.Minute
)

// underAttackSolves tracks distinct solving IPs per vhost over a sliding window,
// fed inline from the challenge solve-event stream (leg 2). Self-declared bot
// UAs are excluded at record time (§5): an honest crawler that happened to solve
// is not a farm node. Its own mutex — the record path (verify goroutine) and the
// read path (emit tick) are different goroutines.
type underAttackSolves struct {
	mu      sync.Mutex
	win     time.Duration
	perHost map[string]map[string]time.Time // host -> ip -> last solve seen
}

func newUnderAttackSolves(win time.Duration) *underAttackSolves {
	if win <= 0 {
		win = underAttackSolveWindow
	}
	return &underAttackSolves{win: win, perHost: make(map[string]map[string]time.Time)}
}

// record notes a solve by ip on host at now. Cheap: one map insert under lock
// (the callback runs inline on the latency-sensitive verify path). A per-host
// cap keeps the critical section — and the map — bounded even under a
// high-cardinality rotation attack; at the cap stale entries are pruned inline
// and, if still saturated, the new IP is dropped (the verdict is already firing).
func (s *underAttackSolves) record(host, ip string, now time.Time) {
	if s == nil || host == "" || ip == "" {
		return
	}
	s.mu.Lock()
	m := s.perHost[host]
	if m == nil {
		m = make(map[string]time.Time)
		s.perHost[host] = m
	}
	if _, exists := m[ip]; !exists && len(m) >= underAttackSolveIPCap {
		cutoff := now.Add(-s.win)
		for k, ts := range m {
			if ts.Before(cutoff) {
				delete(m, k)
			}
		}
		if len(m) >= underAttackSolveIPCap {
			s.mu.Unlock()
			return
		}
	}
	m[ip] = now
	s.mu.Unlock()
}

// ratePerMin returns the distinct solving IPs seen on host within the window
// ending at now, pruning stale entries for that host as it goes. The scan is
// bounded by underAttackSolveIPCap, so the lock is never held long against the
// verify-path record().
func (s *underAttackSolves) ratePerMin(host string, now time.Time) int {
	if s == nil {
		return 0
	}
	cutoff := now.Add(-s.win)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.perHost[host]
	if m == nil {
		return 0
	}
	for ip, ts := range m {
		if ts.Before(cutoff) {
			delete(m, ip)
		}
	}
	n := len(m)
	if n == 0 {
		delete(s.perHost, host)
	}
	// window == 1 min so distinct-in-window is already per-minute; scale if a
	// non-default window is ever configured.
	if s.win != time.Minute {
		return int(float64(n) * float64(time.Minute) / float64(s.win))
	}
	return n
}

// prune drops stale IPs and empty hosts across all vhosts (memory guard, called
// from pruneEmitMaps).
func (s *underAttackSolves) prune(now time.Time) {
	if s == nil {
		return
	}
	cutoff := now.Add(-s.win)
	s.mu.Lock()
	for host, m := range s.perHost {
		for ip, ts := range m {
			if ts.Before(cutoff) {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(s.perHost, host)
		}
	}
	s.mu.Unlock()
}

// attackVhost is the per-vhost under-attack state.
type attackVhost struct {
	on         bool
	since      time.Time
	confirm    int       // consecutive qualifying ticks toward entry
	belowFloor time.Time // when pressure first dropped below floor; zero = not below
	lastEval   time.Time // last tick this vhost reached evalUnderAttack
	// override: 0 none, +1 forced on (operator `attack on`), -1 forced off
	// (`attack off`: leave + suppress re-entry until suppressUntil).
	override int8
	// overrideExpires bounds a forced-ON override: past it the override
	// clears back to AUTO control (evalUnderAttack tick; the read path
	// honours it too). Zero = no bound (admin override). Scoped callers get
	// a 24h ceiling, mirroring the scoped manual-challenge TTL cap
	// (slice-D residual, resolved by operator decision 2026-09-22).
	overrideExpires time.Time
	suppressUntil   time.Time
	evidence      string // last transition's evidence (kept consistent with `on`)
}

// underAttackTracker holds the per-vhost state machine and the solve-rate feed.
// Self-contained (own mutex), mirroring subnetGoodBotState.
type underAttackTracker struct {
	mu     sync.Mutex
	hosts  map[string]*attackVhost
	solves *underAttackSolves
}

func newUnderAttackTracker() *underAttackTracker {
	return &underAttackTracker{
		hosts:  make(map[string]*attackVhost),
		solves: newUnderAttackSolves(underAttackSolveWindow),
	}
}

// prune drops idle host states (off, no override, past any suppression) and
// stale solve entries. Idle entries are dropped regardless of a leftover confirm
// streak so a vhost that briefly qualified then vanished does not leak.
func (t *underAttackTracker) prune(now time.Time) {
	if t == nil {
		return
	}
	t.solves.prune(now)
	t.mu.Lock()
	for host, st := range t.hosts {
		if !st.on && st.override == 0 && now.After(st.suppressUntil) {
			delete(t.hosts, host)
		}
	}
	t.mu.Unlock()
}

// activeHosts returns vhosts currently ON or under an operator override, so the
// emit loop keeps evaluating them (and can de-escalate) even after their traffic
// drops out of the short/long candidate sets.
func (t *underAttackTracker) activeHosts() []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for host, st := range t.hosts {
		if st.on || st.override != 0 {
			out = append(out, host)
		}
	}
	return out
}

// underAttackHosts returns, in a single locked pass, the vhosts that are
// EFFECTIVELY under attack — the same truth VhostAttackState reports: an
// operator `on` override (override==+1), or the auto state (st.on) when not
// overridden. A forced-off override (override==-1) is excluded even if st.on.
// Callers that need the count (handleChallengeSummary) use this instead of
// activeHosts()+VhostAttackState (N+1 lock acquisitions over a set that can
// shift between them); activeHosts() keeps its wider "on OR any override"
// membership because the emit loop must also re-evaluate forced-off hosts.
func (t *underAttackTracker) underAttackHosts() []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for host, st := range t.hosts {
		if st == nil {
			continue
		}
		if st.override == +1 || (st.override == 0 && st.on) {
			out = append(out, host)
		}
	}
	return out
}

// RecordUnderAttackSolve feeds the solve-rate tracker from the challenge solve
// stream (subscribed in the webdetector register when UNDER_ATTACK is on).
// Nil-safe and cheap; self-declared bot UAs are excluded (§5).
func (e *Engine) RecordUnderAttackSolve(s ChallengeSolve) {
	if e == nil || e.attack == nil {
		return
	}
	if isBotUA(s.UA) {
		return // an honest crawler that solved is not a farm node
	}
	e.attack.solves.record(s.Host, s.IP, time.Now())
}

// underAttackUniqFloor is "the arm threshold" leg 3 refers to: the uniqIP level
// that already arms the vhost challenge.
func (e *Engine) underAttackUniqFloor() int {
	if e.cfg.ChallengeSuspiciousUniqIPOn > 0 {
		return e.cfg.ChallengeSuspiciousUniqIPOn
	}
	if e.cfg.ChallengeSuspiciousMinUniqIP > 0 {
		return e.cfg.ChallengeSuspiciousMinUniqIP
	}
	return 300 // conservative fallback; a real flood is far above this
}

// attackTransition is a pending enter/leave decided under the tracker lock and
// emitted after it is released (no history/notify I/O under the mutex).
type attackTransition struct {
	on       bool
	evidence string
	mode     string // "auto" | "manual" — recorded in history/notify
}

// evalUnderAttack runs the per-vhost state machine for one tick. Called from
// emitIPChallenges right after `challenged` (== the vhost's effective challenge
// state) is known, so the "reachable only from CHALLENGED" invariant holds.
// row carries the per-vhost long-window pressure metrics (uniqIP/err/bot).
func (e *Engine) evalUnderAttack(now time.Time, host string, challenged bool, row SuspiciousRow, out chan<- core.Alert) {
	t := e.attack
	if t == nil || host == "" {
		return
	}

	solves := t.solves.ratePerMin(host, now)
	pressure := row.UniqueIPs >= e.underAttackUniqFloor() && row.ErrRatio >= e.cfg.UnderAttackErrFloor
	qualifies := challenged &&
		solves >= e.cfg.UnderAttackSolvesMin &&
		pressure &&
		row.BotRatio <= e.cfg.UnderAttackBotCeil

	t.mu.Lock()
	st := t.hosts[host]
	if st == nil {
		st = &attackVhost{}
		t.hosts[host] = st
	}

	// A long gap since the last evaluation means a pending confirm streak is
	// stale (the vhost fell out of the candidate set and came back) — reset it so
	// entry always needs CONFIRM_TICKS *fresh* consecutive ticks.
	if !st.on && !st.lastEval.IsZero() && now.Sub(st.lastEval) > underAttackConfirmResetGap {
		st.confirm = 0
	}
	st.lastEval = now

	// An `attack off` suppression that has served its holddown expires back to
	// auto control.
	if st.override == -1 && !now.Before(st.suppressUntil) {
		st.override = 0
	}
	// A TTL-bounded forced-ON override (scoped caller) that has served its
	// window expires back to auto control: st.on stays true, so the vhost
	// leaves UNDER_ATTACK via the normal exit rules on the following ticks
	// rather than dropping the shield mid-attack.
	if st.override == +1 && !st.overrideExpires.IsZero() && !now.Before(st.overrideExpires) {
		st.override = 0
		st.overrideExpires = time.Time{}
	}

	var trans *attackTransition

	switch {
	case st.override == +1:
		// Operator forced ON: enter (once) and hold until the override clears.
		if !st.on {
			st.on, st.since, st.belowFloor = true, now, time.Time{}
			st.evidence = "operator forced (attack on)"
			trans = &attackTransition{on: true, evidence: st.evidence, mode: "manual"}
		}

	case st.override == -1:
		// Operator forced OFF: leave (once) and suppress re-entry for the holddown.
		if st.on {
			st.on, st.confirm, st.belowFloor = false, 0, time.Time{}
			st.evidence = "operator cleared (attack off)"
			trans = &attackTransition{on: false, evidence: st.evidence, mode: "manual"}
		} else {
			st.confirm = 0
		}

	case !st.on:
		// Entry path: qualify for CONFIRM_TICKS consecutive ticks.
		if qualifies {
			st.confirm++
			if st.confirm >= e.cfg.UnderAttackConfirmTicks {
				st.on, st.since, st.belowFloor = true, now, time.Time{}
				st.evidence = underAttackEvidence(solves, row)
				trans = &attackTransition{on: true, evidence: st.evidence, mode: "auto"}
			}
		} else {
			st.confirm = 0
		}

	default:
		// Currently ON: exit logic.
		switch {
		case !challenged:
			// The challenge itself cleared — cannot be under attack any longer.
			st.on, st.confirm, st.belowFloor = false, 0, time.Time{}
			st.evidence = "challenge cleared"
			trans = &attackTransition{on: false, evidence: st.evidence, mode: "auto"}
		case pressure:
			st.belowFloor = time.Time{} // pressure back up; reset the exit clock
		default:
			if st.belowFloor.IsZero() {
				st.belowFloor = now
			}
			if now.Sub(st.belowFloor) >= e.cfg.UnderAttackHolddown {
				st.on, st.confirm, st.belowFloor = false, 0, time.Time{}
				st.evidence = fmt.Sprintf("pressure below floor for %s", e.cfg.UnderAttackHolddown)
				trans = &attackTransition{on: false, evidence: st.evidence, mode: "auto"}
			}
		}
	}
	t.mu.Unlock()

	if trans != nil {
		e.emitUnderAttack(now, host, trans.on, row, solves, trans.evidence, trans.mode, out)
	}
}

// deescalateUnderAttack force-exits an active under-attack state for a host the
// emit loop has just determined is no longer challenged at all — the genuine
// full-suppression sites (cfm.allow bypass, or exclude/ignore with no manual
// challenge keeping it) that `continue` before the main hook. Called from those
// sites with the loop's own decision, so it never fires for a vhost still
// challenged by an alternate branch (uniqpaths, or a kept manual challenge).
// No-op when the host has no active state.
func (e *Engine) deescalateUnderAttack(now time.Time, host, reason string, out chan<- core.Alert) {
	t := e.attack
	if t == nil || host == "" {
		return
	}
	t.mu.Lock()
	st := t.hosts[host]
	if st == nil || (!st.on && st.override == 0) {
		if st != nil {
			st.lastEval = now
		}
		t.mu.Unlock()
		return
	}
	mode := "auto"
	if st.override != 0 {
		mode = "manual"
	}
	wasOn := st.on
	if st.on {
		st.on, st.belowFloor = false, time.Time{}
		st.evidence = reason
	}
	// A full suppression drops any operator override too (cfm.allow is absolute;
	// exclude/ignore here already lost their manual-challenge tie-break).
	st.override = 0
	st.confirm = 0
	st.lastEval = now
	t.mu.Unlock()

	if wasOn {
		e.emitUnderAttack(now, host, false, SuspiciousRow{Host: host}, 0, reason, mode, out)
	}
}

// underAttackEvidence renders the operator one-liner recorded on entry.
func underAttackEvidence(solves int, row SuspiciousRow) string {
	return fmt.Sprintf("challenge defeated: %d solving IPs/min; uniqIP=%d err=%.0f%% bot=%.0f%%",
		solves, row.UniqueIPs, row.ErrRatio*100, row.BotRatio*100)
}

// emitUnderAttack writes the durable history event and the operator
// notification for an enter/leave transition. Called with the tracker unlocked.
// mode ("auto"|"manual") records whether the transition was detector- or
// operator-driven.
func (e *Engine) emitUnderAttack(now time.Time, host string, on bool, row SuspiciousRow, solves int, evidence, mode string, out chan<- core.Alert) {
	typ, kind, action := "vhost_under_attack_off", "WEB/VHOST_UNDER_ATTACK_OFF", "attack_off"
	if on {
		typ, kind, action = "vhost_under_attack_on", "WEB/VHOST_UNDER_ATTACK_ON", "attack_on"
	}

	// dryrun is logged for operator visibility of the posture. In I1 it does not
	// change behaviour (there is no enforcement yet); it will gate the enforcement
	// ladder in later increments via Extra["enforcement"]="dryrun" (see below).
	logging.LogfCHALLENGES("[challenge][vhost] under_attack=%v host=%s mode=%s dryrun=%v %s", on, host, mode, e.cfg.UnderAttackDryRun, evidence)

	e.appendHistory(HistoryEvent{
		TsUnix: now.Unix(),
		Type:   typ,
		Host:   host,
		Mode:   mode,
		Reason: evidence,
		UniqIP: row.UniqueIPs,
		RPS:    row.RPS,
	})

	if out == nil {
		return
	}
	// I1 is detect-only, so there is no enforcement to gate here. When the
	// enforcement ladder lands (I3+), a dry-run action must be flagged with
	// Extra["enforcement"]="dryrun" — the exact key the section sink honours
	// (autoblock_sink.go; wafsec uses the same) — NOT an ad-hoc key.
	a := core.Alert{
		When:  now,
		Kind:  core.AlertKind(kind),
		Key:   host,
		Count: row.UniqueIPs,
		Extra: map[string]string{
			"host":           host,
			"action":         action,
			"mode":           mode,
			"reason":         evidence,
			"solves_per_min": strconv.Itoa(solves),
			// Key is the vhost; tell the sink not to scrape an IP out of samples.
			core.ExtraIPScope: core.IPScopeHost,
		},
	}
	select {
	case out <- a:
	default:
	}
}

// SetVhostAttackOverride forces a vhost's under-attack state. on=true forces it
// ON (operator `attack on`); on=false leaves it and suppresses auto re-entry for
// the holddown measured from now (`attack off` always wins). This records the
// intent only; the next evalUnderAttack tick actuates the flip and emits the
// transition — and activeHosts() keeps the vhost in the candidate set until then,
// so the tick runs even with no traffic. Surfaced via
// `cfm webtop attack on|off <vhost>` (increment I1b); callers pass time.Now().
//
// ttl bounds a forced-ON override: past now+ttl the override expires back to
// AUTO control (so an armed vhost leaves UNDER_ATTACK by the normal exit
// rules). ttl <= 0 means unbounded (admin). A scoped caller's override is
// TTL-bound like its panic-button arm — the API handler passes the 24h
// ceiling. ttl is ignored for on=false (the holddown already bounds it).
func (e *Engine) SetVhostAttackOverride(host string, on bool, now time.Time, ttl time.Duration) {
	if e == nil || e.attack == nil || host == "" {
		return
	}
	t := e.attack
	t.mu.Lock()
	st := t.hosts[host]
	if st == nil {
		st = &attackVhost{}
		t.hosts[host] = st
	}
	if on {
		st.override = +1
		if ttl > 0 {
			st.overrideExpires = now.Add(ttl)
		} else {
			st.overrideExpires = time.Time{}
		}
	} else {
		st.override = -1
		st.overrideExpires = time.Time{}
		st.suppressUntil = now.Add(e.cfg.UnderAttackHolddown)
	}
	t.mu.Unlock()
}

// VhostAttackState reports whether a vhost is currently in UNDER_ATTACK, since
// when, and the last transition's evidence line (kept consistent with `on`).
// Read path for the surfaces (I1b). An operator override is reflected
// immediately — a just-issued `attack on|off` sets only the intent (the auto
// state flips on the next tick), so honouring the override here keeps the
// surfaces consistent with the operator's action without waiting a tick.
func (e *Engine) VhostAttackState(host string) (on bool, since time.Time, evidence string) {
	if e == nil || e.attack == nil || host == "" {
		return false, time.Time{}, ""
	}
	t := e.attack
	t.mu.Lock()
	defer t.mu.Unlock()
	if st := t.hosts[host]; st != nil {
		switch st.override {
		case +1:
			// An expired TTL-bounded override reads as AUTO immediately —
			// don't wait for the tick to clear it (the tick still owns the
			// actual state transition).
			if !st.overrideExpires.IsZero() && !time.Now().Before(st.overrideExpires) {
				return st.on, st.since, st.evidence
			}
			return true, st.since, st.evidence
		case -1:
			return false, st.since, st.evidence
		}
		return st.on, st.since, st.evidence
	}
	return false, time.Time{}, ""
}
