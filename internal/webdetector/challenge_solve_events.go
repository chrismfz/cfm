package webdetector

import (
	"sync"

	core "cfm/internal/detectors/core"
)

// InputEvent adapts a solve to the detector framework's event shape. Scope
// carries the vhost (the key a solver-farm detector aggregates on) and SrcIP the
// solver, so a detector can measure how widely spread the solvers of one vhost
// are without knowing anything about the challenge internals.
//
// Signal carries the UA-plausibility verdict (empty when the UA is coherent), so
// a detector can report what share of a cluster submitted a self-contradictory
// User-Agent without re-parsing it.
//
// Fingerprint carries the client's TLS ClientHello id (TLSFP), the one signal a
// solve does not author (its stack emits the handshake before any HTTP). The
// solver-farm detector groups on it to spot a low-and-slow farm whose solvers
// span many subnets/countries but collapse onto a single fingerprint — a shape
// no diverse human audience produces. It is a group-by key, never matched to a
// value: a new tool with a new fingerprint trips the same shape.
//
// Humanity and CountryISO are evidence for the solver-farm finding (the hs
// distribution and country split of a flagged cluster), never a detection
// input. Humanity is filled only behind the HumanityScored gate, exactly like
// HumanitySuffix: a solve the Rung-1 scorer never saw carries nil, never a
// fabricated hs=0. HumanityNoPayload is set only by a scored verify, so the
// gate covers the hs=- case too. Only PASSED solves are published (a Rung-1
// reject returns before publishChallengeSolveEvent), so under an arm the
// failing population is not here: it is the challenge_v2_reject history rows.
func (s ChallengeSolve) InputEvent() core.InputEvent {
	var hs *core.Humanity
	if s.HumanityScored {
		hs = &core.Humanity{
			Score:     s.HumanityScore,
			Tells:     s.HumanityTells,
			NoPayload: s.HumanityNoPayload,
		}
	}
	return core.InputEvent{
		Source:      "challenge",
		Reason:      "CHALLENGE_SOLVED",
		Signal:      s.UAReason,
		Scope:       s.Host, // the aggregation key (the vhost), not s.Scope (the verify surface)
		SrcIP:       s.IP,
		Path:        s.URI,
		UserAgent:   s.UA,
		Fingerprint: s.TLSFP,
		CountryISO:  s.CountryISO,
		Humanity:    hs,
		Count:       1,
	}
}

var (
	solveSubsMu sync.RWMutex
	solveSubs   []func(ChallengeSolve)
)

// SubscribeChallengeSolveEvents registers a callback invoked for every solved
// challenge. Callbacks must be cheap and non-blocking — they run inline on the
// verify path, which is latency-sensitive; the solver-farm detector's callback
// only enqueues into its buffer.
func SubscribeChallengeSolveEvents(fn func(ChallengeSolve)) {
	if fn == nil {
		return
	}
	solveSubsMu.Lock()
	solveSubs = append(solveSubs, fn)
	solveSubsMu.Unlock()
}

// ResetChallengeSolveSubscribers drops every registered callback. The detectors
// manager calls it from stopAll, because a config reload tears down and
// re-instantiates every detector: without this the factory's Subscribe call adds
// a closure per reload, and the ones belonging to retired detectors keep
// enqueueing into a buffer whose RunOnce loop is gone — an unbounded leak that
// grows with reload count on a stream measured at ~100k solves/day. Reloads are
// routine: the config signature folds in each tailed log's inode, so a nightly
// logrotate forces one.
func ResetChallengeSolveSubscribers() {
	solveSubsMu.Lock()
	solveSubs = nil
	solveSubsMu.Unlock()
}

func publishChallengeSolveEvent(s ChallengeSolve) {
	solveSubsMu.RLock()
	subs := append([]func(ChallengeSolve){}, solveSubs...)
	solveSubsMu.RUnlock()
	for _, fn := range subs {
		fn(s)
	}
}
