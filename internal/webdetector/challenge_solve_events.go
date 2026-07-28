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
func (s ChallengeSolve) InputEvent() core.InputEvent {
	return core.InputEvent{
		Source:    "challenge",
		Reason:    "CHALLENGE_SOLVED",
		Signal:    s.UAReason,
		Scope:     s.Host,
		SrcIP:     s.IP,
		Path:      s.URI,
		UserAgent: s.UA,
		Count:     1,
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
