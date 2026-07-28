package webdetector

import (
	"sync"

	core "cfm/internal/detectors/core"
)

// InputEvent adapts a solve to the detector framework's event shape. Scope
// carries the vhost (the key a solver-farm detector aggregates on) and SrcIP the
// solver, so a detector can measure how widely spread the solvers of one vhost
// are without knowing anything about the challenge internals.
func (s ChallengeSolve) InputEvent() core.InputEvent {
	return core.InputEvent{
		Source:    "challenge",
		Reason:    "CHALLENGE_SOLVED",
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

func publishChallengeSolveEvent(s ChallengeSolve) {
	solveSubsMu.RLock()
	subs := append([]func(ChallengeSolve){}, solveSubs...)
	solveSubsMu.RUnlock()
	for _, fn := range subs {
		fn(s)
	}
}
