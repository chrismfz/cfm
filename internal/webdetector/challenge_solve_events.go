package webdetector

import (
	"sync"
	"time"

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

// WithheldInputEvent is InputEvent for a WITHHELD solve (the withheld stream,
// SubscribeChallengeWithheldEvents): Reason CHALLENGE_WITHHELD, so evidence
// built from it never reads as a client that cleared the vhost.
func (s ChallengeSolve) WithheldInputEvent() core.InputEvent {
	ev := s.InputEvent()
	ev.Reason = "CHALLENGE_WITHHELD"
	return ev
}

// withheldOnce publishes a withheld solve once per (ip, host) per
// withheldDedupTTL. A withheld client gets no cookie, so a farm exit that
// comes back pre-solves again on every visit, where the cookie used to spare
// it the repeat for its lifetime (60m, the default clearance TTL). Counting
// each repeat would lift the solver-farm finding's solves-per-IP — the
// documented farm tell, ~1.0 for a farm — toward a returning human audience's.
// Full store: putIfAbsent reads "seen", so a flood publishes less, never more.
const withheldDedupTTL = 60 * time.Minute

var withheldOnce = pairTTLStore[struct{}]{
	m:          map[string]time.Time{},
	ttl:        withheldDedupTTL,
	maxKeys:    50000,
	sweepEvery: 5 * time.Second,
	fullMsg:    "[challenge] withheld-solve dedup store full (%d): repeat withheld solves are not re-published until pressure drops",
}

var (
	solveSubsMu sync.RWMutex
	solveSubs   []func(ChallengeSolve)
	// withheldSubs hear the WITHHELD solves (SubscribeChallengeWithheldEvents);
	// guarded by solveSubsMu with solveSubs.
	withheldSubs []func(ChallengeSolve)
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
	withheldSubs = nil
	solveSubsMu.Unlock()
}

// SubscribeChallengeWithheldEvents registers a callback for every WITHHELD
// solve: a valid PoW under the unsolicited grain (v2=unsolicited, no challenge
// covered the client) that failed Rung 1, so it got no cookie and was sent on
// to next (challenge_server.go). Same contract as SubscribeChallengeSolveEvents
// (cheap, non-blocking, inline on verify; dropped by
// ResetChallengeSolveSubscribers).
//
// A separate stream, not the solve stream: a withheld solve cleared nothing,
// so the subscribers that read "this client now holds clearance" must not see
// it (challenge_cookie_discard would read a client that never got a cookie as
// one that threw it away). Evidence readers that count WHO solves — the
// solver-farm detector and the challenge_score shadow scorer — subscribe to
// both. Published once per (ip, host) per withheldDedupTTL (withheldOnce). Until 2026-11-18 these solves took
// the solved path unarmed and reached the solver-farm detector anyway: the
// farms' pre-solves on fresh IPs are the very traffic it convicts.
func SubscribeChallengeWithheldEvents(fn func(ChallengeSolve)) {
	if fn == nil {
		return
	}
	solveSubsMu.Lock()
	withheldSubs = append(withheldSubs, fn)
	solveSubsMu.Unlock()
}

func publishChallengeWithheldEvent(s ChallengeSolve) {
	if !withheldOnce.putIfAbsent(challengeV2MarkKey(s.IP, s.Host), struct{}{}, time.Now()) {
		return // this client's withheld solve on this host is already counted
	}
	solveSubsMu.RLock()
	subs := append([]func(ChallengeSolve){}, withheldSubs...)
	solveSubsMu.RUnlock()
	for _, fn := range subs {
		fn(s)
	}
}

func publishChallengeSolveEvent(s ChallengeSolve) {
	solveSubsMu.RLock()
	subs := append([]func(ChallengeSolve){}, solveSubs...)
	solveSubsMu.RUnlock()
	for _, fn := range subs {
		fn(s)
	}
}
