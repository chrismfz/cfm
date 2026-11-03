package core

import "time"

// InputEvent is a generic detector input envelope for non-log sources.
type InputEvent struct {
	When      time.Time
	Source    string
	Reason    string
	Signal    string
	Scope     string
	Count     int
	SrcIP     string
	Method    string
	Path      string
	Status    int
	UserAgent string
	// Fingerprint is an opaque client identity id (e.g. a TLS ClientHello
	// fingerprint) when the source carries one, "" otherwise. A detector may
	// group on it, but must never treat "" as a group key — the empty value pools
	// unrelated clients. It is a group-by key, never a signature to match.
	Fingerprint string
	// CountryISO is the client's ISO-2 country when the source resolved one
	// ("" = not resolved). Evidence only: a detector may report it, but must
	// keep any threshold input on its own lookup so that adding this field
	// changed no decision.
	CountryISO string
	// Humanity is the ChallengeV2 Rung-1 humanity reading for a challenge
	// solve, nil when the source carried none (the rung off, or a source that
	// is not a solve). Evidence only: no detector may gate on it.
	Humanity *Humanity
}

// Humanity carries a ChallengeV2 Rung-1 reading on an InputEvent. A non-nil
// value means the scorer ran (webdetector's HumanityScored gate), so a zero
// Score is a real "scored clean"; a solve the scorer never saw has a nil
// *Humanity — nil is the ONLY "unscored", never a fabricated 0.
type Humanity struct {
	// Score is the Rung-1 score (0 = scored, nothing fired).
	Score int
	// Tells is the comma-joined list of tells that fired ("" when none).
	Tells string
	// NoPayload says the verify carried no parseable humanity body.
	NoPayload bool
}

// NoReport reports whether this reading renders as hs=- on the solve line:
// no payload AND a zero score. A UA-borne opener can still score a
// no-payload solve, and the line then shows that number. Nil-safe (false).
func (h *Humanity) NoReport() bool {
	return h != nil && HumanityNoReport(h.NoPayload, h.Score)
}

// HumanityNoReport is the ONE hs=- predicate, shared by the solve line
// (webdetector ChallengeSolve.HumanitySuffix) and the solver-farm humanity
// buckets, so the two can never disagree about what "no report" is.
func HumanityNoReport(noPayload bool, score int) bool {
	return noPayload && score == 0
}
