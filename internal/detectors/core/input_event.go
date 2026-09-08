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
}
