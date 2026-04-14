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
}
