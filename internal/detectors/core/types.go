package core

import (
	"context"
	"time"
)

type AlertKind string

type Alert struct {
	When    time.Time
	Kind    AlertKind
	Key     string
	Count   int
	Samples []string
	Extra   map[string]string
}

type Sink interface{ Publish(Alert) }

type PeriodicDetector interface {
	Name() string
	Every() time.Duration
	RunOnce(ctx context.Context, out chan<- Alert) error
}

// PositionAware is optional; detectors implement it if they can persist a read position.
type PositionAware interface {
	// Name returns a unique identifier for the detector instance (usually the section name).
	Name() string
	// ApplyPosition lets the manager inject the last saved position before a run.
	ApplyPosition(p Position)
	// Position returns the current read position after a run.
	Position() Position
}
