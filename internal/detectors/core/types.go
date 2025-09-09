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
