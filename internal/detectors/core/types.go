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

// ExtraIPScope is the Alert.Extra key a detector uses to declare what its Key
// identifies. Set it to IPScopeHost when the finding is about a vhost (or any
// non-IP subject) rather than a single source address.
//
// This is not cosmetic. The sink resolves an alert's source IP by falling back
// to scanning Alert.Samples for anything IP-shaped, which is safe only while
// samples are server-generated. A detector whose Key is not an IP AND whose
// samples quote client-controlled text (a User-Agent, a URI, a header) would
// otherwise hand the sink an address chosen by the very client it is reporting
// on — which the sink then feeds to the global ignore list, so a caller could
// suppress its own alert. Declaring the scope makes the fallback stand down.
const (
	ExtraIPScope = "ip_scope"
	IPScopeHost  = "host"
)

type Sink interface{ Publish(Alert) }

type PeriodicDetector interface {
	Name() string
	Every() time.Duration
	RunOnce(ctx context.Context, out chan<- Alert) error
}

// LineSource is a generic, non-blocking line iterator for logs.
// ReadNext returns (line, nil) when a full line is available,
// and ("", io.EOF) when the source is caught up.
// It MUST NOT block waiting for new lines; detectors call it in a loop per RunOnce.
//
// Lifecycle:
//
//   Open()     — called at the start of each RunOnce tick.
//                For FileTailer/DirTailer this is a no-op after the first call
//                (fd stays open between ticks to eliminate per-tick syscalls and
//                buffer reallocations).
//
//   ReadNext() — drain available lines, non-blocking.
//
//   Close()    — called at the end of each RunOnce tick.
//                For FileTailer/DirTailer this is a checkpoint: saves position to
//                persistent state, but does NOT close the fd.  Zero syscalls.
//
//   Shutdown() — called once when the detector is stopped (context cancelled).
//                Performs real fd cleanup.  Safe to call multiple times.
type LineSource interface {
	Open() error
	ReadNext(ctx context.Context) (string, error)
	Position() (offset uint64, inode uint64, ts int64)
	Close() error    // between-tick checkpoint; keeps fd + buffer warm
	Shutdown() error // final cleanup; closes fd; called when detector stops
}

// Shutdowner is an optional interface that detectors implement when they wrap
// a LineSource and want to propagate Shutdown() to it.
// run.go checks for this interface after the periodic loop exits.
//
// Implementation in a detector is a one-liner:
//
//   func (d *MyDetector) Shutdown() error { return d.src.Shutdown() }
type Shutdowner interface {
	Shutdown() error
}

// PositionAware is optional; detectors implement it if they can persist a read position.
type PositionAware interface {
	Name() string
	ApplyPosition(p Position)
	Position() Position
}
