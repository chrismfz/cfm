//go:build linux

package lsm

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ErrBPFLSMUnavailable is returned by NewLoader when the running
// kernel cannot accept the BPF LSM programs cfm-lsm needs. The
// preflight checks (see preflight.go) are the cheap pre-load probe
// that explains *why*; this error is what NewLoader returns when an
// actual load attempt fails.
var ErrBPFLSMUnavailable = errors.New("BPF LSM unavailable on this kernel")

// Loader owns the lifecycle of cfm-lsm's BPF programs: load, attach
// to LSM hooks, drain the ring buffer, detach on Close.
//
// The Loader does not block. Events flow from a goroutine started by
// Start into a buffered channel returned by Events. Callers consume
// the channel and forward into the wider CFM event bus.
//
// Phase-1 scope: only CFML-EXEC-001 (memfd exec) is wired up.
type Loader struct {
	objs      cfmlsmObjects
	memfdLink link.Link
	reader    *ringbuf.Reader

	events  chan Event
	errors  chan error
	stopOne sync.Once
	wg      sync.WaitGroup
}

// LoaderOptions configures NewLoader.
type LoaderOptions struct {
	// EventBufferSize is the depth of the Go-side channel that
	// receives parsed events. A slow consumer just causes the
	// channel to fill and the BPF ringbuf to back up; the program
	// then drops events at submit time and increments its internal
	// drop counter (visible via the ringbuf's Read.Lost field).
	// Zero defaults to 256.
	EventBufferSize int
}

// NewLoader loads the embedded BPF objects, attaches the enabled
// policy programs to their LSM hooks, and opens the ringbuf reader.
// Call Start to begin draining events; Close to detach + free.
//
// Returns ErrBPFLSMUnavailable wrapped with the underlying cause if
// the kernel refuses to load or attach (BPF LSM not enabled in
// /sys/kernel/security/lsm, verifier rejection, missing BTF, no
// CAP_BPF). Callers should treat that as "host cannot run cfm-lsm"
// and report it via cfm lsm status rather than crashing the daemon.
func NewLoader(opts LoaderOptions) (*Loader, error) {
	if opts.EventBufferSize <= 0 {
		opts.EventBufferSize = 256
	}

	// Remove the historical memlock cap. On kernels < 5.11 BPF maps
	// charge RLIMIT_MEMLOCK; on >=5.11 the charge is unified into
	// cgroup memory and this call is a cheap no-op. Either way it
	// must run before the first map load attempt.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("%w: rlimit.RemoveMemlock: %v", ErrBPFLSMUnavailable, err)
	}

	l := &Loader{
		events: make(chan Event, opts.EventBufferSize),
		errors: make(chan error, 1),
	}

	if err := loadCfmlsmObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("%w: load BPF objects: %v", ErrBPFLSMUnavailable, err)
	}

	prog := l.objs.cfmlsmPrograms.CfmMemfdExec
	if prog == nil {
		l.objs.Close()
		return nil, fmt.Errorf("%w: cfm_memfd_exec program missing from collection", ErrBPFLSMUnavailable)
	}

	attached, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		l.objs.Close()
		return nil, fmt.Errorf("%w: attach lsm/bprm_check_security: %v", ErrBPFLSMUnavailable, err)
	}
	l.memfdLink = attached

	reader, err := ringbuf.NewReader(l.objs.cfmlsmMaps.CfmEvents)
	if err != nil {
		_ = attached.Close()
		l.objs.Close()
		return nil, fmt.Errorf("%w: open ringbuf: %v", ErrBPFLSMUnavailable, err)
	}
	l.reader = reader

	return l, nil
}

// Start begins draining the ring buffer in a goroutine. The provided
// context cancels the drain loop; Close is the orderly path that
// also detaches the programs.
func (l *Loader) Start(ctx context.Context) {
	l.wg.Add(1)
	go l.drain(ctx)
}

// Events returns the channel that receives parsed Event records.
// The channel is closed by Close after the drain goroutine exits;
// callers should range over it.
func (l *Loader) Events() <-chan Event {
	return l.events
}

// Errors returns the channel that receives unrecoverable errors from
// the drain loop. Has capacity 1 — only the first failure is
// surfaced. Closed by Close.
func (l *Loader) Errors() <-chan error {
	return l.errors
}

// Close detaches the BPF programs, closes the ringbuf reader, and
// frees BPF objects. Safe to call multiple times; the actual
// teardown runs once.
func (l *Loader) Close() error {
	var first error
	l.stopOne.Do(func() {
		if l.reader != nil {
			if err := l.reader.Close(); err != nil && first == nil {
				first = err
			}
		}
		l.wg.Wait()
		if l.memfdLink != nil {
			if err := l.memfdLink.Close(); err != nil && first == nil {
				first = err
			}
		}
		if err := l.objs.Close(); err != nil && first == nil {
			first = err
		}
		close(l.events)
		close(l.errors)
	})
	return first
}

func (l *Loader) drain(ctx context.Context) {
	defer l.wg.Done()
	for {
		// Cheap context check between blocking reads. The reader is
		// unblocked by Close calling reader.Close(), which makes
		// Read return ringbuf.ErrClosed.
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			// Surface and exit. The Loader stays alive (programs are
			// still attached) but no further events will appear —
			// caller decides whether to Close + reload.
			select {
			case l.errors <- err:
			default:
			}
			return
		}

		ev, err := parseEvent(rec.RawSample)
		if err != nil {
			// Malformed record. Discard; do not kill the drain loop
			// over a single bad event.
			continue
		}
		select {
		case l.events <- ev:
		case <-ctx.Done():
			return
		}
	}
}
