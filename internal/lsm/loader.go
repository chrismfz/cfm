//go:build linux

package lsm

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
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

// AttachResult records what NewLoader actually managed to attach.
//
// Partial mode is a first-class outcome: a kernel may accept
// CFML-EXEC-001 (whose verifier surface is trivial) but reject
// CFML-EXEC-003 (whose fd-walk hits a complexity ceiling on older
// kernels per docs/cfm-lsm.md). When that happens we prefer
// "one policy live and reported" over "nothing loaded because
// something failed."
type AttachResult struct {
	// Attached is the set of policies whose BPF program is now
	// attached to its LSM hook. Iteration order is stable
	// (matches AllPolicies()).
	Attached []PolicyID

	// Failed maps a policy whose attach attempt failed to the
	// underlying error. A non-empty Failed map combined with a
	// non-empty Attached slice means partial mode.
	Failed map[PolicyID]error
}

// Loader owns the lifecycle of cfm-lsm's BPF programs: load, attach
// to LSM hooks, drain the ring buffer, detach on Close.
//
// The Loader does not block. Events flow from a goroutine started by
// Start into a buffered channel returned by Events. Callers consume
// the channel and forward into the wider CFM event bus.
type Loader struct {
	objs   cfmlsmObjects
	links  map[PolicyID]link.Link
	reader *ringbuf.Reader

	attach  AttachResult
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

	// Policies optionally restricts which policies to attach. Empty
	// or nil means "attach every policy in AllPolicies()." Unknown
	// IDs are ignored. Use this to load only a subset (e.g. for
	// per-policy testing).
	Policies []PolicyID
}

// NewLoader loads the embedded BPF objects, attaches the requested
// policy programs to their LSM hooks, and opens the ringbuf reader.
// Call Start to begin draining events; Close to detach + free.
//
// Returns ErrBPFLSMUnavailable wrapped with the underlying cause if
// the kernel refuses to load *any* program — that is the "host cannot
// run cfm-lsm at all" case. If at least one policy attaches, NewLoader
// succeeds and exposes the per-policy outcome via Attach(); callers
// can inspect Attach().Failed to surface partial-mode warnings.
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
		links:  make(map[PolicyID]link.Link, 2),
		events: make(chan Event, opts.EventBufferSize),
		errors: make(chan error, 1),
		attach: AttachResult{Failed: make(map[PolicyID]error)},
	}

	if err := loadCfmlsmObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("%w: load BPF objects: %v", ErrBPFLSMUnavailable, err)
	}

	wanted := opts.Policies
	if len(wanted) == 0 {
		for _, p := range AllPolicies() {
			wanted = append(wanted, p.ID)
		}
	}

	for _, id := range wanted {
		prog := l.programFor(id)
		if prog == nil {
			// Unknown ID or program absent from this build. Treat as
			// a per-policy failure, not a fatal error.
			l.attach.Failed[id] = fmt.Errorf("no BPF program for policy %s", id)
			continue
		}
		link, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			l.attach.Failed[id] = fmt.Errorf("attach lsm: %w", err)
			continue
		}
		l.links[id] = link
		l.attach.Attached = append(l.attach.Attached, id)
	}

	if len(l.attach.Attached) == 0 {
		// Nothing attached — close objects and surface the first
		// failure so the caller has a concrete reason.
		var firstErr error
		for _, e := range l.attach.Failed {
			firstErr = e
			break
		}
		l.objs.Close()
		if firstErr == nil {
			firstErr = errors.New("no policies attached")
		}
		return nil, fmt.Errorf("%w: %v", ErrBPFLSMUnavailable, firstErr)
	}

	reader, err := ringbuf.NewReader(l.objs.cfmlsmMaps.CfmEvents)
	if err != nil {
		for _, lk := range l.links {
			_ = lk.Close()
		}
		l.objs.Close()
		return nil, fmt.Errorf("%w: open ringbuf: %v", ErrBPFLSMUnavailable, err)
	}
	l.reader = reader

	return l, nil
}

// programFor returns the BPF program in this Loader's collection for
// the given policy, or nil if the policy is unknown.
func (l *Loader) programFor(id PolicyID) *ebpf.Program {
	switch id {
	case PolicyMemfdExec:
		return l.objs.cfmlsmPrograms.CfmMemfdExec
	case PolicyReverseShell:
		return l.objs.cfmlsmPrograms.CfmRevshell
	}
	return nil
}

// Attach returns a snapshot of which policies are currently attached
// and which failed to attach. Safe to call any time after NewLoader
// returns; the underlying state is set once at NewLoader time and
// never mutated thereafter.
func (l *Loader) Attach() AttachResult {
	return l.attach
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
		for _, lk := range l.links {
			if err := lk.Close(); err != nil && first == nil {
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
