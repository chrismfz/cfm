//go:build linux

package lsm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// DefaultPinDir is the canonical bpffs location for cfm-lsm pinned
// state. Override per-instance via LoaderOptions.PinDir (used in
// tests; production should keep this default).
const DefaultPinDir = "/sys/fs/bpf/cfm"

// Layout under the pin directory:
//
//   <pinDir>/maps/cfm_events       — the shared ringbuf map
//   <pinDir>/links/cfm_memfd_exec  — CFML-EXEC-001 attached link
//   <pinDir>/links/cfm_revshell    — CFML-EXEC-003 attached link
//
// Each pinned object exists for as long as the bpffs file exists;
// the kernel only detaches when the last reference is dropped.
// Removing the bpffs file is enough to trigger detach.
const (
	pinSubdirMaps  = "maps"
	pinSubdirLinks = "links"

	pinFileMap         = "cfm_events"
	pinFileLinkMemfd            = "cfm_memfd_exec"
	pinFileLinkRevshell         = "cfm_revshell"
	pinFileLinkFs005Setattr     = "cfm_fs005_setattr"
	pinFileLinkFs005Create      = "cfm_fs005_create"
	pinFileLinkFs005Unlink      = "cfm_fs005_unlink"
	pinFileLinkFs005Link        = "cfm_fs005_link"
	pinFileLinkFs005Rename      = "cfm_fs005_rename"
	pinFileLinkFs005Setxattr    = "cfm_fs005_setxattr"
	pinFileLinkCred002          = "cfm_cred002"
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
//
// Lifetime model — three modes:
//
//   - Unpinned (default): NewLoader with PinDir="". Programs attached
//     for the loader's lifetime; Close() detaches and frees everything.
//     This is the probe-style "verify it works then exit" mode.
//
//   - Pinned-load: NewLoader with PinDir set. Programs attached AND
//     pinned to bpffs. Close() releases the userspace fds but the
//     kernel keeps the pinned programs running. UnpinAll(pinDir)
//     is required to actually detach.
//
//   - Pinned-adopt: AdoptPinned(pinDir). Opens previously-pinned
//     programs and a previously-pinned ringbuf map without
//     reattaching anything. Used by the cfm daemon to read events
//     from programs the operator already enabled via CLI.
type Loader struct {
	objs   cfmlsmObjects
	// links is one slice of attached links per policy. Most policies
	// have a single link; CFML-FS-005 has six (one per LSM hook in
	// the inode_setattr / create / unlink / link / rename / setxattr
	// family). Iteration order matches programsFor(id).
	links map[PolicyID][]link.Link
	reader *ringbuf.Reader

	// pinned is true when the loader is in pinned-load or
	// pinned-adopt mode. Close() then skips link/map detach so the
	// kernel-side state survives the loader's lifetime.
	pinned bool

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

	// Modes maps a policy ID to its enforcement mode. Rewritten into
	// the BPF programs' `volatile const __u8 cfm_enforce_*` globals
	// at load time via spec.RewriteConstants. Policies not present
	// in this map default to monitor (0). Enforce mode (1) makes
	// the BPF program return -EPERM on a match, blocking the exec.
	//
	// Once loaded, the mode is baked into the program's instruction
	// stream — there is no runtime cost beyond a single byte compare.
	// To change a policy's mode the operator must `cfm lsm disable`
	// and re-enable so the constants are rewritten.
	Modes map[PolicyID]Mode

	// PinDir, when non-empty, asks NewLoader to pin the ringbuf map
	// and every successfully-attached link to <PinDir>/maps/ and
	// <PinDir>/links/ respectively. The pin operation is part of
	// NewLoader's atomic-or-fail contract: if any pin fails, every
	// already-pinned entry is removed and the loader rolls back.
	//
	// When PinDir is set, Loader.Close() does NOT remove the pins.
	// It only releases userspace fds; the kernel keeps the pinned
	// programs and map attached. Use UnpinAll(pinDir) to detach.
	PinDir string
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
		links:  make(map[PolicyID][]link.Link, 2),
		events: make(chan Event, opts.EventBufferSize),
		errors: make(chan error, 1),
		attach: AttachResult{Failed: make(map[PolicyID]error)},
	}

	// Load the spec, rewrite per-policy enforce constants, then
	// commit. The const-rewrite must happen BEFORE LoadAndAssign so
	// the BPF program is loaded with the right enforce flags baked
	// in. Once loaded, the mode is permanent for this Loader's
	// lifetime — to change a policy's mode the operator must
	// `cfm lsm disable` and re-enable (so a fresh spec is loaded
	// with new constants).
	spec, err := loadCfmlsm()
	if err != nil {
		return nil, fmt.Errorf("%w: load BPF spec: %v", ErrBPFLSMUnavailable, err)
	}
	if err := rewriteEnforceConstants(spec, opts.Modes); err != nil {
		return nil, fmt.Errorf("%w: rewrite enforce constants: %v", ErrBPFLSMUnavailable, err)
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("%w: load BPF objects: %v", ErrBPFLSMUnavailable, err)
	}

	wanted := opts.Policies
	if len(wanted) == 0 {
		for _, p := range AllPolicies() {
			wanted = append(wanted, p.ID)
		}
	}

	for _, id := range wanted {
		entries := l.programsFor(id)
		if len(entries) == 0 {
			// Unknown ID or programs absent from this build. Treat
			// as a per-policy failure, not a fatal error.
			l.attach.Failed[id] = fmt.Errorf("no BPF program for policy %s", id)
			continue
		}
		// Attach every sub-program. FS-005 has 6 (one per LSM hook);
		// the others have 1 each. If ANY sub-program fails to attach,
		// roll back the ones already attached for this policy so the
		// kernel state stays consistent.
		attached := make([]link.Link, 0, len(entries))
		var attachErr error
		for _, e := range entries {
			lk, err := link.AttachLSM(link.LSMOptions{Program: e.prog})
			if err != nil {
				attachErr = fmt.Errorf("attach lsm %s: %w", e.pinName, err)
				break
			}
			attached = append(attached, lk)
		}
		if attachErr != nil {
			for _, lk := range attached {
				_ = lk.Close()
			}
			l.attach.Failed[id] = attachErr
			continue
		}
		l.links[id] = attached
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
		for _, links := range l.links {
			for _, lk := range links {
				_ = lk.Close()
			}
		}
		l.objs.Close()
		return nil, fmt.Errorf("%w: open ringbuf: %v", ErrBPFLSMUnavailable, err)
	}
	l.reader = reader

	// Pinning happens last, after every attach + ringbuf open
	// succeeded. If any individual pin fails, every entry written so
	// far is rolled back and the loader is torn down.
	if opts.PinDir != "" {
		if err := l.pinAll(opts.PinDir); err != nil {
			// Roll back: remove anything we managed to pin, then
			// close userspace fds so the kernel detaches.
			_ = unpinFiles(opts.PinDir)
			_ = reader.Close()
			for _, links := range l.links {
				for _, lk := range links {
					_ = lk.Close()
				}
			}
			l.objs.Close()
			return nil, fmt.Errorf("%w: pin to %s: %v", ErrBPFLSMUnavailable, opts.PinDir, err)
		}
		l.pinned = true
	}

	return l, nil
}

// pinAll writes the loader's links and ringbuf map to bpffs under
// pinDir. Called only from NewLoader when LoaderOptions.PinDir is
// set; expects the loader's fields to be fully populated.
func (l *Loader) pinAll(pinDir string) error {
	mapsDir := filepath.Join(pinDir, pinSubdirMaps)
	linksDir := filepath.Join(pinDir, pinSubdirLinks)
	for _, d := range []string{pinDir, mapsDir, linksDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	mapPath := filepath.Join(mapsDir, pinFileMap)
	if err := l.objs.cfmlsmMaps.CfmEvents.Pin(mapPath); err != nil {
		return fmt.Errorf("pin map %s: %w", mapPath, err)
	}
	// Each policy has one or more sub-programs; iterate both the
	// link slice we accumulated at attach time AND the matching
	// programEntry slice so we know each link's pin name.
	for id, links := range l.links {
		entries := l.programsFor(id)
		if len(entries) != len(links) {
			return fmt.Errorf("internal: policy %s has %d links but %d entries", id, len(links), len(entries))
		}
		for i, lk := range links {
			path := filepath.Join(linksDir, entries[i].pinName)
			if err := lk.Pin(path); err != nil {
				return fmt.Errorf("pin link %s: %w", path, err)
			}
		}
	}
	return nil
}

// pinLinkFile returns the bpffs filename to use for a given
// policy's pinned link. Returns "" for unknown policy IDs.
// rewriteEnforceConstants updates the BPF spec's `volatile const __u8
// cfm_enforce_*` globals to the per-policy mode the operator asked for.
// Called before LoadAndAssign so the values are baked into the
// program at load time. Policies absent from modes default to monitor
// (the spec's default value of 0).
//
// The constant names must match the C-side declarations in
// cfmlsm.bpf.c. If a name drifts, the rewrite fails loudly rather
// than silently falling back to monitor.
func rewriteEnforceConstants(spec *ebpf.CollectionSpec, modes map[PolicyID]Mode) error {
	rewrites := map[string]uint8{
		"cfm_enforce_memfd_exec":      enforceByte(modes[PolicyMemfdExec]),
		"cfm_enforce_revshell":        enforceByte(modes[PolicyReverseShell]),
		"cfm_enforce_sensitive_write": enforceByte(modes[PolicySensitiveWrite]),
		// CFML-CRED-002 is monitor-only by design (cred_prepare
		// enforce can deadlock systemd). No enforce constant in
		// cfmlsm.bpf.c — intentionally absent here too. enable.go
		// warns and downgrades when an operator sets mode=enforce
		// on CRED-002.
	}
	for name, val := range rewrites {
		vs, ok := spec.Variables[name]
		if !ok {
			return fmt.Errorf("BPF spec missing variable %q — C/Go const names out of sync", name)
		}
		if err := vs.Set(val); err != nil {
			return fmt.Errorf("set %s=%d: %w", name, val, err)
		}
	}
	return nil
}

// enforceByte maps a Mode to the byte the BPF program checks. Only
// ModeEnforce maps to 1; ModeMonitor and ModeDisabled both map to 0
// (a disabled policy still has its program linked but never matches
// because the operator omitted it from LoaderOptions.Policies; the
// enforce flag is irrelevant in that path).
func enforceByte(m Mode) uint8 {
	if m == ModeEnforce {
		return 1
	}
	return 0
}

// pinLinkFile returns the primary bpffs filename for a policy's
// pinned links. For policies with a single program (EXEC-001 /
// EXEC-003 / CRED-002) this is THE pin file; for FS-005 it is the
// first of six. Used as a convenience by tests and by anywhere
// the code only needs ONE canonical filename per policy.
//
// Most production paths should use pinLinkFiles (plural) instead.
func pinLinkFile(id PolicyID) string {
	names := pinLinkFiles(id)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// pinLinkFiles returns every bpffs filename a policy's pinned links
// occupy. Empty for unknown policies. Used by InspectPinned to
// recognise a policy's presence (any one file is enough to imply
// the policy is enabled) and by UnpinAll to find the files to
// remove. The names match programsFor's pinName values.
func pinLinkFiles(id PolicyID) []string {
	switch id {
	case PolicyMemfdExec:
		return []string{pinFileLinkMemfd}
	case PolicyReverseShell:
		return []string{pinFileLinkRevshell}
	case PolicySensitiveWrite:
		return []string{
			pinFileLinkFs005Setattr,
			pinFileLinkFs005Create,
			pinFileLinkFs005Unlink,
			pinFileLinkFs005Link,
			pinFileLinkFs005Rename,
			pinFileLinkFs005Setxattr,
		}
	case PolicyCredEscal:
		return []string{pinFileLinkCred002}
	}
	return nil
}

// AdoptPinned opens previously-pinned cfm-lsm state at pinDir and
// returns a Loader whose Start/Events/Errors/Close work the same
// as an unpinned Loader, except that Close does not detach — the
// kernel-side programs and map remain attached and pinned. Use
// UnpinAll(pinDir) when you want to actually detach.
//
// Intended for the cfm daemon's startup path: the operator runs
// `cfm lsm enable` ahead of time (which pins the state), and the
// daemon then adopts that state to read events.
//
// Returns ErrBPFLSMUnavailable wrapped with the underlying cause
// when the pinned state is absent, malformed, or the kernel has
// since dropped it.
func AdoptPinned(pinDir string, opts LoaderOptions) (*Loader, error) {
	if opts.EventBufferSize <= 0 {
		opts.EventBufferSize = 256
	}
	mapPath := filepath.Join(pinDir, pinSubdirMaps, pinFileMap)
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: open pinned map %s: %v", ErrBPFLSMUnavailable, mapPath, err)
	}
	l := &Loader{
		links:  make(map[PolicyID][]link.Link, 2),
		events: make(chan Event, opts.EventBufferSize),
		errors: make(chan error, 1),
		attach: AttachResult{Failed: make(map[PolicyID]error)},
		pinned: true,
	}
	l.objs.cfmlsmMaps.CfmEvents = m

	// Walk each known policy's pinned links. Missing links are not
	// fatal — they just mean that policy wasn't enabled at pin time.
	// A policy with MULTIPLE sub-links (FS-005) is treated as
	// attached if ALL of its sub-links open successfully; partial-pin
	// state would mean an interrupted enable or a manual rm — we
	// surface that as a Failed entry rather than half-adopting.
	linksDir := filepath.Join(pinDir, pinSubdirLinks)
	for _, p := range AllPolicies() {
		names := pinLinkFiles(p.ID)
		if len(names) == 0 {
			continue
		}
		// First pass: do any of this policy's links exist? If none,
		// the policy was simply not enabled.
		anyExists := false
		for _, name := range names {
			if _, err := os.Stat(filepath.Join(linksDir, name)); err == nil {
				anyExists = true
				break
			}
		}
		if !anyExists {
			continue
		}
		// Second pass: open each link. Track them in a temp slice so
		// we can roll back if any one fails.
		adopted := make([]link.Link, 0, len(names))
		var adoptErr error
		for _, name := range names {
			path := filepath.Join(linksDir, name)
			lk, err := link.LoadPinnedLink(path, nil)
			if err != nil {
				adoptErr = fmt.Errorf("open pinned link %s: %w", path, err)
				break
			}
			adopted = append(adopted, lk)
		}
		if adoptErr != nil {
			for _, lk := range adopted {
				_ = lk.Close()
			}
			l.attach.Failed[p.ID] = adoptErr
			continue
		}
		l.links[p.ID] = adopted
		l.attach.Attached = append(l.attach.Attached, p.ID)
	}
	if len(l.attach.Attached) == 0 {
		_ = m.Close()
		return nil, fmt.Errorf("%w: no pinned links found under %s", ErrBPFLSMUnavailable, linksDir)
	}
	reader, err := ringbuf.NewReader(m)
	if err != nil {
		for _, links := range l.links {
			for _, lk := range links {
				_ = lk.Close()
			}
		}
		_ = m.Close()
		return nil, fmt.Errorf("%w: open ringbuf on pinned map: %v", ErrBPFLSMUnavailable, err)
	}
	l.reader = reader
	return l, nil
}

// UnpinAll removes every pinned cfm-lsm entry under pinDir. The
// kernel detaches programs and frees maps once the last reference
// is dropped, which on bpffs means once the file is unlinked. Safe
// to call when pinDir does not exist; returns nil in that case.
func UnpinAll(pinDir string) error {
	if _, err := os.Stat(pinDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return unpinFiles(pinDir)
}

func unpinFiles(pinDir string) error {
	var first error
	for _, sub := range []string{pinSubdirLinks, pinSubdirMaps} {
		dir := filepath.Join(pinDir, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if first == nil {
				first = err
			}
			continue
		}
		for _, e := range entries {
			path := filepath.Join(dir, e.Name())
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				if first == nil {
					first = err
				}
			}
		}
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
			if first == nil {
				first = err
			}
		}
	}
	if err := os.Remove(pinDir); err != nil && !os.IsNotExist(err) {
		if first == nil {
			first = err
		}
	}
	return first
}

// PinnedState describes what currently exists under pinDir without
// actually opening anything. Useful for `cfm lsm status` so it can
// report the live attach state without hitting the kernel.
type PinnedState struct {
	// PinDir is the directory inspected. Always set.
	PinDir string

	// Exists is true when pinDir is present on disk. False when
	// cfm-lsm has not been enabled (or was disabled and cleaned up).
	Exists bool

	// MapPresent indicates the shared ringbuf map is pinned.
	MapPresent bool

	// Links lists which policy links are currently pinned.
	Links []PolicyID
}

// InspectPinned returns the structured pin state without opening
// any BPF objects. Safe to call without CAP_BPF — it only stats
// files under pinDir.
func InspectPinned(pinDir string) PinnedState {
	st := PinnedState{PinDir: pinDir}
	if _, err := os.Stat(pinDir); err != nil {
		return st
	}
	st.Exists = true
	if _, err := os.Stat(filepath.Join(pinDir, pinSubdirMaps, pinFileMap)); err == nil {
		st.MapPresent = true
	}
	for _, p := range AllPolicies() {
		names := pinLinkFiles(p.ID)
		if len(names) == 0 {
			continue
		}
		// A policy is considered "pinned" when at least one of its
		// sub-link files exists. For FS-005 a partial pin set means
		// a previous enable was interrupted; the policy still shows
		// up here so the operator sees something to clean up.
		for _, name := range names {
			if _, err := os.Stat(filepath.Join(pinDir, pinSubdirLinks, name)); err == nil {
				st.Links = append(st.Links, p.ID)
				break
			}
		}
	}
	return st
}

// programEntry pairs a BPF program with its bpffs pin filename. One
// policy maps to one entry for the simple cases (EXEC-001 / EXEC-003
// / CRED-002) and to six entries for CFML-FS-005 (one per LSM hook
// in the inode_* family).
type programEntry struct {
	prog    *ebpf.Program
	pinName string
}

// programsFor returns every BPF program a policy attaches to,
// alongside the bpffs filename each one pins to. Empty for unknown
// policies. Iteration order is stable so pin layout is deterministic.
func (l *Loader) programsFor(id PolicyID) []programEntry {
	progs := l.objs.cfmlsmPrograms
	switch id {
	case PolicyMemfdExec:
		return []programEntry{{progs.CfmMemfdExec, pinFileLinkMemfd}}
	case PolicyReverseShell:
		return []programEntry{{progs.CfmRevshell, pinFileLinkRevshell}}
	case PolicySensitiveWrite:
		return []programEntry{
			{progs.CfmFs005Setattr, pinFileLinkFs005Setattr},
			{progs.CfmFs005Create, pinFileLinkFs005Create},
			{progs.CfmFs005Unlink, pinFileLinkFs005Unlink},
			{progs.CfmFs005Link, pinFileLinkFs005Link},
			{progs.CfmFs005Rename, pinFileLinkFs005Rename},
			{progs.CfmFs005Setxattr, pinFileLinkFs005Setxattr},
		}
	case PolicyCredEscal:
		return []programEntry{{progs.CfmCred002, pinFileLinkCred002}}
	}
	return nil
}

// WatchedUidsMap returns the BPF hash map that CFML-FS-005 consults
// to decide whether the calling task's uid is "watched" (a web-class
// user / panel-managed account / etc.). The map's keys are uid
// (__u32); presence-of-key means watched. Populated by the daemon
// (see internal/lsm/maps.go) at adoption time.
func (l *Loader) WatchedUidsMap() *ebpf.Map {
	return l.objs.cfmlsmMaps.CfmWatchedUids
}

// WatchedInodesMap returns the BPF hash map that CFML-FS-005 consults
// for sensitive-file inode numbers. Keys are inode numbers (__u64).
// Populated by the daemon from the operator-configurable
// sensitive-paths list at adoption time.
func (l *Loader) WatchedInodesMap() *ebpf.Map {
	return l.objs.cfmlsmMaps.CfmWatchedInodes
}

// SetuidInodesMap returns the BPF hash map that CFML-CRED-002 consults
// for the "legitimate setuid binary" allowlist. Keys are inode
// numbers of every file on disk with S_ISUID set; presence means
// "uid 0 transition through this binary is expected." Populated by
// the daemon walking standard setuid paths at adoption time.
func (l *Loader) SetuidInodesMap() *ebpf.Map {
	return l.objs.cfmlsmMaps.CfmSetuidInodes
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

// Close releases the loader's userspace fds.
//
// In unpinned mode this detaches every BPF program (closing the
// last fd on a link is what triggers kernel detach). In pinned mode
// the pinned bpffs entries keep their own kernel references, so
// closing the userspace fds here does NOT detach — the programs
// remain attached until UnpinAll(pinDir).
//
// Safe to call multiple times; the actual teardown runs once.
func (l *Loader) Close() error {
	var first error
	l.stopOne.Do(func() {
		if l.reader != nil {
			if err := l.reader.Close(); err != nil && first == nil {
				first = err
			}
		}
		l.wg.Wait()
		for _, links := range l.links {
			for _, lk := range links {
				if err := lk.Close(); err != nil && first == nil {
					first = err
				}
			}
		}
		if l.pinned {
			// objs holds program + map fds we got from
			// loadCfmlsmObjects (unpinned path) or from
			// LoadPinnedMap (pinned-adopt path). Closing those just
			// drops userspace refs; the bpffs entries keep the
			// kernel-side state alive. AdoptPinned populates only
			// the map field, so this Close is still correct.
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
