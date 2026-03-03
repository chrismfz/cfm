package core

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DirTailer implements LineSource for a directory (DirectAdmin/cPanel style).
// It tails many files and merges them into one non-blocking stream.
//
// Each emitted line is prefixed with:
//
//	@host=<host>\t<rawline>
//
// so downstream parsers can recover per-vhost metadata.
//
// Lifecycle (mirrors FileTailer):
//
//	Open()     — first call scans the directory and opens all tailers.
//	             Subsequent calls (between ticks) are no-ops: all fds stay warm.
//	Close()    — saves positions to persistent state (checkpoint), but does NOT
//	             close fds.  The tailers map is kept intact.
//	Shutdown() — real teardown: closes all fds, clears the map, sets opened=false.
type DirTailer struct {
	Dir       string
	Recursive bool
	Glob      string // basename glob, e.g. "*.log"

	mu       sync.Mutex
	opened   bool
	files    []string
	tailers  map[string]*FileTailer
	lastPos  map[string]Position // in-memory resume (across ticks / new-file discovery)
	rr       int                 // round-robin pointer for fair file rotation
	lastScan time.Time

	ScanEvery time.Duration

	// optional persistent state (restart-safe per-file resume)
	st      *State
	detName string
}

func NewDirTailer(dir string, recursive bool, glob string) *DirTailer {
	if glob == "" {
		glob = "*.log"
	}
	return &DirTailer{
		Dir:       dir,
		Recursive: recursive,
		Glob:      glob,
		tailers:   make(map[string]*FileTailer),
		lastPos:   make(map[string]Position),
		ScanEvery: 30 * time.Second,
	}
}

// SetState enables persistent resume across process restarts.
func (d *DirTailer) SetState(st *State, detName string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st = st
	d.detName = detName
}

// Open is a no-op after the first call.
// On the first call it scans the directory and opens all discovered files.
func (d *DirTailer) Open() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Fast path: already open from a previous tick — nothing to do.
	// All fds are still warm, all bufio.Readers are in place.
	if d.opened {
		return nil
	}

	d.scanLocked(true)

	for _, p := range d.files {
		if _, ok := d.tailers[p]; ok {
			// Existing tailer from before Shutdown() — reopen its fd.
			_ = d.tailers[p].Open()
			continue
		}
		t := d.newTailerLocked(p)
		if err := t.Open(); err != nil {
			continue
		}
		d.tailers[p] = t
	}

	d.opened = true
	return nil
}

// Close is a between-tick checkpoint.
//
// It saves each tailer's current position to persistent state so that a
// process restart can resume from the right offset.  It does NOT close any
// file handles — all fds remain open and warm for the next tick.
func (d *DirTailer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.opened {
		return nil
	}

	for p, t := range d.tailers {
		off, ino, ts := t.Position()
		d.lastPos[p] = Position{Offset: off, Inode: ino, TS: ts}
		if d.st != nil && d.detName != "" {
			d.st.Put(FileStateKey(d.detName, p), Position{Offset: off, Inode: ino, TS: ts})
		}
		// t.Close() is itself a no-op for FileTailer — fd stays open.
		// Call it anyway so the contract is fulfilled for any other LineSource
		// that might be wired in here.
		_ = t.Close()
	}
	return nil
}

// Shutdown closes all file handles and tears down the tailers map.
// Called once when the detector is stopped.
func (d *DirTailer) Shutdown() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for p, t := range d.tailers {
		off, ino, ts := t.Position()
		d.lastPos[p] = Position{Offset: off, Inode: ino, TS: ts}
		if d.st != nil && d.detName != "" {
			d.st.Put(FileStateKey(d.detName, p), Position{Offset: off, Inode: ino, TS: ts})
		}
		_ = t.Shutdown()
	}
	d.tailers = make(map[string]*FileTailer)
	d.opened = false
	return nil
}

func (d *DirTailer) Position() (offset uint64, inode uint64, ts int64) {
	return 0, 0, 0
}

func (d *DirTailer) ReadNext(ctx context.Context) (string, error) {
	d.mu.Lock()
	if !d.opened {
		d.mu.Unlock()
		return "", io.EOF
	}
	d.mu.Unlock()

	// ── periodic rescan: discover newly created files ─────────────────────────
	// Opening new files is done OUTSIDE the main lock to avoid blocking concurrent
	// ReadNext() calls (the open syscall can block on NFS / slow storage).
	d.mu.Lock()
	now := time.Now()
	if d.ScanEvery > 0 && (d.lastScan.IsZero() || now.Sub(d.lastScan) >= d.ScanEvery) {
		d.scanLocked(false)

		var needOpen []string
		for _, p := range d.files {
			if _, ok := d.tailers[p]; !ok {
				needOpen = append(needOpen, p)
			}
		}

		// Snapshot what we need for resume — under the lock.
		stCopy := d.st
		detNameCopy := d.detName
		lastPosCopy := make(map[string]Position, len(d.lastPos))
		for k, v := range d.lastPos {
			lastPosCopy[k] = v
		}
		d.mu.Unlock()

		// Open new files outside the lock.
		newTailers := make(map[string]*FileTailer, len(needOpen))
		for _, p := range needOpen {
			t := NewFileTailer(p)
			if stCopy != nil && detNameCopy != "" {
				if pos, ok := stCopy.Get(FileStateKey(detNameCopy, p)); ok {
					t.ApplyResume(pos.Inode, pos.Offset)
				}
			}
			if pos, ok := lastPosCopy[p]; ok {
				t.ApplyResume(pos.Inode, pos.Offset)
			}
			if err := t.Open(); err != nil {
				continue
			}
			newTailers[p] = t
		}

		d.mu.Lock()
		for p, t := range newTailers {
			d.tailers[p] = t
		}
		d.mu.Unlock()
	} else {
		d.mu.Unlock()
	}

	// ── snapshot paths + round-robin pointer (under lock) ────────────────────
	d.mu.Lock()
	paths := make([]string, 0, len(d.tailers))
	for p := range d.tailers {
		paths = append(paths, p)
	}
	rr := d.rr
	d.mu.Unlock()

	if len(paths) == 0 {
		return "", io.EOF
	}

	// Try each tailer at most once per ReadNext() call (non-blocking).
	for i := 0; i < len(paths); i++ {
		idx := (rr + i) % len(paths)
		path := paths[idx]

		d.mu.Lock()
		t := d.tailers[path]
		d.mu.Unlock()
		if t == nil {
			continue
		}

		line, err := t.ReadNext(ctx)
		if err == nil {
			host := extractHostFromPath(path)
			out := "@host=" + host + "\t" + line
			d.mu.Lock()
			d.rr = (idx + 1) % len(paths)
			d.mu.Unlock()
			return out, nil
		}

		if err == io.EOF {
			continue
		}

		// Unrecoverable error on this tailer — shut it down and remove it.
		// Use Shutdown() (not Close()) to actually close the fd.
		_ = t.Shutdown()
		d.mu.Lock()
		delete(d.tailers, path)
		d.mu.Unlock()
	}

	return "", io.EOF
}

// ── internal helpers ──────────────────────────────────────────────────────────

// newTailerLocked creates a FileTailer with resume position applied.
// Caller must hold d.mu.
func (d *DirTailer) newTailerLocked(p string) *FileTailer {
	t := NewFileTailer(p)
	if d.st != nil && d.detName != "" {
		if pos, ok := d.st.Get(FileStateKey(d.detName, p)); ok {
			t.ApplyResume(pos.Inode, pos.Offset)
		}
	}
	if pos, ok := d.lastPos[p]; ok {
		t.ApplyResume(pos.Inode, pos.Offset)
	}
	return t
}

func (d *DirTailer) scanLocked(first bool) {
	d.lastScan = time.Now()

	var files []string
	_ = filepath.WalkDir(d.Dir, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if de.IsDir() {
			if !d.Recursive && path != d.Dir {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		lb := strings.ToLower(base)
		// skip compressed / rotated files
		if strings.HasSuffix(lb, ".gz") || strings.HasSuffix(lb, ".bz2") ||
			strings.HasSuffix(lb, ".xz") || strings.HasSuffix(lb, ".zst") ||
			strings.HasSuffix(lb, ".zip") {
			return nil
		}
		if d.Glob != "" {
			if ok, _ := filepath.Match(d.Glob, base); !ok {
				return nil
			}
		}
		if info, e := os.Stat(path); e == nil && !info.Mode().IsRegular() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	d.files = files
}

func extractHostFromPath(path string) string {
	base := filepath.Base(path)
	lb := strings.ToLower(base)

	for _, suf := range []string{".gz", ".bz2", ".xz", ".zst", ".zip"} {
		if strings.HasSuffix(lb, suf) {
			base = strings.TrimSuffix(base, suf)
			lb = strings.ToLower(base)
			break
		}
	}

	// Virtualmin
	base = strings.TrimSuffix(base, "_access_log")
	base = strings.TrimSuffix(base, "_error_log")
	base = stripDashDateSuffix(base)

	// cPanel domlogs
	base = strings.TrimSuffix(base, "-ssl_log")
	base = strings.TrimSuffix(base, "-bytes_log")
	base = strings.TrimSuffix(base, "-ftp_log")

	// DirectAdmin / custom (strip longer suffixes first)
	lb = strings.ToLower(base)
	if strings.HasSuffix(lb, ".error.log") {
		base = base[:len(base)-len(".error.log")]
	} else if strings.HasSuffix(lb, ".bytes.log") {
		base = base[:len(base)-len(".bytes.log")]
	} else if strings.HasSuffix(lb, ".access.log") {
		base = base[:len(base)-len(".access.log")]
	} else {
		base = strings.TrimSuffix(base, ".log")
		base = strings.TrimSuffix(base, ".access")
		base = strings.TrimSuffix(base, ".bytes")
		base = strings.TrimSuffix(base, ".error")
	}

	base = stripDotNumericSuffix(base)
	base = strings.TrimSpace(base)
	if base == "" {
		return "unknown"
	}
	return strings.ToLower(base)
}

func stripDotNumericSuffix(s string) string {
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		if isAllDigits(s[i+1:]) {
			return s[:i]
		}
	}
	return s
}

func stripDashDateSuffix(s string) string {
	if i := strings.LastIndexByte(s, '-'); i > 0 {
		tail := s[i+1:]
		if (len(tail) == 8 || len(tail) == 12) && isAllDigits(tail) {
			return s[:i]
		}
	}
	return s
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
