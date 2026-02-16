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
// It prefixes each emitted line with:
//   @host=<host>\t<rawline>
// so downstream can recover host (vhost) metadata.
type DirTailer struct {
	Dir       string
	Recursive bool
	Glob      string // filename glob (basename match), e.g "*.log"

	// internal
	mu        sync.Mutex
	started   bool
	opened    bool
	files     []string
	tailers   map[string]*FileTailer
	lastPos   map[string]Position // per file resume across ticks
	rr        int                 // round-robin pointer
	lastScan  time.Time

	ScanEvery time.Duration

        // optional persistent state (for restart-safe per-file resume)
        st       *State
        detName  string // detector section name, e.g. "webdetector"
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
// detName should be the detector section name (e.g. "webdetector").
func (d *DirTailer) SetState(st *State, detName string) {
        d.mu.Lock()
        defer d.mu.Unlock()
        d.st = st
        d.detName = detName
}

func (d *DirTailer) Open() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.opened {
		// We deliberately keep opened across engine ticks? No: engine calls Close().
		// So Open() should re-open tailers using stored positions.
		return nil
	}

	// initial scan
	d.scanLocked(true)

	// open all tailers and apply saved positions
	for _, p := range d.files {
		if _, ok := d.tailers[p]; ok {
			continue
		}
		t := NewFileTailer(p)

                // persistent resume (restart-safe)
                if d.st != nil && d.detName != "" {
                        key := FileStateKey(d.detName, p)
                        if pos, ok := d.st.Get(key); ok {
                                t.ApplyResume(pos.Inode, pos.Offset)
                        }
                }

		// apply resume if we have it
		if pos, ok := d.lastPos[p]; ok {
			t.ApplyResume(pos.Inode, pos.Offset)
		}
		if err := t.Open(); err != nil {
			continue
		}
		d.tailers[p] = t
	}

	d.opened = true
	return nil
}

func (d *DirTailer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Save positions + close all handles, but keep lastPos so next tick resumes.
	for p, t := range d.tailers {
		off, ino, ts := t.Position()
		d.lastPos[p] = Position{Offset: off, Inode: ino, TS: ts}

                // persistent store
                if d.st != nil && d.detName != "" {
                        key := FileStateKey(d.detName, p)
                        d.st.Put(key, Position{Offset: off, Inode: ino, TS: ts})
                }

		_ = t.Close()
	}
	d.tailers = make(map[string]*FileTailer)
	d.opened = false
	return nil
}

func (d *DirTailer) Position() (offset uint64, inode uint64, ts int64) {
	// DirTailer doesn't have a single inode/offset; return zeros.
	// Webdetector uses state for file mode; for folder mode we keep in-memory resume.
	return 0, 0, 0
}

func (d *DirTailer) ReadNext(ctx context.Context) (string, error) {
	d.mu.Lock()
	opened := d.opened
	d.mu.Unlock()

	if !opened {
		return "", io.EOF
	}

	// periodic rescan to discover new files (cpanel domlogs etc)
	// CRITICAL FIX: Open files OUTSIDE the lock to avoid blocking other ReadNext() calls
	d.mu.Lock()
	now := time.Now()
	if d.ScanEvery > 0 && (d.lastScan.IsZero() || now.Sub(d.lastScan) >= d.ScanEvery) {
		d.scanLocked(false)

		// Identify files that need opening (under lock)
		var needOpen []string
		for _, p := range d.files {
			if _, ok := d.tailers[p]; ok {
				continue
			}


			needOpen = append(needOpen, p)
		}
		
		// Snapshot state for resume (under lock)
		stCopy := d.st
		detNameCopy := d.detName
		lastPosCopy := make(map[string]Position, len(d.lastPos))
		for k, v := range d.lastPos {
			lastPosCopy[k] = v
		}
		d.mu.Unlock()
		
		// Open files OUTSIDE lock (CRITICAL FIX - this is where the blocking happens)
		newTailers := make(map[string]*FileTailer)
		for _, p := range needOpen {
			t := NewFileTailer(p)
			
			// persistent resume for newly discovered files
			if stCopy != nil && detNameCopy != "" {
				key := FileStateKey(detNameCopy, p)
				if pos, ok := stCopy.Get(key); ok {
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

		// Quick lock to add new tailers
		d.mu.Lock()
		for p, t := range newTailers {
			d.tailers[p] = t



			}
		d.mu.Unlock()
	} else {
		d.mu.Unlock()
	}

	// snapshot tailers + rr pointer
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
			// prefix host metadata for adapters
			out := "@host=" + host + "\t" + line

			d.mu.Lock()
			d.rr = (idx + 1) % len(paths)
			d.mu.Unlock()

			return out, nil
		}

		if err == io.EOF {
			continue
		}
		// On error: drop this tailer (best-effort)
		_ = t.Close()
		d.mu.Lock()
		delete(d.tailers, path)
		d.mu.Unlock()
	}

	return "", io.EOF
}


func (d *DirTailer) scanLocked(first bool) {
	d.lastScan = time.Now()

	var files []string
	root := d.Dir

	_ = filepath.WalkDir(root, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if de.IsDir() {
			if !d.Recursive && path != root {
				return filepath.SkipDir
			}
			return nil
		}

		base := filepath.Base(path)

		// skip compressed / rotated junk
		lb := strings.ToLower(base)
		if strings.HasSuffix(lb, ".gz") || strings.HasSuffix(lb, ".bz2") || strings.HasSuffix(lb, ".xz") || strings.HasSuffix(lb, ".zst") || strings.HasSuffix(lb, ".zip") {
			return nil
		}

		if d.Glob != "" {
			if ok, _ := filepath.Match(d.Glob, base); !ok {
				return nil
			}
		}

		// Must be a regular file
		if info, e := os.Stat(path); e == nil {
			if !info.Mode().IsRegular() {
				return nil
			}
		}

		files = append(files, path)
		return nil
	})

	d.files = files
}

func extractHostFromPath(path string) string {
	base := filepath.Base(path)
	lb := strings.ToLower(base)

	// NOTE: scanLocked() already skips compressed files ("*.gz" etc), but keep safe.
	for _, suf := range []string{".gz", ".bz2", ".xz", ".zst", ".zip"} {
		if strings.HasSuffix(lb, suf) {
			base = strings.TrimSuffix(base, suf)
			lb = strings.ToLower(base)
			break
		}
	}

	// Virtualmin: example.com_access_log / example.com_error_log
	base = strings.TrimSuffix(base, "_access_log")
	base = strings.TrimSuffix(base, "_error_log")
	base = stripDashDateSuffix(base) // if you ever scan rotated non-gz: ..._log-YYYYMMDD

	// cPanel domlogs commonly use: domain.tld-ssl_log / domain.tld-bytes_log
	// (also sometimes with extra rotation suffixes)
	base = strings.TrimSuffix(base, "-ssl_log")
	base = strings.TrimSuffix(base, "-bytes_log")
	base = strings.TrimSuffix(base, "-ftp_log")

	// DirectAdmin/custom naming (strip longer suffixes first)
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

	// Strip numeric rotation suffixes like ".1", ".2", ".10"
	// IMPORTANT: do NOT use filepath.Ext() here (it would strip ".gr", ".com", etc).
	base = stripDotNumericSuffix(base)
	base = strings.TrimSpace(base)
	if base == "" {
		return "unknown"
	}
	return strings.ToLower(base)
}

func stripDotNumericSuffix(s string) string {
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		tail := s[i+1:]
		if isAllDigits(tail) {
			return s[:i]
		}
	}
	return s
}

func stripDashDateSuffix(s string) string {
	// remove trailing -YYYYMMDD (8 digits) or -YYYYMMDDHHMM (12 digits)
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
