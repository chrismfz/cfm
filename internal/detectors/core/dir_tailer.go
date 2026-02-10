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
	d.mu.Lock()
	now := time.Now()
	if d.ScanEvery > 0 && (d.lastScan.IsZero() || now.Sub(d.lastScan) >= d.ScanEvery) {
		d.scanLocked(false)
		// add new tailers if any (open immediately at end unless we have lastPos)
		for _, p := range d.files {
			if _, ok := d.tailers[p]; ok {
				continue
			}
			t := NewFileTailer(p)
                        // persistent resume for newly discovered files too
                        if d.st != nil && d.detName != "" {
                                key := FileStateKey(d.detName, p)
                                if pos, ok := d.st.Get(key); ok {
                                        t.ApplyResume(pos.Inode, pos.Offset)
                                }
                        }

			if pos, ok := d.lastPos[p]; ok {
				t.ApplyResume(pos.Inode, pos.Offset)
			}
			if err := t.Open(); err != nil {
				continue
			}
			d.tailers[p] = t
		}
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
		if strings.HasSuffix(lb, ".gz") || strings.HasSuffix(lb, ".bz2") || strings.HasSuffix(lb, ".zip") {
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

	// strip common suffixes
	base = strings.TrimSuffix(base, ".log")
	base = strings.TrimSuffix(base, ".access")
	base = strings.TrimSuffix(base, ".bytes")
	base = strings.TrimSuffix(base, ".error")

	// strip any remaining extension
	if ext := filepath.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	return strings.ToLower(base)
}
