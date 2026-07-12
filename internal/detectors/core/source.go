package core

import (
	"bufio"
	"context"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

// FileTailer implements LineSource for plain files with rotation awareness.
//
// Key design decisions:
//
//  1. The fd is kept open between ticks (Open is a no-op when already open).
//     This eliminates 3 syscalls (open/fstat/lseek) and one 256 KB buffer
//     allocation on every single tick for every detector — the dominant source
//     of heap churn seen in the pprof profile.
//
//  2. The bufio.Reader is allocated exactly once and reused forever via
//     r.Reset(newFile) when rotation forces a real fd swap.  This is why
//     Shutdown() nils t.f but NOT t.r.
//
//  3. All rotation / deletion / truncation safeguards live in ReadNext() and
//     are completely unaffected by the above — they trigger on the first EOF
//     after the event, exactly as before.
type FileTailer struct {
	Path string
	// StartAtEnd controls first-open behavior when there is no resume state.
	// true  -> start tailing from EOF (default)
	// false -> start reading from BOF (replay existing file contents)
	StartAtEnd bool

	mu         sync.Mutex
	f          *os.File
	r          *bufio.Reader // allocated once; reused via r.Reset() on rotation
	off        int64
	inode      uint64
	lastLineTS int64

	// Idle backoff: limit how often we Stat() at EOF to reduce syscalls.
	idleStatMinInterval time.Duration
	lastEOFStat         time.Time

	// Faster recovery when the path is missing (rm / rotate gap).
	missingStatMinInterval time.Duration

	// Resume position — set via ApplyResume before the first Open().
	LastOffset int64
	LastInode  uint64
}

func NewFileTailer(path string) *FileTailer {
	return &FileTailer{
		Path:                   path,
		StartAtEnd:             true,
		idleStatMinInterval:    200 * time.Millisecond,
		missingStatMinInterval: 50 * time.Millisecond,
	}
}

// ApplyResume sets the resume position (used by manager after loading state).
func (t *FileTailer) ApplyResume(inode, offset uint64) {
	t.LastInode = inode
	t.LastOffset = int64(offset)
}

// Open opens the file and seeks to the correct position.
//
// If the fd is already open (t.f != nil) this is a no-op: the fd, read
// position, and bufio.Reader buffer all remain valid from the previous tick.
// This is the common case and costs zero syscalls.
func (t *FileTailer) Open() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Fast path: fd already open from previous tick.  Nothing to do.
	if t.f != nil {
		return nil
	}

	f, err := os.Open(t.Path)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	curInode := inodeOf(st)

	// Decide starting offset.
	//   No resume info at all  → start at end ("now"), avoid replaying old logs.
	//   Resume known, inode changed (rename+newfile rotation) → start at 0 so we
	//     don't miss lines written to the new file before this tick.
	//   Resume known, same inode → seek to saved offset (or 0 if file was truncated).
	off := int64(0)
	if t.StartAtEnd {
		off = st.Size()
	}
	resumeKnown := t.LastInode != 0 || t.LastOffset != 0
	if resumeKnown && t.LastInode != curInode {
		off = 0
	}
	if t.LastInode == curInode {
		switch {
		case t.LastOffset >= 0 && t.LastOffset <= st.Size():
			off = t.LastOffset
		case t.LastOffset > st.Size():
			off = 0 // truncated
		}
	}

	if _, err := f.Seek(off, io.SeekStart); err != nil {
		_ = f.Close()
		return err
	}

	t.f = f
	// Allocate the reader buffer exactly once.  Subsequent re-opens after
	// rotation will call t.r.Reset(newFile) below, reusing this allocation.
	if t.r == nil {
		t.r = bufio.NewReaderSize(f, 256*1024)
	} else {
		t.r.Reset(f)
	}
	t.inode = curInode
	t.off = off
	return nil
}

// Close is a between-tick checkpoint.
//
// For a single FileTailer (not inside DirTailer) there is nothing to persist
// here — position is saved by run.go via state.Put(pa.Position()) after each
// successful RunOnce.  So this is truly a no-op.
//
// Call Shutdown() for real fd cleanup when the detector stops.
func (t *FileTailer) Close() error {
	return nil
}

// Shutdown closes the file handle.  Safe to call multiple times.
// The bufio.Reader buffer (t.r) is kept alive so that if this tailer is ever
// reopened (e.g. after a daemon reload), Open() can call r.Reset(newFile)
// instead of allocating a fresh 256 KB buffer.
func (t *FileTailer) Shutdown() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f != nil {
		err := t.f.Close()
		t.f = nil
		// t.r intentionally kept: r.Reset(f) on next Open() reuses the buffer.
		return err
	}
	return nil
}

// safeClose closes a file handle, tolerating nil.
func safeClose(f *os.File) error {
	if f == nil {
		return nil
	}
	return f.Close()
}

// reopenAtEndUnlocked reopens the file at its current end (used after a
// rotation where we don't want to replay the old file's tail).
// Caller must hold t.mu.
func (t *FileTailer) reopenAtEndUnlocked() error {
	f, err := os.Open(t.Path)
	if err != nil {
		_ = safeClose(t.f)
		t.f = nil
		return err
	}
	st2, err := f.Stat()
	if err != nil {
		_ = safeClose(f)
		_ = safeClose(t.f)
		t.f = nil
		return err
	}
	end := st2.Size()
	if _, err := f.Seek(end, io.SeekStart); err != nil {
		_ = safeClose(f)
		_ = safeClose(t.f)
		t.f = nil
		return err
	}
	_ = safeClose(t.f)
	t.f = f
	// Reuse the existing reader buffer — just swap the underlying fd.
	if t.r == nil {
		t.r = bufio.NewReaderSize(f, 256*1024)
	} else {
		t.r.Reset(f)
	}
	t.inode = inodeOf(st2)
	t.off = end
	t.lastEOFStat = time.Time{}
	return nil
}

// reopenAtStartUnlocked reopens the file at offset 0 (used after rotation or
// truncation where we want to read from the beginning of the new/reset file).
// Caller must hold t.mu.
func (t *FileTailer) reopenAtStartUnlocked() error {
	f, err := os.Open(t.Path)
	if err != nil {
		_ = safeClose(t.f)
		t.f = nil
		return err
	}
	st2, err := f.Stat()
	if err != nil {
		_ = safeClose(f)
		_ = safeClose(t.f)
		t.f = nil
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = safeClose(f)
		_ = safeClose(t.f)
		t.f = nil
		return err
	}
	_ = safeClose(t.f)
	t.f = f
	// Reuse the existing reader buffer — just swap the underlying fd.
	if t.r == nil {
		t.r = bufio.NewReaderSize(f, 256*1024)
	} else {
		t.r.Reset(f)
	}
	t.inode = inodeOf(st2)
	t.off = 0
	t.lastEOFStat = time.Time{}
	return nil
}

func (t *FileTailer) ReadNext(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// ── fd missing (deleted file, or Open() failed) ──────────────────────────
	if t.f == nil {
		// Rate-limited re-stat: avoid hammering the VFS while the file is absent.
		now := time.Now()
		minInt := t.missingStatMinInterval
		if minInt <= 0 {
			minInt = 50 * time.Millisecond
		}
		if !t.lastEOFStat.IsZero() && now.Sub(t.lastEOFStat) < minInt {
			return "", io.EOF
		}
		t.lastEOFStat = now
		if _, err := os.Stat(t.Path); err == nil {
			_ = t.reopenAtStartUnlocked()
		}
		return "", io.EOF
	}

	// ── fast path: read one line ──────────────────────────────────────────────
	// We deliberately skip Stat() on every read — it's done only at EOF.
	// ReadSlice (NOT ReadString/ReadBytes): those accumulate an un-delimited
	// stream WITHOUT bound (collectFragments grows a []byte until the delimiter
	// or EOF; the buffer size only limits a single fill), so a pathological
	// oversized log line would OOM the detector — and the ErrBufferFull-drain
	// below was DEAD CODE because ReadString never returns ErrBufferFull.
	// ReadSlice caps each read at the buffer and returns ErrBufferFull, which
	// makes that drain live. Same fix as the ingest socket (audit F26).
	line, err := t.r.ReadSlice('\n')
	if err == nil {
		t.off += int64(len(line))
		t.lastLineTS = time.Now().Unix()
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		// ReadSlice returns a slice into t.r's buffer, invalidated by the next
		// read — copy to a string before returning it to the retaining caller.
		return string(line), nil
	}

	// ── oversized line (content ≥ 256 KiB, fills the buffer) ─────────────────
	// ReadSlice returned a full-buffer fragment + bufio.ErrBufferFull. Drain to
	// the next newline (advancing the offset so resume skips the bad line);
	// without draining we'd re-read the same fragment forever and freeze the
	// detector. Memory stays bounded to the buffer.
	if err == bufio.ErrBufferFull {
		if len(line) > 0 {
			t.off += int64(len(line))
		}
		dropped := len(line)
		for {
			// Bound the per-call drain. A regular access log hits EOF long before
			// this, but a misconfigured LOG_PATH (a FIFO, or a huge newline-free
			// blob) could otherwise drain gigabytes while holding t.mu in a single
			// call. Cap it and resume on the next call — t.off already advanced, so
			// this makes forward progress rather than erroring (unlike the shared
			// readBoundedLine, which resets its subprocess source instead).
			if dropped > maxLineDrain {
				t.lastLineTS = time.Now().Unix()
				return "", nil
			}
			frag, e2 := t.r.ReadSlice('\n')
			if len(frag) > 0 {
				t.off += int64(len(frag))
				dropped += len(frag)
			}
			if e2 == nil {
				t.lastLineTS = time.Now().Unix()
				return "", nil // oversized line skipped; caller ignores empty
			}
			if e2 == bufio.ErrBufferFull {
				continue
			}
			if e2 == io.EOF {
				return "", io.EOF
			}
			return "", e2
		}
	}

	// ── EOF: check for rotation / truncation ─────────────────────────────────
	if err == io.EOF {
		// Rate-limit the Stat() to keep the non-blocking contract while idle.
		now := time.Now()
		if t.idleStatMinInterval > 0 && !t.lastEOFStat.IsZero() &&
			now.Sub(t.lastEOFStat) < t.idleStatMinInterval {
			return "", io.EOF
		}
		t.lastEOFStat = now

		// Stat the PATH (not the fd) to detect rename+newfile rotation.
		st, serr := os.Stat(t.Path)
		if serr != nil {
			// File deleted (rm -f, rotate+delete).
			// Close the stale fd; ReadNext will reopen when the file reappears.
			_ = safeClose(t.f)
			t.f = nil
			// t.r intentionally kept — Reset() on next reopen reuses the buffer.
			t.inode = 0
			t.lastEOFStat = time.Now()
			return "", io.EOF
		}

		curIn := inodeOf(st)
		if curIn != t.inode || t.off > st.Size() {
			// Rotation (new inode) or truncation (echo > file, same inode, size shrank).
			// Read from start so we don't miss lines written to the new/reset file.
			_ = t.reopenAtStartUnlocked()
		}
		return "", io.EOF
	}

	return "", err
}

// SetIdleStatInterval overrides how often Stat() is called while the tailer
// is idle at EOF.  Zero disables rate limiting.
func (t *FileTailer) SetIdleStatInterval(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.idleStatMinInterval = d
	t.lastEOFStat = time.Time{}
}

func (t *FileTailer) Position() (offset uint64, inode uint64, ts int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return uint64(t.off), t.inode, t.lastLineTS
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
