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

// LineSource is a generic, non-blocking line iterator for logs.
// ReadNext returns (line, nil) when a full line is available,
// and ("", io.EOF) when the source is caught up.
// It MUST NOT block waiting for new lines; detectors call it in a loop per RunOnce.
type LineSource interface {
	Open() error
	ReadNext(ctx context.Context) (string, error)
	Position() (offset uint64, inode uint64, ts int64)
	Close() error
}

// FileTailer implements LineSource for plain files with rotation awareness.
type FileTailer struct {
	Path       string
	mu         sync.Mutex
	f          *os.File
	r          *bufio.Reader
	off        int64
	inode      uint64
	lastLineTS int64

        // Idle backoff: limit how often we Stat() at EOF (non-blocking).
        idleStatMinInterval time.Duration
        lastEOFStat         time.Time

	// Optional: resume position (set via ApplyResume)
	LastOffset int64
	LastInode  uint64
}

// Optional explicit resume (used by manager after loading state).

func (t *FileTailer) ApplyResume(inode, offset uint64) {
	t.LastInode = inode
	t.LastOffset = int64(offset)
}

func NewFileTailer(path string) *FileTailer {
        return &FileTailer{
                Path:                path,
                // sensible default: only check rotation at most 5x/sec when idle
                idleStatMinInterval: 200 * time.Millisecond,
        }
}

func (t *FileTailer) Open() error {
	t.mu.Lock()
	defer t.mu.Unlock()

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

	// Decide starting offset: resume if valid, else start at end ("now")
	//off := st.Size() //old method
	// Decide starting offset.
	// If we have NO resume info at all => start at end ("now") to avoid replaying old logs.
	// If we DO have resume info and inode changed (rotate rename+newfile) => start at 0
	// so we don't miss lines already written to the new file before this tick.
	off := st.Size()
	resumeKnown := (t.LastInode != 0 || t.LastOffset != 0)
	if resumeKnown && t.LastInode != curInode {
		off = 0
	}

	if t.LastInode == curInode {
		switch {
		case t.LastOffset >= 0 && t.LastOffset <= st.Size():
			off = t.LastOffset
		case t.LastOffset > st.Size():
			// file was truncated (e.g., logrotate with truncate)
			// start from beginning to avoid missing any new lines
			off = 0
		}
	}


    if _, err := f.Seek(off, io.SeekStart); err != nil {
        _ = f.Close()
        return err
    }

	t.f = f
	t.r = bufio.NewReaderSize(f, 256*1024)
	t.inode = curInode
	t.off = off
	return nil
}







// safeClose ensures file handles are closed safely
func safeClose(f *os.File) error {
    if f == nil {
        return nil
    }
    return f.Close()
}

// reopenAtEndUnlocked reopens the tailed file at its end after rotation/truncate.
// Caller must hold t.mu.
func (t *FileTailer) reopenAtEndUnlocked() error {
    f, err := os.Open(t.Path)
    if err != nil {
        _ = safeClose(t.f)
        t.f, t.r = nil, nil
        return err
    }

    st2, err := f.Stat()
    if err != nil {
        _ = safeClose(f)
        _ = safeClose(t.f)
        t.f, t.r = nil, nil
        return err
    }

    end := st2.Size()
    if _, err := f.Seek(end, io.SeekStart); err != nil {
        _ = safeClose(f)
        _ = safeClose(t.f)
        t.f, t.r = nil, nil
        return err
    }

    _ = safeClose(t.f)
    t.f = f
    t.r = bufio.NewReaderSize(f, 256*1024)
    t.inode = inodeOf(st2)
    t.off = end
    t.lastEOFStat = time.Time{}
    return nil
}




// reopenAtStartUnlocked reopens the tailed file at offset 0.
// Caller must hold t.mu.
func (t *FileTailer) reopenAtStartUnlocked() error {
    f, err := os.Open(t.Path)
    if err != nil {
        _ = safeClose(t.f)
        t.f, t.r = nil, nil
        return err
    }
    st2, err := f.Stat()
    if err != nil {
        _ = safeClose(f)
        _ = safeClose(t.f)
        t.f, t.r = nil, nil
        return err
    }
    if _, err := f.Seek(0, io.SeekStart); err != nil {
        _ = safeClose(f)
        _ = safeClose(t.f)
        t.f, t.r = nil, nil
        return err
    }
    _ = safeClose(t.f)
    t.f = f
    t.r = bufio.NewReaderSize(f, 256*1024)
    t.inode = inodeOf(st2)
    t.off = 0
    t.lastEOFStat = time.Time{}
    return nil
}






func (t *FileTailer) ReadNext(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.f == nil {
		return "", io.EOF
	}

       // NOTE: We deliberately avoid Stat() here.
       // We only Stat on EOF to detect rotation/truncate, which removes a syscall per line.
	// Attempt one line (non-blocking)
	line, err := t.r.ReadString('\n')
	if err != nil {

               if err == io.EOF {
                       // We are caught up. Optionally check for rotation/truncate,
                       // but rate-limit this Stat() while idle to reduce syscalls.
                       now := time.Now()
                       if t.idleStatMinInterval > 0 && !t.lastEOFStat.IsZero() &&
                               now.Sub(t.lastEOFStat) < t.idleStatMinInterval {
                               return "", io.EOF
                       }
                       t.lastEOFStat = now

                       // Check for rotation/truncate (non-blocking path).


                       // IMPORTANT: stat the PATH, not the FD, so we can detect rename+newfile rotation.
                       st, serr := os.Stat(t.Path)
                       if serr != nil {
                               // Keep non-blocking contract, but don't rotate on stat failure
                               return "", io.EOF
                       }

                       curIn := inodeOf(st)
                       if curIn != t.inode || t.off > st.Size() {
                               // After rotate/truncate, read from start to avoid missing lines written
                               // before this tick (webdetector is non-blocking + closes each run).
                               _ = t.reopenAtStartUnlocked()
                       }
                       return "", io.EOF
               }
               return "", err



	}
	t.off += int64(len(line))
	t.lastLineTS = time.Now().Unix()
	// trim trailing newline
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	return line, nil
}




// SetIdleStatInterval lets callers override how often Stat() is allowed
// while the tailer is idle (at EOF). Zero disables the rate limit.
func (t *FileTailer) SetIdleStatInterval(d time.Duration) {
        t.mu.Lock()
        defer t.mu.Unlock()
        t.idleStatMinInterval = d
        // reset timer so next EOF can check immediately
        t.lastEOFStat = time.Time{}
}




func (t *FileTailer) Position() (offset uint64, inode uint64, ts int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return uint64(t.off), t.inode, t.lastLineTS
}

func (t *FileTailer) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f != nil {
		err := t.f.Close()
		t.f = nil
		t.r = nil
		return err
	}
	return nil
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
