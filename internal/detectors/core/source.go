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
	return &FileTailer{Path: path}
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
		f.Close()
		return err
	}
	curInode := inodeOf(st)

	// Decide starting offset: resume if valid, else start at end ("now")
	off := st.Size()

if t.LastOffset > 0 && t.LastOffset <= st.Size() && t.LastInode == curInode {
	off = t.LastOffset
}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return err
	}

	t.f = f
	t.r = bufio.NewReaderSize(f, 256*1024)
	t.inode = curInode
	t.off = off
	return nil
}

func (t *FileTailer) ReadNext(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.f == nil {
		return "", io.EOF
	}

	// Detect rotation/truncate before read
	st, err := t.f.Stat()
	if err == nil {
		curIn := inodeOf(st)
		if curIn != t.inode || t.off > st.Size() {
			// Reopen and jump to end ("now")
			_ = t.f.Close()
			f, err := os.Open(t.Path)
			if err != nil {
				t.f = nil
				t.r = nil
				return "", io.EOF
			}
			st2, _ := f.Stat()
			end := st2.Size()
			if _, err := f.Seek(end, io.SeekStart); err != nil {
				f.Close()
				t.f = nil
				t.r = nil
				return "", io.EOF
			}
			t.f = f
			t.r = bufio.NewReaderSize(f, 256*1024)
			t.inode = inodeOf(st2)
			t.off = end
		}
	}

	// Attempt one line (non-blocking)
	line, err := t.r.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return "", io.EOF // caught up
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
