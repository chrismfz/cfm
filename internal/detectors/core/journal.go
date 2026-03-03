package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// JournalTailer implements LineSource by invoking `journalctl`.
// It fetches NEW entries since the last known timestamp (Position.TS).
// Position() reports the most-recent timestamp we observed.
type JournalTailer struct {
	Unit    string   // e.g. "sshd.service"
	Matches []string // optional journalctl match expressions

	mu      sync.Mutex
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	reader  *bufio.Reader
	lastTS  int64
	startTS int64
}

func NewJournalTailer(unit string) *JournalTailer {
	return &JournalTailer{Unit: unit}
}

func (j *JournalTailer) ApplyResume(inode, offset uint64, ts int64) {
	j.lastTS = ts
}

func (j *JournalTailer) setStartTS(ts int64) { j.startTS = ts }

func (j *JournalTailer) Open() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	args := []string{"-o", "short-unix", "--no-pager"}
	since := j.lastTS
	if j.startTS > 0 {
		since = j.startTS
	}
	// journalctl --since is inclusive; bump by +1s to avoid replaying the
	// last seen entry on the next tick.
	if since > 0 {
		since++
	}
	if since <= 1 {
		args = append(args, "--since=now")
	} else {
		args = append(args, "--since=@"+strconv.FormatInt(since, 10))
	}
	if j.Unit != "" {
		args = append(args, "-u", j.Unit)
	}
	for _, m := range j.Matches {
		if m != "" {
			args = append(args, m)
		}
	}

	cmd := exec.Command("journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	j.cmd = cmd
	j.stdout = stdout
	j.reader = bufio.NewReaderSize(stdout, 256*1024)
	return nil
}

// Close is a between-tick no-op for JournalTailer.
// journalctl is a one-shot process that exits at EOF anyway; the real
// cleanup happens in Shutdown().
func (j *JournalTailer) Close() error {
	return nil
}

// Shutdown terminates the journalctl process and releases resources.
func (j *JournalTailer) Shutdown() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.stdout != nil {
		_ = j.stdout.Close()
		j.stdout = nil
	}
	if j.cmd != nil && j.cmd.Process != nil {
		_ = j.cmd.Process.Kill()
		_, _ = j.cmd.Process.Wait()
		j.cmd = nil
	}
	j.reader = nil
	return nil
}

func (j *JournalTailer) ReadNext(ctx context.Context) (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.reader == nil {
		return "", io.EOF
	}

	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func(r *bufio.Reader) {
		line, err := r.ReadString('\n')
		ch <- res{line, err}
	}(j.reader)

	select {
	case <-ctx.Done():
		return "", io.EOF
	case out := <-ch:
		if out.err != nil {
			if out.err == io.EOF {
				return "", io.EOF
			}
			return "", out.err
		}
		line := strings.TrimRight(out.line, "\r\n")
		// Format: "<secs>.<usec> <rest>"
		if i := strings.IndexByte(line, ' '); i > 0 {
			tsStr := line[:i]
			if dot := strings.IndexByte(tsStr, '.'); dot > 0 {
				tsStr = tsStr[:dot]
			}
			if sec, err := strconv.ParseInt(tsStr, 10, 64); err == nil && sec > j.lastTS {
				j.lastTS = sec
			}
			line = line[i+1:]
		}
		return line, nil
	}
}

func (j *JournalTailer) Position() (offset uint64, inode uint64, ts int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return 0, 0, j.lastTS
}

func (j *JournalTailer) String() string {
	since := "now"
	if j.startTS > 0 {
		since = "@" + strconv.FormatInt(j.startTS+1, 10)
	} else if j.lastTS > 0 {
		since = "@" + strconv.FormatInt(j.lastTS+1, 10)
	}
	filter := j.Unit
	if filter == "" && len(j.Matches) > 0 {
		filter = strings.Join(j.Matches, " ")
	}
	return fmt.Sprintf("journalctl --since=%s -o short-unix %s", since, filter)
}
