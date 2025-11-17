// internal/detectors/core/docker.go
package core

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"sync"
	"time"
)

// DockerTailer implements LineSource using `docker logs`.
type DockerTailer struct {
	Container string   // π.χ. "mailcowdockerized-postfix-mailcow-1"
	ExtraArgs []string // optional extra args (e.g. ["--details"])

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdout io.ReadCloser
	reader *bufio.Reader

	lastTS  int64 // Unix seconds of last seen line (for resume)
	startTS int64 // optional explicit start (can be set by detector)
}

// NewDockerTailer creates a new tailer for given container.
func NewDockerTailer(container string, extraArgs ...string) *DockerTailer {
	return &DockerTailer{
		Container: container,
		ExtraArgs: extraArgs,
	}
}

// ApplyResume: we χρησιμοποιούμε μόνο το TS, όπως στο JournalTailer.
func (d *DockerTailer) ApplyResume(inode, offset uint64, ts int64) {
	d.lastTS = ts
}

// Optional: allow detector να ορίσει "από πότε" explicit.
func (d *DockerTailer) SetStartTS(ts int64) { d.startTS = ts }

// Open starts a one-shot `docker logs` process.
func (d *DockerTailer) Open() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	args := []string{"logs", "--timestamps"}

	// Από πότε:
	since := d.lastTS
	if d.startTS > 0 {
		since = d.startTS
	}
	if since > 0 {
		// docker περιμένει RFC3339
		t := time.Unix(since+1, 0).UTC()
		args = append(args, "--since", t.Format(time.RFC3339))
	} else {
		// Πρώτο run: για να μην μας πνίξει ιστορικό, μπορείς να βάλεις tail=0 ή tail=N.
		args = append(args, "--tail", "0")
	}

	// Extra args από config, αν υπάρχουν (π.χ. --details).
	args = append(args, d.ExtraArgs...)

	// Τέλος, το container name
	args = append(args, d.Container)

	cmd := exec.Command("docker", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	// stderr το αφήνουμε να χαθεί ή μπορείς να το κατευθύνεις σε /dev/null
	if err := cmd.Start(); err != nil {
		return err
	}

	d.cmd = cmd
	d.stdout = stdout
	d.reader = bufio.NewReaderSize(stdout, 256*1024)
	return nil
}

func (d *DockerTailer) ReadNext(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.reader == nil {
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
	}(d.reader)

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
		line := out.line
		// Trim CRLF
		if len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
			line = line[:len(line)-1]
		}
		// Εδώ θα μπορούσαμε να κάνουμε parsing Docker timestamps αν χρειαστεί.
		// Για απλότητα (και να μην εξαρτόμαστε από format), κρατάμε "πότε" το διαβάσαμε.
		d.lastTS = time.Now().Unix()

		return line, nil
	}
}

func (d *DockerTailer) Position() (offset uint64, inode uint64, ts int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Δεν έχουμε έννοια offset/inode στο docker logs, μόνο TS.
	return 0, 0, d.lastTS
}

func (d *DockerTailer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stdout != nil {
		_ = d.stdout.Close()
		d.stdout = nil
	}
	if d.cmd != nil && d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
		_, _ = d.cmd.Process.Wait()
		d.cmd = nil
	}
	d.reader = nil
	return nil
}
