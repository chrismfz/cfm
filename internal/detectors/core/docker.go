// internal/detectors/core/docker.go
package core

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DockerTailer implements LineSource using `docker logs`.
type DockerTailer struct {
	Container string   // e.g. "mailcowdockerized-postfix-mailcow-1"
	ExtraArgs []string // optional extra args (e.g. ["--details"])

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdout io.ReadCloser
	reader *bufio.Reader

	lastTS  int64
	startTS int64
}

func NewDockerTailer(container string, extraArgs ...string) *DockerTailer {
	return &DockerTailer{
		Container: container,
		ExtraArgs: extraArgs,
	}
}

func (d *DockerTailer) ApplyResume(inode, offset uint64, ts int64) {
	d.lastTS = ts
}

func (d *DockerTailer) SetStartTS(ts int64) { d.startTS = ts }

func (d *DockerTailer) Open() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	args := []string{"logs"}
	since := d.lastTS
	if d.startTS > 0 {
		since = d.startTS
	}
	if since > 0 {
		t := time.Unix(since+1, 0).UTC()
		args = append(args, "--since", t.Format(time.RFC3339))
	}

	hasTail := false
	for _, a := range d.ExtraArgs {
		if strings.HasPrefix(a, "--tail") {
			hasTail = true
			break
		}
	}
	if !hasTail && since == 0 {
		args = append(args, "--tail", "0")
	}

	args = append(args, d.ExtraArgs...)
	args = append(args, d.Container)

	cmd := exec.Command("docker", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	d.cmd = cmd
	d.stdout = stdout
	d.reader = bufio.NewReaderSize(stdout, 256*1024)
	return nil
}

// Close is a between-tick no-op for DockerTailer.
// docker logs is a one-shot process; real cleanup happens in Shutdown().
func (d *DockerTailer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cleanupLocked(false)
}

// Shutdown terminates the docker logs process and releases resources.
func (d *DockerTailer) Shutdown() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cleanupLocked(true)
}

func (d *DockerTailer) cleanupLocked(kill bool) error {
	if d.stdout != nil {
		_ = d.stdout.Close()
		d.stdout = nil
	}
	var waitErr error
	if d.cmd != nil {
		if kill && d.cmd.Process != nil {
			_ = d.cmd.Process.Kill()
		}
		waitErr = d.cmd.Wait()
		d.cmd = nil
	}
	d.reader = nil
	return waitErr
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
		// readBoundedLine, not ReadString: ReadString accumulates an un-delimited
		// stream without bound (a compromised container's stdout could OOM us).
		line, err := readBoundedLine(r)
		ch <- res{line, err}
	}(d.reader)

	select {
	case <-ctx.Done():
		return "", io.EOF
	case out := <-ch:
		if out.err != nil {
			// errOversizedLine (a never-terminated line past the drain cap) ends
			// this tick; Close() kills the process and the next tick respawns it.
			// A container that keeps streaming newline-free data makes no forward
			// progress but is tick-paced and bounded to ~8 MB — far better than the
			// pre-fix unbounded accumulation (OOM).
			if out.err == io.EOF {
				return "", io.EOF
			}
			return "", out.err
		}
		// readBoundedLine already stripped the trailing '\n'; this now also strips a
		// trailing '\r', so a CRLF docker line yields "foo" rather than the pre-fix
		// "foo\r" (a latent dangling-CR fix, not a regression).
		line := out.line
		if len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
			line = line[:len(line)-1]
		}
		d.lastTS = time.Now().Unix()
		return line, nil
	}
}

func (d *DockerTailer) Position() (offset uint64, inode uint64, ts int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return 0, 0, d.lastTS
}
