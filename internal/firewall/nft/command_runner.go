package nft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const defaultNFTCommandTimeout = 10 * time.Second

// nftSem limits the number of concurrent nft subprocesses to prevent fork-storm
// conditions during large feed updates or high-frequency detector activity.
// Four concurrent nft processes is enough for parallelism without saturating the
// fork table. Operations that cannot acquire a slot wait until one is free.
var nftSem = make(chan struct{}, 4)

func acquireSem(ctx context.Context) error {
	select {
	case nftSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func releaseSem() { <-nftSem }

type commandErrorMeta struct {
	ExitCode   int
	TimedOut   bool
	Canceled   bool
	StderrTail string
}

type commandResult struct {
	Stdout string
	Stderr string
	Meta   commandErrorMeta
}

func runCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (commandResult, error) {
	return runCommandLimited(ctx, timeout, 0, name, args...)
}

func runCommandLimited(ctx context.Context, timeout time.Duration, maxStdout int, name string, args ...string) (commandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		if timeout <= 0 {
			timeout = defaultNFTCommandTimeout
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	if err := acquireSem(ctx); err != nil {
		return commandResult{}, err
	}
	defer releaseSem()

	cmd := exec.CommandContext(ctx, name, args...)
	stdout := limitedBuffer{max: maxStdout}
	stderr := tailBuffer{max: 64 << 10}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	res := commandResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil && stdout.truncated {
		return res, fmt.Errorf("%s %s output exceeds %d bytes", name, strings.Join(args, " "), maxStdout)
	}
	if err == nil {
		return res, nil
	}

	meta := commandErrorMeta{ExitCode: -1, StderrTail: stderrSnippet(res.Stderr)}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		meta.TimedOut = true
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		meta.Canceled = true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		meta.ExitCode = ee.ExitCode()
	}
	res.Meta = meta
	return res, &commandExecError{Name: name, Args: args, Meta: meta, Err: err}
}

type limitedBuffer struct {
	bytes.Buffer
	max       int
	truncated bool
}

type tailBuffer struct {
	buf []byte
	max int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.max <= 0 {
		return n, nil
	}
	if len(p) >= b.max {
		b.buf = append(b.buf[:0], p[len(p)-b.max:]...)
		return n, nil
	}
	overflow := len(b.buf) + len(p) - b.max
	if overflow > 0 {
		copy(b.buf, b.buf[overflow:])
		b.buf = b.buf[:len(b.buf)-overflow]
	}
	b.buf = append(b.buf, p...)
	return n, nil
}

func (b *tailBuffer) String() string { return string(b.buf) }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.max <= 0 {
		_, err := b.Buffer.Write(p)
		return n, err
	}
	remaining := b.max - b.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.Buffer.Write(p[:remaining])
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return n, nil
}

type commandExecError struct {
	Name string
	Args []string
	Meta commandErrorMeta
	Err  error
}

func (e *commandExecError) Error() string {
	parts := []string{fmt.Sprintf("%s %s failed: %v", e.Name, strings.Join(e.Args, " "), e.Err)}
	if e.Meta.ExitCode >= 0 {
		parts = append(parts, "exit_code="+strconv.Itoa(e.Meta.ExitCode))
	}
	if e.Meta.TimedOut {
		parts = append(parts, "timed_out=true")
	}
	if e.Meta.Canceled {
		parts = append(parts, "canceled=true")
	}
	if e.Meta.StderrTail != "" {
		parts = append(parts, "stderr="+strconv.Quote(e.Meta.StderrTail))
	}
	return strings.Join(parts, " ")
}

func (e *commandExecError) Unwrap() error { return e.Err }

func stderrSnippet(s string) string {
	s = strings.TrimSpace(s)
	const max = 240
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}

func runNFTCommand(ctx context.Context, args ...string) (commandResult, error) {
	return runCommand(ctx, defaultNFTCommandTimeout, "nft", args...)
}

// ListRulesetJSON returns the host-wide nftables ruleset in terse JSON form.
// It is intentionally fixed-argument: diagnostics need third-party tables,
// but callers must not be able to turn this read path into arbitrary nft input.
func ListRulesetJSON(ctx context.Context) ([]byte, error) {
	const maxRulesetJSON = 8 << 20
	res, err := runCommandLimited(ctx, defaultNFTCommandTimeout, maxRulesetJSON, "nft", "-j", "-t", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	return []byte(res.Stdout), nil
}

// HostRulesetJSON implements the optional CLI diagnostic probe.
func (b *Backend) HostRulesetJSON() ([]byte, error) {
	return ListRulesetJSON(context.Background())
}

func runNFTCommandInput(ctx context.Context, input string, args ...string) (commandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultNFTCommandTimeout)
		defer cancel()
	}

	if err := acquireSem(ctx); err != nil {
		return commandResult{}, err
	}
	defer releaseSem()

	cmd := exec.CommandContext(ctx, "nft", args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := commandResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		return res, nil
	}
	meta := commandErrorMeta{ExitCode: -1, StderrTail: stderrSnippet(res.Stderr)}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		meta.TimedOut = true
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		meta.Canceled = true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		meta.ExitCode = ee.ExitCode()
	}
	res.Meta = meta
	return res, &commandExecError{Name: "nft", Args: args, Meta: meta, Err: err}
}
