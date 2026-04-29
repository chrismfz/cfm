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

func acquireSem() { nftSem <- struct{}{} }
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

	acquireSem()
	defer releaseSem()

	cmd := exec.CommandContext(ctx, name, args...)
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
	return res, &commandExecError{Name: name, Args: args, Meta: meta, Err: err}
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

func runNFTCommandInput(ctx context.Context, input string, args ...string) (commandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultNFTCommandTimeout)
		defer cancel()
	}

	acquireSem()
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
