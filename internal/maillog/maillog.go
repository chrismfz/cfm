// Package maillog does on-demand, bounded tails of the mail logs — exim
// (exim_mainlog), dovecot, and postfix. It backs the read-only MCP tool
// `mail_log_tail` via GET /api/v1/system/mail-log?which=exim|dovecot|postfix.
//
// This is the raw-log enabler for outbound-abuse investigations: the exim
// mainlog is where `A=dovecot_login:<user>` (authenticated senders) and
// `cwd=/home/<user>/…` (injecting scripts) live, and neither is reachable from
// any other read tool.
//
// Same cost discipline as mysql_log_tail / dmesg_tail / ip_forensics: NO
// continuous overhead — nothing retained. A call reads only the last N lines via
// `tail -n N` (backward from EOF, so a multi-GB log is never read whole), under a
// timeout, with an optional case-insensitive grep and a capped result. The log
// path is resolved from a fixed per-service candidate allow-list — never a
// caller-supplied path.
package maillog

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	DefaultLines  = 500
	MaxLines      = 20000
	DefaultLimit  = 200
	MaxLimit      = 2000
	maxStoredLine = 16 * 1024 // a wrapped SMTP response / long header can be long
	scanTimeout   = 20 * time.Second
	readerBufSize = 1024 * 1024
)

// candidates lists the standard log paths per service, in resolution order.
// Fixed allow-list — the caller only picks a `which`, never a path. The exim
// set mirrors the exim/queues detector's mainlog candidates; dovecot/postfix on
// RHEL/cPanel share /var/log/maillog, on Debian/Ubuntu /var/log/mail.log.
var candidates = map[string][]string{
	"exim": {
		"/var/log/exim_mainlog",
		"/var/log/exim/mainlog",
		"/var/log/exim4/mainlog",
	},
	"dovecot": {
		"/var/log/maillog",
		"/var/log/mail.log",
		"/var/log/dovecot.log",
		"/var/log/dovecot-info.log",
	},
	"postfix": {
		"/var/log/maillog",
		"/var/log/mail.log",
		"/var/log/postfix.log",
	},
}

// Which returns the sorted set of valid `which` values (for docs/validation).
func Which() []string { return []string{"exim", "dovecot", "postfix"} }

// Result is one log-tail outcome.
type Result struct {
	Kind      string   `json:"kind"` // exim | dovecot | postfix
	LogFile   string   `json:"log_file"`
	Found     bool     `json:"found"` // false when no candidate log exists (service not installed / logs elsewhere)
	Lines     []string `json:"lines"`
	Scanned   int      `json:"scanned"`
	Matched   int      `json:"matched"`
	Truncated bool     `json:"truncated"`
}

// Tail returns the last matching lines of the exim/dovecot/postfix log. A
// missing log is NOT an error — Found=false is returned so the caller can say
// "that MTA/service isn't logging here" rather than failing.
func Tail(ctx context.Context, which string, lines, limit int, grep string) (Result, error) {
	which = strings.ToLower(strings.TrimSpace(which))
	if which == "" {
		which = "exim"
	}
	paths, ok := candidates[which]
	if !ok {
		return Result{}, fmt.Errorf("unknown mail log %q (want exim|dovecot|postfix)", which)
	}
	if lines <= 0 {
		lines = DefaultLines
	}
	if lines > MaxLines {
		lines = MaxLines
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	logFile := ""
	for _, p := range paths {
		if fileExists(p) {
			logFile = p
			break
		}
	}
	res := Result{Kind: which, LogFile: logFile, Lines: make([]string, 0, limit)}
	if logFile == "" {
		return res, nil // Found=false, not an error
	}
	res.Found = true

	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	g := strings.ToLower(strings.TrimSpace(grep))
	err := streamTail(cctx, logFile, lines, func(line string) {
		res.Scanned++
		if g != "" && !strings.Contains(strings.ToLower(line), g) {
			return
		}
		res.Matched++
		if len(res.Lines) < limit {
			res.Lines = append(res.Lines, truncLine(line))
		} else {
			res.Truncated = true
		}
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// ScanTail streams the last `lines` lines of the `which` mail log to fn, with NO
// result cap — for callers that COUNT/classify over the whole tail window rather
// than return lines for display (Tail is the capped display variant). Returns the
// resolved log file ("" when none exists, in which case fn is never called), the
// number of lines scanned, and any error. Same bounded `tail -n N` backward read
// + timeout as Tail; the log path comes from the fixed candidate allow-list,
// never the caller.
func ScanTail(ctx context.Context, which string, lines int, fn func(string)) (logFile string, scanned int, err error) {
	which = strings.ToLower(strings.TrimSpace(which))
	if which == "" {
		which = "exim"
	}
	paths, ok := candidates[which]
	if !ok {
		return "", 0, fmt.Errorf("unknown mail log %q (want exim|dovecot|postfix)", which)
	}
	if lines <= 0 {
		lines = DefaultLines
	}
	if lines > MaxLines {
		lines = MaxLines
	}
	for _, p := range paths {
		if fileExists(p) {
			logFile = p
			break
		}
	}
	if logFile == "" {
		return "", 0, nil // no candidate log → not an error
	}
	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	err = streamTail(cctx, logFile, lines, func(line string) {
		scanned++
		fn(line)
	})
	return logFile, scanned, err
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// streamTail runs `tail -n N file`, feeding each line to fn. tail reads backward
// from EOF, so the read is bounded to the tail window regardless of file size.
// Over-long lines are truncated (not fatal) via a bounded bufio.Reader — mirrors
// mysqllog.streamTail (the fix for the bufio.Scanner "token too long" 502).
//
// A non-zero `tail` exit (file unreadable, or rotated/removed in the race window
// between the caller's existence check and exec) is surfaced as an error rather
// than swallowed: swallowing it would return a CLEAN EMPTY read, which a
// saturation-signal caller (mailruntime's 1a-sig collector) would then read as
// "log quiet, all healthy" — exactly the "unknown must never read as OK" trap
// (CLAUDE.md §6). The timeout and read-error cases keep priority over it.
func streamTail(ctx context.Context, file string, lines int, fn func(string)) error {
	cmd := exec.CommandContext(ctx, tailPath(), "-n", fmt.Sprintf("%d", lines), file)
	var stderr bytes.Buffer // tail writes a single short diagnostic line; no cap needed
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		stdout.Close()
		return err
	}
	r := bufio.NewReaderSize(stdout, readerBufSize)
	readErr := scanBoundedLines(r, fn)
	_, _ = io.Copy(io.Discard, stdout) // drain so tail can exit
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return fmt.Errorf("scan timed out after %s", scanTimeout)
	}
	if readErr != nil {
		return readErr
	}
	if waitErr != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("tail failed: %v: %s", waitErr, msg)
		}
		return fmt.Errorf("tail failed: %v", waitErr)
	}
	return nil
}

// scanBoundedLines reads newline-delimited lines from r, emitting each via fn. A
// line longer than r's buffer is emitted truncated to the buffer prefix and the
// rest discarded up to the next newline, so memory is bounded and an over-long
// line is never fatal. Unit-tested. io.EOF is the normal terminator.
func scanBoundedLines(r *bufio.Reader, fn func(string)) error {
	for {
		chunk, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			fn(strings.TrimRight(string(chunk), "\r\n"))
			for err == bufio.ErrBufferFull {
				_, err = r.ReadSlice('\n')
			}
			if err == nil {
				continue
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(chunk) > 0 {
			fn(strings.TrimRight(string(chunk), "\r\n"))
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func truncLine(s string) string {
	if len(s) <= maxStoredLine {
		return s
	}
	return s[:maxStoredLine] + "…"
}

func tailPath() string {
	if p, err := exec.LookPath("tail"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/tail", "/bin/tail"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "tail"
}
