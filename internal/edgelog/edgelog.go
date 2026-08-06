// Package edgelog does on-demand, bounded lookups of one source IP in the edge
// (OpenResty/Angie) access log — the "what did this IP actually request?" raw
// context an operator would otherwise get by hand with
// `tail -n N access.log | grep <ip>`. It backs the read-only MCP tool
// `ip_forensics` / GET /api/v1/system/ip-forensics.
//
// Cost discipline (this is the whole point): there is NO continuous overhead —
// nothing is retained, no ring, no DB, no background scan. Work happens ONLY on
// an explicit call, and is bounded from every side:
//   - reads only the last N lines via `tail -n N` (tail seeks backward from EOF,
//     so a multi-GB log is NOT read whole — I/O is bounded to the tail window);
//   - a context timeout caps wall-clock even on a pathological file;
//   - the returned match set is hard-capped.
//
// The target log is auto-detected from a fixed allow-list of known edge access
// logs — never an arbitrary caller-supplied path.
package edgelog

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// accessLogCandidates are the known CFM edge access logs, in priority order
// (OpenResty first, then Angie; main log before the cfm-formatted split). The
// first that exists is used unless the caller names one from this same set.
var accessLogCandidates = []string{
	"/usr/local/openresty/nginx/logs/access.log",
	"/var/log/angie/access.log",
	"/usr/local/openresty/nginx/logs/access.cfm.log",
	"/var/log/angie/access.cfm.log",
	"/var/log/nginx/access.log",
}

const (
	DefaultTailLines = 300_000
	MaxTailLines     = 2_000_000
	DefaultLimit     = 200
	MaxLimit         = 1000
	scanTimeout      = 20 * time.Second

	maxLineToken  = 4 * 1024 * 1024 // scanner ceiling: tolerate long URIs/UAs without aborting the call
	maxStoredLine = 8 * 1024        // truncate each retained match so worst-case memory = limit×this
)

// Result is the outcome of an IP lookup.
type Result struct {
	IP        string   `json:"ip"`
	LogFile   string   `json:"log_file"`
	TailLines int      `json:"tail_lines"` // how many trailing lines were scanned
	Scanned   int      `json:"scanned"`    // lines actually read from tail
	Matched   int      `json:"matched"`    // total matches found (may exceed len(Lines))
	Truncated bool     `json:"truncated"`  // matches beyond the returned cap existed
	Lines     []string `json:"lines"`      // raw matching log lines, oldest→newest
}

// AvailableLogs returns the candidate access logs that currently exist, so the
// tool/handler can report choices and validate a caller-named source.
func AvailableLogs() []string {
	out := make([]string, 0, len(accessLogCandidates))
	for _, p := range accessLogCandidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	return out
}

// resolveLog picks the log to scan: if want is non-empty it MUST be one of the
// allow-listed candidates (basename or full path) and must exist; otherwise the
// first existing candidate is used.
func resolveLog(want string) (string, error) {
	avail := AvailableLogs()
	if len(avail) == 0 {
		return "", fmt.Errorf("no edge access log found (looked in %d known locations)", len(accessLogCandidates))
	}
	want = strings.TrimSpace(want)
	if want == "" {
		return avail[0], nil
	}
	for _, p := range avail {
		if p == want || strings.HasSuffix(p, "/"+want) {
			return p, nil
		}
	}
	return "", fmt.Errorf("requested log %q is not an available edge access log; choices: %s", want, strings.Join(avail, ", "))
}

// GrepIP returns the raw lines mentioning ip within the last tailLines lines of
// the resolved edge access log. Bounded: tail window, context timeout, output
// cap, per-line retention cap. ip must be a valid IP (rejects arbitrary
// strings). source, when set, selects among AvailableLogs.
//
// The IP is canonicalized (so 2001:DB8::1 matches a log's 2001:db8::1) and
// matched as a standalone address token — NOT a bare substring — so "1.2.3.4"
// does not match "1.2.3.45". Note the token can still appear in a non-address
// field (URI/referer); the caller reads the raw line and sees the real client
// field. Only the current log is scanned (rotated .gz are not), so reach is
// bounded to what's still in the live file.
func GrepIP(ctx context.Context, ip string, source string, tailLines, limit int) (Result, error) {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Result{}, fmt.Errorf("invalid IP %q", ip)
	}
	ip = parsed.String() // canonical form (lowercased/compressed) for matching + display
	if tailLines <= 0 {
		tailLines = DefaultTailLines
	}
	if tailLines > MaxTailLines {
		tailLines = MaxTailLines
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	logFile, err := resolveLog(source)
	if err != nil {
		return Result{}, err
	}

	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	res := Result{IP: ip, LogFile: logFile, TailLines: tailLines, Lines: make([]string, 0, limit)}
	err = streamTailMatches(cctx, logFile, tailLines, func(line string) bool {
		res.Scanned++
		if !mentionsIP(line, ip) {
			return true
		}
		res.Matched++
		if len(res.Lines) < limit {
			res.Lines = append(res.Lines, truncLine(line))
		} else {
			res.Truncated = true
		}
		return true
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// streamTailMatches runs `tail -n <tailLines> <file>` and feeds each line to fn.
// tail reads backward from EOF, so the disk read is bounded to the tail window
// regardless of the file's total size. Output is streamed (never fully buffered).
func streamTailMatches(ctx context.Context, file string, tailLines int, fn func(line string) bool) error {
	cmd := exec.CommandContext(ctx, tailPath(), "-n", fmt.Sprintf("%d", tailLines), file)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		stdout.Close() // Wait (which normally closes the pipe) is never reached on a Start failure
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineToken)
	for sc.Scan() {
		if !fn(sc.Text()) {
			break
		}
	}
	scanErr := sc.Err()
	// Drain any unread output so tail can exit even if we stopped early (fn
	// returning false) — otherwise it could block on a full pipe until the ctx
	// SIGKILL. Harmless no-op on the normal full-drain-to-EOF path.
	_, _ = io.Copy(io.Discard, stdout)
	_ = cmd.Wait() // reap; status ignored (SIGPIPE on early stop, timeout surfaces via ctx)
	if ctx.Err() != nil {
		return fmt.Errorf("scan timed out after %s (log too large for the tail window)", scanTimeout)
	}
	return scanErr
}

// mentionsIP reports whether ip (already canonical) appears in line as a
// standalone address token, i.e. not immediately flanked by characters that
// could be part of a longer IP literal. This stops "1.2.3.4" from matching
// "1.2.3.45"/"11.2.3.4" while staying format-agnostic (no assumption about which
// field the address sits in).
func mentionsIP(line, ip string) bool {
	for from := 0; from+len(ip) <= len(line); {
		i := strings.Index(line[from:], ip)
		if i < 0 {
			return false
		}
		i += from
		if ipBoundary(line, i-1) && ipBoundary(line, i+len(ip)) {
			return true
		}
		from = i + 1
	}
	return false
}

// ipBoundary reports whether the byte at idx is a valid edge of an IP token
// (out of range = line start/end = boundary). Digits, hex letters, '.', ':' are
// IP-internal, so an address adjacent to one of them is part of a longer run.
func ipBoundary(s string, idx int) bool {
	if idx < 0 || idx >= len(s) {
		return true
	}
	c := s[idx]
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F', c == '.', c == ':':
		return false
	default:
		return true
	}
}

// truncLine caps a retained match so worst-case memory is limit×maxStoredLine.
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
