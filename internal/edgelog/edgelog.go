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
	"sort"
	"strings"
	"time"
)

// accessLogCandidates are the known CFM edge access logs. The one selected by
// default is the most-recently-modified of those that exist (see availableFrom
// — it tracks the ACTIVE edge, not this list order); this static order is only
// the tiebreak when mtimes are equal. A caller may name any one from this set.
var accessLogCandidates = []string{
	"/usr/local/openresty/nginx/logs/access.log",
	"/var/log/angie/access.log",
	"/usr/local/openresty/nginx/logs/access.cfm.log",
	"/var/log/angie/access.cfm.log",
	"/var/log/nginx/access.log",
}

// errorLogCandidates are the known CFM edge ERROR logs. Same most-recently-
// modified default-selection + allow-list discipline as the access candidates
// (this static order is only the equal-mtime tiebreak). This is where the edge
// Lua writes ngx.log(): panel
// decision logonly verdicts ([cfm_panel_decision] logonly=would_enforce …),
// module-load failures, and Lua runtime errors.
var errorLogCandidates = []string{
	"/usr/local/openresty/nginx/logs/error.log",
	"/var/log/angie/error.log",
	"/var/log/nginx/error.log",
}

const (
	DefaultTailLines = 300_000
	MaxTailLines     = 2_000_000
	DefaultLimit     = 200
	MaxLimit         = 1000
	scanTimeout      = 20 * time.Second

	// Error logs are far smaller and denser than access logs, and are usually
	// read for "the last few matching lines", so the error tail window is much
	// smaller than the access one.
	DefaultErrorTailLines = 5_000
	MaxErrorTailLines     = 200_000

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

// availableFrom returns the candidates that currently exist as regular files,
// most-recently-modified FIRST.
//
// The ordering is load-bearing, not cosmetic: a node fronts its traffic with
// exactly one engine (Angie OR OpenResty), but the OTHER engine's log file
// often still exists as a stale/empty leftover from a disabled install. A
// static "OpenResty-first" order would then default-select that wrong-engine
// empty log (observed live: edge_error_tail read an empty
// /usr/local/openresty/nginx/logs/error.log on an Angie node). mtime tracks the
// ACTIVE edge — it is the one actually being written — so most-recent-first
// makes the default (avail[0]) the live log. Stable sort keeps the original
// candidate order as the tiebreak when mtimes are equal.
func availableFrom(candidates []string) []string {
	type ent struct {
		path string
		mod  time.Time
	}
	ents := make([]ent, 0, len(candidates))
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			ents = append(ents, ent{path: p, mod: fi.ModTime()})
		}
	}
	sort.SliceStable(ents, func(i, j int) bool { return ents[i].mod.After(ents[j].mod) })
	out := make([]string, len(ents))
	for i, e := range ents {
		out[i] = e.path
	}
	return out
}

// resolveFrom picks the log to scan from candidates: if want is non-empty it
// MUST be one of the allow-listed candidates (basename or full path) and must
// exist; otherwise the most-recently-modified existing candidate is used (via
// availableFrom). kind names the log class for error messages ("access" /
// "error").
func resolveFrom(candidates []string, want, kind string) (string, error) {
	avail := availableFrom(candidates)
	if len(avail) == 0 {
		return "", fmt.Errorf("no edge %s log found (looked in %d known locations)", kind, len(candidates))
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
	return "", fmt.Errorf("requested log %q is not an available edge %s log; choices: %s", want, kind, strings.Join(avail, ", "))
}

// AvailableLogs returns the candidate access logs that currently exist, so the
// tool/handler can report choices and validate a caller-named source.
func AvailableLogs() []string { return availableFrom(accessLogCandidates) }

// AvailableErrorLogs returns the candidate ERROR logs that currently exist.
func AvailableErrorLogs() []string { return availableFrom(errorLogCandidates) }

func resolveLog(want string) (string, error) { return resolveFrom(accessLogCandidates, want, "access") }

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

// ErrorTailResult is the outcome of an edge error-log tail.
type ErrorTailResult struct {
	LogFile   string   `json:"log_file"`
	Grep      string   `json:"grep,omitempty"`
	TailLines int      `json:"tail_lines"` // trailing lines scanned
	Scanned   int      `json:"scanned"`    // lines actually read from tail
	Matched   int      `json:"matched"`    // total lines matching grep (may exceed len(Lines))
	Truncated bool     `json:"truncated"`  // older matches were dropped to keep the newest `limit`
	Lines     []string `json:"lines"`      // matching lines, oldest→newest, capped to the NEWEST `limit`
}

// TailError returns lines from the last tailLines lines of the resolved edge
// ERROR log, optionally filtered to a case-insensitive substring (grep ""
// returns every tail line). Unlike GrepIP (which keeps the FIRST `limit`
// matches for a specific IP), this keeps the NEWEST `limit` matches — an error
// tail is read for "what happened most recently". Bounded the same way: tail
// window, context timeout, per-line retention cap. source, when set, selects
// among AvailableErrorLogs.
func TailError(ctx context.Context, grep, source string, tailLines, limit int) (ErrorTailResult, error) {
	if tailLines <= 0 {
		tailLines = DefaultErrorTailLines
	}
	if tailLines > MaxErrorTailLines {
		tailLines = MaxErrorTailLines
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	needle := strings.ToLower(strings.TrimSpace(grep))

	logFile, err := resolveFrom(errorLogCandidates, source, "error")
	if err != nil {
		return ErrorTailResult{}, err
	}

	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	res := ErrorTailResult{LogFile: logFile, Grep: strings.TrimSpace(grep), TailLines: tailLines}
	// Ring of the newest `limit` matches: append until full, then slide.
	buf := make([]string, 0, limit)
	err = streamTailMatches(cctx, logFile, tailLines, func(line string) bool {
		res.Scanned++
		if needle != "" && !strings.Contains(strings.ToLower(line), needle) {
			return true
		}
		res.Matched++
		if len(buf) < limit {
			buf = append(buf, truncLine(line))
		} else {
			copy(buf, buf[1:])
			buf[limit-1] = truncLine(line)
			res.Truncated = true
		}
		return true
	})
	res.Lines = buf
	if err != nil {
		return res, err
	}
	return res, nil
}

// ScanError streams the last tailLines of the resolved edge ERROR log and
// invokes fn for every line that contains ANY of substrs (case-insensitive; an
// empty substrs list matches every line). Each line passed to fn is truncated to
// the same per-line cap as the tail tools. Bounded like TailError (tail window,
// context timeout). Returns the resolved log file and how many lines were
// scanned.
//
// Unlike TailError (which keeps only the NEWEST `limit` matches in a ring),
// ScanError observes EVERY match in the window — for aggregators (e.g. the
// panel-logonly FP hunt) that must count all hits, not just the most recent.
// The caller bounds its own memory by what it accumulates in fn.
func ScanError(ctx context.Context, substrs []string, source string, tailLines int, fn func(line string)) (logFile string, scanned int, err error) {
	if tailLines <= 0 {
		tailLines = DefaultErrorTailLines
	}
	if tailLines > MaxErrorTailLines {
		tailLines = MaxErrorTailLines
	}
	lower := make([]string, 0, len(substrs))
	for _, s := range substrs {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			lower = append(lower, s)
		}
	}

	logFile, err = resolveFrom(errorLogCandidates, source, "error")
	if err != nil {
		return "", 0, err
	}

	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	err = streamTailMatches(cctx, logFile, tailLines, func(line string) bool {
		scanned++
		if len(lower) > 0 {
			ll := strings.ToLower(line)
			matched := false
			for _, s := range lower {
				if strings.Contains(ll, s) {
					matched = true
					break
				}
			}
			if !matched {
				return true
			}
		}
		fn(truncLine(line))
		return true
	})
	return logFile, scanned, err
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
