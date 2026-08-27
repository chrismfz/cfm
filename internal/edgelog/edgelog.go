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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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

	// Rotated-log reach (opt-in): how many rotated siblings to scan by default
	// and at most, plus the shared line budget across ALL rotated files so an
	// operator who asks for rotated reach can't trigger an unbounded multi-GB
	// decompress. The live file's own tail window is unaffected.
	DefaultRotatedFiles = 10
	MaxRotatedFiles     = 60
	rotatedScanBudget   = MaxTailLines

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
	IP           string   `json:"ip"`
	LogFile      string   `json:"log_file"`      // the live log (default source)
	FilesScanned []string `json:"files_scanned"` // every file read: live first, then rotated newest→oldest
	TailLines    int      `json:"tail_lines"`    // how many trailing lines were scanned in the LIVE file
	Scanned      int      `json:"scanned"`       // lines actually read across all scanned files
	Matched      int      `json:"matched"`       // total matches found (may exceed len(Lines))
	Truncated    bool     `json:"truncated"`     // matches beyond the returned cap, or scan bound hit
	Lines        []string `json:"lines"`         // raw matching log lines, newest file first
}

// Opts tunes an IP lookup. The zero value is the historical behaviour: scan only
// the live access log's tail (no rotated reach).
type Opts struct {
	Source         string // which allow-listed access log to treat as live; "" = most-recent
	TailLines      int    // live-file tail window (0 → DefaultTailLines)
	Limit          int    // max matching lines returned (0 → DefaultLimit)
	IncludeRotated bool   // also scan rotated siblings (.1, .2.gz, -YYYYMMDD.gz, …)
	MaxFiles       int    // cap rotated siblings scanned (0 → DefaultRotatedFiles)
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

// GrepIP returns the raw lines mentioning ip within the last o.TailLines lines of
// the resolved edge access log. Bounded: tail window, context timeout, output
// cap, per-line retention cap. ip must be a valid IP (rejects arbitrary
// strings). o.Source, when set, selects among AvailableLogs.
//
// The IP is canonicalized (so 2001:DB8::1 matches a log's 2001:db8::1) and
// matched as a standalone address token — NOT a bare substring — so "1.2.3.4"
// does not match "1.2.3.45". Note the token can still appear in a non-address
// field (URI/referer); the caller reads the raw line and sees the real client
// field.
//
// By default only the live log is scanned. With o.IncludeRotated the resolved
// log's rotated siblings (access.log.1, access.log.2.gz, access.log-YYYYMMDD.gz,
// …) are ALSO scanned, newest→oldest, so forensics can reach evidence from
// before the last logrotate. That reach is still bounded: at most o.MaxFiles
// siblings, a shared rotatedScanBudget of lines across all of them, and the same
// single scanTimeout covering the whole call (gz is streamed, never buffered
// whole). Matches are returned live-first then newest-sibling-first, capped at
// o.Limit; Truncated is set if the cap or any bound was hit.
func GrepIP(ctx context.Context, ip string, o Opts) (Result, error) {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Result{}, fmt.Errorf("invalid IP %q", ip)
	}
	ip = parsed.String() // canonical form (lowercased/compressed) for matching + display
	tailLines := o.TailLines
	if tailLines <= 0 {
		tailLines = DefaultTailLines
	}
	if tailLines > MaxTailLines {
		tailLines = MaxTailLines
	}
	limit := o.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	logFile, err := resolveLog(o.Source)
	if err != nil {
		return Result{}, err
	}

	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	res := Result{IP: ip, LogFile: logFile, TailLines: tailLines, Lines: make([]string, 0, limit)}
	// One match handler shared by the live tail and every rotated scan, so the
	// output cap / Matched count / Truncated flag are accounted uniformly.
	onLine := func(line string) bool {
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
	}

	res.FilesScanned = append(res.FilesScanned, logFile)
	tailCapped, err := streamTailBounded(cctx, logFile, tailLines, onLine)
	if tailCapped {
		// The live file had more lines than the tail window — a real reach
		// bound between "now" and the rotated archives; never silent.
		res.Truncated = true
	}
	if err != nil {
		return res, err
	}

	if o.IncludeRotated {
		maxFiles := o.MaxFiles
		if maxFiles <= 0 {
			maxFiles = DefaultRotatedFiles
		}
		if maxFiles > MaxRotatedFiles {
			maxFiles = MaxRotatedFiles
		}
		budget := rotatedScanBudget
		siblings, siblingsFound := rotatedSiblings(logFile, maxFiles)
		if siblingsFound > len(siblings) {
			res.Truncated = true // the file cap hid older siblings
		}
		for _, rf := range siblings {
			if cctx.Err() != nil || budget <= 0 {
				// Ran out of time/budget before this file — mark it and any
				// remaining files as unscanned reach.
				res.Truncated = true
				break
			}
			res.FilesScanned = append(res.FilesScanned, rf)
			// A single unreadable/corrupt rotated file must not fail the whole
			// lookup — the live-file result is already in hand; skip and go on,
			// but NEVER silently: coverage is shorter than it looks.
			if scanErr := scanWholeForIP(cctx, rf, &budget, onLine); scanErr != nil {
				if cctx.Err() != nil {
					res.Truncated = true
					break
				}
				res.Truncated = true // corrupt sibling = evidence hole
				continue
			}
			// Budget exhausted mid-file (possibly the last one, where the
			// loop-top guard won't run again): the reach was cut short.
			if budget <= 0 {
				res.Truncated = true
			}
		}
	}
	return res, nil
}

// rotatedSiblings returns the rotated variants of live (same directory, name
// starting with "<base>." or "<base>-": .1, .1.gz, -20260810.gz, …), most
// recently modified FIRST, capped at maxFiles. The second return is the TOTAL
// number of siblings found, so a caller can detect that the file cap silently
// hid some (found > len(paths)). The live file itself, empty files, and
// non-regular entries are excluded. A directory it can't read yields nothing
// (best-effort — the live result still stands).
func rotatedSiblings(live string, maxFiles int) ([]string, int) {
	dir := filepath.Dir(live)
	base := filepath.Base(live)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0
	}
	type fe struct {
		path string
		mod  time.Time
	}
	var out []fe
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == base {
			continue
		}
		if !strings.HasPrefix(name, base+".") && !strings.HasPrefix(name, base+"-") {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			continue
		}
		out = append(out, fe{filepath.Join(dir, name), info.ModTime()})
	}
	total := len(out)
	sort.SliceStable(out, func(i, j int) bool { return out[i].mod.After(out[j].mod) })
	if len(out) > maxFiles {
		out = out[:maxFiles]
	}
	paths := make([]string, len(out))
	for i, e := range out {
		paths[i] = e.path
	}
	return paths, total
}

// errScanBudgetExceeded is returned by scanWholeForIP when the scanner found
// MORE lines while the private countdown was already at zero — i.e. the file
// was cut short by the budget, not by EOF. Callers translate it into
// truncation flags (never into files_failed: the file is fine).
var errScanBudgetExceeded = errors.New("scan budget exceeded")

// scanWholeForIP streams a rotated file from the start (gz-transparent) feeding
// each line to fn, decrementing the shared budget. Unlike the live tail this
// reads the whole file, but the caller's budget + ctx timeout bound the work,
// and gz is streamed through gzip.Reader (never decompressed whole into memory).
func scanWholeForIP(ctx context.Context, path string, budget *int, fn func(line string) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineToken)
	for sc.Scan() {
		if *budget <= 0 {
			// The caller's budget is spent but the file has MORE lines: this
			// distinction (budget-cut vs clean EOF) must reach the caller so
			// truncation can be flagged even on the LAST scanned file.
			return errScanBudgetExceeded
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		*budget--
		if !fn(sc.Text()) {
			return nil
		}
	}
	return sc.Err()
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
	return scanLog(ctx, errorLogCandidates, source, "error", tailLines, DefaultErrorTailLines, MaxErrorTailLines, substrs, fn)
}

// scanLog is the shared engine behind ScanError/ScanAccess: resolve one
// allow-listed log, tail the last tailLines (clamped to [_, maxTail], defTail
// when unset), and invoke fn for every line containing ANY of substrs
// (case-insensitive; empty substrs matches every line), each truncated to the
// per-line cap. Bounded by the tail window + a context timeout.
func scanLog(ctx context.Context, candidates []string, source, kind string, tailLines, defTail, maxTail int, substrs []string, fn func(line string)) (logFile string, scanned int, err error) {
	if tailLines <= 0 {
		tailLines = defTail
	}
	if tailLines > maxTail {
		tailLines = maxTail
	}
	lower := make([]string, 0, len(substrs))
	for _, s := range substrs {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			lower = append(lower, s)
		}
	}

	logFile, err = resolveFrom(candidates, source, kind)
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

// ScanAccess is the access-log twin of ScanError: it streams the last tailLines
// of the resolved edge ACCESS log and invokes fn for every line containing ANY
// of substrs (case-insensitive; empty substrs matches every line). Same
// allow-listed resolution, tail-window bound, context timeout and per-line
// truncation. Used by aggregators that must COUNT every match in the window
// (e.g. edge_health's 421 fingerprint), not just keep the newest few.
func ScanAccess(ctx context.Context, substrs []string, source string, tailLines int, fn func(line string)) (logFile string, scanned int, err error) {
	return scanLog(ctx, accessLogCandidates, source, "access", tailLines, DefaultTailLines, MaxTailLines, substrs, fn)
}

// tailHasMoreThan reports whether file holds MORE than n lines, via a bounded
// `tail -n n+1` probe whose output is only COUNTED — never handed to anyone —
// so callers get the cap answer without any off-by-one line leaking into their
// data (the reason a plain N+1 probe feeding the callback is wrong).
func tailHasMoreThan(ctx context.Context, file string, n int) (bool, error) {
	cmd := exec.CommandContext(ctx, tailPath(), "-n", fmt.Sprintf("%d", n+1), file)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := cmd.Start(); err != nil {
		stdout.Close() // Wait (which normally closes the pipe) is never reached on a Start failure
		return false, err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineToken)
	seen := 0
	capped := false
	for sc.Scan() {
		seen++
		if seen > n {
			capped = true
			break // answer known — drain below so tail can exit cleanly
		}
	}
	scanErr := sc.Err()
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return capped, fmt.Errorf("tail scan timed out: %w", ctx.Err())
	}
	if scanErr != nil {
		return capped, scanErr
	}
	// The early break above drains to EOF, so a non-nil waitErr here is a REAL
	// failure (permission denied, missing file, …) — never swallow it into an
	// authoritative-looking empty answer.
	if waitErr != nil {
		return capped, fmt.Errorf("tail %s: %w", file, waitErr)
	}
	return capped, nil
}

// streamTailMatches runs `tail -n <tailLines> <file>` and feeds each line to
// fn — EXACTLY tailLines semantics: when the file is longer, the oldest lines
// are dropped and fn never sees them; no probe line leaks through. tail reads
// backward from EOF, so disk read is bounded to the tail window regardless of
// total file size; output is streamed (never fully buffered). Callers that
// ALSO need to know whether content was dropped pair this with tailHasMoreThan
// via streamTailBounded.
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
	stoppedEarly := false
	for sc.Scan() {
		if !fn(sc.Text()) {
			stoppedEarly = true
			break
		}
	}
	scanErr := sc.Err()
	// Drain any unread output so tail can exit even if we stopped early (fn
	// returning false) — otherwise it could block on a full pipe until the ctx
	// SIGKILL. Harmless no-op on the normal full-drain-to-EOF path.
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return fmt.Errorf("tail scan timed out: %w", ctx.Err())
	}
	if scanErr != nil {
		return scanErr
	}
	// A non-zero tail exit WITHOUT our own early stop means the evidence this
	// function would have returned is empty/partial for a real reason (e.g.
	// permission-denied writes only to stderr, scanner sees clean EOF) — that
	// must surface as an error, never as "zero lines, all good".
	if waitErr != nil && !stoppedEarly {
		return fmt.Errorf("tail %s: %w", file, waitErr)
	}
	return nil
}

// streamTailBounded pairs the cap probe with the exact-window stream for
// callers that need both answers (capped ⇒ the caller flags truncation).
func streamTailBounded(ctx context.Context, file string, tailLines int, fn func(line string) bool) (capped bool, err error) {
	capped, perr := tailHasMoreThan(ctx, file, tailLines)
	if perr != nil {
		return false, perr
	}
	err = streamTailMatches(ctx, file, tailLines, fn)
	return capped, err
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
