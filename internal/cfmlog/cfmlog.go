// Package cfmlog does on-demand, bounded tails of CFM's own observability logs
// and of allow-listed systemd unit journals. It backs two read-only MCP tools:
//
//	cfm_log_tail  → GET /api/v1/system/cfm-log?which=<key>   (CFM's own logs)
//	journal_tail  → GET /api/v1/system/journal?unit=<unit>   (journalctl -u <unit>)
//
// CFM's logs live under /var/log/cfm/ on current installs, with a few legacy
// /var/log/cfm.* fallbacks some older hosts still write to; both are in the
// per-key candidate list below.
//
// Same cost discipline as maillog/mysqllog/dmesg: NO continuous overhead —
// nothing retained. A call reads only the last N lines (file: `tail -n N`, read
// backward from EOF so a multi-GB log is never read whole; journal: `journalctl
// -n N`), under a timeout, with an optional case-insensitive grep and a capped
// result. Neither source is a caller-supplied path/unit: the file tail resolves
// a fixed per-key candidate allow-list, and the journal tail validates the unit
// against a fixed allow-list (so an admin read tool can't tail arbitrary units).
package cfmlog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"cfm/internal/logscan"
)

const (
	DefaultLines  = 500
	MaxLines      = 20000
	DefaultLimit  = 200
	MaxLimit      = 2000
	maxStoredLine = 16 * 1024
	scanTimeout   = 20 * time.Second
	readerBufSize = 1024 * 1024
	maxStderrCap  = 4 * 1024

	// Rotated-log reach (opt-in): the live tail only sees the current file, so an
	// event from before the last logrotate is invisible until you also scan the
	// rotated siblings (foo.log.1, foo.log.2.gz, …). That reach is bounded: at
	// most MaxRotatedFiles siblings, a shared rotatedScanBudget of lines across ALL
	// of them, and one timeout — so asking for history can't trigger an unbounded
	// multi-GB decompress. The live tail window (`lines`) is unaffected.
	DefaultRotatedFiles = 10
	MaxRotatedFiles     = 60
	rotatedScanBudget   = MaxLines * 10 // 200k lines across all rotated siblings
)

// ErrUnknownSource / ErrUnitNotAllowed classify caller (400) faults so the HTTP
// layer can distinguish them from server-side stream/exec failures (502).
var (
	ErrUnknownSource  = errors.New("unknown cfm log source")
	ErrUnitNotAllowed = errors.New("unit not allow-listed")
)

// fileCandidates maps a CFM-log key to its candidate paths, in resolution order
// (the /var/log/cfm/ default first, then the legacy /var/log/cfm.* location some
// hosts still write to). Fixed allow-list — the caller only picks a key. Mirrors
// the log paths CFM writes (see configs/logrotate-cfm + internal/config LOG_FILE
// keys); a config-overridden path is intentionally not followed (a read tool
// missing a relocated log returns found=false, never an error).
var fileCandidates = map[string][]string{
	"main":         {"/var/log/cfm/cfm.log", "/var/log/cfm.log"},
	"error":        {"/var/log/cfm/cfm-error.log"},
	"api":          {"/var/log/cfm/cfm.api.log", "/var/log/cfm.api.log"},
	"detector":     {"/var/log/cfm/cfm.detector.log", "/var/log/cfm/detectors.log"},
	"challenges":   {"/var/log/cfm/cfm.challenges.log", "/var/log/cfm/challenge.access.log"},
	"smtp":         {"/var/log/cfm/cfm.smtp.log", "/var/log/cfm.smtp.log"},
	"mysql":        {"/var/log/cfm/cfm.mysql.log"},
	"waf":          {"/var/log/cfm/cfm.waf.log"},
	"clam":         {"/var/log/cfm/cfm.clam.log"},
	"socket":       {"/var/log/cfm/cfm.socket.log"},
	"lsm":          {"/var/log/cfm/cfm.lsm.log", "/var/log/cfm/lsm.log"},
	"service":      {"/var/log/cfm/cfm-service.log", "/var/log/cfm-service.log"},
	"abuse_shadow": {"/var/log/cfm/cfm.abuse_shadow.log"},
}

// FileSources returns the sorted set of valid cfm-log keys (for docs/validation).
func FileSources() []string { return sortedKeys(fileCandidates) }

// journalUnits is the allow-list of systemd units the journal tail may read,
// keyed by the normalized unit name (lowercased, `.service` stripped). Bounds an
// admin read tool to the CFM + hosting-stack units rather than any unit on the
// box, matching how service_status curates its default set.
var journalUnits = map[string]bool{
	"cfm":       true,
	"angie":     true,
	"openresty": true,
	"nginx":     true,
	"httpd":     true,
	"apache2":   true,
	"mysql":     true,
	"mysqld":    true,
	"mariadb":   true,
	"exim":      true,
	"dovecot":   true,
	"postfix":   true,
	"sshd":      true,
	"clamd":     true,
	"named":     true,
}

// JournalUnits returns the sorted allow-listed unit names (for docs/validation).
func JournalUnits() []string {
	out := make([]string, 0, len(journalUnits))
	for u := range journalUnits {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// Result is one file-log-tail outcome. WindowFull is true when the tail window
// (`lines`) was saturated — i.e. older lines exist beyond what was scanned, so a
// grep that matched nothing is NOT proof the event never happened (raise `lines`).
type Result struct {
	Kind         string   `json:"kind"`
	LogFile      string   `json:"log_file"`
	Found        bool     `json:"found"`                   // false when no candidate path exists (log elsewhere / feature off)
	FilesScanned []string `json:"files_scanned,omitempty"` // set only in rotated mode: live first, then rotated siblings newest→oldest
	Lines        []string `json:"lines"`
	Scanned      int      `json:"scanned"`     // lines read across ALL scanned files
	Matched      int      `json:"matched"`     // total grep matches (may exceed len(Lines))
	Truncated    bool     `json:"truncated"`   // output capped at `limit`, or a rotated scan bound (budget/timeout/file cap/corrupt gz) was hit
	WindowFull   bool     `json:"window_full"` // LIVE tail window saturated — older lines exist in this file (raise `lines` or set `rotated`)
}

// JournalResult is one journal-tail outcome. Note carries a journalctl failure
// (permission denied / unknown unit / unsupported flag) so a failed read is
// surfaced rather than masquerading as "nothing logged".
type JournalResult struct {
	Unit       string   `json:"unit"`
	Available  bool     `json:"available"` // false when journalctl is absent (non-systemd host)
	Lines      []string `json:"lines"`
	Scanned    int      `json:"scanned"`
	Matched    int      `json:"matched"`
	Truncated  bool     `json:"truncated"`
	WindowFull bool     `json:"window_full"`
	Note       string   `json:"note,omitempty"`
}

func clampLinesLimit(lines, limit int) (int, int) {
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
	return lines, limit
}

// TailFile returns the last matching lines of a CFM log. A missing log is NOT an
// error — Found=false is returned so the caller can say "that log isn't present"
// rather than failing. An unknown key is ErrUnknownSource (a caller fault).
//
// `rotated` (0 = live file only, the default) also scans up to that many rotated
// siblings (foo.log.1, foo.log.2.gz, …) newest→oldest, gz-transparent, to reach
// evidence from before the last logrotate. That reach is bounded: at most
// MaxRotatedFiles siblings, a shared rotatedScanBudget of lines across all of them,
// and one timeout. Matches are collected live-window-first then newest-sibling-first
// and still capped at `limit`; any scan bound hit (output cap, file cap, budget,
// timeout, or a corrupt gz) sets Truncated.
func TailFile(ctx context.Context, which string, lines, limit, rotated int, grep string) (Result, error) {
	which = strings.ToLower(strings.TrimSpace(which))
	if which == "" {
		which = "main"
	}
	paths, ok := fileCandidates[which]
	if !ok {
		return Result{}, fmt.Errorf("unknown cfm log %q (want one of: %s): %w", which, strings.Join(FileSources(), ", "), ErrUnknownSource)
	}
	lines, limit = clampLinesLimit(lines, limit)

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
	// One match handler shared by the live tail and every rotated scan, so Scanned/
	// Matched/Lines accumulate identically across all files.
	collect := func(line string) {
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
	}

	cmd := exec.CommandContext(cctx, tailPath(), "-n", fmt.Sprintf("%d", lines), logFile)
	_, err := streamCmd(cctx, cmd, collect)
	// WindowFull reflects the LIVE file only (the tail window), so it keeps meaning
	// "this file has older lines" independent of rotated reach.
	res.WindowFull = res.Scanned >= lines

	if rotated <= 0 {
		return res, err
	}
	// Rotated reach: scan the newest `rotated` siblings, gz-transparent, under a
	// shared line budget. A per-file open/gz/budget failure never fails the call —
	// the live result is already in hand — but it is NEVER silent: it sets Truncated
	// so "coverage is shorter than it looks" reaches the caller.
	res.FilesScanned = append(res.FilesScanned, logFile) // live first
	if rotated > MaxRotatedFiles {
		rotated = MaxRotatedFiles
	}
	siblings, found := logscan.RotatedSiblings(logFile, rotated)
	if found > len(siblings) {
		res.Truncated = true // the file cap hid older siblings
	}
	budget := rotatedScanBudget
	for _, rf := range siblings {
		if cctx.Err() != nil || budget <= 0 {
			res.Truncated = true // ran out of time/budget before this file
			break
		}
		res.FilesScanned = append(res.FilesScanned, rf)
		if scanErr := logscan.ScanWhole(cctx, rf, &budget, func(l string) bool { collect(l); return true }); scanErr != nil {
			if cctx.Err() != nil {
				res.Truncated = true
				break
			}
			res.Truncated = true // budget-cut or corrupt/unreadable sibling = evidence hole
			continue
		}
		if budget <= 0 {
			res.Truncated = true // budget exhausted mid-file (possibly the last one)
		}
	}
	return res, err
}

// TailJournal returns the last matching lines of an allow-listed unit's journal.
// An unknown/blocked unit is ErrUnitNotAllowed (a caller fault). A host without
// journalctl is NOT an error (Available=false). A journalctl that runs but FAILS
// (permission, unknown unit, unsupported flag) is surfaced via Note — never
// silently returned as an empty success — so "did the service fail to start?"
// can't be answered with a false "nothing logged".
func TailJournal(ctx context.Context, unit string, lines, limit int, grep string) (JournalResult, error) {
	norm := strings.ToLower(strings.TrimSpace(unit))
	norm = strings.TrimSuffix(norm, ".service")
	if norm == "" {
		return JournalResult{}, fmt.Errorf("unit required (one of: %s): %w", strings.Join(JournalUnits(), ", "), ErrUnitNotAllowed)
	}
	if !journalUnits[norm] {
		return JournalResult{}, fmt.Errorf("unit %q not allow-listed (want one of: %s): %w", unit, strings.Join(JournalUnits(), ", "), ErrUnitNotAllowed)
	}
	lines, limit = clampLinesLimit(lines, limit)

	res := JournalResult{Unit: norm, Lines: make([]string, 0, limit)}
	jc := journalctlPath()
	if jc == "" {
		res.Note = "journalctl not available (non-systemd host)"
		return res, nil // Available=false, not an error
	}
	res.Available = true

	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	g := strings.ToLower(strings.TrimSpace(grep))
	// -n bounds output to the last N lines; --no-pager so it never blocks on a
	// pager; short-iso for stable timestamps. grep is applied in-process (not
	// journalctl -g) for parity with the file tail and to avoid PCRE differences.
	cmd := exec.CommandContext(cctx, jc, "-u", norm+".service", "-n", fmt.Sprintf("%d", lines), "--no-pager", "-o", "short-iso")
	stderr, err := streamCmd(cctx, cmd, func(line string) {
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
	res.WindowFull = res.Scanned >= lines
	// A journalctl failure is surfaced as a Note (soft), not a hard error: the
	// tool stays usable (Available=true) and the operator sees WHY it was empty.
	if err != nil {
		note := firstLine(strings.TrimSpace(stderr))
		if note == "" {
			note = err.Error()
		}
		res.Note = "journalctl failed: " + truncLine(note)
	}
	return res, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// capWriter captures at most cap bytes of a child's stderr (the rest discarded),
// so a runaway stderr can't blow memory while we still get the leading message.
type capWriter struct {
	buf []byte
	cap int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.cap - len(w.buf); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		w.buf = append(w.buf, p[:room]...)
	}
	return len(p), nil // always "accept" so the child never blocks on a full pipe
}

func (w *capWriter) String() string { return string(w.buf) }

// streamCmd starts cmd, feeds each stdout line to fn (bounded), captures stderr
// (bounded), drains, and waits. Returns the captured stderr and a non-nil error
// on timeout / pipe error / non-zero exit. Over-long stdout lines are truncated,
// never fatal.
func streamCmd(ctx context.Context, cmd *exec.Cmd, fn func(string)) (string, error) {
	errW := &capWriter{cap: maxStderrCap}
	cmd.Stderr = errW
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		stdout.Close()
		return errW.String(), err
	}
	r := bufio.NewReaderSize(stdout, readerBufSize)
	readErr := scanBoundedLines(r, fn)
	_, _ = io.Copy(io.Discard, stdout) // drain so the child can exit
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return errW.String(), fmt.Errorf("scan timed out after %s", scanTimeout)
	}
	if readErr != nil {
		return errW.String(), readErr
	}
	if waitErr != nil {
		return errW.String(), waitErr
	}
	return errW.String(), nil
}

// scanBoundedLines reads newline-delimited lines from r, emitting each via fn. A
// line longer than r's buffer is emitted truncated to the buffer prefix and the
// rest discarded up to the next newline, so memory is bounded and an over-long
// line is never fatal (mirrors maillog/mysqllog — the bufio.Scanner "token too
// long" fix). io.EOF is the normal terminator.
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

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func truncLine(s string) string {
	if len(s) <= maxStoredLine {
		return s
	}
	return s[:maxStoredLine] + "…"
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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

func journalctlPath() string {
	if p, err := exec.LookPath("journalctl"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/journalctl", "/bin/journalctl"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
