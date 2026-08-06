// Package mysqllog does on-demand, bounded tails of the MySQL/MariaDB error log
// and slow-query log — the "MySQL pressure is high, what's erroring / what's
// slow?" companion to the mysql_pressure view. It backs the read-only MCP tools
// `mysql_log_tail` (error log) and `mysql_slow_queries` (slow log) via
// GET /api/v1/system/mysql-log?which=error|slow.
//
// Same cost discipline as dmesg_tail / ip_forensics: NO continuous overhead —
// nothing retained, no DB connection needed (the log files exist regardless of
// the governor's DB link). A call reads only the last N lines via `tail -n N`
// (backward from EOF, so a multi-GB log is never read whole), under a timeout,
// with an optional case-insensitive grep and a capped result. The log path is
// resolved from my.cnf + a fixed candidate list — never a caller-supplied path.
package mysqllog

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	DefaultLines  = 200
	MaxLines      = 5000
	DefaultLimit  = 200
	MaxLimit      = 2000
	maxStoredLine = 16 * 1024 // slow-log SQL lines can be long; cap retained length
	scanTimeout   = 20 * time.Second
)

// myCnfCandidates are the config files scanned for log paths, in order.
var myCnfCandidates = []string{"/etc/my.cnf", "/etc/mysql/my.cnf", "/etc/mariadb/my.cnf"}

// errorLogCommon / slowLogCommon are distro fallbacks when my.cnf doesn't name
// the path. Entries containing '*' are globbed; the newest match wins.
var (
	errorLogCommon = []string{
		"/var/log/mysqld.log", "/var/log/mysql/error.log", "/var/log/mariadb/mariadb.log",
		"/var/lib/mysql/*.err", "/var/lib/mariadb/*.err",
	}
	slowLogCommon = []string{
		"/var/log/mysql/mysql-slow.log", "/var/log/mysql-slow.log",
		"/var/log/mariadb/mariadb-slow.log", "/var/lib/mysql/*-slow.log", "/var/lib/mysql/slow.log",
	}
)

// Result is one log-tail outcome.
type Result struct {
	Kind      string   `json:"kind"` // error | slow
	LogFile   string   `json:"log_file"`
	Found     bool     `json:"found"` // false for slow when no slow log exists (likely disabled)
	Lines     []string `json:"lines"`
	Scanned   int      `json:"scanned"`
	Matched   int      `json:"matched"`
	Truncated bool     `json:"truncated"`
}

// Tail returns the last matching lines of the error or slow log. kind must be
// "error" or "slow". A missing slow log is NOT an error — Found=false is
// returned so the caller can say "slow query log not enabled/found".
func Tail(ctx context.Context, kind string, lines, limit int, grep string) (Result, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		kind = "error"
	}
	if kind != "error" && kind != "slow" {
		return Result{}, fmt.Errorf("unknown log kind %q (want error|slow)", kind)
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

	logFile := resolveLog(kind)
	res := Result{Kind: kind, LogFile: logFile, Lines: make([]string, 0, limit)}
	if logFile == "" {
		// error log truly missing is worth flagging; a missing slow log usually
		// just means it's disabled.
		if kind == "error" {
			return res, fmt.Errorf("could not locate the MySQL error log")
		}
		return res, nil // Found=false, no error
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

// resolveLog finds the error or slow log path: my.cnf directive first, then the
// common candidates (globs resolved to the newest match). "" if none found.
func resolveLog(kind string) string {
	var directive string
	var common []string
	if kind == "slow" {
		directive, common = "slow_query_log_file", slowLogCommon
	} else {
		directive, common = "log_error", errorLogCommon
	}
	for _, cfg := range myCnfCandidates {
		if p := parseMyCnfPath(cfg, directive); p != "" {
			if fileExists(p) {
				return p
			}
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				if n := newestGlob(filepath.Join(p, "*.err")); n != "" {
					return n
				}
			}
		}
	}
	for _, c := range common {
		if strings.ContainsRune(c, '*') {
			if n := newestGlob(c); n != "" {
				return n
			}
			continue
		}
		if fileExists(c) {
			return c
		}
	}
	return ""
}

// parseMyCnfPath pulls a `key = value` path from a my.cnf. `log-error` and
// `log_error` are treated as equivalent (MySQL accepts both spellings).
func parseMyCnfPath(cfgPath, key string) string {
	f, err := os.Open(cfgPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	keyDash := strings.ReplaceAll(key, "_", "-")
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:eq]))
		if k != key && k != keyDash {
			continue
		}
		v := strings.TrimSpace(line[eq+1:])
		v = strings.Trim(v, "\"'")
		if v != "" {
			return v
		}
	}
	return ""
}

func newestGlob(pattern string) string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	type ent struct {
		path string
		mod  int64
	}
	ents := make([]ent, 0, len(matches))
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		ents = append(ents, ent{m, fi.ModTime().UnixNano()})
	}
	if len(ents) == 0 {
		return ""
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].mod > ents[j].mod })
	return ents[0].path
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// readerBufSize bounds how much of a single line is held in memory. A line
// longer than this (a slow-query log entry can carry huge SQL) is truncated to
// this prefix and the remainder drained to the next newline — so one monster
// line can neither blow memory nor abort the whole call (the old bufio.Scanner
// returned ErrTooLong and 502'd the request; see mysql_slow_queries bug).
const readerBufSize = 1024 * 1024

// streamTail runs `tail -n N file`, feeding each line to fn. tail reads backward
// from EOF, so the read is bounded to the tail window regardless of file size.
// Over-long lines are truncated (not fatal) via a bounded bufio.Reader.
func streamTail(ctx context.Context, file string, lines int, fn func(string)) error {
	cmd := exec.CommandContext(ctx, tailPath(), "-n", fmt.Sprintf("%d", lines), file)
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
	_ = cmd.Wait()
	if ctx.Err() != nil {
		return fmt.Errorf("scan timed out after %s", scanTimeout)
	}
	return readErr
}

// scanBoundedLines reads newline-delimited lines from r, emitting each via fn.
// A line longer than r's buffer is emitted truncated to the buffer prefix and
// the rest is discarded up to the next newline (never buffered), so memory is
// bounded to the reader's buffer size and an over-long line is not fatal.
// Separated from exec so it is unit-tested. io.EOF is the normal terminator.
func scanBoundedLines(r *bufio.Reader, fn func(string)) error {
	for {
		chunk, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			// Over-long line: `chunk` is the buffer-sized prefix (no newline).
			// Emit it (copied) truncated, then drain the rest of this line.
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
