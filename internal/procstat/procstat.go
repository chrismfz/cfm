// Package procstat produces a top-like snapshot of processes by reading /proc
// directly (no external tools, no cgo). It backs the read-only MCP tool
// `process_list` / GET /api/v1/system/processes.
//
// SECURITY: the default snapshot exposes only process COMM (the executable
// name). Full argv is read only when Details is explicitly requested, is bounded,
// and passes through a best-effort secret sanitizer before it can be returned.
package procstat

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Process is one row of the snapshot. CPUPct is normalised so that one fully
// busy core ≈ 100% (like top), computed from a short two-sample delta.
//
// Detail fields are omitted from the ordinary top-like view. Argv is never raw:
// when requested it is bounded and sanitized first.
type Process struct {
	PID     int     `json:"pid"`
	PPID    int     `json:"ppid"`
	User    string  `json:"user"`
	State   string  `json:"state"` // R,S,D,Z,T,I…
	CPUPct  float64 `json:"cpu_pct"`
	MemPct  float64 `json:"mem_pct"`
	RSSKB   int64   `json:"rss_kb"`
	Threads int     `json:"threads"`
	Comm    string  `json:"comm"` // executable name only in the default view

	Children       []int    `json:"children,omitempty"`
	Argv           []string `json:"argv,omitempty"`
	ArgvRedactions int      `json:"argv_redactions,omitempty"`
	ArgvTruncated  bool     `json:"argv_truncated,omitempty"`
}

// Options controls process selection. With zero-value Options except Limit this
// is exactly the historical Top behaviour: all processes ranked by CPU/RSS and
// truncated to Limit. Match/PID are filters and are deliberately applied BEFORE
// sorting/truncation so an idle named process is not lost just because it is not
// in the global top-N.
type Options struct {
	Limit   int
	Match   string
	PID     int
	Details bool
}

// sampleInterval is how long we wait between the two CPU-time samples. Long
// enough for a stable %cpu, short enough to keep the endpoint snappy.
const sampleInterval = 150 * time.Millisecond

const (
	maxArgvBytes = 8 * 1024
	maxArgBytes  = 2 * 1024
)

// procTimes is one pid's cumulative CPU jiffies (utime+stime) at a sample.
type procTimes struct{ jiffies uint64 }

// Top returns the n busiest processes by CPU, then RSS. It is kept as the
// compatibility wrapper for the original process_list behaviour.
func Top(n int) ([]Process, error) {
	return List(Options{Limit: n})
}

// List returns a process snapshot with optional filtering and opt-in details.
// Limit is clamped to [1,200] with the historical default of 15.
func List(opts Options) ([]Process, error) {
	total1, ok := totalJiffies()
	if !ok {
		return nil, errors.New("procstat: cannot read /proc/stat")
	}
	first := sampleProcJiffies()

	time.Sleep(sampleInterval)

	total2, ok := totalJiffies()
	if !ok {
		return nil, errors.New("procstat: cannot read /proc/stat")
	}
	dTotal := float64(0)
	if total2 > total1 {
		dTotal = float64(total2 - total1)
	}
	numCPU := float64(numCPUs())
	memTotalKB := memTotalKB()

	pids := listPIDs()
	uidCache := map[uint32]string{}
	all := make([]Process, 0, len(pids))
	for _, pid := range pids {
		p, ok := readProcess(pid, uidCache)
		if !ok {
			continue
		}
		// %cpu from the delta of this pid's jiffies over the interval, scaled so
		// a single saturated core reads ~100%.
		if prev, seen := first[pid]; seen && dTotal > 0 {
			now := currentProcJiffies(pid)
			if now > prev.jiffies {
				p.CPUPct = round1(100 * numCPU * float64(now-prev.jiffies) / dTotal)
			}
		}
		if memTotalKB > 0 {
			p.MemPct = round1(100 * float64(p.RSSKB) / float64(memTotalKB))
		}
		all = append(all, p)
	}

	selected := selectProcesses(all, opts)
	if !opts.Details {
		return selected, nil
	}

	children := buildChildIndex(all)
	for i := range selected {
		if ids := children[selected[i].PID]; len(ids) > 0 {
			selected[i].Children = append([]int(nil), ids...)
		}
		argv, redactions, truncated := readSanitizedArgv(selected[i].PID)
		selected[i].Argv = argv
		selected[i].ArgvRedactions = redactions
		selected[i].ArgvTruncated = truncated
	}
	return selected, nil
}

func normalizeLimit(n int) int {
	if n < 1 {
		return 15
	}
	if n > 200 {
		return 200
	}
	return n
}

// selectProcesses applies filters before the historical CPU/RSS ranking and
// limit. Kept separate so the ordering/compatibility rule can be unit-tested
// deterministically without depending on live /proc load.
func selectProcesses(in []Process, opts Options) []Process {
	match := strings.ToLower(strings.TrimSpace(opts.Match))
	out := make([]Process, 0, len(in))
	for _, p := range in {
		if opts.PID > 0 && p.PID != opts.PID {
			continue
		}
		if match != "" && !strings.Contains(strings.ToLower(p.Comm), match) {
			continue
		}
		out = append(out, p)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].CPUPct != out[j].CPUPct {
			return out[i].CPUPct > out[j].CPUPct
		}
		if out[i].RSSKB != out[j].RSSKB {
			return out[i].RSSKB > out[j].RSSKB
		}
		return out[i].PID < out[j].PID
	})
	if n := normalizeLimit(opts.Limit); len(out) > n {
		out = out[:n]
	}
	return out
}

func buildChildIndex(rows []Process) map[int][]int {
	m := make(map[int][]int)
	for _, p := range rows {
		if p.PPID >= 0 {
			m[p.PPID] = append(m[p.PPID], p.PID)
		}
	}
	for ppid := range m {
		sort.Ints(m[ppid])
	}
	return m
}

func listPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// sampleProcJiffies reads every pid's cumulative CPU jiffies once (sample 1).
func sampleProcJiffies() map[int]procTimes {
	m := map[int]procTimes{}
	for _, pid := range listPIDs() {
		if j, ok := procJiffies(pid); ok {
			m[pid] = procTimes{jiffies: j}
		}
	}
	return m
}

func currentProcJiffies(pid int) uint64 {
	if j, ok := procJiffies(pid); ok {
		return j
	}
	return 0
}

// procJiffies returns utime+stime from /proc/<pid>/stat.
func procJiffies(pid int) (uint64, bool) {
	f := statFields(pid)
	if f == nil {
		return 0, false
	}
	// After the comm split, f[0]=state (field 3). utime=field14→f[11],
	// stime=field15→f[12].
	if len(f) < 13 {
		return 0, false
	}
	utime, e1 := strconv.ParseUint(f[11], 10, 64)
	stime, e2 := strconv.ParseUint(f[12], 10, 64)
	if e1 != nil || e2 != nil {
		return 0, false
	}
	return utime + stime, true
}

// readProcess fills the non-CPU fields from /proc/<pid>/stat + dir ownership.
func readProcess(pid int, uidCache map[uint32]string) (Process, bool) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return Process{}, false
	}
	s := string(raw)
	lp := strings.IndexByte(s, '(')
	rp := strings.LastIndexByte(s, ')')
	if lp < 0 || rp < 0 || rp < lp {
		return Process{}, false
	}
	comm := s[lp+1 : rp]
	f := strings.Fields(s[rp+1:])
	if len(f) < 22 {
		return Process{}, false
	}
	pagesKB := int64(os.Getpagesize()) / 1024
	rssPages, _ := strconv.ParseInt(f[21], 10, 64) // field 24 → f[21]
	threads, _ := strconv.Atoi(f[17])              // field 20 → f[17]
	ppid, _ := strconv.Atoi(f[1])                  // field 4  → f[1]

	p := Process{
		PID:     pid,
		PPID:    ppid,
		State:   f[0],
		Comm:    comm,
		Threads: threads,
		RSSKB:   rssPages * pagesKB,
		User:    procOwner(pid, uidCache),
	}
	return p, true
}

// statFields returns the whitespace-split fields AFTER the comm parenthesis.
func statFields(pid int) []string {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return nil
	}
	s := string(raw)
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 || rp+1 >= len(s) {
		return nil
	}
	return strings.Fields(s[rp+1:])
}

// procOwner resolves the owning username from the /proc/<pid> dir ownership.
func procOwner(pid int, cache map[uint32]string) string {
	fi, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	if name, seen := cache[st.Uid]; seen {
		return name
	}
	name := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(name); err == nil && u.Username != "" {
		name = u.Username
	}
	cache[st.Uid] = name
	return name
}

var sensitiveArgKeys = map[string]struct{}{
	"password":              {},
	"passwd":                {},
	"pass":                  {},
	"token":                 {},
	"api-key":               {},
	"apikey":                {},
	"secret":                {},
	"authorization":         {},
	"auth-token":            {},
	"access-token":          {},
	"refresh-token":         {},
	"client-secret":         {},
	"dsn":                   {},
	"database-url":          {},
	"db-url":                {},
	"pgpassword":            {},
	"mysql-pwd":             {},
	"aws-secret-access-key": {},
	"github-token":          {},
	"private-key":           {},
	"credential":            {},
	"credentials":           {},
}

var (
	// Username may be empty (e.g. redis://:password@host), so the userinfo
	// prefix deliberately permits zero characters between // and the colon.
	uriUserinfoRE = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/@\s]*:)([^@\s/]+)(@)`)
	querySecretRE = regexp.MustCompile(`(?i)([?&](?:password|passwd|pass|token|api[_-]?key|secret|authorization|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret)=)([^&\s]+)`)
	authHeaderRE  = regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic)?\s*)[^\s]+`)
)

func canonicalArgKey(s string) string {
	s = strings.TrimSpace(strings.TrimLeft(s, "-"))
	s = strings.ToLower(s)
	return strings.ReplaceAll(s, "_", "-")
}

func isSensitiveArgKey(s string) bool {
	_, ok := sensitiveArgKeys[canonicalArgKey(s)]
	return ok
}

func mysqlStylePasswordArgv(args []string) bool {
	if len(args) == 0 {
		return false
	}
	base := strings.ToLower(filepath.Base(args[0]))
	switch base {
	case "mysql", "mariadb", "mysqldump", "mariadb-dump", "mysqladmin", "mysqlcheck":
		return true
	default:
		return false
	}
}

// splitCmdline converts a bounded /proc/<pid>/cmdline read into argv. If the
// total read cap cut the final argument in half, that fragment is never returned:
// it is impossible to know whether a delimiter needed for secret recognition was
// beyond the cap, so fail closed with a marker instead.
func splitCmdline(raw []byte, truncated bool) []string {
	if len(raw) == 0 {
		return nil
	}
	partialLast := truncated && raw[len(raw)-1] != 0
	parts := bytes.Split(raw, []byte{0})
	args := make([]string, 0, len(parts))
	for i, part := range parts {
		if i == len(parts)-1 && len(part) == 0 {
			continue
		}
		if partialLast && i == len(parts)-1 {
			args = append(args, "[TRUNCATED]")
			continue
		}
		args = append(args, string(part))
	}
	return args
}

// readSanitizedArgv is deliberately bounded before parsing. It never returns the
// raw /proc cmdline; every complete argument passes through sanitizeArgv first,
// and an argument cut by the total cap is replaced with [TRUNCATED].
func readSanitizedArgv(pid int) ([]string, int, bool) {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, 0, false
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxArgvBytes+1))
	if err != nil {
		return nil, 0, false
	}
	truncated := len(raw) > maxArgvBytes
	if truncated {
		raw = raw[:maxArgvBytes]
	}
	if len(raw) == 0 {
		return nil, 0, truncated
	}

	args := splitCmdline(raw, truncated)
	out, redactions, argTruncated := sanitizeArgv(args)
	return out, redactions, truncated || argTruncated
}

// sanitizeArgv is best-effort rather than a claim that arbitrary positional
// secrets can be identified. It covers common flag/env/header/URI forms and
// keeps both individual args and the total /proc read bounded.
func sanitizeArgv(args []string) ([]string, int, bool) {
	out := make([]string, 0, len(args))
	redactions := 0
	truncated := false
	mysqlShortP := mysqlStylePasswordArgv(args)

	for i := 0; i < len(args); i++ {
		a := args[i]

		if key, _, ok := strings.Cut(a, "="); ok && isSensitiveArgKey(key) {
			out = append(out, clampArg(key+"=[REDACTED]", &truncated))
			redactions++
			continue
		}

		if isSensitiveArgKey(a) && i+1 < len(args) {
			out = append(out, clampArg(a, &truncated), "[REDACTED]")
			redactions++
			i++
			continue
		}

		if mysqlShortP {
			if a == "-p" && i+1 < len(args) {
				out = append(out, "-p", "[REDACTED]")
				redactions++
				i++
				continue
			}
			if strings.HasPrefix(a, "-p") && len(a) > 2 && !strings.HasPrefix(a, "--") {
				out = append(out, "-p[REDACTED]")
				redactions++
				continue
			}
		}

		s, n := redactInlineSecrets(a)
		redactions += n
		out = append(out, clampArg(s, &truncated))
	}
	return out, redactions, truncated
}

func redactInlineSecrets(s string) (string, int) {
	n := 0
	if m := uriUserinfoRE.FindAllStringIndex(s, -1); len(m) > 0 {
		n += len(m)
		s = uriUserinfoRE.ReplaceAllString(s, `$1[REDACTED]$3`)
	}
	if m := querySecretRE.FindAllStringIndex(s, -1); len(m) > 0 {
		n += len(m)
		s = querySecretRE.ReplaceAllString(s, `$1[REDACTED]`)
	}
	if m := authHeaderRE.FindAllStringIndex(s, -1); len(m) > 0 {
		n += len(m)
		s = authHeaderRE.ReplaceAllString(s, `$1[REDACTED]`)
	}
	return s, n
}

func clampArg(s string, truncated *bool) string {
	if len(s) <= maxArgBytes {
		return s
	}
	*truncated = true
	return s[:maxArgBytes] + "…"
}

// totalJiffies sums the aggregate CPU fields from the first line of /proc/stat.
func totalJiffies() (uint64, bool) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	line := raw
	if i := strings.IndexByte(string(raw), '\n'); i > 0 {
		line = raw[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 || fields[0] != "cpu" {
		return 0, false
	}
	var sum uint64
	for _, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			continue
		}
		sum += v
	}
	return sum, true
}

var numCPUOnce struct {
	sync.Once
	n int
}

func numCPUs() int {
	numCPUOnce.Do(func() {
		raw, err := os.ReadFile("/proc/stat")
		if err != nil {
			numCPUOnce.n = 1
			return
		}
		n := 0
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
				n++
			}
		}
		if n < 1 {
			n = 1
		}
		numCPUOnce.n = n
	})
	return numCPUOnce.n
}

func memTotalKB() int64 {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					return v
				}
			}
		}
	}
	return 0
}

func round1(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}
