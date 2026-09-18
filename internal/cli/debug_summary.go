// Package cli — summary builder, /proc/maps parser, and config sanitiser
// for `cfm debug`. Pure functions; no I/O. Easy to unit-test independently.
package cli

import (
	"bufio"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cfm/internal/secretkeys"
)

// procMapsSummary is a tiny digest of /proc/<pid>/maps suitable for
// summary.txt. Total VIRT (matches /proc/<pid>/status:VmSize) bucketed
// by mapping kind so a "huge VIRT" reading can be attributed.
type procMapsSummary struct {
	TotalMappings   int
	AnonymousBytes  int64
	FileBackedBytes int64
	SharedBytes     int64 // /SYSV*, /dev/shm/*, /memfd:* — shdict-style mappings
	HeapBytes       int64
	StackBytes      int64
}

// procMapsLineRE matches a single line of /proc/<pid>/maps.
//   address           perms offset  dev   inode  pathname (optional)
//   00400000-00452000 r-xp 00000000 fd:00 173521 /usr/lib/foo
//
// The line shape is stable across Linux versions; this regex covers the
// 32-bit and 64-bit variants. We capture only the address range and the
// optional pathname — perms/offset/dev/inode are not needed for the
// summary.
var procMapsLineRE = regexp.MustCompile(`^([0-9a-f]+)-([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\S+\s*(.*)$`)

// summariseProcMaps parses /proc/<pid>/maps text into a procMapsSummary.
// Unknown / malformed lines are silently skipped; the goal is a lossy
// digest, not a faithful re-emit.
func summariseProcMaps(content string) procMapsSummary {
	var s procMapsSummary
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20) // /proc/maps can have long lines on heavy mmap users
	for sc.Scan() {
		line := sc.Text()
		m := procMapsLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		start, err1 := strconv.ParseUint(m[1], 16, 64)
		end, err2 := strconv.ParseUint(m[2], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		size := int64(end - start)
		s.TotalMappings++
		path := strings.TrimSpace(m[3])
		switch {
		case path == "" || path == "[anon]" || strings.HasPrefix(path, "[anon"):
			s.AnonymousBytes += size
		case path == "[heap]":
			s.HeapBytes += size
		case strings.HasPrefix(path, "[stack"):
			s.StackBytes += size
		case strings.HasPrefix(path, "/SYSV") ||
			strings.HasPrefix(path, "/dev/shm/") ||
			strings.HasPrefix(path, "/memfd:") ||
			strings.HasPrefix(path, "/run/shm"):
			s.SharedBytes += size
		default:
			// Anything left with a path is a file-backed mapping
			// (libraries, binaries, mmap'd data files).
			s.FileBackedBytes += size
		}
	}
	return s
}

// Secret-key detection lives in internal/secretkeys (single source of truth,
// shared with the read-only MCP detectors_config redactor) so the two paths
// can't drift on what counts as a secret: e.g. "bridge_token", "hmac_secret",
// "clamd_password", "api_key" are all caught (a bare "key" root is not).

// configLineRE matches `key = value` (with optional whitespace and
// surrounding quotes on the value). Comment lines and section headers
// pass through unchanged.
var configLineRE = regexp.MustCompile(`^(\s*)([A-Za-z_][A-Za-z0-9_.\-]*)(\s*=\s*)(.*)$`)

// alreadyRedactedRE matches the sanitiser's own output so a second
// pass leaves the line alone (idempotence).
var alreadyRedactedRE = regexp.MustCompile(`^<redacted len=\d+>$`)

// sanitiseConfig redacts secret-looking values in cfm.conf-style files.
// Comments (#) and section headers ([…]) pass through untouched. Values
// matching a secret key get replaced with "<redacted len=N>" so the
// operator can still confirm the secret is set without leaking it.
//
// Idempotent: running twice doesn't double-redact. Returns the
// transformed file as a string.
func sanitiseConfig(content string) string {
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "[") {
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}
		m := configLineRE.FindStringSubmatch(line)
		if m == nil {
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}
		key := m[2]
		if !secretkeys.IsSecret(key) {
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}
		// Strip surrounding quotes from the value to compute the real
		// secret length, then write the redaction.
		val := strings.TrimSpace(m[4])
		val = strings.TrimSuffix(strings.TrimPrefix(val, `"`), `"`)
		val = strings.TrimSuffix(strings.TrimPrefix(val, "'"), "'")
		// Idempotence: if the value is already our redacted form, pass
		// through unchanged so a second sanitiser pass doesn't claim
		// the redaction marker itself is the secret.
		if alreadyRedactedRE.MatchString(val) {
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}
		fmt.Fprintf(&b, "%s%s%s<redacted len=%d>\n", m[1], m[2], m[3], len(val))
	}
	return b.String()
}

// pprofTopLine is one parsed entry from `go tool pprof -top` output.
type pprofTopLine struct {
	FlatBytes int64   // raw "flat" value (units depend on profile type)
	FlatPct   float64 // % of total
	CumBytes  int64
	CumPct    float64
	Function  string
	Unit      string // "MB", "ms", "s" — copied from the profile's Showing line
}

// pprofTopLineRE matches a row produced by `go tool pprof -top`. Example:
//
//	   12.34MB  4.56%  4.56%    20.00MB  7.40% github.com/foo/bar.Baz
//
// or:
//
//	  3450ms 20.00% 35.00%    9000ms 56.21%  net/http.(*Server).Serve
//
// Captured groups: 1=flat, 2=unit, 3=flatPct, 4=cumBytes, 5=cumUnit, 6=cumPct, 7=fn.
var pprofTopLineRE = regexp.MustCompile(`^\s+([\d.]+)([a-zA-Z%]*)\s+([\d.]+)%\s+[\d.]+%\s+([\d.]+)([a-zA-Z%]*)\s+([\d.]+)%\s+(.+)$`)

// parsePProfTop pulls the top N rows out of `go tool pprof -top` output.
// Skips header lines (Showing, total samples). Stops at the first blank
// line or after `n` rows.
func parsePProfTop(out string, n int) []pprofTopLine {
	if n <= 0 {
		return nil
	}
	var rows []pprofTopLine
	for _, line := range strings.Split(out, "\n") {
		if len(rows) >= n {
			break
		}
		m := pprofTopLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		flat, _ := strconv.ParseFloat(m[1], 64)
		flatPct, _ := strconv.ParseFloat(m[3], 64)
		cum, _ := strconv.ParseFloat(m[4], 64)
		cumPct, _ := strconv.ParseFloat(m[6], 64)
		rows = append(rows, pprofTopLine{
			FlatBytes: int64(flat),
			FlatPct:   flatPct,
			CumBytes:  int64(cum),
			CumPct:    cumPct,
			Function:  strings.TrimSpace(m[7]),
			Unit:      m[2],
		})
	}
	return rows
}

// procStatusFields extracts the lines from /proc/<pid>/status that
// matter most for a daemon-health summary. Returns a small map; missing
// keys are simply absent from the result.
func procStatusFields(content string) map[string]string {
	want := map[string]bool{
		"Name": true, "State": true, "VmRSS": true, "VmSize": true,
		"VmHWM": true, "VmData": true, "VmStk": true, "Threads": true,
		"voluntary_ctxt_switches": true, "nonvoluntary_ctxt_switches": true,
	}
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if !want[k] {
			continue
		}
		out[k] = strings.TrimSpace(v)
	}
	return out
}

// workerSample is one snapshot of a worker process's vital stats,
// recorded by the orchestrator at intervals during the trace window.
type workerSample struct {
	At        time.Time
	PID       int
	VmRSSKB   int64
	VmSizeKB  int64
	Threads   int
	FDs       int
	MapsCount int
}

// summaryInput is everything the orchestrator hands to buildSummary.
// All fields optional; buildSummary writes "n/a" for missing data.
type summaryInput struct {
	BundlePath string
	StartedAt  time.Time
	Duration   time.Duration

	// Daemon
	DaemonPID         int
	DaemonProcStatus  string // raw /proc/<pid>/status content
	DaemonCPUStart    int64  // jiffies at run start
	DaemonCPUEnd      int64  // jiffies at run end
	DaemonElapsedSec  float64
	DaemonClkTck      int64
	DaemonGoroutines  int   // parsed from /debug/pprof/goroutine?debug=1
	DaemonPProfTop    []pprofTopLine
	DaemonHeapTop     []pprofTopLine

	// Workers
	WorkerSamples []workerSample // ordered ascending by At for each PID

	// Manifest
	Manifest map[string]string // file → "ok" / "skipped: …" / "error: …"
}

// buildSummary renders summary.txt — a scannable digest the operator
// pastes back. Detail files in the bundle have the full data.
func buildSummary(in summaryInput) string {
	var b strings.Builder

	fmt.Fprintf(&b, "cfm debug bundle\n")
	fmt.Fprintf(&b, "================\n\n")
	fmt.Fprintf(&b, "bundle_path: %s\n", in.BundlePath)
	fmt.Fprintf(&b, "started_at:  %s\n", in.StartedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "duration:    %s\n\n", in.Duration)

	// ── Daemon ────────────────────────────────────────────────────────
	b.WriteString("Daemon\n------\n")
	if in.DaemonPID == 0 {
		b.WriteString("(daemon not found — was cfm running when the bundle was captured?)\n\n")
	} else {
		fmt.Fprintf(&b, "pid:         %d\n", in.DaemonPID)
		fields := procStatusFields(in.DaemonProcStatus)
		for _, k := range []string{"State", "Threads", "VmRSS", "VmSize", "VmHWM"} {
			if v, ok := fields[k]; ok {
				fmt.Fprintf(&b, "%-12s %s\n", k+":", v)
			}
		}
		// CPU% over the trace window: (delta_ticks / clk_tck) / elapsed_sec
		if in.DaemonClkTck > 0 && in.DaemonElapsedSec > 0 {
			delta := in.DaemonCPUEnd - in.DaemonCPUStart
			cpuPct := float64(delta) * 100.0 / (in.DaemonElapsedSec * float64(in.DaemonClkTck))
			fmt.Fprintf(&b, "cpu_pct:     %.2f (over %.1fs window)\n", cpuPct, in.DaemonElapsedSec)
		}
		// Negative value is the orchestrator's "fetch failed" sentinel
		// (e.g. apiserver returned 401, or wasn't reachable). Show
		// "unavailable" instead of 0 so the operator doesn't read it
		// as "the daemon has no goroutines" (which can't happen for a
		// live Go runtime).
		if in.DaemonGoroutines < 0 {
			fmt.Fprintf(&b, "goroutines:  unavailable\n")
		} else {
			fmt.Fprintf(&b, "goroutines:  %d\n", in.DaemonGoroutines)
		}
		b.WriteByte('\n')

		if len(in.DaemonPProfTop) > 0 {
			b.WriteString("Top hot functions (CPU profile):\n")
			for i, row := range in.DaemonPProfTop {
				if i >= 5 {
					break
				}
				fmt.Fprintf(&b, "  %5.2f%%  %5.2f%% cum  %s\n", row.FlatPct, row.CumPct, row.Function)
			}
			b.WriteByte('\n')
		}
		if len(in.DaemonHeapTop) > 0 {
			b.WriteString("Top heap allocators (in_use_space):\n")
			for i, row := range in.DaemonHeapTop {
				if i >= 5 {
					break
				}
				fmt.Fprintf(&b, "  %5.2f%%  %5.2f%% cum  %s\n", row.FlatPct, row.CumPct, row.Function)
			}
			b.WriteByte('\n')
		}
	}

	// ── Workers ───────────────────────────────────────────────────────
	b.WriteString("Workers\n-------\n")
	byPID := map[int][]workerSample{}
	for _, s := range in.WorkerSamples {
		byPID[s.PID] = append(byPID[s.PID], s)
	}
	if len(byPID) == 0 {
		b.WriteString("(no nginx/angie workers sampled)\n\n")
	} else {
		pids := make([]int, 0, len(byPID))
		for p := range byPID {
			pids = append(pids, p)
		}
		sort.Ints(pids)
		fmt.Fprintf(&b, "%-8s %-12s %-12s %-8s %-8s %-12s %-12s\n",
			"pid", "rss_start", "rss_end", "growth", "growth/min", "size_start", "size_end")
		for _, pid := range pids {
			samples := byPID[pid]
			if len(samples) == 0 {
				continue
			}
			first := samples[0]
			last := samples[len(samples)-1]
			elapsedMin := last.At.Sub(first.At).Minutes()
			growth := last.VmRSSKB - first.VmRSSKB
			growthPerMin := 0.0
			if elapsedMin > 0 {
				growthPerMin = float64(growth) / elapsedMin
			}
			fmt.Fprintf(&b, "%-8d %-12s %-12s %-8s %-12s %-12s %-12s\n",
				pid,
				humanKB(first.VmRSSKB),
				humanKB(last.VmRSSKB),
				humanKB(growth),
				humanKB(int64(growthPerMin))+"/min",
				humanKB(first.VmSizeKB),
				humanKB(last.VmSizeKB),
			)
		}
		b.WriteByte('\n')

		// If any worker grew by more than 5 MB/min over the window, that's
		// the regression signal worth flagging up front.
		var leakers []string
		for _, pid := range pids {
			samples := byPID[pid]
			if len(samples) < 2 {
				continue
			}
			elapsedMin := samples[len(samples)-1].At.Sub(samples[0].At).Minutes()
			if elapsedMin <= 0 {
				continue
			}
			growthMB := float64(samples[len(samples)-1].VmRSSKB-samples[0].VmRSSKB) / 1024.0
			rate := growthMB / elapsedMin
			if rate >= 5 {
				leakers = append(leakers, fmt.Sprintf("pid=%d (+%.1f MB/min)", pid, rate))
			}
		}
		if len(leakers) > 0 {
			fmt.Fprintf(&b, "⚠ workers growing ≥ 5 MB/min: %s\n\n", strings.Join(leakers, ", "))
		}
	}

	// ── Manifest ──────────────────────────────────────────────────────
	b.WriteString("Captured artifacts\n------------------\n")
	if len(in.Manifest) == 0 {
		b.WriteString("(no manifest entries)\n")
	} else {
		keys := make([]string, 0, len(in.Manifest))
		for k := range in.Manifest {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-32s %s\n", k, in.Manifest[k])
		}
	}
	b.WriteByte('\n')
	return b.String()
}

// humanKB renders a kilobyte count as MB / GB with one decimal. Negative
// values render as "-1.2 MB" (used for growth that went negative).
func humanKB(kb int64) string {
	abs := kb
	sign := ""
	if abs < 0 {
		abs = -abs
		sign = "-"
	}
	switch {
	case abs >= 1024*1024:
		return fmt.Sprintf("%s%.1f GB", sign, float64(abs)/(1024*1024))
	case abs >= 1024:
		return fmt.Sprintf("%s%.1f MB", sign, float64(abs)/1024)
	default:
		return fmt.Sprintf("%s%d KB", sign, abs)
	}
}

// goroutineCountFromDebug1 extracts the integer goroutine total from the
// header of `/debug/pprof/goroutine?debug=1` output. The first non-empty
// line is "goroutine profile: total NNN".
func goroutineCountFromDebug1(content string) int {
	for _, ln := range strings.Split(content, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "goroutine profile: total ") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(ln, "goroutine profile: total "))
		if err == nil {
			return n
		}
	}
	return 0
}
