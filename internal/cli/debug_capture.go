// Package cli — capture helpers for `cfm debug`.
//
// Each capture function is small and returns either raw bytes (for blobs
// like pprof / /proc/$pid/maps) or a structured value (for trace samples
// the orchestrator stitches into one file). The orchestrator in debug.go
// wires them together; this file exists so each helper is independently
// unit-testable and the orchestrator stays readable.
//
// Capture helpers must be tolerant: a single failed capture (e.g. the
// daemon isn't listening on /debug/pprof) must not abort the whole
// bundle. Each returns ([]byte, error); the orchestrator records the
// error in manifest.txt and continues with the remaining items.
package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"cfm/internal/clihttp"
)

// captureProcStatus reads /proc/<pid>/status. Used for VmRSS/VmSize/Threads.
func captureProcStatus(pid int) ([]byte, error) {
	return os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
}

// captureProcIO reads /proc/<pid>/io. Available on most kernels with
// CONFIG_TASK_IO_ACCOUNTING; returns ENOENT if not.
func captureProcIO(pid int) ([]byte, error) {
	return os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "io"))
}

// captureProcMaps reads /proc/<pid>/maps. Can be large for processes
// with many shared-library / mmap'd-file mappings; orchestrator decides
// whether to keep the raw file alongside the parsed summary.
func captureProcMaps(pid int) ([]byte, error) {
	return os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "maps"))
}

// captureProcMapsGzipped returns the gzipped /proc/<pid>/maps contents.
// Raw maps for a leaking worker can be hundreds of KB to several MB
// (each mapped temp file is one line); gzipping keeps the bundle small
// while preserving the file paths an operator needs to identify the
// leak source.
func captureProcMapsGzipped(pid int) ([]byte, error) {
	raw, err := captureProcMaps(pid)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// procPPid reads /proc/<pid>/stat and returns the parent PID. Uses the
// same last-')' parse as procCPUTicks since field 4 (PPid) sits after
// the (comm) group.
func procPPid(pid int) (int, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	last := bytes.LastIndexByte(b, ')')
	if last < 0 || last+2 >= len(b) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	rest := strings.Fields(string(b[last+2:]))
	if len(rest) < 2 {
		return 0, fmt.Errorf("truncated /proc/%d/stat", pid)
	}
	// rest[0] is state; rest[1] is PPid.
	ppid, err := strconv.Atoi(rest[1])
	if err != nil {
		return 0, err
	}
	return ppid, nil
}

// procCmdline returns /proc/<pid>/cmdline with NUL separators replaced
// by spaces. Returns "" on read error so callers can fall through.
func procCmdline(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(b), "\x00", " ")
}

// filterCFMManagedWorkers narrows a list of "worker process" PIDs to
// those that belong to a CFM-managed nginx/angie/openresty install,
// dropping unrelated worker processes such as the cPanel-stack
// `nginx` master, imunify360-webs, or any other vendor-shipped HTTP
// server that happens to use the "worker process" naming convention.
//
// Two-stage detection, ordered by reliability:
//
//   1. Direct binary signal: if the worker's own cmdline starts with
//      `angie:`, it's ours. cPanel does not ship the `angie` binary —
//      it uses `nginx` (under /usr/sbin/nginx) and bundles its own
//      stack. So the `angie:` prefix is exclusive to CFM-managed
//      installs.
//
//   2. Master cmdline signal (for nginx/openresty deployments where
//      the binary alone doesn't tell them apart from cPanel's nginx):
//      check the parent process's cmdline for one of the path tokens
//      that the install scripts (install-angie.sh / install-openresty.sh)
//      embed in the angie/openresty invocation. The tokens cover both
//      the angie config-suffix style (`.conf.cfm`) and the openresty
//      paths (`/usr/share/cfm/` for the config source,
//      `/usr/local/openresty/nginx/` for the prefix dir).
//
// Returns only PIDs we're confident are CFM-managed. Drops everything
// else; manifest in the caller records the dropped count for the
// operator's visibility.
func filterCFMManagedWorkers(workerPIDs []int) []int {
	cfmMasterTokens := []string{
		".conf.cfm",                  // /etc/angie/angie.conf.cfm (install-angie.sh:691)
		"/usr/share/cfm/",            // /usr/share/cfm/configs/openresty.conf (install-openresty.sh:464)
		"/usr/local/openresty/nginx", // openresty prefix path (install-openresty.sh:466)
		"/etc/cfm/",                  // any future direct -c reference
		"/var/lib/cfm/",              // cfm-managed temp/cert/state paths
		"/var/run/cfm/",              // bridge socket paths
		"cfm_nginx.conf",             // future possibility
		"cfm_angie.conf",             // future possibility
	}
	out := make([]int, 0, len(workerPIDs))
	for _, pid := range workerPIDs {
		// Stage 1: exclusive binary-name signal.
		worker := procCmdline(pid)
		if strings.HasPrefix(worker, "angie:") {
			out = append(out, pid)
			continue
		}
		// Stage 2: master-cmdline path signal for nginx/openresty.
		ppid, err := procPPid(pid)
		if err != nil || ppid <= 1 {
			continue
		}
		master := procCmdline(ppid)
		if master == "" {
			continue
		}
		for _, tok := range cfmMasterTokens {
			if strings.Contains(master, tok) {
				out = append(out, pid)
				break
			}
		}
	}
	return out
}

// procCPUTicks returns the cumulative user+system CPU jiffies from
// /proc/<pid>/stat. Two calls separated by a sleep give a CPU% sample
// without spawning `top`. The fields layout in /proc/[pid]/stat is
// described in proc(5); fields 14 (utime) and 15 (stime) are after the
// "(comm)" group, which can itself contain spaces and parens — so we
// parse from the LAST ')' rather than splitting on whitespace.
func procCPUTicks(pid int) (int64, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	s := string(b)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	rest := strings.Fields(s[idx+2:])
	// rest[0] is "state" (field 3); utime is field 14 → rest[11], stime field 15 → rest[12].
	if len(rest) < 13 {
		return 0, fmt.Errorf("truncated /proc/%d/stat: %d fields after comm", pid, len(rest))
	}
	utime, err := strconv.ParseInt(rest[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse utime: %w", err)
	}
	stime, err := strconv.ParseInt(rest[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse stime: %w", err)
	}
	return utime + stime, nil
}

// procThreadCount returns the number of threads (entries under
// /proc/<pid>/task) for the given process.
func procThreadCount(pid int) (int, error) {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "task"))
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// procFDCount returns the number of file descriptors held by the process.
// Useful for spotting fd leaks alongside RSS growth.
func procFDCount(pid int) (int, error) {
	entries, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// pidsByCommandSubstring returns PIDs of processes whose /proc/<pid>/cmdline
// contains the given substring. Replacement for shell-based pgrep without
// a fork/exec dependency. Reads cmdline directly so spaces/quoting inside
// the command line don't trip word-boundary matching.
func pidsByCommandSubstring(needle string) ([]int, error) {
	if needle == "" {
		return nil, errors.New("empty needle")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		// cmdline uses NUL separators; replace with spaces for substring search.
		cmd := strings.ReplaceAll(string(b), "\x00", " ")
		if strings.Contains(cmd, needle) {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out, nil
}

// fetchPprof downloads a Go pprof artifact from the daemon's apiserver.
// `endpoint` is the trailing path under /debug/pprof/ — e.g. "profile",
// "heap", "goroutine?debug=2". For "profile", the apiserver expects a
// `seconds=N` query argument; the caller passes that in `endpoint` to
// keep this helper agnostic.
//
// Times out at dur+10s so a missed-by-1s deadline doesn't abandon the
// fetch when the apiserver finishes the profile slightly late.
func fetchPprof(baseURL, endpoint string, dur time.Duration) ([]byte, error) {
	timeout := dur + 10*time.Second
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	url := strings.TrimRight(baseURL, "/") + "/debug/pprof/" + strings.TrimLeft(endpoint, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Use clihttp.Do so the apiserver bearer token (set in main's
	// debug-case dispatch) is injected as Authorization: Bearer <tok>.
	// Without this the apiserver answers 401 for every pprof endpoint
	// — losing CPU/heap/goroutine profiles, which are the highest-value
	// items in the bundle.
	resp, err := clihttp.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pprof %s: %s", endpoint, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// runPProfTop renders a human-readable top of a pprof profile blob using
// `go tool pprof -top -cum`. If `go` isn't on PATH, returns a sentinel
// error so the orchestrator can keep the .pb.gz blob and skip the text.
//
// Profile is fed via stdin so we don't need to write a temp file just to
// pipe it back out.
func runPProfTop(profile []byte) ([]byte, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return nil, errors.New("go binary not on PATH; raw profile retained")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "tool", "pprof", "-top", "-cum", "-")
	cmd.Stdin = bytes.NewReader(profile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pprof top: %w (stderr=%q)", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// tailFile returns the last `n` lines of a file. Reads from the end in
// 64 KB chunks; sufficient for log tails which rarely have lines longer
// than a kilobyte. Returns less than n lines if the file is shorter.
func tailFile(path string, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.Open(path) // #nosec G304 -- caller passes a known-safe log path
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	if size == 0 {
		return nil, nil
	}

	const chunk = 64 * 1024
	var buf bytes.Buffer
	newlines := 0
	pos := size
	for pos > 0 && newlines <= n {
		read := int64(chunk)
		if pos < read {
			read = pos
		}
		pos -= read
		tmp := make([]byte, read)
		if _, err := f.ReadAt(tmp, pos); err != nil && err != io.EOF {
			return nil, err
		}
		// Prepend; we read from the end backwards.
		buf2 := bytes.Buffer{}
		buf2.Write(tmp)
		buf2.Write(buf.Bytes())
		buf = buf2
		newlines = bytes.Count(buf.Bytes(), []byte{'\n'})
	}
	// Trim leading content until we have at most n+1 newlines.
	out := buf.Bytes()
	for newlines > n {
		i := bytes.IndexByte(out, '\n')
		if i < 0 {
			break
		}
		out = out[i+1:]
		newlines--
	}
	return out, nil
}

// captureJournal runs `journalctl -u cfm --since "<since> ago" --no-pager`
// when systemd is present. Returns ENOENT if journalctl isn't on PATH —
// the orchestrator records the skip in manifest.txt.
func captureJournal(since time.Duration, unit string) ([]byte, error) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, errors.New("journalctl not on PATH (systemd not installed?)")
	}
	if unit == "" {
		unit = "cfm"
	}
	sinceArg := fmt.Sprintf("%d seconds ago", int(since.Seconds()))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "-u", unit, "--since", sinceArg, "--no-pager")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// If the unit doesn't exist or there's no record, journalctl
		// returns non-zero. Surface stderr so the operator sees the
		// reason, but don't fail the bundle.
		return stdout.Bytes(), fmt.Errorf("journalctl exit: %w (stderr=%q)", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// captureSocketState runs `ss -lntp` and returns the output. Useful for
// confirming the apiserver and bridge listeners are up and seeing
// connection counts.
func captureSocketState() ([]byte, error) {
	if _, err := exec.LookPath("ss"); err != nil {
		return nil, errors.New("ss not on PATH (iproute2 not installed?)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ss", "-lntp").Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// captureUnixSocket runs `ss -ax 'sport = <socket>'` for unix-socket
// connection-count visibility (the bridge socket lives at
// /var/run/cfm/cfm_nginx.sock). Falls back to plain `ss -ax` filtered
// in-Go if --filter syntax differs by ss version.
func captureUnixSocket(sockPath string) ([]byte, error) {
	if _, err := exec.LookPath("ss"); err != nil {
		return nil, errors.New("ss not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ss", "-ax").Output()
	if err != nil {
		return nil, err
	}
	if sockPath == "" {
		return out, nil
	}
	// Filter to lines mentioning the socket path.
	var keep [][]byte
	for _, ln := range bytes.Split(out, []byte{'\n'}) {
		if len(keep) == 0 {
			// keep header line so the columns make sense
			keep = append(keep, ln)
			continue
		}
		if bytes.Contains(ln, []byte(sockPath)) {
			keep = append(keep, ln)
		}
	}
	return bytes.Join(keep, []byte{'\n'}), nil
}

// captureSystemInfo runs a handful of trivial system-state commands and
// concatenates their output with section headers. Cheap and provides
// the "is this the same box / kernel / disk-full?" sanity layer.
func captureSystemInfo() []byte {
	var out bytes.Buffer
	run := func(label, name string, args ...string) {
		fmt.Fprintf(&out, "===== %s =====\n", label)
		if _, err := exec.LookPath(name); err != nil {
			fmt.Fprintf(&out, "(skipped: %s not on PATH)\n\n", name)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		out.Write(b)
		if err != nil {
			fmt.Fprintf(&out, "(error: %v)\n", err)
		}
		out.WriteByte('\n')
	}
	run("uname -a", "uname", "-a")
	run("uptime", "uptime")
	run("free -h", "free", "-h")
	run("df -h /", "df", "-h", "/")
	run("df -h /var/lib/cfm /var/log/cfm", "df", "-h", "/var/lib/cfm", "/var/log/cfm")
	return out.Bytes()
}
