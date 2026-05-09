// Package cli — `cfm debug` orchestrator.
//
// Single-shot diagnostic capture. Invoked as `cfm debug [flags]`,
// produces a directory under /var/lib/cfm/debug/<UTC-timestamp>/
// containing pprof profiles, /proc snapshots, log tails, WAF state,
// and a scannable summary.txt. Default is /var/lib/cfm/debug rather
// than /tmp because /tmp is mounted noexec on many production hosts —
// see the comment on defaultDebugBundleRoot below.
//
// The orchestrator never writes to global state and never modifies the
// running daemon. It only reads /proc, fetches pprof endpoints, runs
// shell-utility binaries (ss, journalctl, free, df, uname, uptime),
// tails log files, and queries the apiserver for WAF state.
package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cfm/internal/clihttp"
)

const (
	// /var/lib/cfm/debug is the default bundle root rather than /tmp/
	// because /tmp is mounted noexec on many production hosts (a CIS
	// hardening default). When `go tool pprof` is invoked, the Go
	// toolchain extracts a helper binary to $TMPDIR / GOTMPDIR and
	// fork+exec's it; on a noexec /tmp this fails with
	// "fork/exec ...: permission denied" and the heap/cpu top
	// renderings are lost (raw .pb.gz blobs are still saved). The
	// /var/lib/cfm tree is writable+exec by project convention
	// (install-openresty.sh:374-375 already uses it for client_body_temp
	// and proxy_temp). Operators can override with --output.
	defaultDebugBundleRoot = "/var/lib/cfm/debug"
	defaultBundleDuration  = 60 * time.Second
	quickBundleDuration    = 30 * time.Second
	defaultRetainBundles   = 10
	workerSampleInterval   = 30 * time.Second
	// Upper bound for the pprof CPU profile's `seconds=` parameter.
	// The apiserver caps the URL value at 300 and adds a 15s safety
	// margin; in practice longer streams race that deadline (bundle-2
	// from 2026-05-09 returned EOF on a 300s request). 60s of samples
	// is sufficient for diagnosing hot paths; the worker memory trace
	// and daemon CPU trace still run for the full --duration.
	pprofCPUSecondsMax = 60
)

// RunDebug is the entry point invoked from cmd/cfm/main.go.
// args is os.Args[2:] — the trailing portion after `cfm debug`.
func RunDebug(args []string) int {
	opts, err := parseDebugFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cfm debug:", err)
		return 2
	}

	bundlePath := filepath.Join(opts.outputRoot, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(bundlePath, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "cfm debug: cannot create bundle dir %s: %v\n", bundlePath, err)
		return 1
	}

	fmt.Printf("cfm debug: writing bundle to %s\n", bundlePath)
	fmt.Printf("           duration: %s (pprof + worker mem trace)\n", opts.duration)
	fmt.Printf("           apiserver: %s\n", opts.apiAddr)
	fmt.Println()

	manifest := newManifest()

	startedAt := time.Now()
	var wg sync.WaitGroup

	// 1) System info — fast, runs in parallel with the long captures.
	//    Joined to the waitgroup so we never race the summary builder
	//    on its manifest entry.
	wg.Add(1)
	go func() {
		defer wg.Done()
		writeFile(bundlePath, "system.txt", captureSystemInfo(), manifest, "system.txt")
	}()

	// 2) Daemon discovery (find PID).
	daemonPIDs, _ := pidsByCommandSubstring("/usr/bin/cfm daemon")
	var daemonPID int
	if len(daemonPIDs) > 0 {
		daemonPID = daemonPIDs[0]
	}
	if daemonPID == 0 {
		manifest.set("proc-daemon.txt", "skipped: cfm daemon process not found")
	}

	// 3) Worker discovery — narrow to processes managed by CFM.
	//    Without the filter, we'd also catch the cPanel-stack `nginx`
	//    workers, imunify360-webs, and any other vendor HTTP server
	//    that happens to print "worker process" on its cmdline. Their
	//    state is noise for a CFM regression investigation.
	allWorkerPIDs, _ := pidsByCommandSubstring("worker process")
	workerPIDs := filterCFMManagedWorkers(allWorkerPIDs)

	// 4) Daemon /proc snapshot at start (used by summary's CPU% calc).
	clkTck := int64(systemClkTck())
	var daemonStatusStart []byte
	var daemonCPUStart int64
	if daemonPID != 0 {
		daemonStatusStart, _ = captureProcStatus(daemonPID)
		writeFile(bundlePath, "proc-daemon.txt", buildDaemonProcSnapshot(daemonPID, daemonStatusStart), manifest, "proc-daemon.txt")
		daemonCPUStart, _ = procCPUTicks(daemonPID)
	}

	// 5) /proc snapshots for each CFM-managed worker — both the
	//    parsed summary (category aggregates) AND the raw maps (gzipped)
	//    so the operator can identify what file paths are being mmap'd
	//    when they need to chase a leak. Raw maps for a leaking worker
	//    can be hundreds of KB per file; gzip compresses ~10x.
	if len(workerPIDs) > 0 {
		writeFile(bundlePath, "proc-workers.txt", buildWorkerProcSnapshot(workerPIDs), manifest, "proc-workers.txt")
		writeFile(bundlePath, "proc-maps-summary.txt", buildWorkerMapsSummary(workerPIDs), manifest, "proc-maps-summary.txt")
		for _, pid := range workerPIDs {
			name := fmt.Sprintf("proc-maps-raw-%d.txt.gz", pid)
			gz, err := captureProcMapsGzipped(pid)
			if err != nil {
				manifest.set(name, "error: "+err.Error())
				continue
			}
			writeFile(bundlePath, name, gz, manifest, name)
		}
	} else {
		manifest.set("proc-workers.txt", "skipped: no CFM-managed worker processes found")
		manifest.set("proc-maps-summary.txt", "skipped: no CFM-managed worker processes found")
	}
	if dropped := len(allWorkerPIDs) - len(workerPIDs); dropped > 0 {
		manifest.set("worker-discovery", fmt.Sprintf("kept=%d cfm-managed, dropped=%d unrelated (e.g. cPanel nginx, vendor HTTP servers)", len(workerPIDs), dropped))
	}

	// 6) Pprof captures + worker memory trace + daemon CPU trace —
	//    all run concurrently for the duration window. (wg declared
	//    above so the system-info goroutine is also joined.)

	// CPU profile. Cap the requested seconds at pprofCPUSecondsMax even
	// if --duration is longer. Two reasons:
	//   - the apiserver's pprof middleware caps the URL parameter at 300
	//     and adds a 15s safety margin to its write deadline; in practice
	//     5-minute streams race the deadline (bundle-2 returned EOF mid-
	//     stream).
	//   - 60s of CPU samples is enough for diagnosis; longer windows
	//     dilute hot functions with noise rather than improve them.
	// The worker memory trace and daemon CPU trace still run for the full
	// --duration; only the pprof CPU window shrinks.
	if !opts.skipPprof && daemonPID != 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seconds := int(opts.duration.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			if seconds > pprofCPUSecondsMax {
				seconds = pprofCPUSecondsMax
			}
			cpuFetchDur := time.Duration(seconds) * time.Second
			endpoint := fmt.Sprintf("profile?seconds=%d", seconds)
			b, err := fetchPprof(opts.apiAddr, endpoint, cpuFetchDur)
			if err != nil {
				manifest.set("pprof-cpu.pb.gz", "error: "+err.Error())
				return
			}
			writeFile(bundlePath, "pprof-cpu.pb.gz", b, manifest, "pprof-cpu.pb.gz")
			if top, err := runPProfTop(b, bundlePath); err == nil {
				writeFile(bundlePath, "pprof-cpu-top.txt", top, manifest, "pprof-cpu-top.txt")
			} else {
				manifest.set("pprof-cpu-top.txt", "skipped: "+err.Error())
			}
		}()
	} else if opts.skipPprof {
		manifest.set("pprof-cpu.pb.gz", "skipped: --no-pprof")
	}

	// Heap profile + goroutines (fast, fetched once).
	if !opts.skipPprof && daemonPID != 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := fetchPprof(opts.apiAddr, "heap", 5*time.Second)
			if err != nil {
				manifest.set("pprof-heap.pb.gz", "error: "+err.Error())
				return
			}
			writeFile(bundlePath, "pprof-heap.pb.gz", b, manifest, "pprof-heap.pb.gz")
			if top, err := runPProfTop(b, bundlePath); err == nil {
				writeFile(bundlePath, "pprof-heap-top.txt", top, manifest, "pprof-heap-top.txt")
			} else {
				manifest.set("pprof-heap-top.txt", "skipped: "+err.Error())
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := fetchPprof(opts.apiAddr, "goroutine?debug=2", 5*time.Second)
			if err != nil {
				manifest.set("goroutines.txt", "error: "+err.Error())
				return
			}
			writeFile(bundlePath, "goroutines.txt", b, manifest, "goroutines.txt")
		}()
	}

	// Worker memory trace.
	var workerSamples []workerSample
	if len(workerPIDs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			workerSamples = sampleWorkers(workerPIDs, opts.duration, workerSampleInterval)
			writeFile(bundlePath, "worker-mem-trace.txt", renderWorkerSamples(workerSamples), manifest, "worker-mem-trace.txt")
		}()
	} else {
		manifest.set("worker-mem-trace.txt", "skipped: no worker processes")
	}

	// Daemon CPU trace.
	var daemonCPUTrace []daemonCPUSample
	if daemonPID != 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			daemonCPUTrace = sampleDaemonCPU(daemonPID, opts.duration, workerSampleInterval, clkTck)
			writeFile(bundlePath, "daemon-cpu-trace.txt", renderDaemonCPUSamples(daemonCPUTrace), manifest, "daemon-cpu-trace.txt")
		}()
	} else {
		manifest.set("daemon-cpu-trace.txt", "skipped: cfm daemon not found")
	}

	// 7) Logs + journal (parallel, no duration dependency).
	if !opts.skipLogs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writeFile(bundlePath, "logs-tail.txt", captureLogTails(opts.logRoot), manifest, "logs-tail.txt")
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := captureJournal(opts.duration+1*time.Hour, "cfm")
			if err != nil {
				manifest.set("journal-tail.txt", "skipped: "+err.Error())
				return
			}
			writeFile(bundlePath, "journal-tail.txt", b, manifest, "journal-tail.txt")
		}()
	} else {
		manifest.set("logs-tail.txt", "skipped: --no-logs")
		manifest.set("journal-tail.txt", "skipped: --no-logs")
	}

	// 8) Network state.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if b, err := captureSocketState(); err == nil {
			writeFile(bundlePath, "ss-listen.txt", b, manifest, "ss-listen.txt")
		} else {
			manifest.set("ss-listen.txt", "skipped: "+err.Error())
		}
		if b, err := captureUnixSocket("/var/run/cfm/cfm_nginx.sock"); err == nil {
			writeFile(bundlePath, "bridge-conn.txt", b, manifest, "bridge-conn.txt")
		} else {
			manifest.set("bridge-conn.txt", "skipped: "+err.Error())
		}
	}()

	// 9) WAF API state — fetched via the apiserver if reachable.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if b, err := fetchAPI(opts.apiAddr, "/api/v1/waf/hit-rates?hours=1"); err == nil {
			writeFile(bundlePath, "waf-hit-rates.json", b, manifest, "waf-hit-rates.json")
		} else {
			manifest.set("waf-hit-rates.json", "skipped: "+err.Error())
		}
		if b, err := fetchAPI(opts.apiAddr, "/api/v1/waf/exclude/list"); err == nil {
			writeFile(bundlePath, "waf-excludes.json", b, manifest, "waf-excludes.json")
		} else {
			manifest.set("waf-excludes.json", "skipped: "+err.Error())
		}
	}()

	// 10) Sanitised config dump.
	if opts.configPath != "" {
		raw, err := os.ReadFile(opts.configPath) // #nosec G304 -- operator-supplied config path
		if err != nil {
			manifest.set("config.txt", "skipped: "+err.Error())
		} else {
			writeFile(bundlePath, "config.txt", []byte(sanitiseConfig(string(raw))), manifest, "config.txt")
		}
	}

	// Wait for all timed captures to finish.
	wg.Wait()

	// 11) Daemon /proc snapshot at end (for the CPU% in summary).
	var daemonCPUEnd int64
	if daemonPID != 0 {
		daemonCPUEnd, _ = procCPUTicks(daemonPID)
	}
	completedAt := time.Now()

	// 12) Parse pprof tops + goroutines for the summary.
	var pprofTopRows []pprofTopLine
	if b, err := os.ReadFile(filepath.Join(bundlePath, "pprof-cpu-top.txt")); err == nil {
		pprofTopRows = parsePProfTop(string(b), 5)
	}
	var heapTopRows []pprofTopLine
	if b, err := os.ReadFile(filepath.Join(bundlePath, "pprof-heap-top.txt")); err == nil {
		heapTopRows = parsePProfTop(string(b), 5)
	}
	// -1 sentinel = the goroutine fetch failed (apiserver down, 401, etc).
	// The summary builder renders this as "unavailable" rather than the
	// misleading "goroutines: 0" we used to print. A live Go daemon always
	// has at least one goroutine, so 0 was never actually a valid value.
	goCount := -1
	if b, err := fetchPprof(opts.apiAddr, "goroutine?debug=1", 3*time.Second); err == nil {
		goCount = goroutineCountFromDebug1(string(b))
	}

	// 13) Build and write summary.txt.
	summary := buildSummary(summaryInput{
		BundlePath:       bundlePath,
		StartedAt:        startedAt,
		Duration:         completedAt.Sub(startedAt),
		DaemonPID:        daemonPID,
		DaemonProcStatus: string(daemonStatusStart),
		DaemonCPUStart:   daemonCPUStart,
		DaemonCPUEnd:     daemonCPUEnd,
		DaemonElapsedSec: completedAt.Sub(startedAt).Seconds(),
		DaemonClkTck:     clkTck,
		DaemonGoroutines: goCount,
		DaemonPProfTop:   pprofTopRows,
		DaemonHeapTop:    heapTopRows,
		WorkerSamples:    workerSamples,
		Manifest:         manifest.snapshot(),
	})
	writeFile(bundlePath, "summary.txt", []byte(summary), manifest, "summary.txt")
	writeFile(bundlePath, "manifest.txt", []byte(renderManifest(manifest.snapshot())), manifest, "manifest.txt")

	// 14) Prune old bundles.
	if opts.keep > 0 {
		pruneBundles(opts.outputRoot, opts.keep)
	}

	fmt.Printf("\n%s", summary)
	fmt.Printf("Bundle complete: %s\n", bundlePath)
	return 0
}

// debugOpts is the parsed flag set.
type debugOpts struct {
	duration   time.Duration
	outputRoot string
	skipPprof  bool
	skipLogs   bool
	keep       int
	apiAddr    string
	configPath string
	logRoot    string
}

func parseDebugFlags(args []string) (*debugOpts, error) {
	fs := flag.NewFlagSet("cfm debug", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	durFlag := fs.Duration("duration", defaultBundleDuration, "trace duration for pprof + worker mem + daemon CPU")
	quickFlag := fs.Bool("quick", false, "shortcut for --duration 30s --no-logs")
	outputFlag := fs.String("output", defaultDebugBundleRoot, "bundle root directory; bundle goes to <root>/<UTC-timestamp>")
	noPprof := fs.Bool("no-pprof", false, "skip pprof captures (use when apiserver is down)")
	noLogs := fs.Bool("no-logs", false, "skip log tails and journalctl")
	keepFlag := fs.Int("keep", defaultRetainBundles, "retain only the last N bundles in the output dir; 0 to disable pruning")
	apiFlag := fs.String("apiserver", "", "apiserver URL (default: $CFM_API_ADDR or http://127.0.0.1:6060)")
	configFlag := fs.String("config", "/etc/cfm/cfm.conf", "config file to dump (sanitised); empty to skip")
	logRootFlag := fs.String("log-root", "/var/log/cfm", "directory to scan for log tails")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	opts := &debugOpts{
		duration:   *durFlag,
		outputRoot: *outputFlag,
		skipPprof:  *noPprof,
		skipLogs:   *noLogs,
		keep:       *keepFlag,
		apiAddr:    *apiFlag,
		configPath: *configFlag,
		logRoot:    *logRootFlag,
	}
	if *quickFlag {
		opts.duration = quickBundleDuration
		opts.skipLogs = true
	}
	if opts.duration < 1*time.Second {
		return nil, fmt.Errorf("duration must be ≥ 1s")
	}
	if opts.duration > 10*time.Minute {
		return nil, fmt.Errorf("duration must be ≤ 10m (sanity cap)")
	}
	if opts.apiAddr == "" {
		if v := strings.TrimSpace(os.Getenv("CFM_API_ADDR")); v != "" {
			opts.apiAddr = strings.TrimRight(v, "/")
		} else {
			opts.apiAddr = "http://127.0.0.1:6060"
		}
	}
	return opts, nil
}

// manifest tracks per-artifact capture status (ok / skipped / error).
// Concurrent-safe — capture goroutines update it as they finish.
type debugManifest struct {
	mu sync.Mutex
	m  map[string]string
}

func newManifest() *debugManifest {
	return &debugManifest{m: map[string]string{}}
}

func (m *debugManifest) set(name, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[name] = status
}

func (m *debugManifest) snapshot() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.m))
	for k, v := range m.m {
		out[k] = v
	}
	return out
}

// renderManifest produces the manifest.txt content from the captured map.
func renderManifest(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%-32s %s\n", k, m[k])
	}
	return b.String()
}

// writeFile writes data to <bundle>/<name> and records manifest status.
// Records "ok" on success or "error: …" on failure; never panics.
func writeFile(bundle, name string, data []byte, m *debugManifest, manifestKey string) {
	path := filepath.Join(bundle, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		m.set(manifestKey, "error: "+err.Error())
		return
	}
	m.set(manifestKey, fmt.Sprintf("ok (%d bytes)", len(data)))
}

// buildDaemonProcSnapshot concatenates the daemon's /proc/<pid>/{status,io,stat}
// + thread/fd counts into one human-readable text file.
func buildDaemonProcSnapshot(pid int, statusBytes []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "===== /proc/%d/status =====\n", pid)
	b.Write(statusBytes)
	b.WriteString("\n")
	if io, err := captureProcIO(pid); err == nil {
		fmt.Fprintf(&b, "===== /proc/%d/io =====\n", pid)
		b.Write(io)
		b.WriteString("\n")
	}
	tc, _ := procThreadCount(pid)
	fc, _ := procFDCount(pid)
	fmt.Fprintf(&b, "===== /proc/%d/{task,fd} counts =====\n", pid)
	fmt.Fprintf(&b, "threads=%d fds=%d\n", tc, fc)
	return []byte(b.String())
}

// buildWorkerProcSnapshot collects status + io + thread/fd counts for
// every worker PID into one file. Each block is labelled with the PID.
func buildWorkerProcSnapshot(pids []int) []byte {
	var b strings.Builder
	for _, pid := range pids {
		fmt.Fprintf(&b, "===== worker pid=%d =====\n", pid)
		if status, err := captureProcStatus(pid); err == nil {
			b.Write(status)
		} else {
			fmt.Fprintf(&b, "(status read failed: %v)\n", err)
		}
		if io, err := captureProcIO(pid); err == nil {
			b.WriteString("\n--- io ---\n")
			b.Write(io)
		}
		tc, _ := procThreadCount(pid)
		fc, _ := procFDCount(pid)
		fmt.Fprintf(&b, "\nthreads=%d fds=%d\n\n", tc, fc)
	}
	return []byte(b.String())
}

// buildWorkerMapsSummary parses /proc/<pid>/maps for each worker and
// renders the categorised totals. Useful for distinguishing real RSS
// growth from address-space inflation via mmap.
func buildWorkerMapsSummary(pids []int) []byte {
	var b strings.Builder
	for _, pid := range pids {
		raw, err := captureProcMaps(pid)
		if err != nil {
			fmt.Fprintf(&b, "===== worker pid=%d ===== (maps read failed: %v)\n\n", pid, err)
			continue
		}
		s := summariseProcMaps(string(raw))
		fmt.Fprintf(&b, "===== worker pid=%d =====\n", pid)
		fmt.Fprintf(&b, "  total_mappings: %d\n", s.TotalMappings)
		fmt.Fprintf(&b, "  anonymous:      %s\n", humanKB(s.AnonymousBytes/1024))
		fmt.Fprintf(&b, "  file_backed:    %s\n", humanKB(s.FileBackedBytes/1024))
		fmt.Fprintf(&b, "  shared:         %s (SYSV/dev-shm/memfd)\n", humanKB(s.SharedBytes/1024))
		fmt.Fprintf(&b, "  heap:           %s\n", humanKB(s.HeapBytes/1024))
		fmt.Fprintf(&b, "  stack:          %s\n\n", humanKB(s.StackBytes/1024))
	}
	return []byte(b.String())
}

// sampleWorkers periodically reads /proc/<pid>/status for each worker
// across the trace window and returns the time-ordered samples.
func sampleWorkers(pids []int, duration, interval time.Duration) []workerSample {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	deadline := time.Now().Add(duration)
	out := make([]workerSample, 0, len(pids)*int(duration/interval+1))
	// Initial sample.
	out = append(out, sampleWorkersOnce(pids)...)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			out = append(out, sampleWorkersOnce(pids)...)
			if time.Now().After(deadline) {
				return out
			}
		default:
			if time.Now().After(deadline) {
				return out
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// sampleWorkersOnce reads a single point-in-time sample of every worker.
func sampleWorkersOnce(pids []int) []workerSample {
	now := time.Now()
	out := make([]workerSample, 0, len(pids))
	for _, pid := range pids {
		s := workerSample{At: now, PID: pid}
		if status, err := captureProcStatus(pid); err == nil {
			fields := procStatusFields(string(status))
			s.VmRSSKB = parseKBField(fields["VmRSS"])
			s.VmSizeKB = parseKBField(fields["VmSize"])
			if t, err := parseIntField(fields["Threads"]); err == nil {
				s.Threads = t
			}
		}
		s.FDs, _ = procFDCount(pid)
		// MapsCount is expensive; cheap approximation via a line-count
		// of /proc/<pid>/maps.
		if maps, err := captureProcMaps(pid); err == nil {
			s.MapsCount = strings.Count(string(maps), "\n")
		}
		out = append(out, s)
	}
	return out
}

// parseKBField parses a "12345 kB" value from /proc/<pid>/status.
func parseKBField(v string) int64 {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "kB")
	v = strings.TrimSuffix(v, "KB")
	v = strings.TrimSpace(v)
	n, _ := parseInt64(v)
	return n
}

func parseIntField(v string) (int, error) {
	v = strings.TrimSpace(v)
	n, err := parseInt64(v)
	return int(n), err
}

// parseInt64 wraps strconv.ParseInt without dragging the import into
// every helper that needs a number out of /proc text.
func parseInt64(s string) (int64, error) {
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

// renderWorkerSamples produces the worker-mem-trace.txt content — one
// row per (pid, sample-time), tab-separated for easy ingest into
// downstream analysis.
func renderWorkerSamples(samples []workerSample) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# pid\ttime\tvm_rss_kb\tvm_size_kb\tthreads\tfds\tmaps\n")
	for _, s := range samples {
		fmt.Fprintf(&b, "%d\t%s\t%d\t%d\t%d\t%d\t%d\n",
			s.PID, s.At.UTC().Format(time.RFC3339), s.VmRSSKB, s.VmSizeKB,
			s.Threads, s.FDs, s.MapsCount)
	}
	return []byte(b.String())
}

// daemonCPUSample is one entry in the daemon CPU trace.
type daemonCPUSample struct {
	At       time.Time
	CPUTicks int64
	Pct      float64 // CPU% over the interval since the previous sample
}

// sampleDaemonCPU samples the daemon's CPU ticks at `interval` over
// `duration`, computing CPU% per interval.
func sampleDaemonCPU(pid int, duration, interval time.Duration, clkTck int64) []daemonCPUSample {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	deadline := time.Now().Add(duration)
	var out []daemonCPUSample
	first, _ := procCPUTicks(pid)
	out = append(out, daemonCPUSample{At: time.Now(), CPUTicks: first, Pct: 0})
	t := time.NewTicker(interval)
	defer t.Stop()
	prev := first
	prevAt := time.Now()
	for {
		select {
		case now := <-t.C:
			cur, err := procCPUTicks(pid)
			if err != nil {
				return out
			}
			elapsed := now.Sub(prevAt).Seconds()
			pct := 0.0
			if clkTck > 0 && elapsed > 0 {
				pct = float64(cur-prev) * 100.0 / (elapsed * float64(clkTck))
			}
			out = append(out, daemonCPUSample{At: now, CPUTicks: cur, Pct: pct})
			prev = cur
			prevAt = now
			if now.After(deadline) {
				return out
			}
		default:
			if time.Now().After(deadline) {
				return out
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func renderDaemonCPUSamples(samples []daemonCPUSample) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# time\tcpu_ticks\tcpu_pct_since_prev\n")
	for _, s := range samples {
		fmt.Fprintf(&b, "%s\t%d\t%.2f\n", s.At.UTC().Format(time.RFC3339), s.CPUTicks, s.Pct)
	}
	return []byte(b.String())
}

// captureLogTails reads up to 500 lines from each of the standard cfm
// log files. Returns one big buffer with section headers between files.
func captureLogTails(logRoot string) []byte {
	var b strings.Builder
	candidates := []string{
		"cfm.log",
		"cfm.waf.log",
		"cfm.waf.sampled.log",
		"cfm.error.log",
		"api.log",
	}
	for _, name := range candidates {
		path := filepath.Join(logRoot, name)
		fmt.Fprintf(&b, "===== %s =====\n", path)
		data, err := tailFile(path, 500)
		if err != nil {
			fmt.Fprintf(&b, "(read failed: %v)\n\n", err)
			continue
		}
		if len(data) == 0 {
			fmt.Fprintf(&b, "(empty)\n\n")
			continue
		}
		b.Write(data)
		if !strings.HasSuffix(string(data), "\n") {
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// fetchAPI hits an apiserver endpoint that returns JSON and returns
// the body. Used for /api/v1/waf/* state queries.
func fetchAPI(baseURL, path string) ([]byte, error) {
	u := strings.TrimRight(baseURL, "/") + path
	resp, err := clihttp.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: %s", path, resp.Status)
	}
	return readAll(resp.Body)
}

// readAll is io.ReadAll without dragging the import everywhere.
func readAll(r interface {
	Read(p []byte) (int, error)
}) ([]byte, error) {
	var buf [4096]byte
	var out []byte
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}

// pruneBundles deletes everything in `root` except the `keep` newest
// timestamp-named directories. Anything with a non-conforming name is
// left alone.
func pruneBundles(root string, keep int) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	type b struct {
		name string
		t    time.Time
	}
	var bundles []b
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Bundle dirs are named "20060102T150405Z".
		t, err := time.Parse("20060102T150405Z", e.Name())
		if err != nil {
			continue
		}
		bundles = append(bundles, b{name: e.Name(), t: t})
	}
	if len(bundles) <= keep {
		return
	}
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].t.After(bundles[j].t) })
	for _, drop := range bundles[keep:] {
		_ = os.RemoveAll(filepath.Join(root, drop.name))
	}
}

// systemClkTck returns CLK_TCK from sysconf — used to convert /proc
// CPU jiffies into seconds.  Falls back to 100 (the Linux default for
// userland HZ) if the syscall can't resolve it.
func systemClkTck() int {
	// sysconf(_SC_CLK_TCK) — there's no portable way to call this
	// without cgo; on Linux _SC_CLK_TCK is conventionally 100.
	// The user can override via the CFM_DEBUG_CLK_TCK env var if
	// they're on an unusual kernel.
	if v := strings.TrimSpace(os.Getenv("CFM_DEBUG_CLK_TCK")); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			return int(n)
		}
	}
	// Best-effort: getconf CLK_TCK.
	if path, err := exec.LookPath("getconf"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, path, "CLK_TCK").Output()
		if err == nil {
			if n, err2 := parseInt64(strings.TrimSpace(string(out))); err2 == nil && n > 0 {
				return int(n)
			}
		}
	}
	return 100
}

