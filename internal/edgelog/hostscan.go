// Package edgelog — hostscan.go does the HOST-keyed counterpart of GrepIP:
// an on-demand, bounded aggregation of ONE VHOST's traffic across the live
// edge access log plus (optionally) its rotated siblings. It backs the MCP
// `host_access_history` tool / GET /api/v1/webdet/host-access-history — the
// "how much traffic did this domain actually serve over the last N days, who
// from, with which user-agents, and when were the peaks?" view that the live
// ring (edge_access_tail) and the scored state (host_drilldown) cannot give
// for windows older than their retention.
//
// Cost discipline is the same as GrepIP: NO continuous overhead — nothing is
// retained between calls, no background scan. Work happens only on an explicit
// call and is bounded from every side:
//   - the LIVE file is read through `tail -n N` (seek-from-EOF, never the
//     multi-GB file whole);
//   - rotated siblings are streamed gz-transparently with ONE shared line
//     budget across the whole call;
//   - a context timeout caps wall-clock;
//   - every accumulator map is key-capped, so worst-case memory is bounded
//     regardless of what the logs contain;
//   - a rotated file whose mtime predates the window start is skipped without
//     being opened;
//   - unreadable/corrupt rotated files are reported in files_failed instead
//     of failing (or silently shortening) the whole call.
//
// Each INDIVIDUAL file is streamed oldest→newest (tail prints file order;
// rotated archives stream start→end), so pre-window lines within a file are
// simply not aggregated — there is NO early stop: everything is bounded by
// the budget/timeout/file caps above. Across files the walk is live-log first
// then rotated siblings newest-first, but aggregation is order-independent.
//
// Parsing expects the CFM `log_format cfm` family (`key=value` pairs incl.
// `host=$host`, identical on OpenResty and Angie). Lines without a parsable
// host field (foreign formats, e.g. a distro-combined format) are counted as
// skipped, never fatal.
package edgelog

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultHostHours = 24 * 7
	MaxHostHours     = 24 * 90

	// Live-file tail window. Larger than GrepIP's default because a host
	// profile needs real coverage of the live file, which on busy nodes holds
	// the most recent day(s) of traffic.
	DefaultHostTailLines = 1_000_000

	// Shared line budget across ALL files of the call (live included). This —
	// together with the timeout — is what keeps a "last 30 days" ask safe on a
	// node whose rotated logs hold tens of GB decompressed.
	DefaultHostMaxLines = 8_000_000
	MaxHostMaxLines     = 60_000_000

	// Rotated reach defaults higher than GrepIP's 10: monthly forensics wants
	// ~a month of daily siblings.
	DefaultHostFiles = 40

	hostScanTimeout = 120 * time.Second

	// Accumulator key caps. A cap hit does NOT fail the call: totals stay
	// exact (every line is still counted), only the long-tail breakdown of
	// that accumulator becomes approximate.
	maxIPKeys     = 100_000
	maxUAKeys     = 5_000
	maxFamilyKeys = 2_000
	maxPathKeys   = 10_000
	maxCodeKeys   = 32
	maxMethodKeys = 16
	maxPathLen    = 256
	maxFieldLen   = 64

	peakVsMedianFactor = 3.0
	maxPeakHours       = 10
)

// fullAccessLogCandidates are the FULL edge ACCESS logs only — the
// `log_format cfm ... if=$log_main_request` logs holding EVERY vhost's total
// traffic. The focused `access.cfm.log` (challenge/block routing traffic,
// if=$log_cfm_nonempty) and any distro combined-format access.log are
// deliberately NOT candidates: ScanHost promises TOTAL per-vhost traffic and
// requires the key=value `host=` field, so a semantically wrong source must
// never be selected just because its mtime is newest (unlike GrepIP, where any
// raw-line source is fair game).
var fullAccessLogCandidates = []string{
	"/usr/local/openresty/nginx/logs/access.log",
	"/var/log/angie/access.log",
}

// AvailableFullLogs returns the FULL access-log candidates that currently
// exist, so callers can surface what was considered.
func AvailableFullLogs() []string { return availableFrom(fullAccessLogCandidates) }

func resolveFullAccessLog() (string, error) {
	return resolveFrom(fullAccessLogCandidates, "", "access")
}

// badRequestLogFor derives the malformed/aborted sidecar path from the ALREADY
// RESOLVED full access log — never from an independent mtime race. The two
// engines' bad-request logs are sparse/event-driven, so an independent
// most-recently-modified pick could pair valid traffic from the ACTIVE engine
// with stale bad-request data from a DISABLED one; deriving from Dir(full)
// makes that structurally impossible.
func badRequestLogFor(full string) string {
	return filepath.Join(filepath.Dir(full), "access.bad_request.log")
}

// HostOpts tunes a host scan.
type HostOpts struct {
	Hours          int                     // trailing window ending now (ignored when FromUnix>0)
	FromUnix       int64                   // explicit window start (epoch sec); ToUnix=0 → now
	ToUnix         int64                   // explicit window end (epoch sec); [FromUnix, ToUnix) is enforced per line
	TailLines      int                     // live-file tail window (0 → DefaultHostTailLines)
	MaxLines       int                     // shared line budget across all files (0 → DefaultHostMaxLines)
	IncludeRotated bool                    // also scan rotated siblings (the archival reach)
	MaxFiles       int                     // cap rotated siblings scanned (0 → DefaultHostFiles)
	TopN           int                     // entries per top-list (0 → 20, max 50)
	MergeWWW       bool                    // also match the www./bare twin of the host
	ClassifyUA     func(raw string) string // optional UA→family classifier (e.g. webdetector.NormalizeUA)
}

// HostHourBucket is one UTC-hour slice of the request series.
type HostHourBucket struct {
	HourUnix     int64 `json:"hour_unix"`
	Requests     int64 `json:"requests"`
	ClientErrors int64 `json:"client_errors"` // 4xx
	ServerErrors int64 `json:"server_errors"` // 5xx
}

// HostKV is one ranked key/count pair (top IP, UA, path, status code…).
type HostKV struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// HostFileError reports a rotated file that could not be fully read (e.g. a
// corrupt gz stream). The call continues with the remaining siblings.
type HostFileError struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// HostPeak flags an hour whose request volume towers over the window median.
type HostPeak struct {
	HourUnix int64   `json:"hour_unix"`
	Requests int64   `json:"requests"`
	VsMedian float64 `json:"vs_median"`
}

// HostScanResult is the aggregate outcome for one host.
type HostScanResult struct {
	Host         string   `json:"host"`
	MatchedHosts []string `json:"matched_hosts"` // hosts actually counted (MergeWWW twins included)
	LogFile      string   `json:"log_file"`
	FilesScanned []string `json:"files_scanned"`

	WindowFromUnix     int64 `json:"window_from_unix"`
	WindowToUnix       int64 `json:"window_to_unix"`
	CoverageOldestUnix int64 `json:"coverage_oldest_unix,omitempty"` // oldest line timestamp actually seen
	CoverageNewestUnix int64 `json:"coverage_newest_unix,omitempty"`
	FilesSkippedOlder  int   `json:"files_skipped_older,omitempty"` // rotated siblings skipped: mtime < window start

	Scanned           int64 `json:"scanned"`                       // lines read across all scanned files
	SkippedNoHost     int64 `json:"skipped_no_host"`               // lines without a parsable host= field
	Matched           int64 `json:"matched"`                       // in-window lines for the target host
	MatchedNoTS       int64 `json:"matched_no_ts"`                 // matched lines whose timestamp was unparsable
	OutsideWindow     int64 `json:"matched_outside_window"`        // matched-host lines outside [from,to) (seen, not aggregated)
	Truncated         bool  `json:"truncated"`                     // a bound was hit: budget, timeout, live tail window or file cap
	LiveTailTruncated bool  `json:"live_tail_truncated,omitempty"` // specifically: the LIVE file had more lines than the tail window

	FilesFailed []HostFileError `json:"files_failed,omitempty"` // rotated files that could not be fully read

	// LogChangedDuringScan: the underlying log file was truncated or mutated
	// WHILE being read (logrotate copytruncate is the classic case). The scan
	// result for that file may overlap with a rotated sibling (double-count
	// risk) or contain a hole — Truncated is set too, and the affected sibling
	// also appears in files_failed. Treat the call as suspect and re-run.
	LogChangedDuringScan bool `json:"log_changed_during_scan,omitempty"`

	TotalRequests int64 `json:"total_requests"`
	BytesTotal    int64 `json:"bytes_total"` // 0 unless the log carries bytes=$body_bytes_sent (added 2026-08; older logs lack it)

	// BadRequests profiles the malformed/aborted traffic (400/408/414/431/494/
	// 499) from access.bad_request.log — traffic the edge deliberately keeps
	// OUT of the full access.log. Kept SEPARATE so valid-traffic totals keep
	// their provenance; nil when the node has no such log at all.
	// TotalRequestsWithBad = TotalRequests + attributable malformed/aborted
	// requests (bad-request lines whose host parses to this vhost — lines with
	// no usable host cannot be attributed and live only in skipped_no_host).
	BadRequests          *HostScanResult `json:"bad_requests,omitempty"`
	TotalRequestsWithBad int64           `json:"total_requests_with_bad,omitempty"`

	StatusClasses     map[string]int64 `json:"status_classes"`
	Methods           map[string]int64 `json:"methods,omitempty"`
	MethodsCapped     bool             `json:"methods_capped,omitempty"`
	TopStatusCodes    []HostKV         `json:"top_status_codes,omitempty"`
	StatusCodesCapped bool             `json:"status_codes_capped,omitempty"`

	UniqueIPs int      `json:"unique_ips"`
	TopIPs    []HostKV `json:"top_ips"`
	IPsCapped bool     `json:"ips_capped,omitempty"`

	TopUARaw  []HostKV `json:"top_uas_raw"`
	UAsCapped bool     `json:"uas_capped,omitempty"`

	// UA classification is a HEURISTIC (browser-envelope vs automation/bot-like
	// via the injected classifier), NOT bot verification: any non-Mozilla-envelope
	// UA counts as automation. BotRatioPct = BotRequests / (bot+human+empty).
	UAFamilies     []HostKV `json:"ua_families,omitempty"` // ClassifyUA-normalized, classified per line
	FamiliesCapped bool     `json:"ua_families_capped,omitempty"`
	BotRequests    int64    `json:"bot_requests,omitempty"`
	HumanRequests  int64    `json:"human_requests,omitempty"` // browser-envelope UAs
	EmptyUAReqs    int64    `json:"empty_ua_requests,omitempty"`
	BotRatioPct    float64  `json:"bot_ratio_pct,omitempty"`

	TopPaths    []HostKV `json:"top_paths"`
	PathsCapped bool     `json:"paths_capped,omitempty"`

	Hourly               []HostHourBucket `json:"hourly"`
	MedianHourlyRequests float64          `json:"median_hourly_requests"`
	PeakHours            []HostPeak       `json:"peak_hours,omitempty"`
}

// hostHour accumulates one UTC hour.
type hostHour struct {
	requests              int64
	c2xx, c3xx, c4xx, c5x int64
	cother                int64
}

// hostAgg holds every accumulator for one scan. Key caps bound memory;
// per-line counting keeps totals exact even past a cap.
type hostAgg struct {
	classify func(string) string
	targets  map[string]struct{}

	ips     map[string]int64
	uas     map[string]int64
	fams    map[string]int64
	paths   map[string]int64
	codes   map[string]int64
	methods map[string]int64
	hours   map[int64]*hostHour

	ipOverflow, uaOverflow, famOverflow, pathOverflow, codeOverflow, methodOverflow int64

	matched, matchedNoTS, outsideWindow int64
	skippedNoHost                       int64
	bytesTotal                          int64
	botReqs, humanReqs, emptyUAReqs     int64

	oldestTS, newestTS float64
}

func (a *hostAgg) noteTS(ts float64) {
	if a.oldestTS == 0 || ts < a.oldestTS {
		a.oldestTS = ts
	}
	if ts > a.newestTS {
		a.newestTS = ts
	}
}

// feed parses one access-log line and aggregates it when it belongs to the
// target host AND its timestamp lies inside [from, to). Lines arrive in
// chronological ASCENDING order; out-of-window lines are simply not
// aggregated — there is deliberately NO early stop (a stop would truncate the
// scan right before the in-window lines).
func (a *hostAgg) feed(line string, from, to int64) {
	var (
		tsVal, hostVal, clientVal                     string
		statusVal, uaVal, uriVal, bytesVal, methodVal string
	)
	forEachKV(line, func(k, v string) {
		switch k {
		case "msec":
			tsVal = v
		case "ts":
			if tsVal == "" {
				tsVal = v // $time_local fallback (only when msec absent)
			}
		case "host":
			hostVal = v
		case "client":
			clientVal = v
		case "status":
			statusVal = v
		case "ua":
			uaVal = v
		case "uri":
			uriVal = v
		case "bytes":
			bytesVal = v
		case "method":
			methodVal = v
		}
	})

	ts := parseLineTS(tsVal)
	if ts > 0 {
		a.noteTS(ts)
	}

	if hostVal == "" {
		a.skippedNoHost++
		return
	}
	hostVal = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostVal)), ".")
	if _, ok := a.targets[hostVal]; !ok {
		return
	}

	if ts > 0 && (ts < float64(from) || ts >= float64(to)) {
		a.outsideWindow++
		return
	}
	a.matched++
	if ts <= 0 {
		a.matchedNoTS++
	}

	code, _ := strconv.Atoi(statusVal)
	hour := int64(0)
	if ts > 0 {
		hour = int64(ts) - int64(ts)%3600
	}
	bucket, ok := a.hours[hour]
	if !ok {
		bucket = &hostHour{}
		a.hours[hour] = bucket
	}
	switch {
	case code >= 200 && code < 300:
		bucket.c2xx++
	case code >= 300 && code < 400:
		bucket.c3xx++
	case code >= 400 && code < 500:
		bucket.c4xx++
	case code >= 500 && code < 600:
		bucket.c5x++
	default:
		bucket.cother++
	}
	bucket.requests++

	bumpCapped(a.codes, statusVal, maxCodeKeys, &a.codeOverflow)

	if methodVal != "" {
		// Client-controlled token: cap cardinality AND key length so the
		// declared memory bound holds even against hostile extension methods.
		bumpCapped(a.methods, truncateStr(methodVal, maxFieldLen), maxMethodKeys, &a.methodOverflow)
	}
	if clientVal = strings.TrimSpace(clientVal); clientVal != "" {
		bumpCapped(a.ips, clientVal, maxIPKeys, &a.ipOverflow)
	}
	if p := normalizePath(uriVal); p != "" {
		bumpCapped(a.paths, p, maxPathKeys, &a.pathOverflow)
	}

	// UA classification: empty UA counts once (emptyUAReqs); a present UA is
	// either browser-envelope ("mozilla", or no classifier attached) or
	// automation/bot-like (any other family). bot+human+empty == matched.
	if uaVal == "" || uaVal == "-" {
		a.emptyUAReqs++
	} else {
		fam := "mozilla"
		bumpCapped(a.uas, truncateStr(uaVal, maxFieldLen), maxUAKeys, &a.uaOverflow)
		if a.classify != nil {
			fam = a.classify(uaVal)
			if fam == "" {
				fam = "-" // classifier produced nothing: no bot evidence either way
			}
			bumpCapped(a.fams, truncateStr(fam, maxFieldLen), maxFamilyKeys, &a.famOverflow)
		}
		if fam == "mozilla" || fam == "-" || fam == "" {
			a.humanReqs++
		} else {
			a.botReqs++
		}
	}

	if b, err := strconv.ParseInt(bytesVal, 10, 64); err == nil && b > 0 {
		a.bytesTotal += b
	}
}

// WWWTwin returns the www./bare counterpart of h (trimmed, lowercased,
// trailing dot stripped). It is the EXACT twin rule ScanHost applies when
// MergeWWW is set, so callers that must validate scope can check the same
// pair without duplicating the derivation.
func WWWTwin(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if strings.HasPrefix(h, "www.") {
		return strings.TrimPrefix(h, "www.")
	}
	return "www." + h
}

// logChain scans ONE live log plus (optionally) its rotated siblings into a
// single aggregator, tracking per-source evidence. budgetUsed/budgetCap are
// SHARED across chains (main + bad-request) so "shared line budget across all
// files" is literal: budgetUsed is incremented EXACTLY ONCE per consumed line,
// by onLine() alone (single source of truth — scanWholeForIP's private
// countdown is only a protective bound, never accounted again).
type logChain struct {
	agg           *hostAgg
	from, to      int64
	budgetUsed    *int64
	budgetCap     int64
	files         []string
	failed        []HostFileError
	skippedOlder  int
	truncated     bool
	liveTruncated bool
	changed       bool // underlying file truncated/mutated/replaced while being read
	budgetStopped bool // onLine hit the shared cap mid-read (truncated already set)
	scanned       int64
}

func (lc *logChain) onLine() func(string) bool {
	return func(line string) bool {
		if *lc.budgetUsed >= lc.budgetCap {
			lc.budgetStopped = true
			lc.truncated = true
			return false
		}
		*lc.budgetUsed++
		lc.scanned++
		lc.agg.feed(line, lc.from, lc.to)
		return true
	}
}

// scanLive reads the live file's tail with rotation-change detection:
//   - the tail-cap answer is re-checked AFTER the stream (the probe and the
//     stream are separate opens; rotation can push the file past the window
//     in between, which would otherwise drop older lines silently);
//   - a size shrink or an inode/path identity change between pre/post stats
//     means copytruncate/replacement happened under us — flagged, so the
//     caller treats the result as suspect instead of authoritative.
func (lc *logChain) scanLive(ctx context.Context, file string, tailLines int) error {
	st0, _ := os.Stat(file)
	capped, err := streamTailBounded(ctx, file, tailLines, lc.onLine())
	// Best-effort honesty recheck: a probe failure must not fail the scan.
	if postCapped, perr := tailHasMoreThan(ctx, file, tailLines); perr == nil && postCapped {
		capped = true
	}
	st1, _ := os.Stat(file)
	if capped {
		lc.truncated = true
		lc.liveTruncated = true
	}
	if st0 != nil && st1 != nil {
		if !os.SameFile(st0, st1) || sizeShrank(st0.Size(), st1.Size()) {
			lc.changed = true
			lc.truncated = true
		}
	}
	return err
}

// sizeShrank / sizeChanged are the cheap rotation/copytruncate signals: a
// shrink between pre/post stats means the live file was truncated under us;
// ANY size movement on an already-rotated file means it is still being filled.
func sizeShrank(before, after int64) bool  { return after < before }
func sizeChanged(before, after int64) bool { return before != after }

// rotatedSnapshot is the generation fingerprint of one rotated sibling.
type rotatedSnapshot struct {
	path string
	size int64
	mod  time.Time
}

// snapshotRotated fingerprints every rotated sibling of live (uncapped apart
// from the hard maximum) so the caller can detect that the ROTATION SET
// changed while a scan was running.
func snapshotRotated(live string) map[string]rotatedSnapshot {
	out := map[string]rotatedSnapshot{}
	siblings, _ := rotatedSiblings(live, MaxRotatedFiles)
	for _, rf := range siblings {
		if fi, err := os.Stat(rf); err == nil {
			out[rf] = rotatedSnapshot{path: rf, size: fi.Size(), mod: fi.ModTime()}
		}
	}
	return out
}

// rotatedGenerationChanged reports whether the sibling SET or any member's
// identity moved between two snapshots — the signature of a rotation that
// happened mid-scan (new .1 appeared / replaced, sizes or mtimes shifted).
func rotatedGenerationChanged(pre, post map[string]rotatedSnapshot) bool {
	if len(pre) != len(post) {
		return true
	}
	for p, s := range pre {
		cur, ok := post[p]
		if !ok || cur.size != s.size || !cur.mod.Equal(s.mod) {
			return true
		}
	}
	return false
}

// scanSiblings reads the rotated siblings (newest-first, capped at maxFiles).
// A sibling that CHANGES SIZE while being read is mid-copytruncate-fill or
// otherwise unstable — it must not be presented as completed evidence: it gets
// a files_failed entry AND sets truncated/changed.
func (lc *logChain) scanSiblings(ctx context.Context, live string, maxFiles int, from int64) {
	siblings, found := rotatedSiblings(live, maxFiles)
	if found > len(siblings) {
		lc.truncated = true // the file cap silently hid older siblings
	}
	for _, rf := range siblings {
		if ctx.Err() != nil || *lc.budgetUsed >= lc.budgetCap {
			lc.truncated = true
			break
		}
		fi0, serr0 := os.Stat(rf)
		if serr0 == nil && fi0.ModTime().Before(time.Unix(from, 0)) {
			// Last written before the window opened: nothing inside can be in-window.
			lc.skippedOlder++
			continue
		}
		lc.files = append(lc.files, rf)
		remaining := int(lc.budgetCap - *lc.budgetUsed)
		serr := scanWholeForIP(ctx, rf, &remaining, lc.onLine())
		fi1, _ := os.Stat(rf)
		if serr != nil && ctx.Err() == nil {
			// A corrupt/unreadable sibling must not fail (or silently shorten,
			// unreported) the whole archival lookup: record it and go on. A
			// budget stop inside scanWholeForIP returns a nil error, so this
			// only fires for real read/gzip failures.
			lc.failed = append(lc.failed, HostFileError{
				File:   rf,
				Reason: truncateStr(serr.Error(), 128),
			})
		}
		if fi0 != nil && fi1 != nil && sizeChanged(fi0.Size(), fi1.Size()) {
			lc.changed = true
			lc.truncated = true
			lc.failed = append(lc.failed, HostFileError{
				File:   rf,
				Reason: fmt.Sprintf("mutated during scan (size %d→%d)", fi0.Size(), fi1.Size()),
			})
		}
		if lc.budgetStopped {
			// Shared cap reached mid-read: anything after this point (the rest
			// of this file, later siblings) is unreached — truncated was
			// already set by onLine.
			break
		}
	}
}

// ScanHost profiles ONE host's traffic across the resolved edge access log
// (and optionally its rotated siblings) inside [FromUnix, ToUnix). See the
// package doc for the bounding discipline. The result is a pure aggregate —
// no raw log lines are retained or returned.
func ScanHost(ctx context.Context, host string, o HostOpts) (HostScanResult, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return HostScanResult{}, fmt.Errorf("missing host")
	}
	if strings.ContainsAny(h, " \t/\\\"'?&") {
		return HostScanResult{}, fmt.Errorf("invalid host %q", h)
	}

	res := HostScanResult{
		Host:         h,
		MatchedHosts: []string{h},
	}
	targets := map[string]struct{}{h: {}}
	if o.MergeWWW {
		twin := WWWTwin(h)
		targets[twin] = struct{}{}
		res.MatchedHosts = append(res.MatchedHosts, twin)
		sort.Strings(res.MatchedHosts)
	}

	to := o.ToUnix
	if to <= 0 {
		to = time.Now().Unix()
	}
	from := o.FromUnix
	if from <= 0 {
		hours := o.Hours
		if hours <= 0 {
			hours = DefaultHostHours
		}
		if hours > MaxHostHours {
			hours = MaxHostHours
		}
		from = to - int64(hours)*3600
	}
	res.WindowFromUnix = from
	res.WindowToUnix = to

	tailLines := o.TailLines
	if tailLines <= 0 {
		tailLines = DefaultHostTailLines
	}
	if tailLines > MaxTailLines {
		tailLines = MaxTailLines
	}
	budget := int64(o.MaxLines)
	if budget <= 0 {
		budget = DefaultHostMaxLines
	}
	if budget > MaxHostMaxLines {
		budget = MaxHostMaxLines
	}
	topN := o.TopN
	if topN <= 0 {
		topN = 20
	}
	if topN > 50 {
		topN = 50
	}
	// The live tail window can never exceed the shared budget — otherwise the
	// claimed "shared line budget across ALL files" would not bound live I/O.
	if int64(tailLines) > budget {
		tailLines = int(budget)
	}

	logFile, err := resolveFullAccessLog()
	if err != nil {
		return res, err
	}
	res.LogFile = logFile

	cctx, cancel := context.WithTimeout(ctx, hostScanTimeout)
	defer cancel()

	agg := &hostAgg{
		classify: o.ClassifyUA,
		targets:  targets,
		ips:      map[string]int64{},
		uas:      map[string]int64{},
		fams:     map[string]int64{},
		paths:    map[string]int64{},
		codes:    map[string]int64{},
		methods:  map[string]int64{},
		hours:    map[int64]*hostHour{},
	}

	// Two chains over ONE shared line budget: valid traffic (access.log) and
	// the malformed/aborted sidecar (access.bad_request.log). Keeping them as
	// separate provenance sections preserves the valid-vs-malformed split that
	// "crawler or attack?" reasoning needs, while neither class stays invisible.
	// The sidecar is DERIVED from the resolved main log (same engine/dir) —
	// see badRequestLogFor — and fingerprinted before any read so a rotation
	// mid-scan is detected instead of double-counted.
	budgetUsed := int64(0)
	main := &logChain{agg: agg, from: from, to: to, budgetUsed: &budgetUsed, budgetCap: budget}
	preGen := snapshotRotated(logFile)

	main.files = append(main.files, logFile)
	tailErr := main.scanLive(cctx, logFile, tailLines)
	if tailErr != nil {
		// Real read failure on the primary evidence file (permission denied,
		// vanished mid-scan, …): never present as a clean zero-traffic result.
		main.truncated = true
		main.failed = append(main.failed, HostFileError{
			File:   logFile,
			Reason: truncateStr(tailErr.Error(), 128),
		})
	}

	var bad *logChain
	badFile := badRequestLogFor(logFile)
	if fi, ferr := os.Stat(badFile); ferr == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		remaining := budget - budgetUsed
		if remaining <= 0 {
			// Shared budget already exhausted by the main chain: do not start
			// another tail just to drain it — flag and stop here.
			bad = &logChain{agg: &hostAgg{
				targets: targets,
				ips:     map[string]int64{}, uas: map[string]int64{}, fams: map[string]int64{},
				paths: map[string]int64{}, codes: map[string]int64{}, methods: map[string]int64{},
				hours: map[int64]*hostHour{},
			}, from: from, to: to, budgetUsed: &budgetUsed, budgetCap: budget, truncated: true}
			bad.files = append(bad.files, badFile)
		} else {
			badTail := tailLines
			if int64(badTail) > remaining {
				badTail = int(remaining)
			}
			bad = &logChain{agg: &hostAgg{
				classify: o.ClassifyUA,
				targets:  targets,
				ips:      map[string]int64{}, uas: map[string]int64{}, fams: map[string]int64{},
				paths: map[string]int64{}, codes: map[string]int64{}, methods: map[string]int64{},
				hours: map[int64]*hostHour{},
			}, from: from, to: to, budgetUsed: &budgetUsed, budgetCap: budget}
			bad.files = append(bad.files, badFile)
			if berr := bad.scanLive(cctx, badFile, badTail); berr != nil && ctx.Err() == nil {
				bad.failed = append(bad.failed, HostFileError{
					File:   badFile,
					Reason: truncateStr(berr.Error(), 128),
				})
				bad.truncated = true
			}
		}
	}

	if !o.IncludeRotated || ctx.Err() != nil {
		if ctx.Err() != nil {
			main.truncated = true
		}
		finalizeChain(main, agg, &res, topN)
		finalizeBad(bad, &res, topN)
		return res, tailErr
	}

	maxFiles := o.MaxFiles
	if maxFiles <= 0 {
		maxFiles = DefaultHostFiles
	}
	if maxFiles > MaxRotatedFiles {
		maxFiles = MaxRotatedFiles
	}
	if rotatedGenerationChanged(preGen, snapshotRotated(logFile)) {
		// The rotation set moved WHILE we were reading the live logs — the
		// clean double-count case: a freshly appeared/replaced sibling may
		// hold lines already counted from the live tail. Fail honest: skip
		// sibling scanning entirely this call (operator retries).
		main.changed = true
		main.truncated = true
		if bad != nil {
			bad.changed = true
			bad.truncated = true
		}
	} else {
		main.scanSiblings(cctx, logFile, maxFiles, from)
		if bad != nil && tailErr == nil {
			bad.scanSiblings(cctx, badFile, maxFiles, from)
		}
	}
	if ctx.Err() != nil {
		main.truncated = true
		if bad != nil {
			bad.truncated = true
		}
	}

	finalizeChain(main, agg, &res, topN)
	finalizeBad(bad, &res, topN)
	return res, tailErr
}

// finalizeChain folds a chain's accumulators + evidence into res.
func finalizeChain(lc *logChain, agg *hostAgg, res *HostScanResult, topN int) {
	res.LogFile = lc.files[0]
	res.FilesScanned = lc.files
	res.FilesFailed = append(res.FilesFailed, lc.failed...)
	res.FilesSkippedOlder += lc.skippedOlder
	if lc.truncated {
		res.Truncated = true
	}
	if lc.liveTruncated {
		res.LiveTailTruncated = true
	}
	if lc.changed {
		res.LogChangedDuringScan = true
	}
	res.Scanned = lc.scanned
	finalize(agg, res, topN)
}

// finalizeBad attaches the bad-request section (nil when the node has no
// such log) and computes the combined headline total.
func finalizeBad(bad *logChain, res *HostScanResult, topN int) {
	if bad == nil {
		res.TotalRequestsWithBad = res.TotalRequests
		return
	}
	badRes := HostScanResult{
		Host:                 res.Host,
		MatchedHosts:         res.MatchedHosts,
		LogFile:              bad.files[0],
		FilesScanned:         bad.files,
		WindowFromUnix:       res.WindowFromUnix,
		WindowToUnix:         res.WindowToUnix,
		Truncated:            bad.truncated,
		LiveTailTruncated:    bad.liveTruncated,
		LogChangedDuringScan: bad.changed,
		Scanned:              bad.scanned,
		SkippedNoHost:        bad.agg.skippedNoHost,
	}
	finalize(bad.agg, &badRes, topN)
	badRes.FilesFailed = append(badRes.FilesFailed, bad.failed...)
	res.BadRequests = &badRes
	res.Truncated = res.Truncated || bad.truncated
	res.LogChangedDuringScan = res.LogChangedDuringScan || bad.changed
	res.Scanned += bad.scanned // top-level Scanned covers BOTH chains
	res.TotalRequestsWithBad = res.TotalRequests + badRes.TotalRequests
}

// finalize folds the accumulators into ranked lists and derived statistics.
func finalize(agg *hostAgg, res *HostScanResult, topN int) {
	res.Matched = agg.matched
	res.MatchedNoTS = agg.matchedNoTS
	res.OutsideWindow = agg.outsideWindow
	res.SkippedNoHost = agg.skippedNoHost
	// matched already counts ONLY in-window lines (outsideWindow ones return
	// before matched++ in feed), so total == matched by construction.
	res.TotalRequests = agg.matched
	res.BytesTotal = agg.bytesTotal
	if agg.newestTS > 0 {
		res.CoverageNewestUnix = int64(agg.newestTS)
	}
	if agg.oldestTS > 0 {
		res.CoverageOldestUnix = int64(agg.oldestTS)
	}

	var s2, s3, s4, s5, so int64
	for _, hh := range agg.hours {
		s2 += hh.c2xx
		s3 += hh.c3xx
		s4 += hh.c4xx
		s5 += hh.c5x
		so += hh.cother
	}
	res.StatusClasses = map[string]int64{
		"2xx": s2, "3xx": s3, "4xx": s4, "5xx": s5, "other": so,
	}
	res.TopStatusCodes = topK(agg.codes, maxCodeKeys)
	res.StatusCodesCapped = agg.codeOverflow > 0

	res.Methods = agg.methods
	res.MethodsCapped = agg.methodOverflow > 0
	res.UniqueIPs = len(agg.ips)
	res.IPsCapped = agg.ipOverflow > 0
	res.TopIPs = topK(agg.ips, topN)
	res.TopUARaw = topK(agg.uas, topN)
	res.UAsCapped = agg.uaOverflow > 0
	if len(agg.fams) > 0 {
		res.UAFamilies = topK(agg.fams, topN)
	}
	res.FamiliesCapped = agg.famOverflow > 0
	res.BotRequests = agg.botReqs
	res.HumanRequests = agg.humanReqs
	res.EmptyUAReqs = agg.emptyUAReqs
	denom := agg.botReqs + agg.humanReqs + agg.emptyUAReqs
	if denom > 0 {
		res.BotRatioPct = math.Round(float64(agg.botReqs)/float64(denom)*1000) / 10
	}
	res.TopPaths = topK(agg.paths, topN)
	res.PathsCapped = agg.pathOverflow > 0

	hours := make([]HostHourBucket, 0, len(agg.hours))
	for hu, hh := range agg.hours {
		if hu == 0 && hh.requests == agg.matchedNoTS {
			// Synthetic bucket holding timestamp-less matches — not a real
			// hour; keep totals right by skipping it in the series.
			continue
		}
		hours = append(hours, HostHourBucket{
			HourUnix:     hu,
			Requests:     hh.requests,
			ClientErrors: hh.c4xx,
			ServerErrors: hh.c5x,
		})
	}
	sort.Slice(hours, func(i, j int) bool { return hours[i].HourUnix < hours[j].HourUnix })
	res.Hourly = hours
	res.MedianHourlyRequests, res.PeakHours = peakStats(hours)
}

// peakStats computes the median over NON-ZERO hours and flags hours at/above
// peakVsMedianFactor× median (top maxPeakHours by volume).
func peakStats(hours []HostHourBucket) (median float64, peaks []HostPeak) {
	nz := make([]int64, 0, len(hours))
	for _, hb := range hours {
		if hb.Requests > 0 {
			nz = append(nz, hb.Requests)
		}
	}
	if len(nz) == 0 {
		return 0, nil
	}
	sort.Slice(nz, func(i, j int) bool { return nz[i] < nz[j] })
	median = float64(nz[len(nz)/2])
	if len(nz)%2 == 0 {
		median = (float64(nz[len(nz)/2-1]) + float64(nz[len(nz)/2])) / 2
	}
	if median <= 0 {
		return median, nil
	}
	threshold := median * peakVsMedianFactor
	for _, hb := range hours {
		if float64(hb.Requests) >= threshold {
			peaks = append(peaks, HostPeak{
				HourUnix: hb.HourUnix,
				Requests: hb.Requests,
				VsMedian: math.Round(float64(hb.Requests)/median*10) / 10,
			})
		}
	}
	sort.Slice(peaks, func(i, j int) bool {
		if peaks[i].Requests != peaks[j].Requests {
			return peaks[i].Requests > peaks[j].Requests
		}
		return peaks[i].HourUnix < peaks[j].HourUnix
	})
	if len(peaks) > maxPeakHours {
		peaks = peaks[:maxPeakHours]
	}
	return median, peaks
}

// normalizePath strips query string and fragment and caps length, so the path
// histogram groups by route rather than by unique query.
func normalizePath(uri string) string {
	if uri == "" || uri == "-" {
		return ""
	}
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		uri = uri[:i]
	}
	return truncateStr(uri, maxPathLen)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func bumpCapped(m map[string]int64, k string, cap int, overflow *int64) {
	if v, ok := m[k]; ok {
		m[k] = v + 1
		return
	}
	if len(m) >= cap {
		*overflow++
		return
	}
	m[k] = 1
}

// topK returns the highest-count entries (count desc, key asc tiebreak).
func topK(m map[string]int64, n int) []HostKV {
	out := make([]HostKV, 0, len(m))
	for k, v := range m {
		out = append(out, HostKV{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// parseLineTS accepts the two timestamps the cfm log family carries: msec=
// (epoch seconds, fractional — the normal case) and ts= ($time_local, only
// consulted when msec is missing).
func parseLineTS(v string) float64 {
	if v == "" || v == "-" {
		return 0
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
		return f
	}
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", v); err == nil {
		return float64(t.Unix())
	}
	return 0
}

// forEachKV walks a `key=value key="quoted value"` line (the log_format cfm
// family: escape=default for the main format, escape=json for bad_request —
// both parse identically here) and calls fn for every pair. Bare values run to
// the next whitespace; quoted values honor backslash escapes. Malformed tokens
// (no '=') are skipped without aborting the walk.
func forEachKV(line string, fn func(key, val string)) {
	for i := 0; i < len(line); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		keyStart := i
		for i < len(line) && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		if i >= len(line) || line[i] != '=' {
			continue
		}
		key := line[keyStart:i]
		i++
		var val string
		if i < len(line) && line[i] == '"' {
			i++
			vs := i
			for i < len(line) {
				if line[i] == '\\' && i+1 < len(line) {
					i += 2
					continue
				}
				if line[i] == '"' {
					break
				}
				i++
			}
			end := i
			if end > len(line) {
				end = len(line)
			}
			val = line[vs:end]
			if i < len(line) {
				i++ // closing quote
			}
		} else {
			vs := i
			for i < len(line) && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			val = line[vs:i]
		}
		fn(key, val)
	}
}
