package edgelog

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cfmline builds one log_format cfm access line with the fields hostscan
// consumes. bytes>0 appends the bytes=$body_bytes_sent field (the 2026-08
// format addition); ts drives both msec= and the ts="$time_local" fallback.
func cfmline(ts float64, client, host, method, uri string, status int, ua string, nbytes int64) string {
	tl := time.Unix(int64(ts), 0).UTC().Format("02/Jan/2006:15:04:05 -0700")
	s := fmt.Sprintf(
		`ts="%s" msec=%.3f client=%s peer=%s cf="-" host=%s method=%s uri=%s proto="HTTP/1.1" status=%d rt=0.050 urt="0.040" uct="0.010" uht="0.030" sslr="." luams=- ust=200 uaddr=127.0.0.1:8080 uloc="-" sch=https xfp_in="https" xfp_out="https" xfp_trust=1 up=origin pass=1 dst=203.0.113.1:443 ua="%s"`,
		tl, ts, client, client, host, method, uri, status, ua,
	)
	if nbytes > 0 {
		s += fmt.Sprintf(" bytes=%d", nbytes)
	}
	return s
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeGz(t *testing.T, path string, lines []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write([]byte(strings.Join(lines, "\n") + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func requireTail(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
}

func TestForEachKV(t *testing.T) {
	line := `ts="24/Aug/2026:10:00:00 +0000" msec=1756024800.123 junktoken client=203.0.113.9 host=ex.gr uri="/a b.php" ua="Mozilla/5.0 \"x\" y" status=404`
	got := map[string]string{}
	forEachKV(line, func(k, v string) { got[k] = v })
	want := map[string]string{
		"msec":   "1756024800.123",
		"client": "203.0.113.9",
		"host":   "ex.gr",
		"uri":    `/a b.php`,
		// Escape sequences are preserved verbatim (we only need field
		// boundaries; unescaping is not hostscan's job).
		"ua":     `Mozilla/5.0 \"x\" y`,
		"status": "404",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["junktoken"]; ok {
		t.Errorf("malformed token parsed as a pair: %v", got)
	}
}

func TestParseLineTS(t *testing.T) {
	if got := parseLineTS("1756024800.123"); got != 1756024800.123 {
		t.Errorf("msec parse = %v", got)
	}
	want := int64(1787565600) // 2026-08-24 10:00:00 UTC
	tl := time.Unix(want, 0).UTC().Format("02/Jan/2006:15:04:05 -0700")
	if got := parseLineTS(tl); got != float64(want) {
		t.Errorf("time_local parse = %v, want %d", got, want)
	}
	if got := parseLineTS("-"); got != 0 {
		t.Errorf("'-' should be 0, got %v", got)
	}
	if got := parseLineTS("not-a-time"); got != 0 {
		t.Errorf("garbage should be 0, got %v", got)
	}
}

// TestScanHost_LiveAndRotated covers the core aggregation: live + plain + gz
// siblings all feed one aggregate; unrelated hosts and foreign-format lines
// are skipped; tops/classes/hourly/bytes come out right.
func TestScanHost_LiveAndRotated(t *testing.T) {
	requireTail(t)
	base := float64(time.Now().Add(-2 * time.Hour).Truncate(time.Hour).Unix())
	liveLines := []string{
		cfmline(base, "198.51.100.7", "ex.gr", "GET", "/index.php", 200, "Googlebot/2.1", 1200),
		cfmline(base+60, "198.51.100.8", "other.gr", "GET", "/nope", 200, "Mozilla/5.0", 10),
		cfmline(base+120, "198.51.100.7", "ex.gr", "POST", "/login", 404, "curl/8.0", 300),
		cfmline(base+180, "198.51.100.7", "ex.gr", "GET", "/ping", 200, "-", 0), // empty UA
		"<combined-format garbage without kv fields>",                           // skipped_no_host
	}
	rot1 := []string{
		cfmline(base-3600, "198.51.100.9", "ex.gr", "GET", "/media/k2/a.jpg?w=2", 200, "facebookexternalhit/1.1", 80000),
	}
	rot2gz := []string{
		cfmline(base-7200, "198.51.100.9", "www.ex.gr", "GET", "/old", 500, "Bingbot/2.0", 900),
	}

	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, liveLines)
	writeLines(t, filepath.Join(dir, "access.log.1"), rot1)
	writeGz(t, filepath.Join(dir, "access.log.2.gz"), rot2gz)

	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	classify := func(raw string) string {
		switch raw {
		case "Googlebot/2.1":
			return "googlebot"
		case "facebookexternalhit/1.1":
			return "facebookexternalhit"
		case "Bingbot/2.0":
			return "bingbot"
		case "curl/8.0":
			return "curl"
		default:
			return "mozilla"
		}
	}

	res, err := ScanHost(context.Background(), "EX.gr", HostOpts{
		Hours:          48,
		IncludeRotated: true,
		ClassifyUA:     classify,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Host != "ex.gr" || res.LogFile != live {
		t.Fatalf("host/logfile = %q/%q", res.Host, res.LogFile)
	}
	if len(res.FilesScanned) != 3 {
		t.Errorf("files_scanned = %v, want 3 (live+.1+.2.gz)", res.FilesScanned)
	}
	// matched: 3 live ex.gr lines (googlebot, curl, empty-UA) + 1 rot1
	// facebookexternalhit (the www.ex.gr rot2gz line is NOT merged without
	// MergeWWW); other.gr and the garbage line excluded.
	if res.Matched != 4 {
		t.Errorf("matched = %d, want 4", res.Matched)
	}
	if res.SkippedNoHost != 1 {
		t.Errorf("skipped_no_host = %d, want 1", res.SkippedNoHost)
	}
	if res.TotalRequests != 4 {
		t.Errorf("total_requests = %d, want 4 (must equal matched: no double subtract)", res.TotalRequests)
	}
	if res.OutsideWindow != 0 {
		t.Errorf("outside_window = %d, want 0", res.OutsideWindow)
	}
	if res.BytesTotal != 1200+300+80000 {
		t.Errorf("bytes_total = %d, want %d", res.BytesTotal, 1200+300+80000)
	}
	if res.StatusClasses["2xx"] != 3 || res.StatusClasses["4xx"] != 1 || res.StatusClasses["5xx"] != 0 {
		t.Errorf("status_classes = %v", res.StatusClasses)
	}
	if res.UniqueIPs != 2 {
		t.Errorf("unique_ips = %d, want 2 (198.51.100.7/.9)", res.UniqueIPs)
	}
	if len(res.TopIPs) == 0 || res.TopIPs[0].Key != "198.51.100.7" || res.TopIPs[0].Count != 3 {
		t.Errorf("top_ips[0] = %+v, want 198.51.100.7×3", res.TopIPs)
	}
	// googlebot + curl + facebookexternalhit = automation; Mozilla line is
	// another host; the "-" UA counts ONLY as empty.
	if res.BotRequests != 3 || res.HumanRequests != 0 || res.EmptyUAReqs != 1 {
		t.Errorf("bot/human/empty = %d/%d/%d, want 3/0/1",
			res.BotRequests, res.HumanRequests, res.EmptyUAReqs)
	}
	// Path normalization: query stripped.
	foundPath := false
	for _, p := range res.TopPaths {
		if p.Key == "/media/k2/a.jpg" && p.Count == 1 {
			foundPath = true
		}
	}
	if !foundPath {
		t.Errorf("top_paths missing normalized /media/k2/a.jpg: %+v", res.TopPaths)
	}
	if len(res.Hourly) < 2 {
		t.Errorf("hourly buckets = %d, want >=2 distinct hours", len(res.Hourly))
	}
	if res.Truncated {
		t.Error("truncated set on an unbounded run")
	}
}

func TestScanHost_MergeWWW(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, []string{
		cfmline(now-10, "198.51.100.1", "example.gr", "GET", "/", 200, "Mozilla/5.0", 0),
		cfmline(now-20, "198.51.100.2", "www.example.gr", "GET", "/", 200, "Mozilla/5.0", 0),
	})
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	noMerge, err := ScanHost(context.Background(), "example.gr", HostOpts{Hours: 1})
	if err != nil {
		t.Fatal(err)
	}
	if noMerge.Matched != 1 {
		t.Errorf("no-merge matched = %d, want 1", noMerge.Matched)
	}
	merge, err := ScanHost(context.Background(), "example.gr", HostOpts{Hours: 1, MergeWWW: true})
	if err != nil {
		t.Fatal(err)
	}
	if merge.Matched != 2 || len(merge.MatchedHosts) != 2 {
		t.Errorf("merge matched=%d hosts=%v, want 2 both twins", merge.Matched, merge.MatchedHosts)
	}
	mergeRev, err := ScanHost(context.Background(), "WWW.example.gr.", HostOpts{Hours: 1, MergeWWW: true})
	if err != nil {
		t.Fatal(err)
	}
	if mergeRev.Matched != 2 {
		t.Errorf("reverse merge (www→bare, trailing dot, case) matched = %d, want 2", mergeRev.Matched)
	}
}

func TestScanHost_BudgetTruncates(t *testing.T) {
	requireTail(t)
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	lines := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		lines = append(lines, cfmline(float64(time.Now().Unix()-50+int64(i)), fmt.Sprintf("198.51.100.%d", i%5), "ex.gr", "GET", fmt.Sprintf("/p%d", i), 200, "bot/1", 0))
	}
	writeLines(t, live, lines)
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 1, MaxLines: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Error("expected truncated=true when budget exhausted")
	}
	if res.Scanned > 11 {
		t.Errorf("scanned = %d, want <= budget+1", res.Scanned)
	}
}

// TestScanHost_SkipsFilesOlderThanWindow: a sibling whose mtime predates the
// window start is never opened, and once a chronological sibling falls below
// the window floor, scanning stops before reaching even older siblings.
func TestScanHost_SkipsOlderSiblings(t *testing.T) {
	requireTail(t)
	now := time.Now()
	from := now.Add(-1 * time.Hour)

	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, []string{
		cfmline(float64(now.Add(-30*time.Second).Unix()), "198.51.100.1", "ex.gr", "GET", "/now", 200, "Mozilla/5.0", 0),
	})

	// Sibling entirely BELOW the window (150 old lines → below-window streak).
	oldLines := make([]string, 0, 150)
	for i := 0; i < 150; i++ {
		oldLines = append(oldLines, cfmline(float64(from.Add(-48*time.Hour).Add(time.Duration(i)*time.Second).Unix()), "198.51.100.9", "ex.gr", "GET", "/ancient", 200, "bot/1", 0))
	}
	rotOld := filepath.Join(dir, "access.log.1")
	writeLines(t, rotOld, oldLines)

	// Even-older gz sibling that must never be touched.
	rotAncient := filepath.Join(dir, "access.log.2.gz")
	writeGz(t, rotAncient, []string{cfmline(float64(from.Add(-96*time.Hour).Unix()), "198.51.100.9", "ex.gr", "GET", "/never", 200, "bot/1", 0)})

	// Control mtimes: newest first (live > .1 > .2.gz).
	futureProof := func(p string, mod time.Time) {
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	futureProof(live, now)
	futureProof(rotOld, from.Add(-24*time.Hour)) // last written BEFORE window start → skipped by mtime
	futureProof(rotAncient, from.Add(-72*time.Hour))

	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 1, IncludeRotated: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesSkippedOlder != 2 {
		t.Errorf("files_skipped_older = %d, want 2 (both siblings predate the window) (%v)", res.FilesSkippedOlder, res.FilesScanned)
	}
	if len(res.FilesScanned) != 1 {
		t.Errorf("files_scanned = %v, want only the live file", res.FilesScanned)
	}
	if res.Matched != 1 {
		t.Errorf("matched = %d, want 1 (live line only)", res.Matched)
	}
}

func TestScanHost_RejectsBadInput(t *testing.T) {
	if _, err := ScanHost(context.Background(), "", HostOpts{}); err == nil {
		t.Error("empty host must error")
	}
	if _, err := ScanHost(context.Background(), "bad host/gr", HostOpts{}); err == nil {
		t.Error("host with spaces/slash must error")
	}
}

func TestPeakStats(t *testing.T) {
	hours := []HostHourBucket{
		{HourUnix: 1000, Requests: 10},
		{HourUnix: 2000, Requests: 12},
		{HourUnix: 3000, Requests: 11},
		{HourUnix: 4000, Requests: 90}, // ~7.5× median → peak
		{HourUnix: 5000, Requests: 13},
	}
	median, peaks := peakStats(hours)
	if median != 12 {
		t.Errorf("median = %v, want 12", median)
	}
	if len(peaks) != 1 || peaks[0].Requests != 90 || peaks[0].VsMedian != 7.5 {
		t.Errorf("peaks = %+v, want single 90×7.5", peaks)
	}
	if m, p := peakStats(nil); m != 0 || p != nil {
		t.Errorf("empty hours → (%v,%v), want zeros", m, p)
	}
}

// TestScanHost_OldPrefixDoesNotStopScan is the forward-scan regression: files
// are consumed oldest→newest (tail prints file order; archives stream from
// the start), so a pre-window PREFIX must never stop the scan — the in-window
// lines follow AFTER it. 150 old lines then 5 recent ⇒ recent 5 MUST count.
func TestScanHost_OldPrefixDoesNotStopScan(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	from := now - 3600
	lines := make([]string, 0, 155)
	for i := 0; i < 150; i++ {
		lines = append(lines, cfmline(from-1800+float64(i), "198.51.100.9", "ex.gr", "GET", "/ancient", 200, "bot/1", 0))
	}
	for i := 0; i < 5; i++ {
		lines = append(lines, cfmline(now-60+float64(i), "198.51.100.1", "ex.gr", "GET", fmt.Sprintf("/recent%d", i), 200, "Mozilla/5.0", 0))
	}
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, lines)
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 5 || res.TotalRequests != 5 {
		t.Fatalf("matched=%d total=%d, want 5/5 — pre-window prefix must not stop an ascending scan",
			res.Matched, res.TotalRequests)
	}
	if res.OutsideWindow != 150 {
		t.Errorf("outside_window = %d, want 150", res.OutsideWindow)
	}
	if res.Truncated {
		t.Error("truncated must not be set")
	}
}

// Same shape as TestScanHost_OldPrefixDoesNotStopScan but inside a gz rotated
// sibling streamed start→end.
func TestScanHost_GzOldPrefixThenRecent(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	from := now - 3600
	sib := make([]string, 0, 105)
	for i := 0; i < 100; i++ {
		sib = append(sib, cfmline(from-600+float64(i), "198.51.100.9", "ex.gr", "GET", "/old", 200, "bot/1", 0))
	}
	for i := 0; i < 5; i++ {
		sib = append(sib, cfmline(from+60+float64(i), "198.51.100.8", "ex.gr", "GET", fmt.Sprintf("/inwin%d", i), 200, "bot/2", 10))
	}
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, []string{
		cfmline(now-30, "198.51.100.1", "ex.gr", "GET", "/live", 200, "Mozilla/5.0", 0),
	})
	gzf := filepath.Join(dir, "access.log.1.gz")
	writeGz(t, gzf, sib)

	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 1, IncludeRotated: true})
	if err != nil {
		t.Fatal(err)
	}
	// 5 in-window sibling lines + 1 live line; the 100-line old prefix of the
	// sibling must NOT have stopped the scan.
	if res.Matched != 6 || res.TotalRequests != 6 {
		t.Fatalf("matched=%d total=%d, want 6/6 (gz old-prefix must not stop the scan)", res.Matched, res.TotalRequests)
	}
	found := false
	for _, f := range res.FilesScanned {
		if f == gzf {
			found = true
		}
	}
	if !found {
		t.Errorf("gz sibling not scanned: %v", res.FilesScanned)
	}
}

// A corrupt rotated file is reported (files_failed) instead of silently
// shortening coverage or failing the whole call.
func TestScanHost_CorruptGzReported(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, []string{
		cfmline(now-30, "198.51.100.1", "ex.gr", "GET", "/live", 200, "Mozilla/5.0", 0),
	})
	bad := filepath.Join(dir, "access.log.1.gz")
	if err := os.WriteFile(bad, []byte("this is definitely not a gzip stream"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 48, IncludeRotated: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.FilesFailed) != 1 || !strings.HasSuffix(res.FilesFailed[0].File, "access.log.1.gz") {
		t.Errorf("files_failed = %+v, want exactly the corrupt sibling", res.FilesFailed)
	}
	if res.Matched != 1 {
		t.Errorf("matched = %d, want 1 (live unaffected by corrupt sibling)", res.Matched)
	}
}

// HTTP methods are client-controlled: cardinality AND key length are capped.
func TestScanHost_MethodCardinalityCapped(t *testing.T) {
	now := float64(time.Now().Unix())
	a := &hostAgg{
		targets: map[string]struct{}{"ex.gr": {}},
		ips:     map[string]int64{}, uas: map[string]int64{}, fams: map[string]int64{},
		paths: map[string]int64{}, codes: map[string]int64{}, methods: map[string]int64{},
		hours: map[int64]*hostHour{},
	}
	long := strings.Repeat("M", 500)
	for i := 0; i < 40; i++ {
		line := cfmline(now-60+float64(i), "198.51.100.1", "ex.gr", fmt.Sprintf("EXT%d", i), "/", 200, "-", 0)
		// cfmline writes method unquoted; inject one oversized method too.
		if i == 39 {
			line = strings.Replace(line, "method=EXT39", "method="+long, 1)
		}
		a.feed(line, int64(fromOf(now)), int64(now)+10)
	}
	if len(a.methods) > maxMethodKeys {
		t.Errorf("methods keys = %d, want <= %d", len(a.methods), maxMethodKeys)
	}
	for k := range a.methods {
		if len(k) > maxFieldLen {
			t.Errorf("method key longer than cap: %d", len(k))
		}
	}
}

// fromOf mirrors the hour-truncation trick tests use to stay inside windows.
func fromOf(now float64) float64 { return now - 3600 }

// TestScanHost_FullLogResolverContract pins the semantic-source contract of
// the full-log resolver: the focused access.cfm.log (challenge/block routing
// only) is NEVER a candidate — not "a candidate that loses ties", simply not
// one. If no full access.log exists, the scan must fail rather than fall back
// to a semantically wrong source.
func TestScanHost_FullLogResolverContract(t *testing.T) {
	requireTail(t)
	// Exact allowed set: ONLY the two full-traffic access.logs. A future edit
	// adding e.g. /var/log/nginx/access.log (distro combined format) or the
	// focused access.cfm.log must fail here.
	want := []string{
		"/usr/local/openresty/nginx/logs/access.log",
		"/var/log/angie/access.log",
	}
	if len(fullAccessLogCandidates) != len(want) {
		t.Fatalf("fullAccessLogCandidates = %v, want exactly %v", fullAccessLogCandidates, want)
	}
	for i, c := range fullAccessLogCandidates {
		if c != want[i] || strings.Contains(c, ".cfm.") {
			t.Errorf("candidate[%d] = %q, want %q (focused/distro logs are never full-traffic candidates)", i, c, want[i])
		}
	}

	now := float64(time.Now().Unix())
	dir := t.TempDir()
	focused := filepath.Join(dir, "access.cfm.log")
	writeLines(t, focused, []string{
		cfmline(now-10, "198.51.100.2", "ex.gr", "GET", "/focused", 403, "bot/1", 0),
	})
	// No full access.log anywhere — an empty candidate set models exactly that.
	old := fullAccessLogCandidates
	fullAccessLogCandidates = nil
	defer func() { fullAccessLogCandidates = old }()

	if _, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 1}); err == nil {
		t.Fatal("scan succeeded with no full access.log — focused fallback must not happen")
	}
}

// A max_files cap that hides existing siblings is a real reach bound and must
// set truncated=true.
func TestScanHost_MaxFilesCapTruncated(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, []string{
		cfmline(now-30, "198.51.100.1", "ex.gr", "GET", "/live", 200, "Mozilla/5.0", 0),
	})
	sibLine := func(tag string) []string {
		return []string{cfmline(now-90, "198.51.100.2", "ex.gr", "GET", tag, 200, "bot/1", 0)}
	}
	writeGz(t, filepath.Join(dir, "access.log.1.gz"), sibLine("/sib1"))
	writeGz(t, filepath.Join(dir, "access.log.2.gz"), sibLine("/sib2"))
	writeGz(t, filepath.Join(dir, "access.log.3.gz"), sibLine("/sib3"))
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 1, IncludeRotated: true, MaxFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Error("max_files cap hid sibling(s): truncated must be true")
	}
	if got := len(res.FilesScanned); got != 3 {
		t.Errorf("files_scanned = %d, want 3 (live + 2 allowed siblings)", got)
	}
}

// Budget dying INSIDE the last scanned sibling must also surface truncated=true
// (scanWholeForIP returns a nil error on budget exhaustion — previously silent).
func TestScanHost_BudgetDiesMidLastSibling(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	liveLines := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		liveLines = append(liveLines, cfmline(now-100+float64(i), "198.51.100.1", "ex.gr", "GET", fmt.Sprintf("/l%d", i), 200, "-", 0))
	}
	writeLines(t, live, liveLines)
	sib1 := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		sib1 = append(sib1, cfmline(now-50+float64(i), "198.51.100.2", "ex.gr", "GET", fmt.Sprintf("/a%d", i), 200, "-", 0))
	}
	writeGz(t, filepath.Join(dir, "access.log.1.gz"), sib1)
	sib2 := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		sib2 = append(sib2, cfmline(now-600+float64(i), "198.51.100.3", "ex.gr", "GET", fmt.Sprintf("/b%d", i), 200, "-", 0))
	}
	writeGz(t, filepath.Join(dir, "access.log.2.gz"), sib2)
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	// Budget: 5 live + 10 sib1 fit; sib2 dies halfway through.
	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 48, IncludeRotated: true, MaxLines: 20})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Error("budget exhausted inside the last sibling: truncated must be true")
	}
	if res.Scanned != 20 {
		t.Errorf("scanned = %d, want exactly the 20-line budget", res.Scanned)
	}
}

// The [FromUnix, ToUnix) contract is enforced per line: pre-window AND
// future-skewed entries are seen but never aggregated.
func TestScanHost_ToUnixExclusive(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	from := int64(now - 3600)
	to := from + 10
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, []string{
		cfmline(float64(from-5), "198.51.100.1", "ex.gr", "GET", "/before", 200, "-", 0),
		cfmline(float64(from+5), "198.51.100.2", "ex.gr", "GET", "/inside", 200, "-", 0),
		cfmline(float64(to+300), "198.51.100.3", "ex.gr", "GET", "/future-skew", 200, "-", 0),
	})
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{FromUnix: from, ToUnix: to})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || res.TotalRequests != 1 {
		t.Fatalf("matched=%d total=%d, want 1/1 (only /inside)", res.Matched, res.TotalRequests)
	}
	if res.OutsideWindow != 2 {
		t.Errorf("outside_window = %d, want 2 (before + future)", res.OutsideWindow)
	}
}

// TestScanHost_LiveTailCapTruncated pins the silent-hole fix: when the LIVE
// file holds more lines than the tail window, that bound MUST surface as
// truncated=true (+ live_tail_truncated=true) — otherwise rotations could make
// coverage_oldest look complete while a mid-window hole exists.
func TestScanHost_LiveTailCapTruncated(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	lines := make([]string, 0, 60)
	for i := 0; i < 60; i++ { // 60 in-window lines, tail window = 10
		lines = append(lines, cfmline(now-120+float64(i), "198.51.100.1", "ex.gr", "GET", fmt.Sprintf("/p%d", i), 200, "-", 0))
	}
	writeLines(t, live, lines)
	writeGz(t, filepath.Join(dir, "access.log.1.gz"), []string{
		cfmline(now-3600, "198.51.100.2", "ex.gr", "GET", "/yesterday", 200, "-", 0),
	})
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 2, IncludeRotated: true, TailLines: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || !res.LiveTailTruncated {
		t.Fatalf("truncated=%v live_tail_truncated=%v, want both true (live file longer than tail window)", res.Truncated, res.LiveTailTruncated)
	}
	// Exactly the 10 newest live lines + the sibling line are consumed and
	// counted — the cap probe must not add an 11th live line to the data.
	if res.Scanned != 11 || res.Matched != 11 {
		t.Errorf("scanned=%d matched=%d, want 11/11 (10 newest live + 1 sibling)", res.Scanned, res.Matched)
	}
}

// The probe's extra line must never be AGGREGATED: with TailLines=10 over an
// 11-line file whose OLDEST line is the only one for the target host, that
// dropped line must stay invisible (matched=0) while the caps still fire.
func TestScanHost_ProbeLineNotAggregated(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	lines := []string{
		cfmline(now-30, "198.51.100.9", "target.gr", "GET", "/dropped-by-tail-window", 200, "-", 0),
	}
	for i := 0; i < 10; i++ {
		lines = append(lines, cfmline(now-25+float64(i), "198.51.100.1", "other.gr", "GET", fmt.Sprintf("/p%d", i), 200, "-", 0))
	}
	writeLines(t, live, lines)
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "target.gr", HostOpts{Hours: 1, TailLines: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 10 {
		t.Errorf("scanned = %d, want exactly 10 (probe line must not reach aggregation)", res.Scanned)
	}
	if res.Matched != 0 {
		t.Errorf("matched = %d, want 0 — the only target line is outside the requested tail window", res.Matched)
	}
	if !res.LiveTailTruncated || !res.Truncated {
		t.Error("cap flags must still be true")
	}
}

// cfmbadline builds one log_format cfm_bad_request line (escape=json style:
// method/uri quoted) as written to access.bad_request.log.
func cfmbadline(ts float64, client, host, method, uri string, status int, ua string, nbytes int64) string {
	tl := time.Unix(int64(ts), 0).UTC().Format("02/Jan/2006:15:04:05 -0700")
	return fmt.Sprintf(
		`ts="%s" msec=%.3f client=%s peer=%s host=%s method="%s" uri="%s" proto="HTTP/1.1" req_line="%s / HTTP/1.1" status=%d bytes=%d req_len=300 sch=https dst=203.0.113.1:443 ua="%s"`,
		tl, ts, client, client, host, method, uri, method, status, nbytes, ua,
	)
}

// TestScanHost_BadRequestSectionSeparate pins the malformed/aborted
// provenance contract: 400/408/414/431/494/499 traffic lives in its OWN log
// and is reported in its own section — never mixed into valid-traffic totals,
// never invisible.
func TestScanHost_BadRequestSectionSeparate(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, []string{
		cfmline(now-30, "198.51.100.1", "ex.gr", "GET", "/ok", 200, "Mozilla/5.0", 50),
		cfmline(now-20, "198.51.100.2", "ex.gr", "GET", "/also-ok", 404, "bot/1", 60),
	})
	badLog := filepath.Join(dir, "access.bad_request.log")
	writeLines(t, badLog, []string{
		cfmbadline(now-25, "198.51.100.7", "ex.gr", "GET", "/junk", 400, "-", 0),
		cfmbadline(now-15, "198.51.100.7", "ex.gr", "GET", "/hugeheaders", 431, "-", 0),
		cfmbadline(now-10, "198.51.100.8", "other.gr", "GET", "/x", 400, "-", 0),
	})

	oldFull := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, oldFull...)
	defer func() { fullAccessLogCandidates = oldFull }()
	// NOTE no resolver override for the sidecar: it is DERIVED from the main
	// log's directory (same-engine pairing guarantee).

	res, err := ScanHost(context.Background(), "EX.gr", HostOpts{Hours: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalRequests != 2 {
		t.Errorf("total_requests = %d, want 2 (valid only)", res.TotalRequests)
	}
	if res.StatusClasses["4xx"] != 1 {
		t.Errorf("valid-side 4xx = %d, want 1 (the /also-ok)", res.StatusClasses["4xx"])
	}
	if res.BadRequests == nil {
		t.Fatal("bad_requests section missing — malformed traffic went blind")
	}
	bad := res.BadRequests
	if bad.TotalRequests != 2 {
		t.Errorf("bad total = %d, want 2 (ex.gr rows only)", bad.TotalRequests)
	}
	if bad.StatusClasses["4xx"] != 2 {
		t.Errorf("bad 4xx = %d, want 2 (400 + 431)", bad.StatusClasses["4xx"])
	}
	if bad.LogFile != badLog {
		t.Errorf("bad logfile = %q", bad.LogFile)
	}
	if res.TotalRequestsWithBad != 4 {
		t.Errorf("total_with_bad = %d, want 4", res.TotalRequestsWithBad)
	}
	if res.Truncated || bad.Truncated {
		t.Error("truncated must be false on this clean run")
	}

	// Without the sidecar on disk, the section is nil (documented meaning:
	// this engine has no bad-request log) and totals stay consistent.
	if err := os.Remove(badLog); err != nil {
		t.Fatal(err)
	}
	res2, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res2.BadRequests != nil {
		t.Error("bad_requests must be nil when the engine has no such log")
	}
	if res2.TotalRequestsWithBad != res2.TotalRequests {
		t.Errorf("with_bad = %d, want %d (no bad source)", res2.TotalRequestsWithBad, res2.TotalRequests)
	}
}

// TestSizeMutationDetection pins the copytruncate/rotation honesty helpers: a
// shrink or ANY size movement between pre/post stats flags the read.
func TestSizeMutationDetection(t *testing.T) {
	if sizeChanged(100, 100) {
		t.Error("equal sizes must not flag")
	}
	if !sizeShrank(100, 90) {
		t.Error("shrink must flag")
	}
	if sizeShrank(90, 100) {
		t.Error("growth is not a shrink")
	}
	if !sizeChanged(100, 250) {
		t.Error("growth during a rotated-file read must flag too (copytruncate fill)")
	}
}

// TestScanHost_SharedBudgetAcrossChains pins single-source-of-truth budget
// accounting: exactly max_lines lines consumed across live + rotated siblings,
// an EXACT fit never reports truncated, and every source is reached.
func TestScanHost_SharedBudgetAcrossChains(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	liveLines := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		liveLines = append(liveLines, cfmline(now-100+float64(i), "198.51.100.1", "ex.gr", "GET", fmt.Sprintf("/l%d", i), 200, "-", 0))
	}
	writeLines(t, live, liveLines)
	gzLines := func(tag string) []string {
		out := make([]string, 0, 5)
		for i := 0; i < 5; i++ {
			out = append(out, cfmline(now-50+float64(i), "198.51.100.2", "ex.gr", "GET", fmt.Sprintf("%s%d", tag, i), 200, "-", 0))
		}
		return out
	}
	writeGz(t, filepath.Join(dir, "access.log.1.gz"), gzLines("/a"))
	writeGz(t, filepath.Join(dir, "access.log.2.gz"), gzLines("/b"))
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 48, IncludeRotated: true, MaxLines: 15})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 15 {
		t.Errorf("scanned = %d, want exactly 15 (each line charged once)", res.Scanned)
	}
	if res.Truncated {
		t.Error("exact budget fit must NOT report truncated")
	}
	if got := len(res.FilesScanned); got != 3 {
		t.Errorf("files_scanned = %d (%v), want 3 — all sources reached", got, res.FilesScanned)
	}
}

// TestScanHost_LastSiblingBudgetBoundary pins the sentinel contract: when the
// shared budget runs out while the LAST scanned sibling still has unread
// lines, truncated MUST be true (no files_failed — the file is fine) even
// though no later loop iteration exists to notice.
func TestScanHost_LastSiblingBudgetBoundary(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	liveLines := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		liveLines = append(liveLines, cfmline(now-100+float64(i), "198.51.100.1", "ex.gr", "GET", fmt.Sprintf("/l%d", i), 200, "-", 0))
	}
	writeLines(t, live, liveLines)
	sib := make([]string, 0, 6) // one MORE line than the remaining budget (5)
	for i := 0; i < 6; i++ {
		sib = append(sib, cfmline(now-50+float64(i), "198.51.100.2", "ex.gr", "GET", fmt.Sprintf("/s%d", i), 200, "-", 0))
	}
	writeGz(t, filepath.Join(dir, "access.log.1.gz"), sib)
	old := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, old...)
	defer func() { fullAccessLogCandidates = old }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 48, IncludeRotated: true, MaxLines: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 10 {
		t.Errorf("scanned = %d, want exactly 10", res.Scanned)
	}
	if !res.Truncated {
		t.Error("budget exhausted mid-LAST-sibling must set truncated")
	}
	if len(res.FilesFailed) != 0 {
		t.Errorf("files_failed = %v, want empty (budget cut is not corruption)", res.FilesFailed)
	}
}

// TestScanHost_EmptyBadLiveStillScansArchives: copytruncate+notifempty leaves
// an EMPTY live access.bad_request.log right after rotation — that is a valid
// live source with zero current entries, NOT "source absent". The rotated
// archives (.1.gz holding yesterday's malformed attacks) must still be scanned.
func TestScanHost_EmptyBadLiveStillScansArchives(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, []string{
		cfmline(now-30, "198.51.100.1", "ex.gr", "GET", "/ok", 200, "Mozilla/5.0", 50),
	})
	badLog := filepath.Join(dir, "access.bad_request.log")
	if err := os.WriteFile(badLog, nil, 0o644); err != nil { // ZERO bytes, exists
		t.Fatal(err)
	}
	badGz := filepath.Join(dir, "access.bad_request.log.1.gz")
	writeGz(t, badGz, []string{
		cfmbadline(now-3600, "198.51.100.7", "ex.gr", "GET", "/hugeheaders", 431, "-", 0),
		cfmbadline(now-3500, "198.51.100.7", "ex.gr", "GET", "/garbage", 431, "-", 0),
	})

	oldFull := fullAccessLogCandidates
	fullAccessLogCandidates = append([]string{live}, oldFull...)
	defer func() { fullAccessLogCandidates = oldFull }()

	res, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 48, IncludeRotated: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.BadRequests == nil {
		t.Fatal("bad_requests=nil with an existing (empty) live sidecar — archival false negative")
	}
	bad := res.BadRequests
	if bad.TotalRequests != 2 {
		t.Errorf("bad total = %d, want 2 (both archived 431s)", bad.TotalRequests)
	}
	if res.TotalRequestsWithBad != 3 {
		t.Errorf("total_with_bad = %d, want 3 (1 valid + 2 archived malformed)", res.TotalRequestsWithBad)
	}
	found := false
	for _, f := range bad.FilesScanned {
		if f == badGz {
			found = true
		}
	}
	if !found {
		t.Errorf("bad archive not scanned: %v", bad.FilesScanned)
	}

	// Without rotated reach the section still EXISTS (live source present),
	// just empty for the current generation.
	res2, err := ScanHost(context.Background(), "ex.gr", HostOpts{Hours: 48, IncludeRotated: false})
	if err != nil {
		t.Fatal(err)
	}
	if res2.BadRequests == nil || res2.BadRequests.TotalRequests != 0 {
		t.Errorf("include_rotated=false: section=%v, want present with 0 requests", res2.BadRequests)
	}
}

func TestBadRequestLogFor(t *testing.T) {
	cases := [][2]string{
		{"/var/log/angie/access.log", "/var/log/angie/access.bad_request.log"},
		{"/usr/local/openresty/nginx/logs/access.log", "/usr/local/openresty/nginx/logs/access.bad_request.log"},
	}
	for _, c := range cases {
		if got := badRequestLogFor(c[0]); got != c[1] {
			t.Errorf("badRequestLogFor(%q) = %q, want %q (sidecar always pairs with the resolved engine)", c[0], got, c[1])
		}
	}
}

func TestRotatedGenerationChanged(t *testing.T) {
	base := map[string]rotatedSnapshot{
		"/v/a.1.gz": {path: "/v/a.1.gz", size: 10, mod: time.Unix(1000, 0)},
	}
	same := func() map[string]rotatedSnapshot {
		return map[string]rotatedSnapshot{
			"/v/a.1.gz": {path: "/v/a.1.gz", size: 10, mod: time.Unix(1000, 0)},
		}
	}
	if rotatedGenerationChanged(base, same()) {
		t.Error("identical generations must not flag")
	}
	appeared := same()
	appeared["/v/a.2.gz"] = rotatedSnapshot{path: "/v/a.2.gz", size: 5, mod: time.Unix(1001, 0)}
	if !rotatedGenerationChanged(base, appeared) {
		t.Error("new sibling must flag")
	}
	replaced := same()
	delete(replaced, "/v/a.1.gz")
	if !rotatedGenerationChanged(base, replaced) {
		t.Error("removed sibling must flag")
	}
	moved := same()
	moved["/v/a.1.gz"] = rotatedSnapshot{path: "/v/a.1.gz", size: 11, mod: time.Unix(1000, 0)}
	if !rotatedGenerationChanged(base, moved) {
		t.Error("size change must flag")
	}
	touched := same()
	touched["/v/a.1.gz"] = rotatedSnapshot{path: "/v/a.1.gz", size: 10, mod: time.Unix(1002, 0)}
	if !rotatedGenerationChanged(base, touched) {
		t.Error("mtime change must flag")
	}
}

// TestScanHost_SiblingGenerationGuard replays the reviewer's sequence
// deterministically: fingerprint -> live read -> NEW rotated sibling appears ->
// sibling phase must flag changed/truncated and SKIP scanning (no clean
// double-count of lines already aggregated from the live tail).
func TestScanHost_SiblingGenerationGuard(t *testing.T) {
	requireTail(t)
	now := float64(time.Now().Unix())
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	writeLines(t, live, []string{
		cfmline(now-30, "198.51.100.1", "ex.gr", "GET", "/live", 200, "-", 0),
	})

	used := int64(0)
	lc := &logChain{
		agg: &hostAgg{targets: map[string]struct{}{"ex.gr": {}},
			ips: map[string]int64{}, uas: map[string]int64{}, fams: map[string]int64{},
			paths: map[string]int64{}, codes: map[string]int64{}, methods: map[string]int64{},
			hours: map[int64]*hostHour{},
		},
		from: int64(now - 3600), to: int64(now),
		budgetUsed: &used, budgetCap: 1000,
	}

	// 1) stable generation BEFORE the live read...
	preGen := snapshotRotated(live)
	// 2) ...live read happens here (nothing to simulate)...

	// 3)-4) rotation slips in AFTER the fingerprint: new .1.gz with lines that
	// overlap what a live tail would already have counted.
	writeGz(t, filepath.Join(dir, "access.log.1.gz"), []string{
		cfmline(now-60, "198.51.100.2", "ex.gr", "GET", "/just-rotated", 200, "-", 0),
	})

	// 5)+6) sibling phase: guard must fire and scan NOTHING.
	lc.siblingPhase(context.Background(), live, preGen, 40, int64(now-3600))

	if !lc.changed || !lc.truncated {
		t.Fatalf("changed=%v truncated=%v, want both true", lc.changed, lc.truncated)
	}
	if len(lc.files) != 0 {
		t.Errorf("files scanned under guard = %v, want none", lc.files)
	}
	if used != 0 {
		t.Errorf("budget used = %d, want 0 (no sibling lines consumed)", used)
	}
}

func TestWWWTwin(t *testing.T) {
	cases := [][2]string{
		{"ex.gr", "www.ex.gr"},
		{"www.ex.gr", "ex.gr"},
		{"  WWW.Ex.Gr. ", "ex.gr"}, // trim + lowercase + trailing dot
	}
	for _, c := range cases {
		if got := WWWTwin(c[0]); got != c[1] {
			t.Errorf("WWWTwin(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestNormalizePath(t *testing.T) {
	if got := normalizePath("/a/b.php?x=1&y=2"); got != "/a/b.php" {
		t.Errorf("query strip failed: %q", got)
	}
	if got := normalizePath("/f#frag"); got != "/f" {
		t.Errorf("frag strip failed: %q", got)
	}
	long := "/" + strings.Repeat("x", 400)
	if got := normalizePath(long); len(got) != maxPathLen {
		t.Errorf("long path not capped: %d", len(got))
	}
	if got := normalizePath("-"); got != "" {
		t.Errorf("dash should normalize to empty, got %q", got)
	}
}
