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

	old := accessLogCandidates
	accessLogCandidates = append([]string{live}, old...)
	defer func() { accessLogCandidates = old }()

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
	old := accessLogCandidates
	accessLogCandidates = append([]string{live}, old...)
	defer func() { accessLogCandidates = old }()

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
	old := accessLogCandidates
	accessLogCandidates = append([]string{live}, old...)
	defer func() { accessLogCandidates = old }()

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

	old := accessLogCandidates
	accessLogCandidates = append([]string{live}, old...)
	defer func() { accessLogCandidates = old }()

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
	old := accessLogCandidates
	accessLogCandidates = append([]string{live}, old...)
	defer func() { accessLogCandidates = old }()

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

	old := accessLogCandidates
	accessLogCandidates = append([]string{live}, old...)
	defer func() { accessLogCandidates = old }()

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
	old := accessLogCandidates
	accessLogCandidates = append([]string{live}, old...)
	defer func() { accessLogCandidates = old }()

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
		a.feed(line, int64(fromOf(now)))
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
