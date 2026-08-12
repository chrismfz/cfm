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

// writeLog writes n numbered lines, injecting the target IP on some of them.
func writeLog(t *testing.T, n int, ip string, every int) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")
	var b strings.Builder
	for i := 0; i < n; i++ {
		if every > 0 && i%every == 0 {
			b.WriteString(fmt.Sprintf("%s - - [t] \"GET /page%d HTTP/1.1\" 200 10\n", ip, i))
		} else {
			b.WriteString(fmt.Sprintf("10.0.0.1 - - [t] \"GET /other%d HTTP/1.1\" 200 10\n", i))
		}
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestGrepIP_IncludeRotated verifies the opt-in rotated reach: a live file, a
// plain rotated .1, and a gzipped .2.gz are all scanned when IncludeRotated is
// set (and only then), while an unrelated same-dir log is never touched.
func TestGrepIP_IncludeRotated(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	ip := "203.0.113.9"
	logLine := func(path string) string {
		return fmt.Sprintf("%s - - [t] \"GET %s HTTP/1.1\" 200 10\n", ip, path)
	}
	dir := t.TempDir()
	live := filepath.Join(dir, "access.log")
	if err := os.WriteFile(live, []byte(logLine("/live")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "access.log.1"), []byte(logLine("/rot1")), 0o644); err != nil {
		t.Fatal(err)
	}
	// gzipped rotated sibling.
	gzf, err := os.Create(filepath.Join(dir, "access.log.2.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(gzf)
	if _, err := gw.Write([]byte(logLine("/rot2gz"))); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzf.Close(); err != nil {
		t.Fatal(err)
	}
	// An unrelated log in the same dir must be excluded (name doesn't start with "access.log.").
	if err := os.WriteFile(filepath.Join(dir, "other.log"), []byte(logLine("/nope")), 0o644); err != nil {
		t.Fatal(err)
	}

	old := accessLogCandidates
	accessLogCandidates = append([]string{live}, old...)
	defer func() { accessLogCandidates = old }()

	// Default (no rotated): only the live match, one file scanned.
	res, err := GrepIP(context.Background(), ip, Opts{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || len(res.FilesScanned) != 1 {
		t.Fatalf("live-only: matched=%d files=%v, want 1 match / 1 file", res.Matched, res.FilesScanned)
	}

	// With rotated: live + .1 + .2.gz = 3 matches; other.log excluded.
	res2, err := GrepIP(context.Background(), ip, Opts{Limit: 100, IncludeRotated: true})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Matched != 3 {
		t.Fatalf("rotated: matched=%d, want 3 (files=%v)", res2.Matched, res2.FilesScanned)
	}
	if len(res2.FilesScanned) != 3 {
		t.Fatalf("rotated: files_scanned=%v, want 3", res2.FilesScanned)
	}
	joined := strings.Join(res2.Lines, "\n")
	for _, want := range []string{"/live", "/rot1", "/rot2gz"} {
		if !strings.Contains(joined, want) {
			t.Errorf("rotated result missing %q; lines=%v", want, res2.Lines)
		}
	}
	if strings.Contains(joined, "/nope") {
		t.Errorf("unrelated other.log was scanned: %v", res2.Lines)
	}
}

func TestGrepIP_TailAndFilter(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	ip := "203.0.113.7"
	p := writeLog(t, 1000, ip, 10) // 100 lines mention the IP
	// point the resolver at our temp file by prepending it to candidates.
	old := accessLogCandidates
	accessLogCandidates = append([]string{p}, old...)
	defer func() { accessLogCandidates = old }()

	// scan all 1000, cap matches at 40 → truncated.
	res, err := GrepIP(context.Background(), ip, Opts{TailLines: 1000, Limit: 40})
	if err != nil {
		t.Fatal(err)
	}
	if res.LogFile != p {
		t.Fatalf("logFile = %q, want %q", res.LogFile, p)
	}
	if res.Matched != 100 {
		t.Fatalf("matched = %d, want 100", res.Matched)
	}
	if len(res.Lines) != 40 || !res.Truncated {
		t.Fatalf("lines=%d truncated=%v, want 40,true", len(res.Lines), res.Truncated)
	}
	for _, l := range res.Lines {
		if !strings.Contains(l, ip) {
			t.Fatalf("returned line without ip: %q", l)
		}
	}
}

func TestGrepIP_TailWindowBounds(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	ip := "203.0.113.9"
	// 500 lines; only line 0 mentions the IP (the oldest). A tail window of 100
	// must NOT see it — proves we read only the trailing window.
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")
	var b strings.Builder
	b.WriteString(ip + " - - oldest\n")
	for i := 1; i < 500; i++ {
		b.WriteString("10.0.0.1 - - line\n")
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	old := accessLogCandidates
	accessLogCandidates = append([]string{p}, old...)
	defer func() { accessLogCandidates = old }()

	res, err := GrepIP(context.Background(), ip, Opts{TailLines: 100, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 0 {
		t.Fatalf("matched = %d, want 0 (oldest line is outside the 100-line tail)", res.Matched)
	}
}

func TestGrepIP_InvalidIP(t *testing.T) {
	if _, err := GrepIP(context.Background(), "not-an-ip", Opts{}); err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if _, err := GrepIP(context.Background(), "1.2.3.4; rm -rf /", Opts{}); err == nil {
		t.Fatal("expected error for injection-shaped input")
	}
}

func TestMentionsIP_TokenBoundary(t *testing.T) {
	ip := "1.2.3.4"
	yes := []string{
		`1.2.3.4 - - "GET / HTTP/1.1" 200`, // leading field
		`x [1.2.3.4] "GET"`,                // bracketed
		`fwd="1.2.3.4"`,                    // quoted
		`a 1.2.3.4`,                        // trailing
	}
	no := []string{
		`1.2.3.45 - - "GET"`, // longer IP, trailing digit
		`11.2.3.4 - - "GET"`, // longer IP, leading digit
		`1.2.3.4a`,           // hex letter adjacency
		`10.0.0.1 - - "GET"`, // different IP
	}
	for _, l := range yes {
		if !mentionsIP(l, ip) {
			t.Errorf("mentionsIP false, want true: %q", l)
		}
	}
	for _, l := range no {
		if mentionsIP(l, ip) {
			t.Errorf("mentionsIP true, want false: %q", l)
		}
	}
}

func TestGrepIP_NoSubstringOvermatch(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")
	body := "1.2.3.45 - - \"GET /a\" 200\n" + // must NOT match 1.2.3.4
		"1.2.3.4 - - \"GET /b\" 200\n" + // must match
		"11.2.3.4 - - \"GET /c\" 200\n" // must NOT match
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	old := accessLogCandidates
	accessLogCandidates = append([]string{p}, old...)
	defer func() { accessLogCandidates = old }()

	res, err := GrepIP(context.Background(), "1.2.3.4", Opts{TailLines: 100, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || len(res.Lines) != 1 || !strings.Contains(res.Lines[0], "/b") {
		t.Fatalf("expected only the exact-IP line, got matched=%d lines=%v", res.Matched, res.Lines)
	}
}

func TestGrepIP_IPv6Canonicalization(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")
	// log stores the canonical lowercase/compressed form; caller passes an
	// uppercase/uncompressed variant.
	if err := os.WriteFile(p, []byte("2001:db8::1 - - \"GET /\" 200\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := accessLogCandidates
	accessLogCandidates = append([]string{p}, old...)
	defer func() { accessLogCandidates = old }()

	res, err := GrepIP(context.Background(), "2001:0DB8::1", Opts{TailLines: 100, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 {
		t.Fatalf("IPv6 canonicalization failed: matched=%d (want 1)", res.Matched)
	}
	if res.IP != "2001:db8::1" {
		t.Fatalf("result IP not canonical: %q", res.IP)
	}
}

func TestResolveLog_SourceAllowlist(t *testing.T) {
	p := writeLog(t, 1, "1.1.1.1", 0)
	old := accessLogCandidates
	accessLogCandidates = append([]string{p}, old...)
	defer func() { accessLogCandidates = old }()

	// exact + basename resolve to the same file.
	if got, err := resolveLog(p); err != nil || got != p {
		t.Fatalf("resolveLog(full) = %q, %v", got, err)
	}
	if got, err := resolveLog("access.log"); err != nil || got != p {
		t.Fatalf("resolveLog(basename) = %q, %v", got, err)
	}
	// a path not in the allow-list is rejected even if it exists.
	other := filepath.Join(t.TempDir(), "secret.log")
	_ = os.WriteFile(other, []byte("x"), 0o644)
	if _, err := resolveLog(other); err == nil {
		t.Fatal("expected rejection of non-allowlisted path")
	}
}

// writeErrLog writes n numbered error-log lines, tagging every `every`-th line
// with token so it matches a grep. Line index is embedded as "line N".
func writeErrLog(t *testing.T, n int, token string, every int) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "error.log")
	var b strings.Builder
	for i := 0; i < n; i++ {
		if every > 0 && i%every == 0 {
			b.WriteString(fmt.Sprintf("2026/08/12 12:00:%02d [warn] %s marker line %d\n", i%60, token, i))
		} else {
			b.WriteString(fmt.Sprintf("2026/08/12 12:00:%02d [notice] other line %d\n", i%60, i))
		}
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTailError_NewestMatchesAndGrep(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	// 100 matching lines at i=0,10,…,990 (token "LOGONLY").
	p := writeErrLog(t, 1000, "LOGONLY", 10)
	old := errorLogCandidates
	errorLogCandidates = append([]string{p}, old...)
	defer func() { errorLogCandidates = old }()

	// Case-insensitive grep, scan all 1000, cap at 40 → the NEWEST 40 matches
	// (i=600,610,…,990). Older matches dropped → Truncated.
	res, err := TailError(context.Background(), "logonly", "", 1000, 40)
	if err != nil {
		t.Fatal(err)
	}
	if res.LogFile != p {
		t.Fatalf("logFile=%q want %q", res.LogFile, p)
	}
	if res.Matched != 100 {
		t.Fatalf("matched=%d want 100", res.Matched)
	}
	if len(res.Lines) != 40 || !res.Truncated {
		t.Fatalf("lines=%d truncated=%v want 40,true", len(res.Lines), res.Truncated)
	}
	// Newest kept = i=990 (last), oldest kept = i=600 (first).
	if !strings.Contains(res.Lines[len(res.Lines)-1], "line 990") {
		t.Fatalf("newest kept line wrong: %q", res.Lines[len(res.Lines)-1])
	}
	if !strings.Contains(res.Lines[0], "line 600") {
		t.Fatalf("oldest kept line wrong: %q", res.Lines[0])
	}
	for _, l := range res.Lines {
		if !strings.Contains(l, "LOGONLY") { // grep was lowercase; matching is case-insensitive
			t.Fatalf("returned non-matching line: %q", l)
		}
	}
}

func TestTailError_EmptyGrepAndSourceAllowlist(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	p := writeErrLog(t, 50, "X", 0) // no matches injected; every line is a plain line
	old := errorLogCandidates
	errorLogCandidates = append([]string{p}, old...)
	defer func() { errorLogCandidates = old }()

	// Empty grep → every tail line "matches"; newest `limit` returned.
	res, err := TailError(context.Background(), "", "", 50, 10)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 50 || len(res.Lines) != 10 || !res.Truncated {
		t.Fatalf("empty-grep: matched=%d lines=%d truncated=%v want 50,10,true", res.Matched, len(res.Lines), res.Truncated)
	}
	if !strings.Contains(res.Lines[len(res.Lines)-1], "line 49") {
		t.Fatalf("empty-grep newest line wrong: %q", res.Lines[len(res.Lines)-1])
	}

	// A source not on the error-log allow-list is rejected (no arbitrary path).
	if _, err := TailError(context.Background(), "", "/etc/passwd", 0, 0); err == nil {
		t.Fatal("expected rejection of non-allowlisted error-log source")
	}
}

// Reproduces the live bug: on an Angie-fronted node the disabled OpenResty
// error.log still exists (stale/empty) and, under a static "OpenResty-first"
// order, was default-selected over the actively-written Angie log. The resolver
// must default to the most-recently-modified (active) log instead.
func TestAvailableFrom_PrefersMostRecentActiveLog(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	dir := t.TempDir()
	stale := filepath.Join(dir, "openresty-error.log") // exists but disabled engine → old mtime
	fresh := filepath.Join(dir, "angie-error.log")     // active edge → new mtime
	if err := os.WriteFile(stale, []byte("2026/01/01 00:00:00 [warn] stale leftover line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fresh, []byte("2026/08/12 14:00:00 [warn] logonly=would_enforce active line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldT, newT := time.Unix(1_700_000_000, 0), time.Unix(1_800_000_000, 0)
	if err := os.Chtimes(stale, oldT, oldT); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fresh, newT, newT); err != nil {
		t.Fatal(err)
	}
	// Candidate order deliberately lists the STALE one first (mimics the static
	// openresty-before-angie priority that caused the bug).
	old := errorLogCandidates
	errorLogCandidates = []string{stale, fresh}
	defer func() { errorLogCandidates = old }()

	res, err := TailError(context.Background(), "logonly", "", 1000, 50)
	if err != nil {
		t.Fatal(err)
	}
	if res.LogFile != fresh {
		t.Fatalf("default selected %q, want the freshest (active edge) %q", res.LogFile, fresh)
	}
	if res.Matched != 1 {
		t.Fatalf("matched=%d want 1 (the active log's logonly line)", res.Matched)
	}
	// AvailableErrorLogs reports freshest-first too.
	if av := AvailableErrorLogs(); len(av) != 2 || av[0] != fresh {
		t.Fatalf("AvailableErrorLogs()=%v, want freshest %q first", av, fresh)
	}
}

func TestScanError_MatchesAnySubstrAndAllowlist(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("tail not available")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "error.log")
	body := "" +
		"2026/08/12 12:00:00 [warn] [cfm_panel_waf] logonly=would_block rule_id=320\n" +
		"2026/08/12 12:00:01 [warn] [cfm_panel_trace] phase=validate_next\n" + // must NOT match
		"2026/08/12 12:00:02 [notice] ordinary line\n" + // must NOT match
		"2026/08/12 12:00:03 [warn] panel_decision_probe(): [cfm_panel_decision] logonly=would_enforce ip_action=block\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	old := errorLogCandidates
	errorLogCandidates = append([]string{p}, old...)
	defer func() { errorLogCandidates = old }()

	// ScanError observes EVERY match for ANY of the substrings — both markers,
	// not the trace/ordinary lines.
	var got []string
	logFile, scanned, err := ScanError(context.Background(),
		[]string{"[cfm_panel_waf]", "[cfm_panel_decision]"}, "", 1000,
		func(line string) { got = append(got, line) })
	if err != nil {
		t.Fatal(err)
	}
	if logFile != p {
		t.Fatalf("logFile=%q want %q", logFile, p)
	}
	if scanned != 4 {
		t.Fatalf("scanned=%d want 4 (whole file)", scanned)
	}
	if len(got) != 2 {
		t.Fatalf("matched %d lines want 2 (both markers, not trace/ordinary): %v", len(got), got)
	}
	if !strings.Contains(got[0], "[cfm_panel_waf]") || !strings.Contains(got[1], "[cfm_panel_decision]") {
		t.Fatalf("wrong lines captured: %v", got)
	}

	// A source not on the error-log allow-list is rejected (no arbitrary path).
	if _, _, err := ScanError(context.Background(), []string{"x"}, "/etc/passwd", 0,
		func(string) {}); err == nil {
		t.Fatal("expected non-allowlisted source to be rejected")
	}
}
