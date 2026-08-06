package edgelog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	res, err := GrepIP(context.Background(), ip, "", 1000, 40)
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

	res, err := GrepIP(context.Background(), ip, "", 100, 50)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 0 {
		t.Fatalf("matched = %d, want 0 (oldest line is outside the 100-line tail)", res.Matched)
	}
}

func TestGrepIP_InvalidIP(t *testing.T) {
	if _, err := GrepIP(context.Background(), "not-an-ip", "", 0, 0); err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if _, err := GrepIP(context.Background(), "1.2.3.4; rm -rf /", "", 0, 0); err == nil {
		t.Fatal("expected error for injection-shaped input")
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
