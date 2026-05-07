package webdetector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeAnalyzeLog(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.tsv")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	return path
}

func tsv(ts float64, ip, host string) string {
	return fmt.Sprintf("%.0f\t%s\t%s\tget\t/\thttp/1.1\t200\t123\t0.01\t0\t-\tua", ts, ip, host)
}

func newAnalyzeTestEngine(t *testing.T, logPath string) *Engine {
	t.Helper()
	return NewEngine(Config{
		Mode:                  "file",
		LogPath:               logPath,
		TrafficRulesStorePath: filepath.Join(t.TempDir(), "rules.json"),
	})
}

func TestAnalyzeIP_DefaultUnchangedWithoutLast(t *testing.T) {
	logPath := writeAnalyzeLog(t,
		tsv(7000, "1.2.3.4", "old.example"),
		tsv(9500, "1.2.3.4", "new.example"),
		tsv(10000, "5.6.7.8", "anchor.example"),
	)
	e := newAnalyzeTestEngine(t, logPath)

	res, err := e.AnalyzeIP("1.2.3.4", 0)
	if err != nil {
		t.Fatalf("AnalyzeIP: %v", err)
	}
	if res.TotalReq != 2 {
		t.Fatalf("expected unfiltered total=2, got %d", res.TotalReq)
	}
	if res.FirstTS != 7000 || res.LastTS != 9500 {
		t.Fatalf("expected unfiltered range 7000..9500, got %.0f..%.0f", res.FirstTS, res.LastTS)
	}
}

func TestAnalyzeIP_LastFiltersAgainstNewestParsedLogTimestamp(t *testing.T) {
	logPath := writeAnalyzeLog(t,
		tsv(7000, "1.2.3.4", "old.example"),
		tsv(9500, "1.2.3.4", "new.example"),
		tsv(10000, "5.6.7.8", "anchor.example"),
	)
	e := newAnalyzeTestEngine(t, logPath)

	res, err := e.AnalyzeIPWithOptions("1.2.3.4", AnalyzeOptions{Last: 30 * time.Minute})
	if err != nil {
		t.Fatalf("AnalyzeIPWithOptions: %v", err)
	}
	if res.TotalReq != 1 {
		t.Fatalf("expected filtered total=1, got %d", res.TotalReq)
	}
	if res.FirstTS != 9500 || res.LastTS != 9500 {
		t.Fatalf("expected filtered range 9500..9500, got %.0f..%.0f", res.FirstTS, res.LastTS)
	}
	if len(res.VhostCnt) != 1 || res.VhostCnt[0].Key != "new.example" {
		t.Fatalf("expected only new.example vhost, got %#v", res.VhostCnt)
	}
}

func TestAnalyzeHost_LastFiltersMatchedRecords(t *testing.T) {
	logPath := writeAnalyzeLog(t,
		tsv(7000, "1.1.1.1", "site.example"),
		tsv(9500, "2.2.2.2", "site.example"),
		tsv(9600, "2.2.2.2", "site.example"),
		tsv(10000, "9.9.9.9", "anchor.example"),
	)
	e := newAnalyzeTestEngine(t, logPath)

	res, err := e.AnalyzeHostWithOptions("site.example", AnalyzeOptions{Last: 30 * time.Minute})
	if err != nil {
		t.Fatalf("AnalyzeHostWithOptions: %v", err)
	}
	if res.TotalReq != 2 {
		t.Fatalf("expected filtered total=2, got %d", res.TotalReq)
	}
	if res.FirstTS != 9500 || res.LastTS != 9600 {
		t.Fatalf("expected filtered range 9500..9600, got %.0f..%.0f", res.FirstTS, res.LastTS)
	}
	if len(res.IPCnt) != 1 || res.IPCnt[0].Key != "2.2.2.2" || res.IPCnt[0].Count != 2 {
		t.Fatalf("expected only recent IP count, got %#v", res.IPCnt)
	}
}

func TestAnalyzeCLIParseLastVariants(t *testing.T) {
	tests := [][]string{
		{"afixis.gr", "-last", "30m"},
		{"afixis.gr", "--last", "1h"},
		{"1.2.3.4", "--last=15m"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			target, last, err := parseAnalyzeCLIArgs(args)
			if err != nil {
				t.Fatalf("parseAnalyzeCLIArgs: %v", err)
			}
			if target != args[0] || last == "" {
				t.Fatalf("unexpected target/last: %q/%q", target, last)
			}
		})
	}
}

func TestAnalyzeCLIParseDefaultAndInvalidLast(t *testing.T) {
	target, last, err := parseAnalyzeCLIArgs([]string{"afixis.gr"})
	if err != nil {
		t.Fatalf("default parse: %v", err)
	}
	if target != "afixis.gr" || last != "" {
		t.Fatalf("unexpected default target/last: %q/%q", target, last)
	}
	if _, _, err := parseAnalyzeCLIArgs([]string{"afixis.gr", "--last", "bogus"}); err == nil {
		t.Fatalf("expected invalid duration error")
	}
}

func TestAnalyzeHTTPInvalidLastDuration(t *testing.T) {
	e := newAnalyzeTestEngine(t, writeAnalyzeLog(t))
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)

	rr := get(mux, adminCtx(), "/api/v1/webdet/analyze-ip?ip=1.2.3.4&last=bogus")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	var msg map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&msg); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if msg["error"] != "invalid last duration" {
		t.Fatalf("unexpected error JSON: %#v", msg)
	}
}

func TestRunWebTopAnalyzeIncludesLastQuery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/webdet/analyze-host" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("host"); got != "afixis.gr" {
			t.Fatalf("expected host afixis.gr, got %q", got)
		}
		if got := r.URL.Query().Get("last"); got != "30m" {
			t.Fatalf("expected last=30m, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"host":"afixis.gr","total_req":0,"ips":null}`))
	}))
	defer ts.Close()

	if err := RunWebTop(ts.URL, []string{"analyze", "afixis.gr", "-last", "30m"}); err != nil {
		t.Fatalf("RunWebTop: %v", err)
	}
}
