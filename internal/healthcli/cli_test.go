package healthcli

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunSummaryAndJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health/snapshot" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"health.snapshot.v1","node_id":"n1","generated_at":"2026-04-28T00:00:00Z","snapshot":{"node_id":"n1","hostname":"host1","collected_at":"2026-04-28T00:00:00Z","load1":1.2,"ram_used_pct":30,"disk_root_pct":40,"disk_tmp_pct":10,"temp_max_c":55,"rx_mbps":1.1,"tx_mbps":2.2}}`))
	}))
	defer srv.Close()

	if err := Run(srv.URL, nil); err != nil {
		t.Fatalf("summary run: %v", err)
	}
	if err := Run(srv.URL, []string{"json"}); err != nil {
		t.Fatalf("json run: %v", err)
	}
}

func TestRunLiveFallsBackWithoutTTY(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"health.snapshot.v1","node_id":"n1","generated_at":"2026-04-28T00:00:00Z","snapshot":{"node_id":"n1","hostname":"host1","collected_at":"2026-04-28T00:00:00Z"}}`))
	}))
	defer srv.Close()

	if err := Run(srv.URL, []string{"live"}); err != nil {
		t.Fatalf("live fallback run: %v", err)
	}
}

func TestParseInterval(t *testing.T) {
	if got := parseInterval(nil, 0); got != 0 {
		t.Fatalf("unexpected default: %s", got)
	}
	if got := parseInterval([]string{"3"}, 0); got.Seconds() != 3 {
		t.Fatalf("unexpected interval: %s", got)
	}
	if got := parseInterval([]string{"x"}, 5*time.Second); got.Seconds() != 5 {
		t.Fatalf("unexpected fallback: %s", got)
	}
}
