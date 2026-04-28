package healthcli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestHealthCommandOutputs_Table(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health/snapshot" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"health.snapshot.v1","node_id":"n1","generated_at":"2026-04-28T00:00:00Z","snapshot":{"node_id":"n1","hostname":"host1","collected_at":"2026-04-28T00:00:00Z","load1":1.2,"ram_used_pct":30,"disk_root_pct":40,"disk_tmp_pct":10,"temp_max_c":55,"rx_mbps":1.1,"tx_mbps":2.2}}`))
	}))
	defer srv.Close()

	tests := []struct {
		name     string
		args     []string
		wantAll  []string
		wantNone []string
	}{
		{
			name:     "cfm health summary",
			args:     nil,
			wantAll:  []string{"Node: host1", "Host", "Runtime", "Disk", "Network", "CFM", "CFM daemon: down", "Service: unknown", "DNAT: unknown"},
			wantNone: []string{"[cfm health watch]"},
		},
		{
			name:     "cfm health json",
			args:     []string{"json"},
			wantAll:  []string{"\"schema_version\": \"health.snapshot.v1\"", "\"snapshot\"", "\"hostname\": \"host1\""},
			wantNone: []string{"Node: host1"},
		},
		{
			name:    "cfm health watch --interval (one shot for test)",
			args:    []string{"watch", "--interval=2s", "--once"},
			wantAll: []string{"[cfm health watch] interval=2s", "host=host1", "load=1.20"},
		},
		{
			name:    "cfm health live falls back to watch when no TTY",
			args:    []string{"live"},
			wantAll: []string{"[cfm health watch] interval=5s", "host=host1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runWithCapturedStdout(func() error {
				return Run(srv.URL, tc.args)
			})
			if err != nil {
				t.Fatalf("Run error: %v", err)
			}

			for _, want := range tc.wantAll {
				if !strings.Contains(out, want) {
					t.Fatalf("expected output to contain %q\noutput:\n%s", want, out)
				}
			}
			for _, unwanted := range tc.wantNone {
				if strings.Contains(out, unwanted) {
					t.Fatalf("expected output to not contain %q\noutput:\n%s", unwanted, out)
				}
			}
		})
	}
}

func runWithCapturedStdout(fn func() error) (string, error) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	defer r.Close()

	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), runErr
}
