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
			wantAll:  []string{"Node: host1", "Host", "Runtime", "Disk", "Network", "CFM", "CFM daemon: down", "Service: unknown", "DNAT: unknown (frontend=unknown, confidence=low)", "Edge: unknown (unknown)", "Upstream: unknown (unknown)"},
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

func TestRuntimeSectionIncludesFrontendAndWarning(t *testing.T) {
	s := parsedSnapshot{}
	s.Modern.Runtime.DNATEnabled = "on"
	s.Modern.Runtime.DNATFrontend = "angie"
	s.Modern.Runtime.DNATConfidence = "low"
	s.Modern.Runtime.FrontendWorking = "working"
	s.Modern.Runtime.EdgeService = "angie"
	s.Modern.Runtime.EdgeStatus = "active"
	s.Modern.Runtime.UpstreamService = "nginx"
	s.Modern.Runtime.UpstreamStatus = "active"
	s.Modern.Runtime.DNATWarning = "ambiguous ownership: angie(score=5), nginx(score=4)"

	out, err := runWithCapturedStdout(func() error {
		printRuntimeSection(s, cliOptions{NoColor: true})
		return nil
	})
	if err != nil {
		t.Fatalf("printRuntimeSection error: %v", err)
	}
	if !strings.Contains(out, "DNAT: on (frontend=angie, confidence=low)") {
		t.Fatalf("expected frontend output, got:\n%s", out)
	}
	if !strings.Contains(out, "Frontend: angie (working)") {
		t.Fatalf("expected frontend working verdict, got:\n%s", out)
	}
	if !strings.Contains(out, "Edge: angie (active, listening 9080/9043)") {
		t.Fatalf("expected edge role output, got:\n%s", out)
	}
	if !strings.Contains(out, "Upstream: nginx (active)") {
		t.Fatalf("expected upstream role output, got:\n%s", out)
	}
	if !strings.Contains(out, "Warning: ambiguous ownership") {
		t.Fatalf("expected warning output, got:\n%s", out)
	}
}

func TestRuntimeSectionFrontendDegradedReason(t *testing.T) {
	s := parsedSnapshot{}
	s.Modern.Runtime.DNATEnabled = "on"
	s.Modern.Runtime.DNATFrontend = "openresty"
	s.Modern.Runtime.DNATConfidence = "high"
	s.Modern.Runtime.FrontendWorking = "degraded"
	s.Modern.Runtime.FrontendReason = "listener missing on :443"
	s.Modern.Runtime.DNATWarning = "ambiguous ownership: openresty(score=6), nginx(score=6)"

	out, err := runWithCapturedStdout(func() error {
		printRuntimeSection(s, cliOptions{NoColor: true})
		return nil
	})
	if err != nil {
		t.Fatalf("printRuntimeSection error: %v", err)
	}
	if !strings.Contains(out, "Frontend: openresty (degraded: listener missing on :443)") {
		t.Fatalf("expected degraded frontend output, got:\n%s", out)
	}
	if strings.Contains(out, "Warning:") {
		t.Fatalf("expected warning to be suppressed when confidence is high, got:\n%s", out)
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

func TestHealthLabelUnknownIsNeutral(t *testing.T) {
	tests := []string{"", "unknown", "n/a", "UNKNOWN", " N/A "}
	for _, tc := range tests {
		if got := healthLabel(tc); got != okLabel {
			t.Fatalf("healthLabel(%q)=%v, want %v", tc, got, okLabel)
		}
	}
}

func TestStorageOptionalSubsystemNotPresent(t *testing.T) {
	s := parsedSnapshot{
		Modern: modernSample{},
		RawMap: map[string]any{
			"smart_health":  "ok",
			"disk_wearout":  "ok",
			"mdadm_health":  "degraded",
			"zfs_health":    "degraded",
			"mdadm_present": false,
			"zfs_present":   false,
		},
	}

	out, err := runWithCapturedStdout(func() error {
		printStorageSection(s, cliOptions{NoColor: true})
		return nil
	})
	if err != nil {
		t.Fatalf("printStorageSection error: %v", err)
	}
	if !strings.Contains(out, "Storage health [OK]") {
		t.Fatalf("expected overall storage status to remain OK for absent optional subsystems, got:\n%s", out)
	}
	if !strings.Contains(out, "mdadm: not present") || !strings.Contains(out, "ZFS: not present") {
		t.Fatalf("expected explicit not-present labels, got:\n%s", out)
	}
}
