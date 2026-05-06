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

func TestHealthSummaryIncludesChallengeFlowReadiness(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health/snapshot" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"schema_version":"health.snapshot.v1",
			"node_id":"n1",
			"collected_at":"2026-04-28T00:00:00Z",
			"host":{"hostname":"host1"},
			"disk":{},
			"services":[
				{"name":"angie","active":true,"enabled":true,"state":"active"},
				{"name":"openresty","active":false,"enabled":true,"state":"inactive"}
			],
			"cfm_metrics":{},
			"network":{},
			"runtime":{
				"edge_service":"angie",
				"dnat_frontend":"angie",
				"challenge_flow_state":"OK",
				"challenge_flow_code":"ok",
				"challenge_flow_reason":"challenge flow ready"
			}
		}`))
	}))
	defer srv.Close()

	out, err := runWithCapturedStdout(func() error {
		return Run(srv.URL, []string{"--no-color"})
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	for _, want := range []string{"Web stack - Edge Interceptor [OK]", "[OK]  Challenge flow readiness: OK challenge flow ready"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected health summary to contain %q\noutput:\n%s", want, out)
		}
	}
}

func TestRuntimeSectionIncludesDnatEdgeUpstreamAndWarning(t *testing.T) {
	s := parsedSnapshot{}
	s.Modern.Runtime.DNATEnabled = "on"
	s.Modern.Runtime.DNATFrontend = "angie"
	s.Modern.Runtime.DNATConfidence = "low"
	s.Modern.Runtime.FrontendWorking = "working"
	s.Modern.Runtime.EdgeService = "angie"
	s.Modern.Runtime.EdgeStatus = "active"
	s.Modern.Runtime.EdgeConfidence = "high"
	s.Modern.Runtime.EdgeReasonCode = "dnat_targets_owner"
	s.Modern.Runtime.UpstreamService = "nginx"
	s.Modern.Runtime.UpstreamStatus = "active"
	s.Modern.Runtime.UpstreamConfidence = "high"
	s.Modern.Runtime.UpstreamReasonCode = "ports_80_443"
	s.Modern.Runtime.DNATWarning = "ambiguous ownership: angie(score=5), nginx(score=4)"

	out, err := runWithCapturedStdout(func() error {
		printRuntimeSection(s, cliOptions{NoColor: true, DebugRuntime: true})
		return nil
	})
	if err != nil {
		t.Fatalf("printRuntimeSection error: %v", err)
	}
	if !strings.Contains(out, "DNAT: on") {
		t.Fatalf("expected frontend output, got:\n%s", out)
	}
	if strings.Contains(out, "Frontend:") {
		t.Fatalf("expected explicit frontend line to be omitted, got:\n%s", out)
	}
	if !strings.Contains(out, "Edge: angie (confidence=high, via dnat_targets_owner)") {
		t.Fatalf("expected edge role output, got:\n%s", out)
	}
	if !strings.Contains(out, "Upstream: nginx (port 80/443, confidence=high, via ports_80_443)") {
		t.Fatalf("expected upstream role output, got:\n%s", out)
	}
	if !strings.Contains(out, "Warning: ambiguous ownership") {
		t.Fatalf("expected warning output, got:\n%s", out)
	}
}

func TestRuntimeSectionOmitsFrontendDegradedReasonLine(t *testing.T) {
	s := parsedSnapshot{}
	s.Modern.Runtime.DNATEnabled = "on"
	s.Modern.Runtime.DNATFrontend = "openresty"
	s.Modern.Runtime.DNATConfidence = "high"
	s.Modern.Runtime.FrontendWorking = "degraded"
	s.Modern.Runtime.FrontendReason = "listener missing on :443"
	s.Modern.Runtime.DNATWarning = "ambiguous ownership: openresty(score=6), nginx(score=6)"

	out, err := runWithCapturedStdout(func() error {
		printRuntimeSection(s, cliOptions{NoColor: true, DebugRuntime: true})
		return nil
	})
	if err != nil {
		t.Fatalf("printRuntimeSection error: %v", err)
	}
	if strings.Contains(out, "Frontend:") {
		t.Fatalf("expected no explicit frontend line, got:\n%s", out)
	}
	if strings.Contains(out, "Warning:") {
		t.Fatalf("expected warning to be suppressed when confidence is high, got:\n%s", out)
	}
}

func TestCollectWebStackRowsExcludesNginx(t *testing.T) {
	s := parsedSnapshot{
		Modern: modernSample{
			Services: []serviceStatus{
				{Name: "angie", State: "active", Active: true, Enabled: true},
				{Name: "openresty", State: "inactive", Active: false, Enabled: true},
				{Name: "nginx", State: "active", Active: true, Enabled: true},
			},
		},
	}
	rows := collectWebStackRows(s)
	if len(rows) != 2 {
		t.Fatalf("expected 2 web stack rows, got %d", len(rows))
	}
	if rows[0].Name != "angie" || rows[1].Name != "openresty" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestWebStackStatusUsesDetectedEdge(t *testing.T) {
	s := parsedSnapshot{}
	s.Modern.Runtime.EdgeService = "angie"
	s.Modern.Runtime.DNATFrontend = "angie"
	s.Modern.Runtime.ChallengeFlowState = "OK"
	s.Modern.Runtime.ChallengeFlowCode = "ok"
	s.Modern.Runtime.ChallengeFlowReason = "challenge flow ready"
	s.Modern.Services = []serviceStatus{
		{Name: "angie", State: "active", Active: true, Enabled: true},
		{Name: "openresty", State: "inactive", Active: false, Enabled: true},
	}

	out, err := runWithCapturedStdout(func() error {
		printWebStackSection(s, cliOptions{NoColor: true})
		return nil
	})
	if err != nil {
		t.Fatalf("printWebStackSection error: %v", err)
	}
	if !strings.Contains(out, "Web stack - Edge Interceptor [OK]") {
		t.Fatalf("expected OK web stack when selected edge is active, got:\n%s", out)
	}
	want := "[OK]  Challenge flow readiness: OK challenge flow ready"
	if !strings.Contains(out, want) {
		t.Fatalf("expected web stack summary to include %q under Edge Interceptor, got:\n%s", want, out)
	}
}

func TestChallengeFlowReadinessLabels(t *testing.T) {
	tests := []struct {
		name      string
		state     string
		wantLabel healthLabelRank
		wantText  string
	}{
		{name: "ok", state: "OK", wantLabel: okLabel, wantText: "OK ready"},
		{name: "warn", state: "WARN", wantLabel: warnLabel, wantText: "WARN ready"},
		{name: "fail", state: "FAIL", wantLabel: critLabel, wantText: "FAIL ready"},
		{name: "unknown bad state", state: "BROKEN", wantLabel: critLabel, wantText: "BROKEN ready"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLabel, gotText, ok := challengeFlowReadiness(tc.state, "ok", "ready")
			if !ok {
				t.Fatalf("challengeFlowReadiness returned ok=false")
			}
			if gotLabel != tc.wantLabel || gotText != tc.wantText {
				t.Fatalf("challengeFlowReadiness(%q)=(%v, %q), want (%v, %q)", tc.state, gotLabel, gotText, tc.wantLabel, tc.wantText)
			}
		})
	}
}

func TestRuntimeCompactWebStackExcludesNginx(t *testing.T) {
	s := parsedSnapshot{}
	s.Modern.Services = []serviceStatus{
		{Name: "angie", State: "active", Active: true, Enabled: true},
		{Name: "openresty", State: "active", Active: true, Enabled: true},
		{Name: "nginx", State: "active", Active: true, Enabled: true},
	}

	out, err := runWithCapturedStdout(func() error {
		printRuntimeSection(s, cliOptions{NoColor: true, Compact: true})
		return nil
	})
	if err != nil {
		t.Fatalf("printRuntimeSection error: %v", err)
	}
	if strings.Contains(out, "nginx:") {
		t.Fatalf("expected compact web stack to exclude nginx, got:\n%s", out)
	}
}

func TestRuntimeSectionShowsSubcheckWarningsWhenDegraded(t *testing.T) {
	s := parsedSnapshot{}
	s.Modern.Runtime.BridgeSocketStatus = "warn"
	s.Modern.Runtime.BridgeSocketReason = "decision path timeout"
	s.Modern.Runtime.BridgeSocketLatencyMs = 1201
	s.Modern.Runtime.ChallengeListenerStatus = "fail"
	s.Modern.Runtime.ChallengeListenerReason = "connection refused"
	s.Modern.Runtime.SSLCollectorStatus = "auth"

	out, err := runWithCapturedStdout(func() error {
		printRuntimeSection(s, cliOptions{NoColor: true})
		return nil
	})
	if err != nil {
		t.Fatalf("printRuntimeSection error: %v", err)
	}
	for _, want := range []string{"Warning (bridge_socket): decision path timeout (latency=1201ms)", "Warning (challenge_listener): connection refused", "Warning (sslcollector): auth"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
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
