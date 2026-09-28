package webdetector

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPanelSessionAPIChallengeExempt_SharedVectors runs the vectors that
// scripts/tests/cfm_panel_hosts_test.lua also runs against the edge's Step 0d
// gates (cfm_panel_hosts.is_proxy_panel_host + is_session_api), so the
// decision engine's exemption cannot drift from what the edge passes through.
func TestPanelSessionAPIChallengeExempt_SharedVectors(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "scripts", "tests", "fixtures", "panel_session_api.txt"))
	if err != nil {
		t.Fatalf("open shared vectors: %v", err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			t.Fatalf("malformed vector %q", line)
		}
		want := parts[2] == "yes"
		if got := isPanelSessionAPIChallengeExempt(parts[0], parts[1]); got != want {
			t.Errorf("isPanelSessionAPIChallengeExempt(%q, %q) = %v, want %v", parts[0], parts[1], got, want)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 20 {
		t.Fatalf("only %d vectors read; fixture truncated?", n)
	}
}

// Raw-target cases only the engine sees (the edge gets nginx-decoded input).
func TestPanelSessionAPIChallengeExempt_RawTarget(t *testing.T) {
	for _, c := range []struct {
		host, uri string
		want      bool
	}{
		{"cpanel.example.gr", "/cpsess1/json-api/cpanel?cpanel_jsonapi_func=listfiles&dir=/x", true},
		{"cpanel.example.gr", "/cpsess1/execute/Fileman/list_files?dir=%2fhome", true}, // % in the query is fine
		{"cpanel.example.gr", "/cpsess1/execute/%2e%2e/x", false},
		{"cpanel.example.gr", "/cpsess1/execute/../../wp-login.php", false},
		{"cpanel.example.gr", "/cpsess1%2fexecute/x", false},
		{"cpanel.example.gr", "", false},
		{"", "/cpsess1/execute/x", false},
	} {
		if got := isPanelSessionAPIChallengeExempt(c.host, c.uri); got != c.want {
			t.Errorf("isPanelSessionAPIChallengeExempt(%q, %q) = %v, want %v", c.host, c.uri, got, c.want)
		}
	}
}

// The exemption is applied at ingest: such a record never reaches per-IP state.
func TestIngestSkipsPanelSessionAPI(t *testing.T) {
	e := &Engine{hosts: map[string]*hostState{}}
	e.ingest(LogRec{TS: 1000, IP: "203.0.113.9", Host: "cpanel.example.gr", Method: "POST",
		URI: "/cpsess1/execute/Fileman/upload_files", Status: 200}, "")
	if len(e.hosts) != 0 {
		t.Fatalf("panel session API record reached per-host state: %v", e.hosts)
	}
	// Control: the same host's UI page is scored as before.
	e.ingest(LogRec{TS: 1000, IP: "203.0.113.9", Host: "cpanel.example.gr", Method: "GET",
		URI: "/cpsess1/frontend/jupiter/filemanager/index.html", Status: 200}, "")
	if e.hosts["cpanel.example.gr"] == nil {
		t.Fatal("control: a non-API record on the same host must reach per-host state")
	}
}
