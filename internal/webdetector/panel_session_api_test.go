package webdetector

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
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
		{"cpanel.example.gr:443", "/cpsess1/execute/x", false}, // a port fails the host gate (fail closed)
	} {
		if got := isPanelSessionAPIChallengeExempt(c.host, c.uri); got != c.want {
			t.Errorf("isPanelSessionAPIChallengeExempt(%q, %q) = %v, want %v", c.host, c.uri, got, c.want)
		}
	}
}

// The exemption is applied at ingest, AFTER the access ring (triage still sees
// the request), and only when the node config says the edge passes it too.
func TestIngestSkipsPanelSessionAPI(t *testing.T) {
	dir := t.TempDir()
	old := cpanelConfigPath
	cpanelConfigPath = filepath.Join(dir, "cpanel.config")
	t.Cleanup(func() { cpanelConfigPath = old; resetPanelProxyReachForTest() })

	api := LogRec{TS: 1000, IP: "203.0.113.9", Host: "cpanel.example.gr", Method: "post",
		URI: "/cpsess1/execute/fileman/upload_files", Status: 200}

	// Gate off (no cPanel config): scored as before. A spoofed Host on a
	// non-cPanel node must not hide from the engine.
	resetPanelProxyReachForTest()
	e := &Engine{hosts: map[string]*hostState{}}
	e.ingest(api, "")
	if e.hosts["cpanel.example.gr"] == nil {
		t.Fatal("gate off: the request must reach per-host state")
	}

	// Gate on: skipped for scoring.
	if err := os.WriteFile(cpanelConfigPath, []byte("proxysubdomains=1\nproxysubdomainsoverride=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetPanelProxyReachForTest()
	e = &Engine{hosts: map[string]*hostState{}}
	e.ingest(api, "")
	if len(e.hosts) != 0 {
		t.Fatalf("gate on: panel session API record reached per-host state: %v", e.hosts)
	}
	// Control: the same host's UI page is scored as before.
	e.ingest(LogRec{TS: 1000, IP: "203.0.113.9", Host: "cpanel.example.gr", Method: "get",
		URI: "/cpsess1/frontend/jupiter/filemanager/index.html", Status: 200}, "")
	if e.hosts["cpanel.example.gr"] == nil {
		t.Fatal("control: a non-API record on the same host must reach per-host state")
	}
}

func TestPanelProxyHostsReachPanel(t *testing.T) {
	dir := t.TempDir()
	old := cpanelConfigPath
	cpanelConfigPath = filepath.Join(dir, "cpanel.config")
	t.Cleanup(func() { cpanelConfigPath = old; resetPanelProxyReachForTest() })
	for _, c := range []struct {
		cfg  string // "" = no file
		want bool
	}{
		{"a=1\nproxysubdomains=1\nproxysubdomainsoverride=0\n", true},
		{"proxysubdomainsoverride=0\r\nproxysubdomains=1\r\n", true},
		{"proxysubdomains=1\nproxysubdomainsoverride=1\n", false},
		{"proxysubdomains=1\n", false}, // absent override = cPanel default 1
		{"proxysubdomains=0\nproxysubdomainsoverride=0\n", false},
		{"", false},
	} {
		os.Remove(cpanelConfigPath)
		if c.cfg != "" {
			if err := os.WriteFile(cpanelConfigPath, []byte(c.cfg), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		resetPanelProxyReachForTest()
		if got := panelProxyHostsReachPanel(time.Unix(1000, 0)); got != c.want {
			t.Errorf("cfg %q: got %v, want %v", c.cfg, got, c.want)
		}
	}
	// Cached for the TTL, then re-read.
	os.WriteFile(cpanelConfigPath, []byte("proxysubdomains=1\nproxysubdomainsoverride=0\n"), 0o600)
	resetPanelProxyReachForTest()
	t0 := time.Unix(1000, 0)
	panelProxyHostsReachPanel(t0)
	os.WriteFile(cpanelConfigPath, []byte("proxysubdomains=1\nproxysubdomainsoverride=1\n"), 0o600)
	if !panelProxyHostsReachPanel(t0.Add(panelProxyReachTTL - time.Second)) {
		t.Error("cached within TTL")
	}
	if panelProxyHostsReachPanel(t0.Add(panelProxyReachTTL)) {
		t.Error("re-read after TTL")
	}
}

// The Go lists must equal the Lua ones (CLAUDE.md §5: no copy that can drift).
func TestPanelSessionAPI_ListsMatchLua(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "configs", "lua", "cfm_panel_hosts.lua"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		lua string
		goM map[string]bool
	}{
		{`_M.PROXY_PREFIXES = {`, panelProxyPrefixes},
		{`local SESSION_KINDS = {`, panelSessionKinds},
		{`_M.SECOND_LEVEL_LABELS = {`, panelSecondLevel},
	} {
		i := strings.Index(string(src), c.lua)
		if i < 0 {
			t.Fatalf("%s not found in cfm_panel_hosts.lua", c.lua)
		}
		body := string(src[i+len(c.lua):])
		body = body[:strings.IndexByte(body, '}')]
		var luaList, goList []string
		for _, m := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(body, -1) {
			luaList = append(luaList, m[1])
		}
		for k := range c.goM {
			goList = append(goList, k)
		}
		sort.Strings(luaList)
		sort.Strings(goList)
		if strings.Join(luaList, ",") != strings.Join(goList, ",") {
			t.Errorf("%s: lua %v != go %v", c.lua, luaList, goList)
		}
	}
}
