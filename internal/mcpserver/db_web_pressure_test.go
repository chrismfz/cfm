package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/dbwebcorr"
	"cfm/internal/panelmap"
)

// setPanelFixtures points panelmap at temp userdatadomains/userdomains files.
func setPanelFixtures(t *testing.T, userDataDomains, userDomains string) {
	t.Helper()
	tmp := t.TempDir()
	udd := filepath.Join(tmp, "userdatadomains")
	ud := filepath.Join(tmp, "userdomains")
	if err := os.WriteFile(udd, []byte(userDataDomains), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ud, []byte(userDomains), 0o644); err != nil {
		t.Fatal(err)
	}
	oldUDD, oldUD := panelmap.UserDataDomainsPath, panelmap.UserDomainsPath
	panelmap.UserDataDomainsPath, panelmap.UserDomainsPath = udd, ud
	t.Cleanup(func() { panelmap.UserDataDomainsPath, panelmap.UserDomainsPath = oldUDD, oldUD })
}

func accountsFrom(t *testing.T, out map[string]any) []dbwebcorr.Account {
	t.Helper()
	b, err := json.Marshal(out["accounts"])
	if err != nil {
		t.Fatal(err)
	}
	var rows []dbwebcorr.Account
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func hasNoteContaining(out map[string]any, sub string) bool {
	notes, _ := out["notes"].([]string)
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func TestBuildDBWebPressure_FlagsAndAttributes(t *testing.T) {
	setPanelFixtures(t,
		"", // userdatadomains empty
		"chris.com: chris\nbusy.com: busy\n",
	)

	// chris: real CPU, its one vhost takes ~0 traffic → flag.
	// busy: real CPU but heavy traffic → not flagged.
	// root + cpaneleximscanner + mysql.session: non-tenant → dropped.
	cpu := `{"perf_schema_ok":true,"perf_cpu_active":true,"users":[
		{"user":"chris_wp","cpu_sec":2.0,"query_count":900},
		{"user":"busy_db","cpu_sec":3.0,"query_count":4000},
		{"user":"root","cpu_sec":9.0},
		{"user":"cpaneleximscanner","cpu_sec":5.0},
		{"user":"mysql.session","cpu_sec":4.0}
	]}`
	top := `{"per_user":[
		{"User":"chris_wp","Total":3,"Active":1},
		{"User":"busy_db","Total":8,"Active":5}
	]}`
	web := `{"window_sec":60,"rows":[
		{"host":"chris.com","rps":0.01},
		{"host":"busy.com","rps":25.0}
	]}`

	out := buildDBWebPressure(json.RawMessage(cpu), json.RawMessage(top), json.RawMessage(web), 25)

	if out["window_sec"].(int) != 60 {
		t.Errorf("window_sec = %v, want 60", out["window_sec"])
	}
	att := out["web_attribution"].(map[string]any)
	if att["vhosts_seen"].(int) != 2 || att["vhosts_mapped"].(int) != 2 {
		t.Errorf("web_attribution = %v, want seen=2 mapped=2", att)
	}
	if notes, _ := out["notes"].([]string); len(notes) != 0 {
		t.Errorf("notes should be empty here, got %v", notes)
	}

	rows := accountsFrom(t, out)
	for _, r := range rows {
		switch r.Account {
		case "root", "cpaneleximscanner", "mysql.session":
			t.Fatalf("non-tenant user %q should be dropped, got %+v", r.Account, r)
		}
	}
	var chris, busy *dbwebcorr.Account
	for i := range rows {
		switch rows[i].Account {
		case "chris":
			chris = &rows[i]
		case "busy":
			busy = &rows[i]
		}
	}
	if chris == nil || busy == nil {
		t.Fatalf("expected chris and busy accounts, got %+v", rows)
	}
	if !chris.FewHitsHighPressure {
		t.Errorf("chris should be flagged few-hits/high-pressure: %+v", chris)
	}
	if busy.FewHitsHighPressure {
		t.Errorf("busy should NOT be flagged (heavy traffic): %+v", busy)
	}
	if chris.Conns != 3 || chris.Active != 1 {
		t.Errorf("chris conns/active from /top not folded in: %+v", chris)
	}
	if out["flagged"].(int) != 1 {
		t.Errorf("flagged = %v, want 1", out["flagged"])
	}
	if rows[0].Account != "chris" {
		t.Errorf("expected chris first (flagged), got %q", rows[0].Account)
	}
}

func TestBuildDBWebPressure_UnmappedNote(t *testing.T) {
	// No panel files → HostOwners empty → attribution note set.
	oldUDD, oldUD := panelmap.UserDataDomainsPath, panelmap.UserDomainsPath
	panelmap.UserDataDomainsPath = filepath.Join(t.TempDir(), "nope-udd")
	panelmap.UserDomainsPath = filepath.Join(t.TempDir(), "nope-ud")
	t.Cleanup(func() { panelmap.UserDataDomainsPath, panelmap.UserDomainsPath = oldUDD, oldUD })

	cpu := `{"perf_cpu_active":true,"users":[{"user":"acct_db","cpu_sec":1.0}]}`
	web := `{"window_sec":60,"rows":[{"host":"acct.com","rps":0.5}]}`
	out := buildDBWebPressure(json.RawMessage(cpu), nil, json.RawMessage(web), 25)

	att := out["web_attribution"].(map[string]any)
	if att["vhosts_seen"].(int) != 1 || att["vhosts_mapped"].(int) != 0 {
		t.Errorf("web_attribution = %v, want seen=1 mapped=0", att)
	}
	if !hasNoteContaining(out, "attribution empty") {
		t.Errorf("expected an attribution note, got %v", out["notes"])
	}
}

func TestBuildDBWebPressure_NoCPUSignalNote(t *testing.T) {
	setPanelFixtures(t, "", "acct.com: acct\n")
	// perf CPU off and userstat off → cpu_sec 0 everywhere → nothing flags.
	cpu := `{"perf_schema_ok":true,"perf_cpu_active":false,"userstat_ok":false,"userstat_off":true,
		"users":[{"user":"acct_db","cpu_sec":0,"busy_sec":0,"query_count":99999}]}`
	web := `{"window_sec":60,"rows":[{"host":"acct.com","rps":0.0}]}`
	out := buildDBWebPressure(json.RawMessage(cpu), nil, json.RawMessage(web), 25)

	if out["flagged"].(int) != 0 {
		t.Errorf("nothing should flag without a CPU signal, flagged=%v", out["flagged"])
	}
	if !hasNoteContaining(out, "no real CPU signal") {
		t.Errorf("expected a no-CPU-signal note, got %v", out["notes"])
	}
}

func TestBuildDBWebPressure_WindowFallback(t *testing.T) {
	cpu := `{"users":[]}`
	web := `{"rows":[]}`
	out := buildDBWebPressure(json.RawMessage(cpu), nil, json.RawMessage(web), 25)
	if out["window_sec"].(int) != 60 {
		t.Errorf("window_sec fallback = %v, want 60", out["window_sec"])
	}
}

func TestBuildDBWebPressure_BadCPUShapeNoted(t *testing.T) {
	// Valid JSON, wrong shape (users as object, not array) → decode error noted.
	cpu := `{"users":{"oops":true}}`
	web := `{"window_sec":10,"rows":[]}`
	out := buildDBWebPressure(json.RawMessage(cpu), nil, json.RawMessage(web), 25)
	if !hasNoteContaining(out, "unexpected response shape") {
		t.Errorf("expected a cpu decode note, got %v", out["notes"])
	}
}
