package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRulesTransferFlags(t *testing.T) {
	vh, out, err := parseRulesExportFlags([]string{"--vhost", "gokids.gr", "--vhost=www.gokids.gr", "--out", "x.json"})
	if err != nil || strings.Join(vh, ",") != "gokids.gr,www.gokids.gr" || out != "x.json" {
		t.Fatalf("export flags = %v %q %v", vh, out, err)
	}
	for _, bad := range [][]string{{"--vhost"}, {"--out"}, {"gokids.gr"}} {
		if _, _, err := parseRulesExportFlags(bad); err == nil {
			t.Errorf("export %v: want an error", bad)
		}
	}
	f, err := parseRulesImportFlags([]string{"--file=r.json", "--dry-run", "--disabled"})
	if err != nil || f.File != "r.json" || !f.DryRun || !f.Disabled {
		t.Fatalf("import flags = %+v %v", f, err)
	}
	for _, bad := range [][]string{{}, {"--dry-run"}, {"--file", "r.json", "--force"}} {
		if _, err := parseRulesImportFlags(bad); err == nil {
			t.Errorf("import %v: want an error", bad)
		}
	}
}

func adminServer(t *testing.T, mux *http.ServeMux) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(adminCtx()))
	}))
	t.Cleanup(ts.Close)
	return ts
}

// The CLI moves a site's rules: export on one node, dry run and import on
// another, and a second import adds nothing.
func TestRulesTransferCLI(t *testing.T) {
	src, srcMux := newTestEngine(t)
	gokidsLikeRules(t, src)
	dst, dstMux := newTestEngine(t)
	srcTS, dstTS := adminServer(t, srcMux), adminServer(t, dstMux)

	file := filepath.Join(t.TempDir(), "rules.json")
	if err := runRulesWebTop(srcTS.URL, []string{"export", "--vhost", "gokids.gr", "--out", file}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var doc TrafficRulesExportDoc
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Rules) != 3 {
		t.Fatalf("export file: %d rules, %v", len(doc.Rules), err)
	}
	if err := runRulesWebTop(dstTS.URL, []string{"import", "--file", file, "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	if n := len(dst.TrafficRuleList()); n != 0 {
		t.Fatalf("a dry run wrote %d rule(s)", n)
	}
	if err := runRulesWebTop(dstTS.URL, []string{"import", "--file", file, "--disabled"}); err != nil {
		t.Fatal(err)
	}
	got := dst.TrafficRuleList()
	if len(got) != 3 {
		t.Fatalf("imported %d rule(s), want 3", len(got))
	}
	for _, r := range got {
		if r.Enabled {
			t.Errorf("--disabled imported %s enabled", r.ID)
		}
	}
	if err := runRulesWebTop(dstTS.URL, []string{"import", "--file", file}); err != nil {
		t.Fatal(err)
	}
	if n := len(dst.TrafficRuleList()); n != 3 {
		t.Fatalf("a re-import changed the count to %d", n)
	}

	// An invalid rule fails the command with the server's reason.
	doc.Rules[0].Action.Type = "nuke"
	bad, _ := json.Marshal(doc)
	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	err = runRulesWebTop(dstTS.URL, []string{"import", "--file", badFile})
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("bad import err = %v", err)
	}
}
