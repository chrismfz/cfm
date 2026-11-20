package edgecli

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cfm/internal/clihttp"
	"cfm/internal/dnat"
)

const okReport = `{"ok":true,"schema":"system.edge_health.v1","engine":"cfm-edge","version":"1.31.9","overall":"ok",
 "findings":[{"check":"engine-version-trap","severity":"ok","summary":"no trap","next":"ignored for ok"},
             {"check":"origin-real-ip","severity":"ok","summary":"trusted"}]}`

const warnReport = `{"ok":true,"engine":"angie","version":"1.11.4","overall":"warn",
 "findings":[{"check":"origin-premature-close","severity":"warn","summary":"12 drops","next":"look at the origin"},
             {"check":"origin-real-ip","severity":"ok","summary":"trusted"}]}`

func checkDeps(body string, err error, gotWindow *int) (deps, *bytes.Buffer, *bytes.Buffer) {
	d, out, errOut := testDeps(&recorder{}, dnat.Summary{}, nil, nil)
	d.check = func(w int) ([]byte, error) {
		if gotWindow != nil {
			*gotWindow = w
		}
		return []byte(body), err
	}
	return d, out, errOut
}

func TestCheckPrintsEveryFinding(t *testing.T) {
	d, out, _ := checkDeps(okReport, nil, nil)
	if rc := run([]string{"check"}, d); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	for _, want := range []string{"Edge health: OK   (cfm-edge 1.31.9)", "ok       engine-version-trap  no trap", "origin-real-ip       trusted"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "next:") {
		t.Errorf("an ok finding printed its next step:\n%s", out.String())
	}
}

func TestCheckWarnExitsOneWithTheNextStep(t *testing.T) {
	d, out, _ := checkDeps(warnReport, nil, nil)
	if rc := run([]string{"check"}, d); rc != 1 {
		t.Fatalf("rc=%d", rc)
	}
	for _, want := range []string{"Edge health: WARN", "WARN     origin-premature-close  12 drops", "next: look at the origin"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

// An unknown must never read as OK.
func TestCheckUnknownsExitOne(t *testing.T) {
	for name, c := range map[string]struct {
		body string
		err  error
		want string
	}{
		"daemon down":      {"", errors.New("cannot reach the daemon API"), "cannot reach the daemon API"},
		"not ok":           {`{"ok":false,"error":"engine probe failed"}`, nil, "Edge health: UNKNOWN (engine probe failed)"},
		"overall unknown":  {`{"ok":true,"overall":"unknown","findings":[]}`, nil, "Edge health: UNKNOWN"},
		"overall missing":  {`{"ok":true,"findings":[]}`, nil, "Edge health: UNKNOWN"},
		"not json":         {"<html>", nil, "unreadable report"},
		"critical finding": {`{"ok":true,"overall":"critical","findings":[{"check":"x","severity":"critical","summary":"s"}]}`, nil, "CRITICAL"},
	} {
		d, out, errOut := checkDeps(c.body, c.err, nil)
		if rc := run([]string{"check"}, d); rc != 1 {
			t.Errorf("%s: rc=%d", name, rc)
		}
		if !strings.Contains(out.String()+errOut.String(), c.want) {
			t.Errorf("%s: missing %q in %q / %q", name, c.want, out.String(), errOut.String())
		}
	}
}

func TestCheckFlags(t *testing.T) {
	var w int
	d, out, _ := checkDeps(warnReport, nil, &w)
	if rc := run([]string{"check", "--json", "--window", "5000"}, d); rc != 1 || w != 5000 {
		t.Fatalf("rc=%d window=%d", rc, w)
	}
	if strings.TrimSpace(out.String()) != strings.TrimSpace(warnReport) {
		t.Fatalf("--json must print the report as it came:\n%s", out.String())
	}
	d, _, _ = checkDeps(okReport, nil, &w)
	if rc := run([]string{"check", "--window=700"}, d); rc != 0 || w != 700 {
		t.Fatalf("--window=: rc=%d window=%d", rc, w)
	}
	for _, args := range [][]string{{"check", "--window", "x"}, {"check", "--window", "0"}, {"check", "--window"}, {"check", "--window=-3"}, {"check", "extra"}} {
		called := false
		d, _, _ := checkDeps(okReport, nil, nil)
		d.check = func(int) ([]byte, error) { called = true; return nil, nil }
		if rc := run(args, d); rc != 2 || called {
			t.Errorf("%v: rc=%d called=%v", args, rc, called)
		}
	}
}

func TestFetchEdgeHealth(t *testing.T) {
	var gotAuth, gotQuery, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotQuery, gotPath = r.Header.Get("Authorization"), r.URL.RawQuery, r.URL.Path
		switch r.URL.Query().Get("window") {
		case "14":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("<html>" + strings.Repeat("x", 4096) + "</html>"))
			return
		case "15":
			_, _ = w.Write(bytes.Repeat([]byte(" "), maxReport+10))
			return
		}
		if r.URL.Query().Get("window") == "13" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"ok":false,"error":"admin only"}`))
			return
		}
		_, _ = w.Write([]byte(okReport))
	}))
	defer srv.Close()
	oldBase, oldTok := apiBase, clihttp.Token()
	t.Cleanup(func() { apiBase = oldBase; clihttp.SetToken(oldTok) })
	base := srv.URL + "/"
	apiBase = func() string { return base }
	clihttp.SetToken("tok")

	body, err := fetchEdgeHealth(2000)
	if err != nil || !strings.Contains(string(body), `"overall":"ok"`) {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if gotPath != "/api/v1/system/edge-health" || gotQuery != "window=2000" || gotAuth != "Bearer tok" {
		t.Fatalf("path=%q query=%q auth=%q", gotPath, gotQuery, gotAuth)
	}
	if _, err := fetchEdgeHealth(0); err != nil || gotQuery != "" {
		t.Fatalf("no window: query=%q err=%v", gotQuery, err)
	}
	// The daemon's own error body is surfaced, not collapsed to a status.
	if _, err := fetchEdgeHealth(13); err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "admin only") {
		t.Fatalf("err=%v", err)
	}
	// A big error page is clipped; a report over the limit is an error.
	if _, err := fetchEdgeHealth(14); err == nil || len(err.Error()) > 700 || !strings.Contains(err.Error(), "502") {
		t.Fatalf("clip: len=%d err=%.80v", len(err.Error()), err)
	}
	if _, err := fetchEdgeHealth(15); err == nil || !strings.Contains(err.Error(), "larger than 8 MB") {
		t.Fatalf("limit: err=%v", err)
	}
	// Nothing listening: the daemon is down.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	base = deadURL
	if _, err := fetchEdgeHealth(0); err == nil || !strings.Contains(err.Error(), "is cfm running") {
		t.Fatalf("down: err=%v", err)
	}
	base = ""
	if _, err := fetchEdgeHealth(0); err == nil {
		t.Fatal("no API base must be an error")
	}
	// A daemon that does not answer in time is an error, not a hang.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	base = slow.URL
	oldTimeout := checkTimeout
	checkTimeout = 50 * time.Millisecond
	t.Cleanup(func() { checkTimeout = oldTimeout })
	if _, err := fetchEdgeHealth(0); err == nil || !strings.Contains(err.Error(), "did not answer within") || strings.Contains(err.Error(), "is cfm running") {
		t.Fatalf("a timeout must not read as the daemon down: err=%v", err)
	}
}
