package mcpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestWhatsWrongProcessHealthIssuesMapWithoutReclassification(t *testing.T) {
	sources := map[string]string{"process_health": "ok"}
	got := evalProcessHealth(json.RawMessage(`{
		"evaluation":{
			"status":"issues","reliable":true,
			"findings":[
				{"code":"process_d_state_pileup","severity":"critical","state":"D","count":40,"percent":12.5,"top_families":[{"comm":"kworker/u32:7","count":30}],"detail":"40/320 readable processes (12.5%) are processes in uninterruptible D-state"},
				{"code":"process_zombie_accumulation","severity":"warning","state":"Z","count":20,"percent":6.25,"top_families":[{"comm":"php-fpm","count":12}],"detail":"20/320 readable processes (6.3%) are zombie processes"}
			]
		}
	}`), sources)

	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(got), got)
	}
	if got[0].Severity != sevCritical || got[0].Category != "process" || got[0].Title != "D-state process pileup" {
		t.Fatalf("unexpected D-state mapping: %+v", got[0])
	}
	if got[0].Tool != "process_list" || got[0].Args["match"] != "kworker/u32:7" || got[0].Args["details"] != true {
		t.Fatalf("D-state drilldown = tool:%q args:%v", got[0].Tool, got[0].Args)
	}
	if got[1].Severity != sevWarning || got[1].Title != "zombie processes accumulating" {
		t.Fatalf("unexpected zombie mapping: %+v", got[1])
	}
	if sources["process_health"] != "ok" {
		t.Fatalf("healthy transport/reliable evaluation should keep source ok, got %q", sources["process_health"])
	}
}

func TestWhatsWrongProcessHealthDegradedIsAWarningNotHealthy(t *testing.T) {
	got := evaluateWhatsWrong(sec("process_health", `{
		"ok":true,
		"evaluation":{"status":"degraded","reliable":false,"reason":"process snapshot is materially partial: 18/100 PIDs skipped (18.0%)","findings":[]}
	}`))

	if got.Status != "issues" {
		t.Fatalf("status = %q, want issues; result=%+v", got.Status, got)
	}
	if got.Sources["process_health"] != "degraded: process snapshot is materially partial: 18/100 PIDs skipped (18.0%)" {
		t.Fatalf("process_health source = %q", got.Sources["process_health"])
	}
	if len(got.Findings) != 1 || got.Findings[0].Severity != sevWarning || got.Findings[0].Tool != "process_health" {
		t.Fatalf("degraded process health should emit one warning pointing at process_health: %+v", got.Findings)
	}
}

func TestWhatsWrongProcessHealthOKStaysQuiet(t *testing.T) {
	got := evaluateWhatsWrong(sec("process_health", `{
		"ok":true,
		"evaluation":{"status":"ok","reliable":true,"findings":[]}
	}`))
	if got.Status != "ok" || len(got.Findings) != 0 {
		t.Fatalf("clean process health should stay quiet: %+v", got)
	}
	if got.Sources["process_health"] != "ok" {
		t.Fatalf("process_health source = %q, want ok", got.Sources["process_health"])
	}
}

func TestWhatsWrongProcessHealthMalformedEvaluationFailsVisible(t *testing.T) {
	for name, body := range map[string]string{
		"missing evaluation": `{"ok":true}`,
		"ok with findings": `{"evaluation":{"status":"ok","reliable":true,"findings":[{"severity":"warning"}]}}`,
		"unknown status": `{"evaluation":{"status":"mystery","reliable":true,"findings":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := evaluateWhatsWrong(sec("process_health", body))
			if got.Status != "issues" || len(got.Findings) != 1 || got.Findings[0].Severity != sevWarning {
				t.Fatalf("bad process-health evaluation must fail visible: %+v", got)
			}
			if !strings.HasPrefix(got.Sources["process_health"], "degraded: ") {
				t.Fatalf("source = %q, want degraded", got.Sources["process_health"])
			}
		})
	}
}

func TestWhatsWrongFetchesProcessHealthSection(t *testing.T) {
	fd := &fakeDispatch{bodyByPath: map[string][]byte{
		"/api/v1/system/process-health": []byte(`{"ok":true,"evaluation":{"status":"ok","reliable":true,"findings":[]}}`),
	}}
	ts := newTestServer(t, fd)
	res, body := mcpPost(t, ts, testAdminToken,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whats_wrong","arguments":{}}}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("whats_wrong status = %d, body=%s", res.StatusCode, body)
	}
	if !fd.sawPath("/api/v1/system/process-health") {
		t.Fatalf("whats_wrong did not dispatch /api/v1/system/process-health; seen=%v", fd.seen)
	}
}
