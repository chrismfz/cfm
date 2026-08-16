package procstat

import (
	"strings"
	"testing"
)

func evalSnapshot(total int, states map[string]int) HealthSummary {
	return HealthSummary{
		TotalProcesses: total,
		States:         states,
		Scan: ScanSummary{
			PIDsEnumerated: total,
			PIDsReadable:   total,
		},
		TopFamiliesByState: map[string][]StateFamilySummary{},
	}
}

func TestEvaluateHealthBelowThresholdsIsOK(t *testing.T) {
	h := evalSnapshot(400, map[string]int{"S": 379, "D": 7, "Z": 14})
	got := EvaluateHealth(h)
	if got.Status != "ok" || !got.Reliable || len(got.Findings) != 0 || got.Reason != "" {
		t.Fatalf("EvaluateHealth = %+v, want reliable ok with no findings", got)
	}
}

func TestEvaluateHealthClassifiesStateAccumulationAndAttributesFamilies(t *testing.T) {
	h := evalSnapshot(400, map[string]int{"S": 340, "D": 40, "Z": 20})
	h.TopFamiliesByState = map[string][]StateFamilySummary{
		"D": {
			{Comm: "lsphp", Count: 31},
			{Comm: "mysqld", Count: 6},
			{Comm: "backup", Count: 2},
			{Comm: "other", Count: 1},
		},
		"Z": {
			{Comm: "httpd", Count: 12},
			{Comm: "worker", Count: 8},
		},
	}

	got := EvaluateHealth(h)
	if got.Status != "issues" || !got.Reliable || len(got.Findings) != 2 {
		t.Fatalf("EvaluateHealth = %+v, want two reliable findings", got)
	}
	if f := got.Findings[0]; f.Code != "process_d_state_pileup" || f.Severity != "critical" || f.State != "D" || f.Count != 40 || f.Percent != 10.0 {
		t.Fatalf("first finding = %+v, want critical D-state pileup", f)
	}
	if len(got.Findings[0].TopFamilies) != processHealthFindingFamilyLimit || got.Findings[0].TopFamilies[0].Comm != "lsphp" {
		t.Fatalf("D attribution = %+v, want bounded lsphp-first families", got.Findings[0].TopFamilies)
	}
	if !strings.Contains(got.Findings[0].Detail, `top family "lsphp" contributes 31`) {
		t.Fatalf("D detail = %q, want top-family attribution", got.Findings[0].Detail)
	}
	if f := got.Findings[1]; f.Code != "process_zombie_accumulation" || f.Severity != "warning" || f.State != "Z" || f.Count != 20 || f.Percent != 5.0 {
		t.Fatalf("second finding = %+v, want warning zombie accumulation", f)
	}
}

func TestEvaluateHealthThresholdsRequireCountAndRatio(t *testing.T) {
	tests := []struct {
		name      string
		total     int
		state     string
		count     int
		wantIssue bool
		wantSev   string
	}{
		{name: "D count without ratio", total: 1000, state: "D", count: 8},
		{name: "D warning boundary", total: 400, state: "D", count: 8, wantIssue: true, wantSev: "warning"},
		{name: "D critical boundary", total: 320, state: "D", count: 32, wantIssue: true, wantSev: "critical"},
		{name: "Z count without ratio", total: 2000, state: "Z", count: 16},
		{name: "Z warning boundary", total: 1600, state: "Z", count: 16, wantIssue: true, wantSev: "warning"},
		{name: "Z critical boundary", total: 1280, state: "Z", count: 64, wantIssue: true, wantSev: "critical"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			states := map[string]int{"S": tt.total - tt.count, tt.state: tt.count}
			got := EvaluateHealth(evalSnapshot(tt.total, states))
			if !tt.wantIssue {
				if got.Status != "ok" || len(got.Findings) != 0 {
					t.Fatalf("EvaluateHealth = %+v, want no issue", got)
				}
				return
			}
			if got.Status != "issues" || len(got.Findings) != 1 || got.Findings[0].Severity != tt.wantSev {
				t.Fatalf("EvaluateHealth = %+v, want one %s issue", got, tt.wantSev)
			}
		})
	}
}

func TestEvaluateHealthRefusesMateriallyPartialSnapshot(t *testing.T) {
	h := HealthSummary{
		TotalProcesses: 85,
		States:         map[string]int{"D": 40, "Z": 20, "S": 25},
		Scan: ScanSummary{
			PIDsEnumerated: 100,
			PIDsReadable:   85,
			PIDsSkipped:    15,
		},
	}
	got := EvaluateHealth(h)
	if got.Status != "degraded" || got.Reliable || len(got.Findings) != 0 {
		t.Fatalf("EvaluateHealth = %+v, want degraded/no findings", got)
	}
	if !strings.Contains(got.Reason, "15/100 PIDs skipped") {
		t.Fatalf("reason = %q, want explicit skipped accounting", got.Reason)
	}
}

func TestEvaluateHealthRefusesInconsistentAccounting(t *testing.T) {
	h := evalSnapshot(100, map[string]int{"S": 99})
	got := EvaluateHealth(h)
	if got.Status != "degraded" || got.Reliable || len(got.Findings) != 0 {
		t.Fatalf("EvaluateHealth = %+v, want degraded/no findings", got)
	}
	if !strings.Contains(got.Reason, "state accounting") {
		t.Fatalf("reason = %q, want state-accounting error", got.Reason)
	}
}
