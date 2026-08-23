package mcpserver

import (
	"encoding/json"
	"testing"
)

func TestEvalNetfilterPathIgnoresOrderedOverlap(t *testing.T) {
	sources := map[string]string{"netfilter_path": "ok"}
	got := evalNetfilterPath(json.RawMessage(`{"status":"ok","findings":[{"level":"info","code":"ordered_nat_overlap","message":"imunify -100 then cfm -99"}]}`), sources)
	if len(got) != 0 {
		t.Fatalf("ordered overlap must remain visibility-only: %+v", got)
	}
}

func TestEvalNetfilterPathSurfacesAmbiguity(t *testing.T) {
	sources := map[string]string{"netfilter_path": "ok"}
	got := evalNetfilterPath(json.RawMessage(`{"status":"warning","findings":[{"level":"warning","code":"same_priority_ambiguity","message":"both at -100","hook":"input"}]}`), sources)
	if len(got) != 1 || got[0].Tool != "netfilter_path" || got[0].Category != "firewall" {
		t.Fatalf("finding=%+v", got)
	}
	if got[0].Args["hook"] != "input" {
		t.Fatalf("drill-down args=%v", got[0].Args)
	}
}
