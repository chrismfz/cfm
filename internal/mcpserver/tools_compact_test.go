package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompactOverviewSection_FirewallSampled(t *testing.T) {
	rows := make([]any, 1065)
	for i := range rows {
		rows[i] = map[string]any{"ip": "1.2.3." + strings.Repeat("4", 1), "reason": "x"}
	}
	body, _ := json.Marshal(map[string]any{"ok": true, "total": 1065, "permanent": 1065, "rows": rows})

	got := compactOverviewSection("firewall_blocks", body).(map[string]any)
	if got["rows_total"] != 1065 {
		t.Fatalf("rows_total = %v, want 1065", got["rows_total"])
	}
	kept, _ := got["rows"].([]any)
	if len(kept) != overviewRowSample {
		t.Fatalf("kept %d rows, want %d", len(kept), overviewRowSample)
	}
	if got["rows_truncated"] != true {
		t.Fatalf("rows_truncated not set")
	}
	// counts preserved
	if got["total"] != float64(1065) && got["total"] != 1065 {
		t.Fatalf("total not preserved: %v", got["total"])
	}
	// the re-marshaled section must be small now, not the full 1065-row list.
	out, _ := json.Marshal(got)
	if len(out) > 4096 {
		t.Fatalf("compacted firewall section still large: %d bytes", len(out))
	}
}

func TestCompactOverviewSection_WAFDropsRawRows(t *testing.T) {
	rawRows := make([]any, 200)
	for i := range rawRows {
		rawRows[i] = map[string]any{"uri": "/x", "ua": strings.Repeat("a", 200)}
	}
	body, _ := json.Marshal(map[string]any{
		"total_events": 364, "blocked_events": 4, "unique_ips": 358,
		"top_rules": []any{map[string]any{"key": "R", "count": 10}},
		"top_ips":   []any{map[string]any{"key": "1.2.3.4", "count": 3}},
		"rows":      rawRows,
	})

	got := compactOverviewSection("waf_last_hour", body).(map[string]any)
	if _, present := got["rows"]; present {
		t.Fatalf("raw rows should have been dropped")
	}
	// summary fields preserved
	if got["total_events"] == nil || got["top_rules"] == nil || got["top_ips"] == nil {
		t.Fatalf("summary fields lost: %+v", got)
	}
	out, _ := json.Marshal(got)
	if len(out) > 2048 {
		t.Fatalf("compacted waf section still large: %d bytes", len(out))
	}
}

func TestCompactOverviewSection_NonObjectPassthrough(t *testing.T) {
	// an error stub (object) and a raw array must both survive without panic.
	errBody := json.RawMessage(`{"error":"section timed out"}`)
	if _, ok := compactOverviewSection("firewall_blocks", errBody).(map[string]any); !ok {
		t.Fatalf("error object should parse as a map")
	}
	arrBody := json.RawMessage(`[1,2,3]`)
	if got := compactOverviewSection("waf_last_hour", arrBody); got == nil {
		t.Fatalf("array body should pass through, got nil")
	}
}
