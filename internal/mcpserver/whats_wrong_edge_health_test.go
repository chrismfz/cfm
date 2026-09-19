package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"
)

// edgeHealthBody builds a /api/v1/system/edge-health response carrying the
// given (check, severity, summary, next) findings.
func edgeHealthBody(findings ...[4]string) string {
	fs := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		m := map[string]any{"check": f[0], "severity": f[1], "summary": f[2]}
		if f[3] != "" {
			m["next"] = f[3]
		}
		fs = append(fs, m)
	}
	b, _ := json.Marshal(map[string]any{
		"ok": true, "schema": "system.edge_health.v1", "engine": "angie",
		"overall": "warn", "findings": fs,
	})
	return string(b)
}

// healthBodyEdge is a minimal health snapshot that resolves the active edge
// engine, which is what gates the edge_health section.
func healthBodyEdge(engine string) string {
	b, _ := json.Marshal(map[string]any{
		"runtime": map[string]any{
			"edge_service":     engine,
			"frontend_working": "working",
			"edge_status":      "active",
		},
	})
	return string(b)
}

// The incident this whole section exists for: the edge is up, every daemon is
// "active", but the ORIGIN is dropping requests. It must reach whats_wrong as a
// ranked edge finding and flip the overall status to "issues".
func TestWhatsWrong_OriginDropSurfaces(t *testing.T) {
	got := evaluateWhatsWrong(sec(
		"health", healthBodyEdge("angie"),
		"edge_health", edgeHealthBody(
			[4]string{"origin-premature-close", "warn",
				"35 of 50000 requests (0.070%) got a gateway 5xx with NO response header from the origin, across 7 vhosts — an origin-wide fault",
				"edge_error_tail grep=\"upstream prematurely closed\""},
			[4]string{"origin-421-fingerprint", "ok", "no status=421", ""},
			[4]string{"engine-version-trap", "ok", "angie: not default-on", ""},
		),
	))

	if got.Status != "issues" {
		t.Fatalf("status = %q, want issues", got.Status)
	}
	f := findBy(got.Findings, "edge", sevWarning)
	if f == nil {
		t.Fatalf("no edge warning finding: %+v", got.Findings)
	}
	if f.Title != "origin dropping connections" {
		t.Errorf("title = %q, want %q", f.Title, "origin dropping connections")
	}
	if f.Tool != "edge_health" {
		t.Errorf("tool = %q, want edge_health", f.Tool)
	}
	// The drill-down path must survive into the detail — it is what turns the
	// finding into a starting point instead of a dead end.
	if !strings.Contains(f.Detail, "upstream prematurely closed") {
		t.Errorf("detail lost the next-step: %q", f.Detail)
	}
	// Only the warn check becomes a finding; the two `ok` ones must not.
	if n := countCat(got.Findings, "edge"); n != 1 {
		t.Errorf("edge findings = %d, want 1 (ok checks must not surface): %+v", n, got.Findings)
	}
	if got.Sources["edge_health"] != "ok" {
		t.Errorf("sources[edge_health] = %q, want ok", got.Sources["edge_health"])
	}
}

// `ok` and `unknown` must emit nothing. `unknown` in particular fires on any
// node whose engine version is unreadable — surfacing it would cry wolf fleet-wide.
func TestWhatsWrong_EdgeHealthOKAndUnknownAreSilent(t *testing.T) {
	got := evaluateWhatsWrong(sec(
		"health", healthBodyEdge("openresty"),
		"edge_health", edgeHealthBody(
			[4]string{"origin-premature-close", "ok", "no gateway 5xx without a response header", ""},
			[4]string{"engine-version-trap", "unknown", "version unreadable", "check the edge binary"},
			[4]string{"origin-ka-tier", "unknown", "could not read the edge error log", ""},
		),
	))
	if n := countCat(got.Findings, "edge"); n != 0 {
		t.Fatalf("ok/unknown must emit no findings, got %d: %+v", n, got.Findings)
	}
	if got.Status != "ok" {
		t.Errorf("status = %q, want ok", got.Status)
	}
}

// The gate: a node with no resolvable edge engine must not be judged on a stale
// access log left behind by a removed engine, even if the report reads critical.
func TestWhatsWrong_EdgeHealthGatedOnKnownEngine(t *testing.T) {
	crit := edgeHealthBody([4]string{"origin-premature-close", "critical", "origin is dropping everything", ""})

	for _, engine := range []string{"", "unknown", "caddy"} {
		got := evaluateWhatsWrong(sec(
			"health", healthBodyEdge(engine),
			"edge_health", crit,
		))
		if n := countCat(got.Findings, "edge"); n != 0 {
			t.Errorf("edge_service=%q: expected no edge findings, got %d: %+v", engine, n, got.Findings)
		}
		// ...and the skip must be VISIBLE. Reading "ok" here would silently
		// swallow a live origin-drop critical — including when the gate fired
		// only because the health section itself failed.
		if s := got.Sources["edge_health"]; !strings.HasPrefix(s, "degraded:") {
			t.Errorf("edge_service=%q: sources[edge_health] = %q, want a degraded: marker", engine, s)
		}
	}

	// The health section failing outright takes the same path, and must also
	// leave a trace rather than a reassuring "ok".
	missing := evaluateWhatsWrong(sec("edge_health", crit))
	if n := countCat(missing.Findings, "edge"); n != 0 {
		t.Errorf("no health section: expected no edge findings, got %+v", missing.Findings)
	}
	if s := missing.Sources["edge_health"]; !strings.HasPrefix(s, "degraded:") {
		t.Errorf("no health section: sources[edge_health] = %q, want a degraded: marker", s)
	}

	// ...but a known engine lets the same body through.
	got := evaluateWhatsWrong(sec("health", healthBodyEdge("angie"), "edge_health", crit))
	if findBy(got.Findings, "edge", sevCritical) == nil {
		t.Errorf("known engine should surface the critical: %+v", got.Findings)
	}
}

// A check the title map does not know must still reach triage under its own
// name, never be silently dropped (the map is presentation only).
func TestEvalEdgeHealth_UnmappedCheckFallsBack(t *testing.T) {
	fs := evalEdgeHealth(json.RawMessage(edgeHealthBody(
		[4]string{"origin-tier2-future-check", "critical", "something new broke", ""},
	)))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(fs), fs)
	}
	if fs[0].Title != "origin-tier2-future-check" {
		t.Errorf("title = %q, want the raw check name", fs[0].Title)
	}
}

func TestEvalEdgeHealth_MalformedBodyIsSafe(t *testing.T) {
	if fs := evalEdgeHealth(json.RawMessage(`not json`)); fs != nil {
		t.Fatalf("malformed body must yield no findings, got %+v", fs)
	}
}

// A failed edge_health read is recorded in `sources`, never silently treated as
// healthy — the same contract every other whats_wrong section honours.
func TestWhatsWrong_EdgeHealthSectionErrorIsVisible(t *testing.T) {
	got := evaluateWhatsWrong(sec(
		"health", healthBodyEdge("angie"),
		"edge_health", `{"error":"no edge access log found"}`,
	))
	if s := got.Sources["edge_health"]; !strings.HasPrefix(s, "error:") {
		t.Errorf("sources[edge_health] = %q, want an error: prefix", s)
	}
	if n := countCat(got.Findings, "edge"); n != 0 {
		t.Errorf("an errored section must not invent findings, got %+v", got.Findings)
	}
}
