package mcpserver

import (
	"encoding/json"
	"testing"
)

// mailRuntimeBody builds a /api/v1/mail/runtime response body with the given
// per-resource (current, max, pct, sat) values.
func mailRuntimeBody(smtpCur, smtpMax int, smtpPct float64, smtpSat string, spCur, spMax int, spPct float64, spSat string) json.RawMessage {
	m := map[string]any{
		"ok":     true,
		"schema": "system.mail_runtime.v1",
		"snapshot": map[string]any{
			"smtp":  map[string]any{"util": map[string]any{"current": smtpCur, "max": smtpMax, "pct": smtpPct, "known": smtpMax > 0}, "sat": smtpSat},
			"spamd": map[string]any{"util": map[string]any{"current": spCur, "max": spMax, "pct": spPct, "known": spMax > 0}, "sat": spSat},
		},
	}
	b, _ := json.Marshal(m)
	return b
}

func TestEvalMailRuntimeWarnAndCritical(t *testing.T) {
	// The regression shape: SMTP 132/150 (88% → warn), spamd 10/10 (100% → crit).
	body := mailRuntimeBody(132, 150, 88, "warn", 10, 10, 100, "critical")
	fs := evalMailRuntime(body)
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(fs), fs)
	}
	var sawSMTPWarn, sawSpamdCrit bool
	for _, f := range fs {
		if f.Category != "mail" || f.Tool != "mail_runtime" {
			t.Errorf("finding not keyed to mail/mail_runtime: %+v", f)
		}
		switch {
		case f.Severity == sevWarning && f.Title == "SMTP connection pool saturation":
			sawSMTPWarn = true
		case f.Severity == sevCritical && f.Title == "spamd scanner pool saturation":
			sawSpamdCrit = true
		}
	}
	if !sawSMTPWarn {
		t.Errorf("missing SMTP warning finding: %+v", fs)
	}
	if !sawSpamdCrit {
		t.Errorf("missing spamd critical finding: %+v", fs)
	}
}

func TestEvalMailRuntimeOKAndUnknownEmitNothing(t *testing.T) {
	// SMTP ok, spamd unknown (cap unresolved) → NO finding either way; unknown is
	// not a problem and must not be surfaced as one.
	body := mailRuntimeBody(10, 150, 7, "ok", 3, 0, 0, "unknown")
	if fs := evalMailRuntime(body); len(fs) != 0 {
		t.Fatalf("ok/unknown must emit no findings, got %+v", fs)
	}
}

func TestEvalMailRuntimeMalformedBodyIsSafe(t *testing.T) {
	if fs := evalMailRuntime(json.RawMessage(`not json`)); fs != nil {
		t.Fatalf("malformed body must yield nil, got %+v", fs)
	}
}

func TestWhatsWrongLoneWarnFlipsToIssues(t *testing.T) {
	// A lone WARN (no critical) must still flip status to "issues" — covers the
	// counts[sevWarning] branch, not just the critical path.
	sections := map[string]json.RawMessage{
		"mail_runtime": mailRuntimeBody(132, 150, 88, "warn", 2, 10, 20, "ok"),
	}
	res := evaluateWhatsWrong(sections)
	if res.Status != "issues" || res.Counts[sevWarning] != 1 || res.Counts[sevCritical] != 0 {
		t.Fatalf("lone warn: status=%q counts=%v, want issues / 1 warning / 0 critical", res.Status, res.Counts)
	}
}

func TestWhatsWrongIncludesMailRuntimeCritical(t *testing.T) {
	// End-to-end through the pure evaluator: a critical spamd pool becomes a
	// critical finding and flips status to "issues".
	sections := map[string]json.RawMessage{
		"mail_runtime": mailRuntimeBody(10, 150, 7, "ok", 10, 10, 100, "critical"),
	}
	res := evaluateWhatsWrong(sections)
	if res.Sources["mail_runtime"] != "ok" {
		t.Errorf("mail_runtime source = %q, want ok", res.Sources["mail_runtime"])
	}
	if res.Status != "issues" || res.Counts[sevCritical] != 1 {
		t.Fatalf("expected 1 critical / status issues, got status=%q counts=%v", res.Status, res.Counts)
	}
	if res.Findings[0].Category != "mail" || res.Findings[0].Tool != "mail_runtime" {
		t.Errorf("top finding not the mail_runtime one: %+v", res.Findings[0])
	}
}
