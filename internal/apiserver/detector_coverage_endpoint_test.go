package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cfm/internal/detectors/meta"
	"cfm/internal/detectorstatus"
	"cfm/internal/svcstat"
)

func TestDetectorCoverageEndpointAuthzAndMethod(t *testing.T) {
	// The production catalogue fills via init() side effects in
	// internal/detectors (which cannot be imported here — it would close an
	// import cycle through apiserver). Register a minimal fixture instead.
	meta.Register(meta.DetectorMeta{TypeKey: "zz_cov_test_a", Title: "Fixture A"})
	meta.Register(meta.DetectorMeta{TypeKey: "waf_security", Title: "WAF autoblock"})

	mux := http.NewServeMux()
	RegisterDetectorsEndpoints(mux, t.TempDir())
	h := TokenMiddleware("admin-secret", NewTokenStore())(mux)

	// No token → rejected by the admin gate.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/detectors/coverage", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated status=%d want 401/403", rr.Code)
	}

	// Admin bearer → 200 envelope; on a non-systemd runner units come back
	// empty and verdicts degrade to absent/n-a, which is fine.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/detectors/coverage", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		OK     bool   `json:"ok"`
		Schema string `json:"schema"`
		Types  []struct {
			Type    string `json:"type"`
			Verdict string `json:"verdict"`
		} `json:"types"`
		Summary struct {
			TypesTotal int `json:"types_total"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, rr.Body.String())
	}
	if !body.OK || body.Schema != "detectors.coverage.v1" || body.Summary.TypesTotal == 0 ||
		len(body.Types) != body.Summary.TypesTotal {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}

	// POST → 405.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/detectors/coverage", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status=%d want 405", rr.Code)
	}
}

func catalogFixture() []meta.DetectorMeta {
	return []meta.DetectorMeta{
		{TypeKey: "postfix_security", Title: "Postfix security"},
		{TypeKey: "exim_queues", Title: "Exim queues"},
		{TypeKey: "waf_security", Title: "WAF autoblock"},
	}
}

func sec(section, typ string, configured, enabled bool) detectorstatus.RuntimeStatus {
	return detectorstatus.RuntimeStatus{Section: section, Type: typ, Configured: configured, Enabled: enabled}
}

func TestBuildCoverageRowsVerdicts(t *testing.T) {
	svc := func(u string, found, active bool) svcstat.Service {
		s := svcstat.Service{Unit: u + ".service"}
		if found {
			s.Load = "loaded"
		} else {
			s.Load = "not-found"
		}
		if active {
			s.Active = "active"
		} else {
			s.Active = "inactive"
		}
		return s
	}

	t.Run("ok — daemon running and enabled", func(t *testing.T) {
		rows := buildCoverageRows(catalogFixture(),
			[]detectorstatus.RuntimeStatus{sec("postfix_security", "postfix_security", true, true)},
			map[string]svcstat.Service{"postfix": svc("postfix", true, true)})
		if rows[0].Verdict != "ok" || !rows[0].DaemonAware {
			t.Fatalf("verdict=%s note=%s", rows[0].Verdict, rows[0].Note)
		}
	})

	t.Run("gap — daemon running, nothing configured (the forgotten case)", func(t *testing.T) {
		rows := buildCoverageRows(catalogFixture(), nil,
			map[string]svcstat.Service{"exim": svc("exim", true, true)})
		var row coverageType
		for _, r := range rows {
			if r.Type == "exim_queues" {
				row = r
			}
		}
		if row.Verdict != "gap" {
			t.Fatalf("verdict=%s want gap", row.Verdict)
		}
	})

	t.Run("disabled — running but ENABLED=0 everywhere", func(t *testing.T) {
		rows := buildCoverageRows(catalogFixture(),
			[]detectorstatus.RuntimeStatus{sec("postfix_security", "postfix_security", true, false)},
			map[string]svcstat.Service{"postfix": svc("postfix", true, true)})
		if rows[0].Verdict != "disabled" {
			t.Fatalf("verdict=%s", rows[0].Verdict)
		}
	})

	t.Run("dormant — enabled but daemon absent on this host", func(t *testing.T) {
		rows := buildCoverageRows(catalogFixture(),
			[]detectorstatus.RuntimeStatus{sec("postfix_security", "postfix_security", true, true)},
			map[string]svcstat.Service{"postfix": svc("postfix", false, false)})
		if rows[0].Verdict != "dormant" {
			t.Fatalf("verdict=%s", rows[0].Verdict)
		}
	})

	t.Run("absent — no daemon and not configured (must NOT be a complaint)", func(t *testing.T) {
		rows := buildCoverageRows(catalogFixture(), nil,
			map[string]svcstat.Service{})
		for _, r := range rows {
			if r.Type == "postfix_security" && r.Verdict != "absent" {
				t.Fatalf("verdict=%s", r.Verdict)
			}
		}
	})

	t.Run("na — event-driven types carry no daemon verdict", func(t *testing.T) {
		rows := buildCoverageRows(catalogFixture(), nil, map[string]svcstat.Service{})
		for _, r := range rows {
			if r.Type == "waf_security" && r.Verdict != "na" {
				t.Fatalf("verdict=%s", r.Verdict)
			}
		}
	})

	t.Run("installed-but-stopped with enabled section is dormant", func(t *testing.T) {
		rows := buildCoverageRows(catalogFixture(),
			[]detectorstatus.RuntimeStatus{sec("postfix_security", "postfix_security", true, true)},
			map[string]svcstat.Service{"postfix": svc("postfix", true, false)})
		if rows[0].Verdict != "dormant" {
			t.Fatalf("verdict=%s", rows[0].Verdict)
		}
	})

	t.Run("multi-instance grouping by type", func(t *testing.T) {
		rows := buildCoverageRows(catalogFixture(),
			[]detectorstatus.RuntimeStatus{
				sec("exim_queues", "exim_queues", true, false),
				sec("exim_queues:secondary", "exim_queues", true, true),
			},
			map[string]svcstat.Service{"exim": svc("exim", true, true)})
		for _, r := range rows {
			if r.Type != "exim_queues" {
				continue
			}
			if len(r.Sections) != 2 {
				t.Fatalf("instances not grouped: %+v", r.Sections)
			}
			if r.Verdict != "ok" { // one enabled instance covers the type
				t.Fatalf("verdict=%s want ok", r.Verdict)
			}
			return
		}
		t.Fatalf("no exim_queues row: %+v", rows)
	})
}

func TestSummarizeCoverageCounts(t *testing.T) {
	rows := []coverageType{
		{Verdict: "ok"}, {Verdict: "gap"}, {Verdict: "gap"},
		{Verdict: "dormant"}, {Verdict: "absent"}, {Verdict: "na"}, {Verdict: "disabled"},
	}
	s := summarizeCoverage(rows)
	if s.TypesTotal != 7 || s.OK != 1 || s.Gaps != 2 || s.Dormant != 1 || s.Absent != 1 || s.EventOnly != 1 || s.Disabled != 1 {
		t.Fatalf("summary=%+v", s)
	}
}

func TestNormalizeUnitKey(t *testing.T) {
	cases := map[string]string{
		"Postfix.Service": "postfix",
		"pure-ftpd":       "pure-ftpd",
		"  exim  ":        "exim",
	}
	for in, want := range cases {
		if got := normalizeUnitKey(in); got != want {
			t.Errorf("normalizeUnitKey(%q)=%q want %q", in, got, want)
		}
	}
}
