package webdetector

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func gokidsLikeRules(t *testing.T, e *Engine) {
	t.Helper()
	qs := "^(?:(?:fbclid|gclid|utm_[a-z]+|page|paged)(?:=[^&;]*)?(?:[&;]+|$))+$"
	for _, r := range []TrafficRule{
		{Enabled: true, Priority: 100, Scope: TrafficRuleScope{Vhosts: []string{"gokids.gr", "www.gokids.gr"}},
			Match: TrafficRuleMatch{UAAny: []string{"*meta-externalagent*"}}, Action: TrafficRuleAction{Type: TrafficActionBlock}, Note: "block meta"},
		{Enabled: true, Priority: 350, Scope: TrafficRuleScope{Vhosts: []string{"gokids.gr", "www.gokids.gr"}},
			Match: TrafficRuleMatch{CountryIn: []string{"VN", "IN"}}, Action: TrafficRuleAction{Type: TrafficActionBlock}},
		{Enabled: false, Priority: 361, Scope: TrafficRuleScope{Vhosts: []string{"gokids.gr"}},
			Match: TrafficRuleMatch{UAAny: []string{"*GPTBot*"}, Methods: []string{"GET"}, HasQS: true, QSNotRx: qs}, Action: TrafficRuleAction{Type: TrafficActionBlock}},
		{Enabled: true, Priority: 200, Scope: TrafficRuleScope{Vhosts: []string{"other.gr"}},
			Match: TrafficRuleMatch{UAAny: []string{"*bot*"}}, Action: TrafficRuleAction{Type: TrafficActionThrottle, Profile: "soft_bot"}},
	} {
		if _, err := e.TrafficRuleAdd(r); err != nil {
			t.Fatal(err)
		}
	}
}

func exportVia(t *testing.T, mux *http.ServeMux, path string) TrafficRulesExportDoc {
	t.Helper()
	rr := doRequest(mux, adminCtx(), http.MethodGet, path, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("export %s: %d %s", path, rr.Code, rr.Body.String())
	}
	var doc TrafficRulesExportDoc
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func importVia(t *testing.T, mux *http.ServeMux, ctxAdmin bool, query string, doc any) (int, TrafficRuleImportResult) {
	t.Helper()
	body, _ := json.Marshal(doc)
	ctx := adminCtx()
	if !ctxAdmin {
		ctx = scopedCtx("gokids.gr", "www.gokids.gr")
	}
	rr := doRequest(mux, ctx, http.MethodPost, "/api/v1/webdet/rules/import"+query, body)
	var res TrafficRuleImportResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("import response: %v (%s)", err, rr.Body.String())
	}
	return rr.Code, res
}

// The gokids.gr move (orion → rigel, 2026-10-14) in one round trip: export by
// vhost on one node, import on another, same rules, new ids, origin noted.
func TestTrafficRulesExportImportRoundTrip(t *testing.T) {
	src, srcMux := newTestEngine(t)
	gokidsLikeRules(t, src)

	doc := exportVia(t, srcMux, "/api/v1/webdet/rules/export?vhost=GOKIDS.GR")
	if doc.Format != trafficRulesExportFormat || doc.Version != 1 || len(doc.Rules) != 3 {
		t.Fatalf("export: %+v", doc)
	}
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), `"id"`) || strings.Contains(string(raw), "created_at") {
		t.Fatalf("export must not carry ids or timestamps: %s", raw)
	}
	if all := exportVia(t, srcMux, "/api/v1/webdet/rules/export"); len(all.Rules) != 4 {
		t.Fatalf("unfiltered export: %d rules", len(all.Rules))
	}

	dst, dstMux := newTestEngine(t)
	code, dry := importVia(t, dstMux, true, "?dry_run=1", doc)
	if code != http.StatusOK || dry.Add != 3 || len(dry.Added) != 0 || len(dst.TrafficRuleList()) != 0 {
		t.Fatalf("dry run: %d %+v, stored %d", code, dry, len(dst.TrafficRuleList()))
	}
	code, res := importVia(t, dstMux, true, "", doc)
	if code != http.StatusOK || res.Add != 3 || len(res.Added) != 3 {
		t.Fatalf("import: %d %+v", code, res)
	}
	got := dst.TrafficRuleList()
	if len(got) != 3 {
		t.Fatalf("stored %d rules", len(got))
	}
	for i, r := range got {
		want := doc.Rules[i] // both sorted by priority
		if r.Priority != want.Priority || r.Enabled != want.Enabled || trafficRuleKey(r) != trafficRuleKey(TrafficRule{Scope: want.Scope, Match: want.Match, Action: want.Action}) {
			t.Fatalf("rule %d differs: %+v vs %+v", i, r, want)
		}
		if !strings.Contains(r.Note, "(imported ") {
			t.Fatalf("note does not say where it came from: %q", r.Note)
		}
	}
	// Every imported rule enforces like the original.
	if sim := dst.trafficRules.Simulate(TrafficRuleEvalInput{Host: "gokids.gr", UA: "meta-externalagent/1.1"}); !sim.Matched {
		t.Fatalf("imported meta rule does not match: %+v", sim)
	}

	// Importing the same file again adds nothing.
	code, again := importVia(t, dstMux, true, "", doc)
	if code != http.StatusOK || again.Add != 0 || again.Duplicates != 3 || len(dst.TrafficRuleList()) != 3 {
		t.Fatalf("re-import: %d %+v", code, again)
	}
}

func TestTrafficRulesImportDisabledAndWarnings(t *testing.T) {
	src, srcMux := newTestEngine(t)
	gokidsLikeRules(t, src)
	doc := exportVia(t, srcMux, "/api/v1/webdet/rules/export?vhost=gokids.gr")

	dst, dstMux := newTestEngine(t)
	// An existing rule at priority 100 on the same vhost → a warning, not an error.
	if _, err := dst.TrafficRuleAdd(TrafficRule{Enabled: true, Priority: 100, Scope: TrafficRuleScope{Vhosts: []string{"gokids.gr"}},
		Match: TrafficRuleMatch{PathAny: []string{"/x"}}, Action: TrafficRuleAction{Type: TrafficActionBlock}}); err != nil {
		t.Fatal(err)
	}
	code, res := importVia(t, dstMux, true, "?disabled=1", doc)
	if code != http.StatusOK || res.Add != 3 {
		t.Fatalf("import: %d %+v", code, res)
	}
	warned := false
	for _, it := range res.Items {
		if len(it.Warnings) > 0 && strings.Contains(it.Warnings[0], "priority 100") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("no priority warning: %+v", res.Items)
	}
	for _, r := range dst.TrafficRuleList() {
		if strings.Contains(r.Note, "imported") && r.Enabled {
			t.Fatalf("disabled=1 imported an enabled rule: %+v", r)
		}
	}
}

// One bad rule rejects the whole document: nothing is written.
func TestTrafficRulesImportAllOrNothing(t *testing.T) {
	dst, mux := newTestEngine(t)
	doc := TrafficRulesExportDoc{Format: trafficRulesExportFormat, Version: 1, Rules: []TrafficRuleExport{
		{Enabled: true, Priority: 100, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}}, Match: TrafficRuleMatch{UAAny: []string{"*x*"}}, Action: TrafficRuleAction{Type: TrafficActionBlock}},
		{Enabled: true, Priority: 110, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}}, Match: TrafficRuleMatch{QSNotRx: "("}, Action: TrafficRuleAction{Type: TrafficActionBlock}},
		{Enabled: true, Priority: 120, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}}, Action: TrafficRuleAction{Type: "explode"}},
	}}
	code, res := importVia(t, mux, true, "", doc)
	if code != http.StatusBadRequest || res.Invalid != 2 || res.Add != 1 || len(dst.TrafficRuleList()) != 0 {
		t.Fatalf("want 400 with 2 invalid and nothing stored: %d %+v stored=%d", code, res, len(dst.TrafficRuleList()))
	}
	if res.Items[1].Status != "invalid" || !strings.Contains(res.Items[1].Error, "qs_not_rx") {
		t.Fatalf("item 1: %+v", res.Items[1])
	}
}

func TestTrafficRulesImportRejectsForeignDocuments(t *testing.T) {
	_, mux := newTestEngine(t)
	ok := []TrafficRuleExport{{Enabled: true, Priority: 1, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}}, Match: TrafficRuleMatch{UAAny: []string{"*x*"}}, Action: TrafficRuleAction{Type: TrafficActionBlock}}}
	for name, doc := range map[string]TrafficRulesExportDoc{
		"format":  {Format: "something-else", Version: 1, Rules: ok},
		"version": {Format: trafficRulesExportFormat, Version: 2, Rules: ok},
		"empty":   {Format: trafficRulesExportFormat, Version: 1},
	} {
		if code, res := importVia(t, mux, true, "", doc); code != http.StatusBadRequest || res.Error == "" {
			t.Errorf("%s: want 400 with an error, got %d %+v", name, code, res)
		}
	}
	rr := doRequest(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/rules/import", []byte("[not json"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed json: %d", rr.Code)
	}
}

// A scoped (cPanel) token exports only its own rules and cannot import a rule
// for a vhost it does not hold — the whole import is refused.
func TestTrafficRulesTransferScope(t *testing.T) {
	src, mux := newTestEngine(t)
	gokidsLikeRules(t, src)

	rr := doRequest(mux, scopedCtx("gokids.gr", "www.gokids.gr"), http.MethodGet, "/api/v1/webdet/rules/export", nil)
	var doc TrafficRulesExportDoc
	_ = json.Unmarshal(rr.Body.Bytes(), &doc)
	if rr.Code != http.StatusOK || len(doc.Rules) != 3 {
		t.Fatalf("scoped export: %d, %d rules", rr.Code, len(doc.Rules))
	}
	for _, r := range doc.Rules {
		if scopeNamesAny(r.Scope.Vhosts, map[string]bool{"other.gr": true}) {
			t.Fatalf("scoped export leaked another tenant's rule: %+v", r)
		}
	}

	dst, dstMux := newTestEngine(t)
	foreign := TrafficRulesExportDoc{Format: trafficRulesExportFormat, Version: 1, Rules: append(append([]TrafficRuleExport{}, doc.Rules...),
		TrafficRuleExport{Enabled: true, Priority: 5, Scope: TrafficRuleScope{Vhosts: []string{"other.gr"}}, Match: TrafficRuleMatch{UAAny: []string{"*"}}, Action: TrafficRuleAction{Type: TrafficActionBlock}})}
	code, res := importVia(t, dstMux, false, "", foreign)
	if code != http.StatusBadRequest || res.Invalid != 1 || len(dst.TrafficRuleList()) != 0 {
		t.Fatalf("scoped import of a foreign vhost must be refused whole: %d %+v", code, res)
	}
	if code, res := importVia(t, dstMux, false, "", doc); code != http.StatusOK || len(res.Added) != 3 {
		t.Fatalf("scoped import of own vhosts: %d %+v", code, res)
	}
}

func TestTrafficRulesExportSkipsUnsupported(t *testing.T) {
	doc := exportTrafficRules([]TrafficRule{
		{ID: "r_1", Priority: 1, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}}, Unsupported: true},
		{ID: "r_2", Priority: 2, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}}, Action: TrafficRuleAction{Type: "block"}},
	}, nil, "n", time.Now())
	if len(doc.Rules) != 1 || doc.Skipped != 1 {
		t.Fatalf("%+v", doc)
	}
}

func TestWithImportNote(t *testing.T) {
	if got := withImportNote("block meta", "imported from orion 2026-10-14"); got != "block meta (imported from orion 2026-10-14)" {
		t.Fatalf("%q", got)
	}
	long := strings.Repeat("x", maxRuleNoteLen-5)
	if got := withImportNote(long, "imported from orion 2026-10-14"); got != long {
		t.Fatalf("a note that would overflow must stay unchanged")
	}
}
