package webdetector

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Bare `cfm webtop attack` dispatches to the status view: it probes the summary
// endpoint (enabled + authoritative count) and lists under-attack vhosts from
// the challenge list, queried with status=all so lapsed/inactive rows still
// surface. A normal response must not error.
func TestRunAttackStatus_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/challenge/summary":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"under_attack_enabled":true,"under_attack_vhosts":2}`))
		case "/api/v1/challenge/vhosts":
			if got := r.URL.Query().Get("status"); got != "all" {
				t.Fatalf("expected status=all (so lapsed rows surface), got %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			// One under_attack row + one challenged row (must be filtered out).
			_, _ = w.Write([]byte(`[{"host":"a.example","mode":"auto","score":0.9,"uniq_ip":5,"reasons":["x"],"state":"under_attack"},{"host":"b.example","state":"challenged"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	if err := runAttackStatus(ts.URL); err != nil {
		t.Fatalf("runAttackStatus: %v", err)
	}
}

// A failed summary probe (403 for a non-admin caller, 500, transport error)
// must not fail the whole command, and must not be reported as a definitive
// "disabled" — the vhosts list still renders.
func TestRunAttackStatus_SummaryProbeFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/challenge/summary":
			http.Error(w, "forbidden", http.StatusForbidden)
		case "/api/v1/challenge/vhosts":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	if err := runAttackStatus(ts.URL); err != nil {
		t.Fatalf("runAttackStatus (summary 403 is best-effort): %v", err)
	}
}

// The vhosts endpoint is the point of the view, so its failure is a hard error.
func TestRunAttackStatus_VhostsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/challenge/summary" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"under_attack_enabled":false}`))
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()
	if err := runAttackStatus(ts.URL); err == nil {
		t.Fatal("expected error when the vhosts endpoint returns 500")
	}
}

// runAttackWebTop dispatch: no args → status view (server-backed, no error);
// an unknown verb and on/off without a vhost → usage errors, raised before any
// HTTP call so no override is issued.
func TestRunAttackWebTop_Dispatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/challenge/summary":
			_, _ = w.Write([]byte(`{"under_attack_enabled":false}`))
		case "/api/v1/challenge/vhosts":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	if err := runAttackWebTop(ts.URL, nil); err != nil {
		t.Fatalf("no-args dispatch to status: %v", err)
	}
	if err := runAttackWebTop(ts.URL, []string{"bogus"}); err == nil {
		t.Fatal("expected usage error for an unknown verb")
	}
	if err := runAttackWebTop(ts.URL, []string{"on"}); err == nil {
		t.Fatal("expected usage error for `on` with no vhost")
	}
	if err := runAttackWebTop(ts.URL, []string{"off"}); err == nil {
		t.Fatal("expected usage error for `off` with no vhost")
	}
}
