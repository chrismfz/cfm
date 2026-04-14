package apiserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAPIAbuseClassifierBenignTrafficDoesNotTrigger(t *testing.T) {
	c := newAPIAbuseSignalClassifier()
	now := time.Now()
	c.now = func() time.Time { return now }

	for i := 0; i < 12; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
		r.RemoteAddr = "198.51.100.10:1234"
		events := c.Evaluate(r, http.StatusOK, "")
		if len(events) != 0 {
			t.Fatalf("expected no events for benign traffic, got %+v", events)
		}
	}
}

func TestAPIAbuseClassifierScannerPatternsTrigger(t *testing.T) {
	c := newAPIAbuseSignalClassifier()
	now := time.Now()
	c.now = func() time.Time { return now }

	baseReq := func(method, path string) *http.Request {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "203.0.113.5:4444"
		r.Header.Set("User-Agent", "masscan/1.3")
		return r
	}

	var unknown apiAbuseEvent
	for i := 0; i < 8; i++ {
		events := c.Evaluate(baseReq(http.MethodGet, "/random-not-real"), http.StatusNotFound, "route_not_found")
		if i == 7 {
			if len(events) != 1 || events[0].Name != "api_probe" || events[0].Signal != "unknown_endpoint_burst" {
				t.Fatalf("expected unknown endpoint burst event, got %+v", events)
			}
			unknown = events[0]
		}
	}
	if unknown.Count != 8 {
		t.Fatalf("expected count=8 for unknown endpoint burst, got %d", unknown.Count)
	}

	var fuzz apiAbuseEvent
	for i := 0; i < 3; i++ {
		events := c.Evaluate(baseReq(http.MethodGet, "/search/%3cscript%3ealert(1)%3c/script%3e"), http.StatusNotFound, "")
		if i == 2 {
			if len(events) == 0 {
				t.Fatalf("expected fuzz event on threshold crossing")
			}
			fuzz = events[0]
		}
	}
	if fuzz.Name != "api_fuzz" || fuzz.Signal != "path_entropy_or_fuzz" {
		t.Fatalf("expected api_fuzz/path_entropy_or_fuzz, got %+v", fuzz)
	}

	var sensitive apiAbuseEvent
	for i := 0; i < 3; i++ {
		events := c.Evaluate(baseReq(http.MethodGet, "/.env"), http.StatusNotFound, "")
		if i == 2 {
			found := false
			for _, ev := range events {
				if ev.Name == "api_probe" && ev.Signal == "sensitive_path_probe" {
					sensitive = ev
					found = true
				}
			}
			if !found {
				t.Fatalf("expected sensitive path probe event, got %+v", events)
			}
		}
	}
	if sensitive.Count != 3 {
		t.Fatalf("expected sensitive path probe count=3, got %d", sensitive.Count)
	}

	var mismatch apiAbuseEvent
	for i := 0; i < 4; i++ {
		events := c.Evaluate(baseReq(http.MethodPost, "/api/v1/system/status"), http.StatusMethodNotAllowed, "method_not_allowed")
		if i == 3 {
			if len(events) != 1 || events[0].Signal != "method_mismatch_burst" {
				t.Fatalf("expected method mismatch event, got %+v", events)
			}
			mismatch = events[0]
		}
	}
	if mismatch.Name != "api_probe" {
		t.Fatalf("expected api_probe for method mismatch, got %+v", mismatch)
	}

	var unauth apiAbuseEvent
	for i := 0; i < 5; i++ {
		events := c.Evaluate(baseReq(http.MethodGet, "/api/v1/webdet/history"), http.StatusUnauthorized, "auth_missing")
		if i == 4 {
			if len(events) != 1 || events[0].Name != "api_unauthorized_burst" {
				t.Fatalf("expected api_unauthorized_burst, got %+v", events)
			}
			unauth = events[0]
		}
	}
	if unauth.Signal != "unauthorized_burst" || unauth.Count != 5 {
		t.Fatalf("expected unauthorized_burst count=5, got %+v", unauth)
	}
}
