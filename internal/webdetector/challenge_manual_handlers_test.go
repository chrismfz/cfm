package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestEngineForChallengeHandlers() *Engine {
	e := &Engine{}
	e.manualChal.init("")
	return e
}

func TestHandleChallengeVhostAdd_AllowsEmptyJSONBodyWithQueryParams(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/add?host=web-infox.eu&ttl=1h&reason=manual", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	e.handleChallengeVhostAdd(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}
	if got["host"] != "web-infox.eu" {
		t.Fatalf("expected host web-infox.eu, got %#v", got["host"])
	}
	if got["status"] != "active" {
		t.Fatalf("expected status active, got %#v", got["status"])
	}
}

func TestHandleChallengeVhostStatus_WWWCoveredByApexManual(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	// Operator challenges the apex; the bridge enforces it on apex AND www.
	e.ManualChallengeVhost("e-vafeiadis.gr", time.Hour, "manual", "")

	get := func(host string) map[string]interface{} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/status?host="+host, nil)
		rr := httptest.NewRecorder()
		e.handleChallengeVhostStatus(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", host, rr.Code, rr.Body.String())
		}
		var m map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatalf("%s: bad json: %v", host, err)
		}
		return m
	}

	if m := get("e-vafeiadis.gr"); m["manual_active"] != true {
		t.Fatalf("apex: expected manual_active=true, got %#v", m["manual_active"])
	}
	// The regression: before the fix this reported false for the www variant.
	if m := get("www.e-vafeiadis.gr"); m["manual_active"] != true {
		t.Fatalf("www: expected manual_active=true (covered by apex manual), got %#v", m["manual_active"])
	}
}

func TestHandleChallengeVhostAdd_RejectsInvalidJSON(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/add?host=web-infox.eu", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	e.handleChallengeVhostAdd(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid JSON") {
		t.Fatalf("expected invalid JSON error, got: %s", rr.Body.String())
	}
}
