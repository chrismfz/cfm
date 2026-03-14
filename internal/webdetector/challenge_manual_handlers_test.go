package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestEngineForChallengeHandlers() *Engine {
	e := &Engine{}
	e.manualChal.init()
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
