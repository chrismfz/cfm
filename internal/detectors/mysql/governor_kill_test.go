package mysql

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newKillTestGovernor returns a Governor with a fixed process snapshot and no
// real DB handle. handleUserKill's authorization/scope checks run before any
// DB work, so the security-relevant paths (400/404/403) never touch the DB;
// the in-scope path reaches ManualKill, which reports "no database handle"
// (db == nil) — enough to prove the scope gate let it through.
func newKillTestGovernor() *Governor {
	g := &Governor{}
	g.state.Processes = []Process{
		{ID: 1, User: "chris_wp", DB: "chris_wp"},
		{ID: 2, User: "other", DB: "otherdb"},
	}
	return g
}

func postKill(g *Governor, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mysql/user-kill?"+query, nil)
	rr := httptest.NewRecorder()
	g.handleUserKill(rr, req)
	return rr
}

func TestUserKill_BadID(t *testing.T) {
	rr := postKill(newKillTestGovernor(), "id=abc&user=chris_wp")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid id, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserKill_NotFound(t *testing.T) {
	rr := postKill(newKillTestGovernor(), "id=999&user=chris_wp")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown pid, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserKill_OutOfScopeForbidden(t *testing.T) {
	// Scoped caller (user=chris_wp) trying to kill pid 2 (owned by "other").
	rr := postKill(newKillTestGovernor(), "id=2&user=chris_wp&db=chris_wp")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 killing an out-of-scope connection, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserKill_InScopePassesScopeGate(t *testing.T) {
	// In-scope kill must NOT be blocked by scope enforcement. With no DB handle
	// in the test, ManualKill reports "no database handle" (HTTP 500) — which
	// still proves the request passed the 400/404/403 gates and reached the kill.
	rr := postKill(newKillTestGovernor(), "id=1&user=chris_wp&db=chris_wp")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("in-scope kill must not be forbidden, got 403 body=%s", rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json response: %v body=%s", err, rr.Body.String())
	}
	if got, _ := resp["action"].(string); got != "KILL QUERY" {
		t.Fatalf("expected default action KILL QUERY, got %q", got)
	}
	if res, _ := resp["result"].(string); !strings.Contains(res, "no database handle") {
		t.Fatalf("expected the kill to be attempted (no db handle in test), got result=%q", res)
	}
}

func TestUserKill_TypeConnection(t *testing.T) {
	rr := postKill(newKillTestGovernor(), "id=1&type=connection&user=chris_wp")
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if got, _ := resp["action"].(string); got != "KILL CONNECTION" {
		t.Fatalf("expected action KILL CONNECTION for type=connection, got %q", got)
	}
}

func TestUserKill_AdminCanTargetAnyButStillNotFound(t *testing.T) {
	// No user=/db= → admin context (no scope filter). Unknown pid still 404.
	rr := postKill(newKillTestGovernor(), "id=999")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for admin unknown pid, got %d body=%s", rr.Code, rr.Body.String())
	}
}
