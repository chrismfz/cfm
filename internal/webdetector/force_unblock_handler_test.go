package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"cfm/internal/unblock"
)

func newTestEngineForce(t *testing.T) (*Engine, *http.ServeMux) {
	t.Helper()
	e := NewEngine(Config{
		Every:  5 * time.Second,
		Window: 2 * time.Minute,
	})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)
	return e, mux
}

func TestForceUnblockIP_RequiresAdmin(t *testing.T) {
	_, mux := newTestEngineForce(t)
	// No auth in context → RequireAdmin must reject.
	rr := uaDo(mux, context.Background(), http.MethodPost, "/api/v1/webdet/force-unblock-ip?ip=1.2.3.4", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403; body=%s", rr.Code, rr.Body.String())
	}
}

func TestForceUnblockIP_MethodNotAllowed(t *testing.T) {
	_, mux := newTestEngineForce(t)
	rr := uaDo(mux, adminCtx(), http.MethodGet, "/api/v1/webdet/force-unblock-ip?ip=1.2.3.4", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405; body=%s", rr.Code, rr.Body.String())
	}
}

func TestForceUnblockIP_BadIP(t *testing.T) {
	_, mux := newTestEngineForce(t)
	for _, q := range []string{"", "?ip=", "?ip=not-an-ip"} {
		rr := uaDo(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/force-unblock-ip"+q, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("q=%q status=%d, want 400; body=%s", q, rr.Code, rr.Body.String())
		}
	}
}

func TestForceUnblockIP_NoBridge(t *testing.T) {
	// OpenResty mode is off in the test config, so e.nginxBridge is nil: the
	// handler must succeed with an empty (nothing-to-clear) result rather than
	// panic or error.
	_, mux := newTestEngineForce(t)
	rr := uaDo(mux, adminCtx(), http.MethodPost, "/api/v1/webdet/force-unblock-ip?ip=1.2.3.4", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var res unblock.WAFResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rr.Body.String())
	}
	if res.Found || len(res.Cleared) != 0 {
		t.Fatalf("expected empty result with no bridge, got %+v", res)
	}
}
