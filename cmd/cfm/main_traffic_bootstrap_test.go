package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cfm/internal/apiserver"
	webdet "cfm/internal/webdetector"
)

func TestBootstrapTrafficEngineRegistersTrafficSummary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := bootstrapTrafficEngine(ctx); err != nil {
		t.Fatalf("bootstrap traffic engine: %v", err)
	}

	mux := http.NewServeMux()
	apiserver.RegisterTrafficEndpoints(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/summary", nil)
	req = req.WithContext(context.WithValue(
		context.WithValue(req.Context(), webdet.CtxAuthnKey{}, true),
		webdet.CtxRoleKey{},
		webdet.CtxRoleAdmin,
	))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	cancel()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		rr = httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code == http.StatusServiceUnavailable {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected source clear after cancel, got %d body=%s", rr.Code, rr.Body.String())
}
