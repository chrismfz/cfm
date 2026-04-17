package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	webdet "cfm/internal/webdetector"
)

func debugCtx(role string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, role)
	return ctx
}

func TestDebugLiveRequiresAdmin(t *testing.T) {
	mux := http.NewServeMux()
	RegisterDebugEndpoints(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/live", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}

	reqAdmin := httptest.NewRequest(http.MethodGet, "/api/v1/debug/live", nil).WithContext(debugCtx(webdet.CtxRoleAdmin))
	rrAdmin := httptest.NewRecorder()
	mux.ServeHTTP(rrAdmin, reqAdmin)
	if rrAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rrAdmin.Code)
	}
}

func TestDebugCaptureEndpointsRequireAdmin(t *testing.T) {
	mux := http.NewServeMux()
	RegisterDebugEndpoints(mux)

	cases := []struct {
		path string
		meth string
	}{
		{path: "/api/v1/debug/capture", meth: http.MethodPost},
		{path: "/api/v1/debug/capture/test-1", meth: http.MethodGet},
		{path: "/api/v1/debug/export?id=test-1", meth: http.MethodGet},
	}

	for _, tc := range cases {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(tc.meth, tc.path, nil)
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s: expected 403, got %d", tc.meth, tc.path, rr.Code)
		}
	}
}
