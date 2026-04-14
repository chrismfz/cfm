package apiserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	webdet "cfm/internal/webdetector"
)

func requestWithContext(h http.Handler, method, path string, body []byte, ctx context.Context) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func adminOnlyCtx(role string) context.Context {
	ctx := context.WithValue(context.Background(), webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, role)
	return ctx
}

func TestTokenEndpoints_UseCommonAuthorizationHelpers(t *testing.T) {
	store := NewTokenStore()
	mux := http.NewServeMux()
	RegisterTokenEndpoint(mux, store)
	RegisterTokenManagementEndpoints(mux, store)

	tests := []struct {
		name       string
		method     string
		path       string
		body       []byte
		ctx        context.Context
		wantStatus int
	}{
		// token_store.go endpoint
		{name: "issue unauth forbidden", method: http.MethodPost, path: "/api/v1/auth/token", body: []byte(`{"vhosts":["example.com"]}`), ctx: context.Background(), wantStatus: http.StatusForbidden},
		{name: "issue scoped forbidden", method: http.MethodPost, path: "/api/v1/auth/token", body: []byte(`{"vhosts":["example.com"]}`), ctx: adminOnlyCtx(webdet.CtxRoleScoped), wantStatus: http.StatusForbidden},
		{name: "issue admin allowed", method: http.MethodPost, path: "/api/v1/auth/token", body: []byte(`{"vhosts":["example.com"]}`), ctx: adminOnlyCtx(webdet.CtxRoleAdmin), wantStatus: http.StatusOK},

		// token_api.go endpoint
		{name: "list unauth forbidden", method: http.MethodGet, path: "/api/v1/tokens/list", ctx: context.Background(), wantStatus: http.StatusForbidden},
		{name: "list scoped forbidden", method: http.MethodGet, path: "/api/v1/tokens/list", ctx: adminOnlyCtx(webdet.CtxRoleScoped), wantStatus: http.StatusForbidden},
		{name: "list admin allowed", method: http.MethodGet, path: "/api/v1/tokens/list", ctx: adminOnlyCtx(webdet.CtxRoleAdmin), wantStatus: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := requestWithContext(mux, tc.method, tc.path, tc.body, tc.ctx)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantStatus == http.StatusForbidden && rr.Body.String() != "{\"error\":\"forbidden\"}\n" {
				t.Fatalf("expected forbidden message, got %s", rr.Body.String())
			}
		})
	}
}
