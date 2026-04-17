package webdetector

import (
	"context"
	"net/http"
	"testing"
)

func TestAuthzHelpers_AppliedAcrossWebdetectorEndpoints(t *testing.T) {
	_, mux := newTestEngine(t)

	tests := []struct {
		name       string
		path       string
		ctx        context.Context
		wantStatus int
	}{
		// exclude_api_handlers.go
		{name: "exclude unauth", path: "/api/v1/challenge/exclude/list", ctx: context.Background(), wantStatus: http.StatusForbidden},
		{name: "exclude scoped", path: "/api/v1/challenge/exclude/list", ctx: scopedCtx("example.com"), wantStatus: http.StatusOK},
		{name: "exclude admin", path: "/api/v1/challenge/exclude/list", ctx: adminCtx(), wantStatus: http.StatusOK},

		// waf_engine_api_handlers.go
		{name: "waf summary unauth", path: "/api/v1/waf/engine/summary", ctx: context.Background(), wantStatus: http.StatusForbidden},
		{name: "waf summary scoped", path: "/api/v1/waf/engine/summary", ctx: scopedCtx("example.com"), wantStatus: http.StatusOK},
		{name: "waf summary admin", path: "/api/v1/waf/engine/summary", ctx: adminCtx(), wantStatus: http.StatusOK},

		// challenge_api_handlers.go
		{name: "challenge events unauth", path: "/api/v1/challenge/events", ctx: context.Background(), wantStatus: http.StatusForbidden},
		{name: "challenge events scoped", path: "/api/v1/challenge/events?host=example.com", ctx: scopedCtx("example.com"), wantStatus: http.StatusOK},
		{name: "challenge events admin", path: "/api/v1/challenge/events", ctx: adminCtx(), wantStatus: http.StatusOK},

		// http_api.go
		{name: "hot-ips unauth", path: "/api/v1/webdet/hot-ips", ctx: context.Background(), wantStatus: http.StatusForbidden},
		{name: "hot-ips scoped", path: "/api/v1/webdet/hot-ips", ctx: scopedCtx("example.com"), wantStatus: http.StatusForbidden},
		{name: "hot-ips admin", path: "/api/v1/webdet/hot-ips", ctx: adminCtx(), wantStatus: http.StatusOK},

		// history_api_handlers.go
		{name: "history events unauth", path: "/api/v1/webdet/history/events", ctx: context.Background(), wantStatus: http.StatusForbidden},
		{name: "history events scoped", path: "/api/v1/webdet/history/events?host=example.com", ctx: scopedCtx("example.com"), wantStatus: http.StatusOK},
		{name: "history events admin", path: "/api/v1/webdet/history/events", ctx: adminCtx(), wantStatus: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := doRequest(mux, tc.ctx, http.MethodGet, tc.path, nil)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantStatus == http.StatusForbidden && rr.Body.String() != "{\"error\":\"forbidden\"}\n" {
				t.Fatalf("expected forbidden message, got %s", rr.Body.String())
			}
		})
	}
}
