package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newSystemStatusTestServer(t *testing.T) (*TokenStore, http.Handler) {
	t.Helper()
	store := NewTokenStore()
	mux := http.NewServeMux()
	RegisterSystemStatus(mux)
	return store, TokenMiddleware("admin-secret", store)(mux)
}

func doSystemStatusReq(h http.Handler, method, path, token string, withCookie bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if withCookie {
		req.AddCookie(&http.Cookie{Name: "cfm-sid", Value: "pretend-admin-session"})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestSystemStatusEndpoints_Authz(t *testing.T) {
	store, h := newSystemStatusTestServer(t)
	scoped := store.Issue([]string{"mysite.com"}, nil, nil, "viewer", "scoped", time.Hour)

	origRunCachedCommandFn := runCachedCommandFn
	runCachedCommandFn = func(key string, _ time.Duration, _ string, _ ...string) ([]byte, int64, error) {
		switch key {
		case "system_dnat":
			return []byte("dnat-ok\n"), 7, nil
		case "system_ssl_stats":
			return []byte(`{"issuer":"ok"}`), 11, nil
		default:
			return []byte(""), 0, nil
		}
	}
	t.Cleanup(func() { runCachedCommandFn = origRunCachedCommandFn })

	t.Run("scoped token forbidden dnat", func(t *testing.T) {
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/system/dnat", scoped.Token, false)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
		}
	})

	t.Run("scoped token forbidden ssl stats", func(t *testing.T) {
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/system/ssl/stats", scoped.Token, false)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
		}
	})

	t.Run("admin token can read dnat", func(t *testing.T) {
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/system/dnat?cache_ttl=0", "admin-secret", false)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if ok, _ := body["ok"].(bool); !ok {
			t.Fatalf("expected ok=true, got body=%v", body)
		}
		if output, _ := body["output"].(string); output != "dnat-ok\n" {
			t.Fatalf("unexpected output: %q", output)
		}
	})

	t.Run("admin session can read ssl stats", func(t *testing.T) {
		withSessionAllowedStub(t, true)
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/system/ssl/stats?cache_ttl=0", "", true)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if ok, _ := body["ok"].(bool); !ok {
			t.Fatalf("expected ok=true, got body=%v", body)
		}
		stats, ok := body["stats"].(map[string]any)
		if !ok {
			t.Fatalf("expected stats object, got %T (%v)", body["stats"], body["stats"])
		}
		if issuer, _ := stats["issuer"].(string); issuer != "ok" {
			t.Fatalf("unexpected stats payload: %v", stats)
		}
	})
}

func TestSystemStatusEndpoints_MethodNotAllowed(t *testing.T) {
	store, h := newSystemStatusTestServer(t)
	_ = store
	origRunCachedCommandFn := runCachedCommandFn
	runCachedCommandFn = func(_ string, _ time.Duration, _ string, _ ...string) ([]byte, int64, error) {
		return []byte("noop"), 1, nil
	}
	t.Cleanup(func() { runCachedCommandFn = origRunCachedCommandFn })

	rr := doSystemStatusReq(h, http.MethodPost, "/api/v1/system/dnat", "admin-secret", false)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("method not allowed")) {
		t.Fatalf("expected method-not-allowed message, got %s", rr.Body.String())
	}
}
