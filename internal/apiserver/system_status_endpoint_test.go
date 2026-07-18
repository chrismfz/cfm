package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/healthmodel"
	"cfm/internal/healthstore"
)

func newSystemStatusTestServer(t *testing.T) (*TokenStore, http.Handler) {
	t.Helper()
	store := NewTokenStore()
	mux := http.NewServeMux()
	RegisterSystemStatus(mux, nil)
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

	t.Run("scoped token forbidden health snapshot", func(t *testing.T) {
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/snapshot", scoped.Token, false)
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

	t.Run("ssl stats recovers JSON after CLI log-line prefix", func(t *testing.T) {
		origFn := runCachedCommandFn
		runCachedCommandFn = func(key string, _ time.Duration, _ string, _ ...string) ([]byte, int64, error) {
			return []byte("2026-07-18 16:51:59 [sslcollector] snapshot: wrote 2309 exact + 188 wild entries to /var/lib/cfm/sslcollector/dump.json\n{\"ExactHosts\": 2309}\n"), 3, nil
		}
		t.Cleanup(func() { runCachedCommandFn = origFn })

		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/system/ssl/stats?cache_ttl=0", "admin-secret", false)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		stats, ok := body["stats"].(map[string]any)
		if !ok {
			t.Fatalf("expected parsed stats object despite log prefix, got %T (%v)", body["stats"], body["stats"])
		}
		if n, _ := stats["ExactHosts"].(float64); n != 2309 {
			t.Fatalf("unexpected stats payload: %v", stats)
		}
	})

	t.Run("ssl refresh runs command and parses output", func(t *testing.T) {
		origRefresh := runSSLRefreshFn
		var calls int32
		runSSLRefreshFn = func(_ context.Context) ([]byte, error) {
			atomic.AddInt32(&calls, 1)
			return []byte("noise line\n{\"disk\": {\"ExactHosts\": 5}}"), nil
		}
		t.Cleanup(func() { runSSLRefreshFn = origRefresh })

		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/system/ssl/refresh", "admin-secret", false)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET status=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
		}

		rr = doSystemStatusReq(h, http.MethodPost, "/api/v1/system/ssl/refresh", "admin-secret", false)
		if rr.Code != http.StatusOK {
			t.Fatalf("POST status=%d body=%s", rr.Code, rr.Body.String())
		}
		if atomic.LoadInt32(&calls) != 1 {
			t.Fatalf("refresh command calls=%d want=1", calls)
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if ok, _ := body["ok"].(bool); !ok {
			t.Fatalf("expected ok=true, got %v", body)
		}
		if _, isObj := body["stats"].(map[string]any); !isObj {
			t.Fatalf("expected parsed stats object, got %T", body["stats"])
		}
	})

	t.Run("scoped token forbidden ssl refresh", func(t *testing.T) {
		rr := doSystemStatusReq(h, http.MethodPost, "/api/v1/system/ssl/refresh", scoped.Token, false)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusForbidden, rr.Body.String())
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

func TestSystemStatusEndpoints_HealthEndpoints(t *testing.T) {
	origStore := healthstore.Global()
	hs := healthstore.NewRingStore(32)
	healthstore.SetGlobal(hs)
	t.Cleanup(func() { healthstore.SetGlobal(origStore) })

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "local"
	}
	now := time.Now().UTC()
	hs.Append(hostname, healthstore.Sample{NodeID: hostname, Hostname: hostname, CollectedAt: now.Add(-4 * time.Minute), Load1: 1, RamUsedPct: 40, DiskRootPct: 50, DiskTmpPct: 20, TempMaxC: 60, RxMbps: 10, TxMbps: 20})
	hs.Append(hostname, healthstore.Sample{NodeID: hostname, Hostname: hostname, CollectedAt: now.Add(-2 * time.Minute), Load1: 2, RamUsedPct: 45, DiskRootPct: 52, DiskTmpPct: 21, TempMaxC: 61, RxMbps: 12, TxMbps: 22})

	_, h := newSystemStatusTestServer(t)

	t.Run("snapshot returns schema version", func(t *testing.T) {
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/snapshot", "admin-secret", false)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if got, _ := body["schema_version"].(string); got != healthSnapshotSchemaV1 {
			t.Fatalf("schema_version=%q", got)
		}
	})

	t.Run("snapshot degrades gracefully when collector panics", func(t *testing.T) {
		origSnapshotNowFn := healthmodel.TestOnlySwapSnapshotNowFn(func() healthmodel.RawDetectorSnapshot {
			panic("smart probe failure")
		})
		t.Cleanup(func() {
			healthmodel.TestOnlySwapSnapshotNowFn(origSnapshotNowFn)
		})

		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/snapshot", "admin-secret", false)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if got, _ := body["schema_version"].(string); got != healthSnapshotSchemaV1 {
			t.Fatalf("schema_version=%q", got)
		}
		if got, ok := body["error"].(string); !ok || got == "" {
			t.Fatalf("expected degraded error payload, got %v", body)
		}
	})

	t.Run("snapshot cache_ttl reuses cached snapshot", func(t *testing.T) {
		var calls int32
		origCollect := collectHealthSnapshotFn
		origCache := healthSnapCache
		collectHealthSnapshotFn = func(nodeID string, _ firewall.Backend) healthmodel.HealthSnapshotV1 {
			atomic.AddInt32(&calls, 1)
			return healthmodel.HealthSnapshotV1{SchemaVersion: healthSnapshotSchemaV1, NodeID: nodeID, CollectedAt: time.Now().UTC()}
		}
		healthSnapCache = &healthSnapshotCache{}
		t.Cleanup(func() {
			collectHealthSnapshotFn = origCollect
			healthSnapCache = origCache
		})

		for i := 0; i < 3; i++ {
			rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/snapshot?cache_ttl=60s", "admin-secret", false)
			if rr.Code != http.StatusOK {
				t.Fatalf("req %d status=%d body=%s", i, rr.Code, rr.Body.String())
			}
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Fatalf("collector calls=%d want=1 (cache_ttl should reuse cached snapshot)", got)
		}

		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/snapshot", "admin-secret", false)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if got := atomic.LoadInt32(&calls); got != 2 {
			t.Fatalf("collector calls=%d want=2 (no cache_ttl must collect fresh)", got)
		}
	})

	t.Run("timeseries returns deterministic points", func(t *testing.T) {
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/timeseries?window=10m&step=1m", "admin-secret", false)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var body struct {
			SchemaVersion string `json:"schema_version"`
			Points        []struct {
				SampleCount float64 `json:"sample_count"`
			} `json:"points"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body.SchemaVersion != healthTimeseriesSchemaV1 {
			t.Fatalf("schema_version=%q", body.SchemaVersion)
		}
		if len(body.Points) == 0 {
			t.Fatalf("expected non-empty points")
		}
	})

	t.Run("anomalies since filter", func(t *testing.T) {
		publishAPIAnomalyEvent(APIAnomalyEvent{When: now.Add(-10 * time.Minute), Source: "apiserver", Reason: "old", Signal: "old"})
		publishAPIAnomalyEvent(APIAnomalyEvent{When: now.Add(-1 * time.Minute), Source: "apiserver", Reason: "new", Signal: "new"})
		rr := doSystemStatusReq(h, http.MethodGet, "/api/v1/health/anomalies?since=5m", "admin-secret", false)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var body struct {
			SchemaVersion string `json:"schema_version"`
			Count         int    `json:"count"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body.SchemaVersion != healthAnomaliesSchemaV1 {
			t.Fatalf("schema_version=%q", body.SchemaVersion)
		}
		if body.Count < 1 {
			t.Fatalf("expected at least one anomaly in window")
		}
	})

	t.Run("ingest accepted", func(t *testing.T) {
		payload := bytes.NewBufferString(`{"node_id":"` + hostname + `","sample":{"collected_at":"` + time.Now().UTC().Format(time.RFC3339) + `","load1":3.5}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/health/ingest", payload)
		req.Header.Set("Authorization", "Bearer admin-secret")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
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

	rr = doSystemStatusReq(h, http.MethodPost, "/api/v1/health/snapshot", "admin-secret", false)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
	}
}
