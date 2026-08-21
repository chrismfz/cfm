package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A single-vhost query with a mixed-case host must resolve to the lowercase
// key the store is written under — otherwise a live manual challenge on
// example.com is reported "not found" for ?host=Example.COM (the scope check
// already lowercased; only the lookup was left raw).
func TestHandleChallengeVhost_MixedCaseHostResolves(t *testing.T) {
	e, mux := newStep3Engine(t)
	if e.chalAPI == nil {
		t.Skip("engine has no challenge API store")
	}
	e.chalAPI.RecordVhostManual("example.com", true, time.Hour, "manual")

	for _, q := range []string{"Example.COM", "example.com:443"} {
		rr := get(mux, adminCtx(), "/api/v1/challenge/vhost?host="+q)
		if rr.Code != http.StatusOK {
			t.Fatalf("host=%q: expected 200, got %d body=%s", q, rr.Code, rr.Body.String())
		}
		var vq ChallengeVhostState
		if err := json.Unmarshal(rr.Body.Bytes(), &vq); err != nil {
			t.Fatalf("host=%q decode: %v", q, err)
		}
		if vq.Status != "active" || vq.Mode != "manual" {
			t.Fatalf("host=%q: expected active/manual, got %s/%s", q, vq.Status, vq.Mode)
		}
	}
	rr := get(mux, adminCtx(), "/api/v1/challenge/vhost?host=Example.COM")
	if rr.Code != http.StatusOK {
		t.Fatalf("mixed-case host: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var v ChallengeVhostState
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.Status != "active" || v.Mode != "manual" {
		t.Fatalf("expected active/manual, got %s/%s", v.Status, v.Mode)
	}
	if v.TTLSec != 3600 {
		t.Errorf("TTLSec = %d, want 3600", v.TTLSec)
	}
}

// The single-vhost endpoint must report the EFFECTIVE status, matching the list
// endpoint: a manual challenge that lapsed with no later auto tick to rewrite
// the row keeps a stored Status=="active" with a past ExpiresAt (the store has
// no TTL sweeper). Without the effective-status fold, /challenge/vhost returned
// active while /challenge/vhosts omitted it — the CLI then printed the
// self-contradictory "status=active ... left=expired".
func TestHandleChallengeVhost_LapsedManualReportsInactive(t *testing.T) {
	e, mux := newStep3Engine(t)
	if e.chalAPI == nil {
		t.Skip("engine has no challenge API store")
	}
	e.chalAPI.RecordVhostManual("stale.gr", true, time.Hour, "manual")

	// Force the window into the past, as a real TTL expiry would with no
	// subsequent event to rewrite the row.
	e.chalAPI.mu.Lock()
	st := e.chalAPI.vhosts["stale.gr"]
	st.ExpiresAt = time.Now().Add(-time.Minute)
	st.manualUntil = st.ExpiresAt
	e.chalAPI.mu.Unlock()

	rr := get(mux, adminCtx(), "/api/v1/challenge/vhost?host=stale.gr")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var v ChallengeVhostState
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.Status != "inactive" {
		t.Errorf("lapsed manual: Status = %q, want inactive to match the list endpoint", v.Status)
	}
}

// A still-live manual challenge must keep reporting active (the effective-status
// fold must not over-reach and hide a genuine challenge).
func TestHandleChallengeVhost_LiveManualStaysActive(t *testing.T) {
	e, mux := newStep3Engine(t)
	if e.chalAPI == nil {
		t.Skip("engine has no challenge API store")
	}
	e.chalAPI.RecordVhostManual("live.gr", true, time.Hour, "manual")

	rr := get(mux, adminCtx(), "/api/v1/challenge/vhost?host=live.gr")
	var v ChallengeVhostState
	_ = json.Unmarshal(rr.Body.Bytes(), &v)
	if v.Status != "active" {
		t.Errorf("live manual: Status = %q, want active", v.Status)
	}
}

// runChallengeStatus must surface a non-2xx response instead of decoding the
// error body and printing "manual: inactive / auto: inactive" with exit 0.
func TestRunChallengeStatus_ErrorStatusSurfaces(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer ts.Close()

	if err := runChallengeStatus(ts.URL, []string{"victim.com"}); err == nil {
		t.Fatal("runChallengeStatus swallowed a 403 and returned nil")
	}
}

// The happy path must still work after the added status check.
func TestRunChallengeStatus_OKHappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"host":"x.gr","manual_active":true,"expires_at":"2026-08-21T15:04:05Z","reason":"manual"}`))
	}))
	defer ts.Close()

	if err := runChallengeStatus(ts.URL, []string{"x.gr"}); err != nil {
		t.Fatalf("happy path returned error: %v", err)
	}
}

// `challenge host <vhost>` treats a 404 as the normal "not challenged" answer:
// no blank row, no error exit — the endpoint 404s for any host with no record.
func TestRunChallengeHost_NotFoundIsCleanAnswer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer ts.Close()

	if err := runChallengeWebTop(ts.URL, []string{"host", "x.gr"}); err != nil {
		t.Fatalf("challenge host on an unchallenged vhost should exit clean, got: %v", err)
	}
}

// A real error status (not 404) on the single-vhost lookup must still surface,
// rather than decoding the error body into an all-zero row.
func TestRunChallengeHost_ForbiddenSurfaces(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer ts.Close()

	if err := runChallengeWebTop(ts.URL, []string{"host", "x.gr"}); err == nil {
		t.Fatal("challenge host swallowed a 403 and returned nil")
	}
}

// The list and events branches surface an error status too, instead of a
// cryptic "cannot unmarshal object into []..." from decoding the error body.
func TestRunChallengeList_ErrorStatusSurfaces(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer ts.Close()

	if err := runChallengeWebTop(ts.URL, nil); err == nil {
		t.Fatal("challenge list swallowed a 403 and returned nil")
	}
	if err := runChallengeWebTop(ts.URL, []string{"events"}); err == nil {
		t.Fatal("challenge events swallowed a 403 and returned nil")
	}
}

// The `/challenge/vhost/status` endpoint (which `challenge status` calls) must
// not report a lapsed manual challenge as an active AUTO challenge: auto_active
// is gated on the effective-active fold, not the raw stored Status.
func TestHandleChallengeVhostStatus_LapsedManualNotAutoActive(t *testing.T) {
	e, mux := newStep3Engine(t)
	if e.chalAPI == nil {
		t.Skip("engine has no challenge API store")
	}
	e.chalAPI.RecordVhostManual("stale.gr", true, time.Hour, "manual")
	e.chalAPI.mu.Lock()
	st := e.chalAPI.vhosts["stale.gr"]
	st.ExpiresAt = time.Now().Add(-time.Minute)
	st.manualUntil = st.ExpiresAt
	e.chalAPI.mu.Unlock()

	rr := get(mux, adminCtx(), "/api/v1/challenge/vhost/status?host=stale.gr")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var res map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res["auto_active"] == true {
		t.Error("lapsed manual reported as auto_active=true (stale-row false-active)")
	}
	if res["manual_active"] == true {
		t.Error("lapsed manual reported as manual_active=true")
	}
}
