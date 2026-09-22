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

// A LIVE manual challenge must report manual_active=true and auto_active=false:
// while a manual challenge owns the chalAPI row it keeps Mode=="manual", so it
// must not be mislabeled as an active AUTO challenge (which the CLI would print
// as "auto: ACTIVE"). A port-bearing host must also resolve, matching the
// sibling /challenge/vhost endpoint.
func TestHandleChallengeVhostStatus_LiveManualNotAutoActive(t *testing.T) {
	e, mux := newStep3Engine(t)
	if e.chalAPI == nil {
		t.Skip("engine has no challenge API store")
	}
	// Record through the engine so both the manual store and chalAPI are set,
	// as a real operator add would.
	e.ManualChallengeVhost("example.com", time.Hour, "manual", "")

	for _, q := range []string{"example.com", "Example.COM", "example.com:443"} {
		rr := get(mux, adminCtx(), "/api/v1/challenge/vhost/status?host="+q)
		if rr.Code != http.StatusOK {
			t.Fatalf("host=%q: expected 200, got %d body=%s", q, rr.Code, rr.Body.String())
		}
		var res map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			t.Fatalf("host=%q decode: %v", q, err)
		}
		if res["manual_active"] != true {
			t.Errorf("host=%q: manual_active=%v, want true", q, res["manual_active"])
		}
		if res["auto_active"] == true {
			t.Errorf("host=%q: auto_active=true for a manual challenge (mislabel)", q)
		}
	}
}

// The events endpoint must filter on the normalized host, so `challenge host
// Example.COM` shows that vhost's events instead of an always-empty list.
func TestHandleChallengeEvents_MixedCaseHostFilters(t *testing.T) {
	e, mux := newStep3Engine(t)
	if e.chalAPI == nil {
		t.Skip("engine has no challenge API store")
	}
	// RecordVhostManual emits a manual_on event keyed to the canonical host.
	e.chalAPI.RecordVhostManual("example.com", true, time.Hour, "manual")

	rr := get(mux, adminCtx(), "/api/v1/challenge/events?host=Example.COM")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var evs []ChallengeEvent
	if err := json.Unmarshal(rr.Body.Bytes(), &evs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(evs) == 0 {
		t.Error("mixed-case host returned no events — host was not normalized before filtering")
	}
}

// status=all on the list endpoint must report the EFFECTIVE status, matching
// the single-vhost endpoint: a lapsed manual row must read inactive on both.
func TestListVhosts_LapsedManualInactiveInStatusAll(t *testing.T) {
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

	rr := get(mux, adminCtx(), "/api/v1/challenge/vhosts?status=all&limit=200")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var rows []ChallengeVhostState
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.Host == "stale.gr" {
			found = true
			if r.Status != "inactive" {
				t.Errorf("status=all: stale.gr Status=%q, want inactive (must match single-vhost endpoint)", r.Status)
			}
		}
	}
	if !found {
		t.Fatal("stale.gr not present in status=all listing")
	}
}

// A 404 is the "no active challenge" answer, but a disabled challenge store must
// NOT read as unchallenged — the handler returns 503, and the CLI surfaces it.
func TestHandleChallengeVhost_StoreUnavailableIs503(t *testing.T) {
	e := &Engine{} // no chalAPI
	req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost?host=x.gr", nil).WithContext(adminCtx())
	rr := httptest.NewRecorder()
	e.handleChallengeVhost(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("chalAPI nil: want 503, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRunChallengeHost_StoreUnavailableSurfaces(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"challenge API unavailable"}`))
	}))
	defer ts.Close()
	if err := runChallengeWebTop(ts.URL, []string{"host", "x.gr"}); err == nil {
		t.Fatal("challenge host treated a 503 (store unavailable) as a clean answer")
	}
}

// Events are stored canonically at the write chokepoint, so a normalized ?host=
// filter matches an event a non-manual writer recorded under a raw-case host.
func TestChallengeAPIStore_EventHostNormalizedForFilter(t *testing.T) {
	s := NewChallengeAPIStore(100)
	s.addEvent(ChallengeEvent{Ts: time.Now(), Type: "ip_challenge", Host: "Example.COM:443", IP: "1.2.3.4"})
	if evs := s.Events("example.com", "", "", "", 50); len(evs) == 0 {
		t.Fatal("event stored under a non-canonical host was not found by a normalized filter")
	}
}

// runChallengeStatus must surface a non-2xx response instead of decoding the
// error body and printing "manual: inactive / auto: inactive" with exit 0.
// The live TUI must render a manual challenge's REMAINING time, not a bare
// HH:MM:SS: the old code sliced [11:19] off the RFC3339 expiry and dropped the
// date, so a >24h TTL read as "expires in a few hours" when it was tomorrow.
func TestFetchChallengeStatus_ManualShowsRemainingNotClock(t *testing.T) {
	expires := time.Now().Add(34 * time.Hour).UTC().Format(time.RFC3339)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"host":"x.gr","manual_active":true,"expires_at":"` + expires + `","reason":"manual"}`))
	}))
	defer ts.Close()

	active, mode, expiry, err := fetchChallengeStatus(ts.URL, "x.gr")
	if err != nil {
		t.Fatalf("fetchChallengeStatus: %v", err)
	}
	if !active || mode != "manual" {
		t.Fatalf("expected active/manual, got %v/%s", active, mode)
	}
	d, perr := time.ParseDuration(expiry)
	if perr != nil {
		t.Fatalf("expiry %q is not a duration — date-stripped clock regressed: %v", expiry, perr)
	}
	if d < 33*time.Hour {
		t.Errorf("remaining = %s, want ~34h (the date must not be dropped)", d)
	}
}

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
