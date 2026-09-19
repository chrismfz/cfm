package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The feed parse is defensive by contract (mixed-version fleets): unknown
// fields ignored, malformed expires_at degrades to zero (permanent-until-
// next-pull), auth failures surface the upstream body.
func TestFetchFingerprintPolicies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fingerprint-policies/fetch" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Token") != "sekrit" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"generated_at": "2026-09-19T10:00:00+00:00",
			"count": 2,
			"policies": [
				{"fingerprint":"c28caa00","kind":"tls","action":"deny","scope":"global","verdict":"farm","armed_at":"2026-09-19T09:00:00+00:00","expires_at":"2026-09-19T15:00:00+00:00"},
				{"fingerprint":"aabbccdd","action":"challenge_v2","expires_at":null,"future_field":123},
				{"fingerprint":"eeff0011","action":"challenge","expires_at":"not-a-date"}
			],
			"withheld": [{"fingerprint":"ba6b4aad","action":"challenge","reason":"generic_tool_bucket"}]
		}`))
	}))
	defer srv.Close()

	c := &APIClient{BaseURL: srv.URL, Token: "sekrit"}
	rows, err := c.FetchFingerprintPolicies(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows=%d, want 3", len(rows))
	}
	if rows[0].Fingerprint != "c28caa00" || rows[0].Action != "deny" {
		t.Fatalf("row0=%+v", rows[0])
	}
	want, _ := time.Parse(time.RFC3339, "2026-09-19T15:00:00+00:00")
	if !rows[0].ExpiresAt.Equal(want) {
		t.Fatalf("row0 expires=%v, want %v", rows[0].ExpiresAt, want)
	}
	if !rows[1].ExpiresAt.IsZero() {
		t.Fatalf("null expires_at must be zero, got %v", rows[1].ExpiresAt)
	}
	if !rows[2].ExpiresAt.IsZero() {
		t.Fatalf("malformed expires_at must degrade to zero, got %v", rows[2].ExpiresAt)
	}

	c.Token = "wrong"
	if _, err := c.FetchFingerprintPolicies(context.Background()); err == nil {
		t.Fatalf("auth failure must surface an error")
	}
}
