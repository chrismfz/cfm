package webdetector

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"cfm/internal/tlsfp"
)

const fpTestTuple = "1|TLSv1.3|TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519:prime256v1:secp384r1|h2|HTTP/2.0|"

// resetFPPolicies restores the package-level store so tests don't leak into
// each other (the store is deliberately package-level, like the solverfarm
// marks).
func resetFPPolicies(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		SetFingerprintPolicies(nil)
		ConfigureFingerprintPolicyEnforcement(true, nil)
	})
	SetFingerprintPolicies(nil)
	ConfigureFingerprintPolicyEnforcement(true, nil)
}

func fpTestID(t *testing.T) string {
	t.Helper()
	fp, ok := tlsfp.Parse(fpTestTuple)
	if !ok || fp.ID == "" {
		t.Fatalf("test tuple did not parse")
	}
	return fp.ID
}

func TestFingerprintPolicyStore(t *testing.T) {
	resetFPPolicies(t)
	id := fpTestID(t)

	// Nothing armed.
	if got := FingerprintPolicyForID(id); got != "" {
		t.Fatalf("empty store returned %q", got)
	}

	SetFingerprintPolicies([]FingerprintPolicy{
		{ID: id, Action: "deny"},
		{ID: "AABBCCDD", Action: "challenge"},                                       // stored lowercased
		{ID: "11223344", Action: "observe"},                                         // unknown action → dropped
		{ID: "55667788", Action: "challenge_v2", ExpiresAt: time.Now().Add(-time.Hour)}, // expired
	})

	if got := FingerprintPolicyForID(id); got != "deny" {
		t.Fatalf("deny policy: got %q", got)
	}
	if got := FingerprintPolicyForID("aabbccdd"); got != "challenge" {
		t.Fatalf("case-insensitive lookup: got %q", got)
	}
	if got := FingerprintPolicyForID("11223344"); got != "" {
		t.Fatalf("unknown action must be dropped at set time, got %q", got)
	}
	if got := FingerprintPolicyForID("55667788"); got != "" {
		t.Fatalf("expired policy must not bite, got %q", got)
	}

	// Operator escape hatch.
	ConfigureFingerprintPolicyEnforcement(true, []string{" " + id + " "})
	if got := FingerprintPolicyForID(id); got != "" {
		t.Fatalf("ALLOW_FPS-exempt id must not be enforced, got %q", got)
	}

	// Master kill switch.
	ConfigureFingerprintPolicyEnforcement(false, nil)
	if got := FingerprintPolicyForID("aabbccdd"); got != "" {
		t.Fatalf("FP_POLICY=0 must disarm every lookup, got %q", got)
	}

	// Replace-all semantics: a disarmed policy vanishes on the next snapshot.
	ConfigureFingerprintPolicyEnforcement(true, nil)
	SetFingerprintPolicies([]FingerprintPolicy{{ID: "aabbccdd", Action: "challenge_v2"}})
	if got := FingerprintPolicyForID(id); got != "" {
		t.Fatalf("policy missing from the new snapshot must stop, got %q", got)
	}
	if got := FingerprintPolicyForID("aabbccdd"); got != "challenge_v2" {
		t.Fatalf("challenge_v2 lookup: got %q", got)
	}
}

func TestHandleFpPolicy(t *testing.T) {
	resetFPPolicies(t)
	id := fpTestID(t)
	SetFingerprintPolicies([]FingerprintPolicy{{ID: id, Action: "deny"}})

	b := NewNginxBridge("/tmp/fppolicy-test.sock", "tok", time.Minute, time.Minute)

	call := func(token, fp string) (int, map[string]any) {
		req := httptest.NewRequest("GET", "/nginx/fppolicy?fp="+url.QueryEscape(fp), nil)
		if token != "" {
			req.Header.Set("X-CFM-Token", token)
		}
		rec := httptest.NewRecorder()
		b.handleFpPolicy(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	if code, _ := call("", fpTestTuple); code != 403 {
		t.Fatalf("missing token: code=%d, want 403", code)
	}
	if code, _ := call("wrong", fpTestTuple); code != 403 {
		t.Fatalf("wrong token: code=%d, want 403", code)
	}

	code, out := call("tok", fpTestTuple)
	if code != 200 || out["action"] != "deny" || out["id"] != id {
		t.Fatalf("armed lookup: code=%d out=%v", code, out)
	}
	if ttl, _ := out["ttl"].(float64); ttl <= 0 {
		t.Fatalf("ttl missing: %v", out)
	}

	// No / unparseable fingerprint → empty action, still 200 (fail-open).
	if code, out := call("tok", ""); code != 200 || out["action"] != "" {
		t.Fatalf("empty fp: code=%d out=%v", code, out)
	}
	if code, out := call("tok", "garbage"); code != 200 || out["action"] != "" {
		t.Fatalf("garbage fp: code=%d out=%v", code, out)
	}
}

// ── Geo kinds (policy-kinds slice): country/ASN challenge floors ─────────────

func TestGeoPolicyStoreAndLookup(t *testing.T) {
	resetFPPolicies(t)
	t.Cleanup(func() { SetFingerprintPolicyGeoResolver(nil) })

	asnCalls := 0
	asnFn := func() uint64 { asnCalls++; return 6799 }

	// Empty store: no lookup work at all (asnFn never consulted).
	if got := GeoPolicyAction("GR", asnFn); got != "" || asnCalls != 0 {
		t.Fatalf("empty store: got %q asnCalls=%d", got, asnCalls)
	}

	SetFingerprintPolicies([]FingerprintPolicy{
		{ID: "gr", Kind: "country", Action: "challenge_v2"},
		{ID: "6799", Kind: "asn", Action: "challenge"},
		{ID: "US", Kind: "country", Action: "deny"},         // geo deny → dropped (doctrine)
		{ID: "DE", Kind: "country", Action: "challenge", ExpiresAt: time.Now().Add(-time.Minute)}, // expired
		{ID: "notanasn", Kind: "asn", Action: "challenge"},  // unparseable → dropped
		{ID: "FR", Kind: "wat", Action: "challenge"},        // unknown kind → dropped
	})

	// Country match (case-insensitive), before any ASN work.
	asnCalls = 0
	if got := GeoPolicyAction("gr", asnFn); got != "challenge_v2" {
		t.Fatalf("country lookup got %q", got)
	}
	if asnCalls != 0 {
		t.Fatalf("asnFn consulted despite country hit")
	}

	// Country miss → ASN match.
	if got := GeoPolicyAction("IT", asnFn); got != "challenge" {
		t.Fatalf("asn lookup got %q", got)
	}

	// Geo deny was dropped, expired country answers nothing.
	if got := GeoPolicyAction("US", func() uint64 { return 0 }); got != "" {
		t.Fatalf("geo deny must never be enforceable, got %q", got)
	}
	if got := GeoPolicyAction("DE", func() uint64 { return 0 }); got != "" {
		t.Fatalf("expired country policy answered %q", got)
	}

	// FP_POLICY master knob gates geo kinds too.
	ConfigureFingerprintPolicyEnforcement(false, nil)
	if got := GeoPolicyAction("GR", asnFn); got != "" {
		t.Fatalf("disabled enforcement still answered %q", got)
	}
	ConfigureFingerprintPolicyEnforcement(true, nil)

	// Verify-side helper: resolver-driven; nil resolver fails open.
	if got := GeoPolicyActionForIP("203.0.113.9"); got != "" {
		t.Fatalf("nil resolver must fail open, got %q", got)
	}
	SetFingerprintPolicyGeoResolver(func(ip string) (string, uint64) { return "", 6799 })
	if got := GeoPolicyActionForIP("203.0.113.9"); got != "challenge" {
		t.Fatalf("resolver-driven asn lookup got %q", got)
	}
	SetFingerprintPolicyGeoResolver(func(ip string) (string, uint64) { return "GR", 0 })
	if got := GeoPolicyActionForIP("203.0.113.9"); got != "challenge_v2" {
		t.Fatalf("resolver-driven country lookup got %q", got)
	}
}

func TestGeoPoliciesDoNotLeakIntoFingerprintLookup(t *testing.T) {
	resetFPPolicies(t)
	SetFingerprintPolicies([]FingerprintPolicy{
		{ID: "gr", Kind: "country", Action: "challenge"},
	})
	// A country target must never answer a fingerprint-id lookup (separate maps).
	if got := FingerprintPolicyForID("gr"); got != "" {
		t.Fatalf("country policy leaked into fp lookup: %q", got)
	}
}
