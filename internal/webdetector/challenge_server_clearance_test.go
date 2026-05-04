package webdetector

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClearanceTokenValidation(t *testing.T) {
	t.Setenv("CFM_CHALLENGE_SECRET", "unit-test-secret")
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := issueClearanceToken("203.0.113.9", "Example.COM.", "panel:2083", now.Add(5*time.Minute))
	if !verifyClearanceToken(tok, "203.0.113.9", "example.com", "panel:2083", now) {
		t.Fatal("expected valid token")
	}
	if verifyClearanceToken(tok, "203.0.113.9", "example.com", "panel:2083", now.Add(10*time.Minute)) {
		t.Fatal("expected expired token to fail")
	}
	if verifyClearanceToken(tok, "203.0.113.10", "example.com", "panel:2083", now) {
		t.Fatal("expected ip mismatch to fail")
	}
	if verifyClearanceToken(tok, "203.0.113.9", "other.example.com", "panel:2083", now) {
		t.Fatal("expected host mismatch to fail")
	}
	if verifyClearanceToken(tok, "203.0.113.9", "example.com", "web", now) {
		t.Fatal("expected scope mismatch to fail")
	}
}

func TestClearanceTokenTamperedSig(t *testing.T) {
	t.Setenv("CFM_CHALLENGE_SECRET", "unit-test-secret")
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := issueClearanceToken("203.0.113.9", "example.com", "web", now.Add(5*time.Minute))
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	var p clearancePayload
	_ = json.Unmarshal(raw, &p)
	p.Scope = "panel:2083"
	b, _ := json.Marshal(p)
	tampered := base64.RawURLEncoding.EncodeToString(b)
	if verifyClearanceToken(tampered, "203.0.113.9", "example.com", "panel:2083", now) {
		t.Fatal("expected tampered signature to fail")
	}
}

func TestNormalizeClearanceHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":        "example.com",
		"example.com:443":     "example.com",
		"[2001:db8::1]:8443":  "2001:db8::1",
		"[2001:DB8::1].":      "2001:db8::1",
		"MiXeD.Example.com:80": "mixed.example.com",
	}
	for in, want := range cases {
		if got := normalizeClearanceHost(in); got != want {
			t.Fatalf("normalizeClearanceHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClearanceScope(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	if got := clearanceScope(r); got != "web" {
		t.Fatalf("scope default = %q", got)
	}
	r.Header.Set("X-Forwarded-Port", "2087")
	if got := clearanceScope(r); got != "panel:2087" {
		t.Fatalf("scope panel = %q", got)
	}
	r.Header.Set("X-Forwarded-Port", "443")
	if got := clearanceScope(r); got != "web" {
		t.Fatalf("scope https web = %q", got)
	}
}
