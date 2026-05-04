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
		"Example.COM.":         "example.com",
		"example.com:443":      "example.com",
		"[2001:db8::1]:8443":   "2001:db8::1",
		"[2001:DB8::1].":       "2001:db8::1",
		"MiXeD.Example.com:80": "mixed.example.com",
	}
	for in, want := range cases {
		if got := normalizeClearanceHost(in); got != want {
			t.Fatalf("normalizeClearanceHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClearanceScope(t *testing.T) {
	tests := []struct {
		name  string
		panel string
		xfwd  string
		want  string
	}{
		{name: "default web", want: "web"},
		{name: "cpanel 2082", xfwd: "2082", want: "panel:2082"},
		{name: "cpanel 2083", xfwd: "2083", want: "panel:2083"},
		{name: "cpanel 2086", xfwd: "2086", want: "panel:2086"},
		{name: "cpanel 2087", xfwd: "2087", want: "panel:2087"},
		{name: "cpanel 2095", xfwd: "2095", want: "panel:2095"},
		{name: "cpanel 2096", xfwd: "2096", want: "panel:2096"},
		{name: "directadmin 2222", xfwd: "2222", want: "panel:2222"},
		{name: "normalize noisy numeric", xfwd: " :2087/tcp ", want: "panel:2087"},
		{name: "web https", xfwd: "443", want: "web"},
		{name: "panel header precedence", panel: "2096", xfwd: "12096", want: "panel:2096"},
		{name: "panel header normalization", panel: "port=2083", xfwd: "9999", want: "panel:2083"},
		{name: "panel header web override", panel: "443", xfwd: "2087", want: "web"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://example.com/", nil)
			if tt.panel != "" {
				r.Header.Set("X-CFM-Panel-Port", tt.panel)
			}
			if tt.xfwd != "" {
				r.Header.Set("X-Forwarded-Port", tt.xfwd)
			}
			if got := clearanceScope(r); got != tt.want {
				t.Fatalf("clearanceScope() = %q, want %q", got, tt.want)
			}
		})
	}
}
