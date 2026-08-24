package webdetector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	unitTestBridgeSecret = "unit-test-bridge-secret-0123456789abcdef"
	bridgeSecretA        = "bridge-secret-a-0123456789abcdef"
	bridgeSecretB        = "bridge-secret-b-0123456789abcdef"
	bridgeFileSecret     = "bridge-file-secret-0123456789abcdef"
)

func useClearanceBridgeToken(t *testing.T, token string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "cfm_bridge_token.lua")
	if err := os.WriteFile(path, []byte("return "+strconv.Quote(token)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	old := clearanceBridgeTokenPath
	clearanceBridgeTokenPath = path
	t.Cleanup(func() { clearanceBridgeTokenPath = old })
	return path
}

func TestClearanceTokenValidation(t *testing.T) {
	useClearanceBridgeToken(t, unitTestBridgeSecret)
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
	useClearanceBridgeToken(t, unitTestBridgeSecret)
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

func TestClearanceRequiresCanonicalBridgeFile(t *testing.T) {
	old := clearanceBridgeTokenPath
	clearanceBridgeTokenPath = filepath.Join(t.TempDir(), "missing-bridge-token.lua")
	t.Cleanup(func() { clearanceBridgeTokenPath = old })
	clearanceTokenWarnOnce = sync.Once{}
	t.Cleanup(func() { clearanceTokenWarnOnce = sync.Once{} })
	t.Setenv("OPENRESTY_TOKEN", "legacy-environment-secret")

	now := time.Unix(1_700_000_000, 0).UTC()
	if tok := issueClearanceToken("203.0.113.9", "example.com", "web", now.Add(5*time.Minute)); tok != "" {
		t.Fatal("expected token issuance to fail without the canonical bridge file")
	}
}

func TestReadBridgeTokenSecretCanonicalFormat(t *testing.T) {
	const escaped = `bridge-token-"quoted"-\path-0123456789abcdef`
	path := useClearanceBridgeToken(t, escaped)

	if got, ok := readBridgeTokenSecret(path); !ok || got != escaped {
		t.Fatalf("readBridgeTokenSecret() = %q, %t; want %q, true", got, ok, escaped)
	}
	if err := os.WriteFile(path, []byte("return "+strconv.Quote("too-short")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := readBridgeTokenSecret(path); ok {
		t.Fatalf("expected short canonical token to be rejected, got %q", got)
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

func TestClearanceCookieName(t *testing.T) {
	cases := map[string]string{
		"web":          "cfm_clearance",
		"":             "cfm_clearance",
		"panel:2082":   "cfm_clearance_p2082",
		"panel:2083":   "cfm_clearance_p2083",
		"panel:2086":   "cfm_clearance_p2086",
		"panel:2087":   "cfm_clearance_p2087",
		"panel:2095":   "cfm_clearance_p2095",
		"panel:2096":   "cfm_clearance_p2096",
		"panel:2222":   "cfm_clearance_p2222",
		"panel:":       "cfm_clearance", // malformed: no port
		"panel:20x87":  "cfm_clearance", // malformed: non-digit
		"panel:2087; ": "cfm_clearance", // malformed: header-injection shape
		"other":        "cfm_clearance",
	}
	for scope, want := range cases {
		if got := clearanceCookieName(scope); got != want {
			t.Fatalf("clearanceCookieName(%q) = %q, want %q", scope, got, want)
		}
	}
}

func TestClearanceUsesBridgeTokenNotChallengeSecret(t *testing.T) {
	bridge := useClearanceBridgeToken(t, bridgeSecretA)
	t.Setenv("CFM_CHALLENGE_SECRET", "challenge-secret-a")
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := issueClearanceToken("203.0.113.9", "example.com", "panel:2087", now.Add(5*time.Minute))
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	var p clearancePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	payload := "1|" + strconv.FormatInt(p.Exp, 10) + "|" + p.IP + "|" + normalizeClearanceHost(p.Host) + "|" + p.Scope + "|" + p.Nonce
	mac := hmac.New(sha256.New, []byte(bridgeSecretA))
	mac.Write([]byte(payload))
	if got := hex.EncodeToString(mac.Sum(nil)); got != p.HMAC {
		t.Fatalf("expected clearance signature to use bridge token")
	}
	// Changing the challenge secret alone must not invalidate clearance.
	t.Setenv("CFM_CHALLENGE_SECRET", "challenge-secret-b")
	if !verifyClearanceToken(tok, "203.0.113.9", "example.com", "panel:2087", now) {
		t.Fatal("expected token to remain valid after challenge secret change")
	}
	// Rotating the canonical bridge token must invalidate clearance.
	if err := os.WriteFile(bridge, []byte("return "+strconv.Quote(bridgeSecretB)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if verifyClearanceToken(tok, "203.0.113.9", "example.com", "panel:2087", now) {
		t.Fatal("expected token to fail after bridge token change")
	}
}

func TestClearanceUsesBridgeFileToken(t *testing.T) {
	useClearanceBridgeToken(t, bridgeFileSecret)
	now := time.Unix(1_700_000_000, 0).UTC()
	tok := issueClearanceToken("203.0.113.9", "example.com", "panel:2087", now.Add(5*time.Minute))
	if tok == "" {
		t.Fatal("expected token issuance with bridge file secret")
	}
	if !verifyClearanceToken(tok, "203.0.113.9", "example.com", "panel:2087", now) {
		t.Fatal("expected verification with bridge file secret")
	}
}
