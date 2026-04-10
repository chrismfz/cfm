package webdetector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/panelauth"
)

func TestAuthorizePluginAssertionAcceptsDerivedKey(t *testing.T) {
	dir := t.TempDir()
	writeCFMConf(t, dir, "AUTH_TOKEN=shared-secret\n")
	setConfigDir(t, dir)

	derivedKey, err := panelauth.DerivePluginAssertionKey()
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	token := signedAssertionForTest(t, "alice", "nonce-accept-1", derivedKey, time.Now().UTC())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil)
	req.Header.Set("X-CFM-Actor-Assertion", token)
	user, status, authErr, reason := authorizePluginAssertion(req)
	if authErr != nil {
		t.Fatalf("authorize error=%v reason=%s status=%d", authErr, reason, status)
	}
	if user != "alice" {
		t.Fatalf("expected user alice, got %q", user)
	}
}

func TestAuthorizePluginAssertionRejectsMismatchedAuthToken(t *testing.T) {
	dir := t.TempDir()
	writeCFMConf(t, dir, "AUTH_TOKEN=server-token\n")
	setConfigDir(t, dir)

	wrongKey := []byte("this-is-not-the-derived-auth-token-key")
	token := signedAssertionForTest(t, "alice", "nonce-reject-1", wrongKey, time.Now().UTC())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cpanel/user-info", nil)
	req.Header.Set("X-CFM-Actor-Assertion", token)
	_, status, authErr, reason := authorizePluginAssertion(req)
	if authErr == nil {
		t.Fatalf("expected authorization error")
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", status)
	}
	if reason != "token_invalid_signature" {
		t.Fatalf("expected token_invalid_signature, got %q", reason)
	}
}

func writeCFMConf(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "cfm.conf"), []byte(body), 0o600); err != nil {
		t.Fatalf("write cfm.conf: %v", err)
	}
}

func setConfigDir(t *testing.T, dir string) {
	t.Helper()
	prev := os.Getenv("CFM_CONFIG_DIR")
	if err := os.Setenv("CFM_CONFIG_DIR", dir); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Setenv("CFM_CONFIG_DIR", prev) })
}

func signedAssertionForTest(t *testing.T, sub, nonce string, key []byte, now time.Time) string {
	t.Helper()
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]any{
		"sub":   sub,
		"aud":   "cfm-plugin-cpanel",
		"iat":   now.Unix(),
		"exp":   now.Add(2 * time.Minute).Unix(),
		"nonce": nonce,
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(head + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return head + "." + payload + "." + sig
}
