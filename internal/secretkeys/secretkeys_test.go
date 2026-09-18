package secretkeys

import "testing"

func TestIsSecret(t *testing.T) {
	secret := []string{
		"CHALLENGE_TOKEN", "OPENRESTY_TOKEN", "bridge_token",
		"HMAC_SECRET", "clamd_password", "API_KEY", "apikey",
		"private_key", "privatekey",
	}
	for _, k := range secret {
		if !IsSecret(k) {
			t.Errorf("IsSecret(%q) = false, want true", k)
		}
	}
	// The pattern matches api_key / private_key, NOT a bare "key" root — so a
	// key PATH like TLS_KEY_PATH is not matched (and a path is not secret material
	// anyway). Documented here so the boundary is deliberate, not accidental.
	notSecret := []string{
		"MODE", "DRY_RUN", "BLOCK", "MIN_SOLVES", "HUMANITY_MIN_OBS",
		"MINORITY_PCT", "ENABLED", "LOG_PATH", "THRESHOLD", "TLS_KEY_PATH",
	}
	for _, k := range notSecret {
		if IsSecret(k) {
			t.Errorf("IsSecret(%q) = true, want false", k)
		}
	}
	// Fail-safe over-match: a non-secret threshold whose NAME contains "token"
	// is matched, so callers that must keep it visible (detectors_config's
	// TOKEN_IP) rely on their own allowlist, not on this returning false.
	if !IsSecret("TOKEN_IP") {
		t.Error("IsSecret(\"TOKEN_IP\") = false; the detectors_config allowlist assumes it matches")
	}
}
