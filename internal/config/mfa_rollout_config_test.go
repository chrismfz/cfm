package config

import (
	"strings"
	"testing"
)

func TestParseCFMConf_MFARolloutKeys(t *testing.T) {
	cfg, err := ParseCFMConf(strings.NewReader(`
AUTH_MFA_LOGIN_VERIFY_ENABLED=false
AUTH_MFA_TOTP_ENROLL_ENABLED=true
AUTH_MFA_TOTP_PILOT_USERS=alice, bob
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Debug.AuthMFALoginVerifyEnabled {
		t.Fatal("expected login verify to be disabled")
	}
	if !cfg.Debug.AuthMFATOTPEnrollEnabled {
		t.Fatal("expected TOTP enroll to be enabled")
	}
	if got := len(cfg.Debug.AuthMFATOTPPilotUsers); got != 2 {
		t.Fatalf("expected 2 pilot users, got %d", got)
	}
}

func TestParseCFMConf_MFALoginVerifyDefaultsEnabled(t *testing.T) {
	cfg, err := ParseCFMConf(strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.Debug.AuthMFALoginVerifyEnabled {
		t.Fatal("expected default AUTH_MFA_LOGIN_VERIFY_ENABLED=true")
	}
}

func TestIsKnownKey_MFARolloutKeys(t *testing.T) {
	for _, key := range []string{
		"AUTH_MFA_LOGIN_VERIFY_ENABLED",
		"AUTH_MFA_TOTP_ENROLL_ENABLED",
		"AUTH_MFA_TOTP_PILOT_USERS",
	} {
		if !IsKnownKey(key) {
			t.Fatalf("expected key %s to be known", key)
		}
	}
}
