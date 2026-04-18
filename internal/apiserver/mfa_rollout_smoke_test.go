package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cfgpkg "cfm/internal/config"
	"github.com/chrismfz/goauth"
)

func TestMFARolloutMiddleware_TOTPEnrollPilotGate(t *testing.T) {
	origPolicy := activeMFARolloutPolicy
	origUserFromCtx := authUserFromContext
	t.Cleanup(func() {
		activeMFARolloutPolicy = origPolicy
		authUserFromContext = origUserFromCtx
	})

	activeMFARolloutPolicy = mfaRolloutPolicy{
		loginVerifyEnabled: true,
		totpEnrollEnabled:  true,
		pilotUsers:         map[string]struct{}{"pilot": {}},
	}
	authUserFromContext = func(_ context.Context) (*goauth.User, bool) {
		u := &goauth.User{Username: "other"}
		return u, true
	}

	next := MFARolloutMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "https://host/mfa/totp/enroll/start", nil)
	rr := httptest.NewRecorder()
	next.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-pilot user, got %d", rr.Code)
	}
}

func TestMFARolloutMiddleware_NonMFARoutesUnaffected(t *testing.T) {
	origPolicy := activeMFARolloutPolicy
	t.Cleanup(func() { activeMFARolloutPolicy = origPolicy })
	activeMFARolloutPolicy = mfaRolloutPolicy{loginVerifyEnabled: false, totpEnrollEnabled: false}

	next := MFARolloutMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/status", nil)
	rr := httptest.NewRecorder()
	next.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected non-MFA route pass-through, got %d", rr.Code)
	}
}

func TestSmoke_AdminLoginAndVerifyRoutesUnderCFMAdminPrefix(t *testing.T) {
	origPolicy := activeMFARolloutPolicy
	t.Cleanup(func() { activeMFARolloutPolicy = origPolicy })
	activeMFARolloutPolicy.loginVerifyEnabled = true

	m := http.NewServeMux()
	RegisterLoginRoutes(m)
	m.HandleFunc("/cfm-admin/", func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/cfm-admin")
		if r2.URL.Path == "" {
			r2.URL.Path = "/"
		}
		m.ServeHTTP(w, r2)
	})

	loginReq := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/login", nil)
	loginRR := httptest.NewRecorder()
	m.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("expected login GET 200, got %d", loginRR.Code)
	}

	verifyReq := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/login/verify", nil)
	verifyRR := httptest.NewRecorder()
	m.ServeHTTP(verifyRR, verifyReq)
	if verifyRR.Code != http.StatusOK {
		t.Fatalf("expected verify GET 200, got %d", verifyRR.Code)
	}
}

func TestSmoke_BearerTokenAPIUnaffectedByMFARollout(t *testing.T) {
	store := NewTokenStore()
	m := http.NewServeMux()
	m.HandleFunc("/api/v1/system/status", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	origPolicy := activeMFARolloutPolicy
	t.Cleanup(func() { activeMFARolloutPolicy = origPolicy })
	activeMFARolloutPolicy = mfaRolloutPolicy{loginVerifyEnabled: false, totpEnrollEnabled: false}

	h := TokenMiddleware("admin-token", store)(MFARolloutMiddleware(m))

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/status", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected bearer route success, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSetMFARolloutPolicyFromConfig(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.Debug.AuthMFALoginVerifyEnabled = false
	cfg.Debug.AuthMFATOTPEnrollEnabled = true
	cfg.Debug.AuthMFATOTPPilotUsers = []string{" Alice ", "bob"}

	setMFARolloutPolicyFromConfig(cfg)
	if mfaLoginVerifyEnabled() {
		t.Fatal("expected login verify disabled from config")
	}
	if !activeMFARolloutPolicy.totpEnrollEnabled {
		t.Fatal("expected TOTP enroll enabled")
	}
	if _, ok := activeMFARolloutPolicy.pilotUsers["alice"]; !ok {
		t.Fatal("expected normalized pilot user alice")
	}
}
