package apiserver

import (
	"net/http"
	"strings"

	cfgpkg "cfm/internal/config"
)

type mfaRolloutPolicy struct {
	loginVerifyEnabled bool
	totpEnrollEnabled  bool
	pilotUsers         map[string]struct{}
}

var activeMFARolloutPolicy = mfaRolloutPolicy{loginVerifyEnabled: true}

func setMFARolloutPolicyFromConfig(cfg *cfgpkg.Config) {
	policy := mfaRolloutPolicy{loginVerifyEnabled: true}
	if cfg == nil {
		activeMFARolloutPolicy = policy
		return
	}

	policy.loginVerifyEnabled = cfg.Debug.AuthMFALoginVerifyEnabled
	policy.totpEnrollEnabled = cfg.Debug.AuthMFATOTPEnrollEnabled
	if len(cfg.Debug.AuthMFATOTPPilotUsers) > 0 {
		policy.pilotUsers = make(map[string]struct{}, len(cfg.Debug.AuthMFATOTPPilotUsers))
		for _, u := range cfg.Debug.AuthMFATOTPPilotUsers {
			u = strings.ToLower(strings.TrimSpace(u))
			if u != "" {
				policy.pilotUsers[u] = struct{}{}
			}
		}
	}
	activeMFARolloutPolicy = policy
}

func mfaLoginVerifyEnabled() bool {
	return activeMFARolloutPolicy.loginVerifyEnabled
}

func MFARolloutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isTOTPEnrollPath(r.URL.Path) {
			if !activeMFARolloutPolicy.totpEnrollEnabled {
				http.Error(w, `{"error":"totp enrollment rollout is disabled"}`, http.StatusNotFound)
				return
			}
			if !isTOTPPilotUser(r) {
				http.Error(w, `{"error":"totp enrollment not enabled for this account"}`, http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isTOTPEnrollPath(path string) bool {
	return path == "/mfa/totp/enroll/start" || path == "/mfa/totp/enroll/confirm" ||
		path == "/cfm-admin/mfa/totp/enroll/start" || path == "/cfm-admin/mfa/totp/enroll/confirm"
}

func isTOTPPilotUser(r *http.Request) bool {
	if len(activeMFARolloutPolicy.pilotUsers) == 0 {
		return true
	}
	user, ok := authUserFromContext(r.Context())
	if !ok {
		return false
	}
	_, ok = activeMFARolloutPolicy.pilotUsers[strings.ToLower(strings.TrimSpace(user.Username))]
	return ok
}
