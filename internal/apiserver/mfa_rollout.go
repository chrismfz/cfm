package apiserver

import (
	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
)

// mfaRolloutPolicy is what is left of the staged MFA rollout: the switch for
// the verification step at login.
//
// There used to be a second gate, for TOTP enrollment
// (AUTH_MFA_TOTP_ENROLL_ENABLED, AUTH_MFA_TOTP_PILOT_USERS), enforced by a
// middleware that matched /mfa/totp/enroll/*. Enrollment is served at
// /me/security/mfa/totp/enroll/*, so the gate never matched a real request:
// enrollment was open to every cfm-admin user on every node, whatever the two
// keys said. It was retired (2026-11) rather than repaired, because repairing
// it would have switched enrollment off wherever the keys still held their
// shipped defaults. The keys are still parsed, so an existing cfm.conf loads,
// and are ignored.
type mfaRolloutPolicy struct {
	loginVerifyEnabled bool
}

var activeMFARolloutPolicy = mfaRolloutPolicy{loginVerifyEnabled: true}

func setMFARolloutPolicyFromConfig(cfg *cfgpkg.Config) {
	policy := mfaRolloutPolicy{loginVerifyEnabled: true}
	if cfg == nil {
		activeMFARolloutPolicy = policy
		return
	}

	policy.loginVerifyEnabled = cfg.Debug.AuthMFALoginVerifyEnabled
	if cfg.Debug.AuthMFATOTPEnrollKeysSet {
		logging.LogfAPI("[apiserver] NOTE: AUTH_MFA_TOTP_ENROLL_ENABLED and AUTH_MFA_TOTP_PILOT_USERS are retired and ignored — TOTP enrollment is available to every cfm-admin user (it always was: the gate never matched the enrollment routes). Remove them from cfm.conf.")
	}
	activeMFARolloutPolicy = policy
}

func mfaLoginVerifyEnabled() bool {
	return activeMFARolloutPolicy.loginVerifyEnabled
}
