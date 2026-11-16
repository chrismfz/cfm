# MFA controlled rollout & regression checklist

This runbook stages MFA in phases so existing API/automation auth remains stable.

## Phase 1 — Login MFA verification wiring (config-gated)

1. Deploy code with `AUTH_MFA_LOGIN_VERIFY_ENABLED=true` (default).
2. Verify `/cfm-admin/login` still accepts password-only users and only redirects to `/cfm-admin/login/verify` for MFA-required sessions.
3. If rollback is needed, set `AUTH_MFA_LOGIN_VERIFY_ENABLED=false` and restart cfm.
   **This locks out every account that has TOTP enabled**: their login stops
   at the MFA step, which is then switched off. Before rolling back, reset
   MFA for those accounts (`cfm auth mfa reset --username <user> ...`, Phase 3)
   or keep the switch on. While it is off, enrollment start answers `409`, so
   no account enrolls into that state.

## Phase 2 — TOTP enrollment from user settings

Enrollment is available to every cfm-admin user while
`AUTH_MFA_LOGIN_VERIFY_ENABLED` is on (with it off, enrollment start answers
`409`: see Phase 1). There is no other rollout switch for it: `AUTH_MFA_TOTP_ENROLL_ENABLED` and `AUTH_MFA_TOTP_PILOT_USERS` were
retired in 2026-11. Their gate matched `/mfa/totp/enroll/*`, while enrollment
is served at `/me/security/mfa/totp/enroll/*`, so it never restricted anyone.
The keys are still accepted in `cfm.conf` and ignored; the daemon logs a note
at start when either is present.

Check, in Settings or with `POST /cfm-admin/me/security/mfa/totp/enroll/start`
and `.../confirm`:

1. `enroll/start` with a session alone answers `401 re-authentication
   required (password or recent MFA proof)`; with `{"password": "..."}` it
   answers 200. Settings sends the password from the field next to the
   button. Within 10 minutes of an MFA login no password is needed.
2. The answer carries `qr_data_url`, a PNG made on the node. The page shows
   it and makes no request to any other host (browser network tab). The
   `otpauth://` URI contains the TOTP secret and must not leave the node.
3. Starting an enrollment on an account that already has MFA leaves MFA on:
   the old authenticator keeps working until the new code is confirmed.
4. The code used to confirm cannot be used again to log in; the next one
   works.

## Phase 3 — CLI admin recovery/reset tooling for support

Use cfm auth CLI as support-only operations:

```bash
cfm auth mfa reset --username <user> --actor <support-user> --reason "ticket-123"
cfm auth mfa recovery-regenerate --username <user> --actor <support-user> --reason "ticket-123"
cfm auth mfa status --username <user>
```

## Regression checklist

### Login success/failure matrix

| Scenario | Expected |
|---|---|
| Valid password, no MFA configured | `/cfm-admin/login` success, session created |
| Valid password, MFA required, verify enabled | redirect to `/cfm-admin/login/verify` |
| Valid password, MFA required, verify disabled | no verify redirect; upstream MFA-required payload returned |
| Invalid password | `401` JSON error |
| Invalid `/login/verify` code | `401` JSON error |

### Recovery code one-time-use behavior

- Enroll MFA and generate recovery codes.
- Use one recovery code once at `/cfm-admin/login/verify` with `method=recovery_code`.
- Reuse same code and confirm failure (`401`).
- Regenerate recovery codes and confirm old codes no longer work.

### Audit log event verification for MFA operations

Confirm auth audit entries include actor/target/reason/event for:

- MFA reset (`mfa_reset`)
- MFA recovery regeneration (`mfa_recovery_rotate`)
- MFA enrollment and verification events from login and user settings workflows.

## Non-session access regression guardrails (must remain unchanged)

- Bearer-token API clients:
  - representative endpoint: `GET /api/v1/system/status` with `Authorization: Bearer <token>`
- Trusted-IP routes:
  - allowlisted source IP should continue to bypass session auth as before.
