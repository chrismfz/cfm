# MFA controlled rollout & regression checklist

This runbook stages MFA in phases so existing API/automation auth remains stable.

## Phase 1 — Login MFA verification wiring (config-gated)

1. Deploy code with `AUTH_MFA_LOGIN_VERIFY_ENABLED=true` (default).
2. Verify `/cfm-admin/login` still accepts password-only users and only redirects to `/cfm-admin/login/verify` for MFA-required sessions.
3. If rollback is needed, set `AUTH_MFA_LOGIN_VERIFY_ENABLED=false` and restart cfm.

## Phase 2 — Pilot-only TOTP enrollment from user settings

1. Keep global gate off initially: `AUTH_MFA_TOTP_ENROLL_ENABLED=false`.
2. Define pilot users:
   - `AUTH_MFA_TOTP_PILOT_USERS=""` (default: no pilot users)
   - `AUTH_MFA_TOTP_PILOT_USERS=alice,bob` (comma-separated usernames; pilot-only behavior applies when global enrollment remains disabled)
3. Enable enrollment gate:
   - `AUTH_MFA_TOTP_ENROLL_ENABLED=true`
4. Confirm only pilot users can access:
   - `POST /cfm-admin/mfa/totp/enroll/start`
   - `POST /cfm-admin/mfa/totp/enroll/confirm`

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
