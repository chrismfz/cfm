# CFM Improvements

This file records product/security improvements that should remain visible even when they are not yet implemented. It complements `Audit.md` and is intentionally implementation-oriented.

## CFM control-plane protection: `api_abuse` -> `cfm_endpoints`

### Decision

Evolve/rename the existing `api_abuse` detector into a first-class **`cfm_endpoints`** detector that protects CFM's own admin/API surface through the same detector/sink/enforcement/notification pipeline used for Exim, Dovecot, cPanel, WAF, etc.

This protection is a **built-in product safety feature and must be ON by default even when no `[cfm_endpoints]` section or entire `detectors.conf` file exists.**

Desired config semantics:

```ini
; Optional. Absence does NOT disable CFM endpoint protection.
[cfm_endpoints]
; values here override built-in defaults
```

Implementation rule:

- if `[cfm_endpoints]` exists, instantiate it with built-in defaults plus operator overrides;
- if it does not exist, instantiate one implicit/synthetic `cfm_endpoints` detector with safe built-in defaults;
- disabling it, if we decide to support that at all, should require an explicit opt-out rather than omission of config;
- keep `[api_abuse]` temporarily as a deprecated compatibility alias/migration path, but do not run both detectors against the same event stream;
- emit a one-time deprecation warning when `[api_abuse]` is used.

The detector should continue to use **structured in-process security events** as its enforcement input. Logs are for audit/forensics and may also be parsed by tools, but should not become the primary IPC mechanism between the apiserver and detector.

### Existing protection to preserve and consolidate

Today CFM already has useful protection, but it is split across mechanisms:

- login application throttling / account lock in `internal/apiserver/login_rate_limit.go`;
- `internal/apiserver/auth_autoblock.go` polls goauth `auth_log` and performs an nft block after repeated login failures;
- `internal/apiserver/security_log.go` classifies API anomalies and publishes structured `APIAnomalyEvent` values;
- `[api_abuse]` subscribes to those events and already supports staged observe -> challenge -> detector-sink block behaviour.

The target design is to consolidate enforcement through `cfm_endpoints` and the normal detector sink so CFM gets the same capabilities as other protected services:

```text
CFM admin/API event
    -> structured security event
    -> cfm_endpoints
    -> detector section policy
    -> global IGNORE / leniency
    -> challenge and/or nft block
    -> block reporting
    -> cfm.detector.log
    -> Slack/mail notification pipeline
```

`auth_autoblock.go` should eventually become redundant once login failure events are fed to `cfm_endpoints` with equivalent or better thresholds/tests. Do not remove it until parity is proven.

### Signals / event families

Initial detector inputs should include at least:

```text
AUTH_LOGIN_FAIL
AUTH_LOGIN_RATE_LIMIT
AUTH_ACCOUNT_LOCK

AUTH_TOKEN_INVALID
AUTH_TOKEN_MALFORMED
AUTH_TOKEN_EXPIRED          (if distinguishable without leaking token details)
AUTH_SCOPED_DENIED
AUTH_SCOPE_VIOLATION

ENDPOINT_404_BURST
ENDPOINT_METHOD_PROBE
ENDPOINT_SENSITIVE_PROBE
ENDPOINT_FUZZ

API_RATE_LIMIT
API_HEAVY_ENDPOINT_BURST

CHALLENGE_FAIL / CHALLENGE_VERIFY_ABUSE
CSRF_REJECT / ORIGIN_REJECT
```

Later, the per-auth-mechanism rate limiter can emit authenticated-abuse signals such as a valid token/client making excessive expensive requests.

Important policy distinction: a valid admin/scoped credential behaving badly is not automatically equivalent to an unauthenticated hostile IP. Prefer credential-level throttling + notification first; do not blindly nft-block a trusted cfm-web source because a valid admin token entered a runaway loop.

## `cfm.api.log` as the canonical one-line control-plane audit trail

Keep using **`cfm.api.log`** rather than introducing another overlapping admin log.

The goal is a stable, grep/awk/parser-friendly **one physical line per authentication attempt** and one-line records for significant control-plane security decisions.

### Login attempts

Every credential attempt should append one line, success or failure. Example shape:

```text
[apiserver] event=auth_attempt kind=login result=fail src_ip=203.0.113.10 peer_ip=127.0.0.1 entry=edge scheme=https user=admin method=POST path=/login status=401
[apiserver] event=auth_attempt kind=login result=success src_ip=203.0.113.10 peer_ip=127.0.0.1 entry=edge scheme=https user=admin method=POST path=/login status=200 mfa=required
```

Also log MFA/passkey/recovery verification attempts as separate one-line auth events where useful, e.g. `kind=mfa_totp`, `kind=mfa_passkey`, `kind=recovery_code`, without recording submitted codes/assertions.

### Token/API authentication attempts

Every supplied token authentication attempt should append one line, success or failure. Example shapes:

```text
[apiserver] event=auth_attempt kind=token result=success src_ip=203.0.113.20 entry=6061 scheme=https auth_mech=token_admin method=GET path=/api/v1/system/status status=200

[apiserver] event=auth_attempt kind=token result=success src_ip=203.0.113.30 entry=edge scheme=https auth_mech=token_scoped token_id=42 method=GET path=/api/v1/webdet/drilldown status=200

[apiserver] event=auth_attempt kind=token result=invalid src_ip=203.0.113.40 entry=6061 scheme=https auth_mech=unknown method=GET path=/api/v1/system/status status=401
```

Rules:

- **never log raw bearer/token material**;
- never log passwords, MFA codes, WebAuthn assertions, request bodies, session IDs or clearance-cookie values;
- for a valid scoped token, a stable non-secret `token_id` is useful;
- for the global admin token, use `auth_mech=token_admin`; no secret-derived value is required unless a safe non-secret credential ID is introduced later;
- invalid token attempts need no token fingerprint by default; IP + request metadata is enough for abuse detection;
- log a supplied invalid token as an auth failure even if a valid browser session cookie also exists; invalid explicit bearer credentials must never silently fall back to session auth.

### Common fields

Use a single helper/schema so login, token, rate-limit and authorization-denial events agree on identity semantics:

```text
event
kind
result / reason
src_ip
peer_ip
entry=edge|6060|6061|other
effective scheme=http|https
auth_mech=session_cookie|token_admin|token_scoped|embed_bootstrap_cookie|unknown
safe user/token_id when applicable
method
path
status
request_id (recommended)
```

`src_ip` and `scheme` must come from the trusted-request identity/effective-scheme work documented in `Audit.md`, not directly from attacker-controlled forwarded headers.

Keep the line format deterministic enough that detectors/support tools can parse `key=value` tokens without multiline state. Values that can contain spaces/quotes should be consistently quoted/escaped.

## Detector policy notes

The existing `api_abuse` staged model is useful but should become easier to reason about. Avoid hidden double aggregation where an HTTP classifier emits only every Nth event and the detector then applies another large threshold without documenting the effective raw-request threshold.

Prefer named signal thresholds/policies where confidence differs. Examples:

- repeated wrong passwords -> app throttle/account lock first, then detector TTL block;
- repeated invalid bearer attempts -> throttle + detector TTL block;
- `.env`, `.git`, traversal/fuzz probing of the CFM listener -> high-confidence short TTL block can happen faster;
- scope violations from a valid scoped credential -> alert/throttle conservatively; investigate before aggressive IP blocking;
- valid admin token excessive rate -> credential-level rate limiting + high-severity notification, not automatic nft block by default.

All nft enforcement should continue through the normal detector section sink so global ignore, leniency, cooldown, reporting, `cfm.detector.log`, and Slack/mail behavior remain consistent.

## Acceptance checklist

- [x] `cfm_endpoints` exists as the canonical detector name.
- [x] Protection runs with built-in defaults even when no detector section is present.
- [x] `[api_abuse]` is a deprecated alias/migration path and does not create duplicate subscriptions/double counting.
- [x] Every login credential attempt writes exactly one parse-friendly `cfm.api.log` auth-attempt line.
- [x] MFA/passkey verification failures/successes have safe one-line audit records where applicable.
- [x] Every supplied API token authentication attempt writes exactly one auth-attempt line.
- [x] No secrets/passwords/codes/session IDs/tokens are written to the log.
- [x] Structured events, not log tailing, feed `cfm_endpoints` enforcement.
- [x] Login failures are fed into the detector pipeline.
- [x] Existing login throttle/account-lock behavior is preserved.
- [ ] Existing `auth_autoblock` is removed only after detector enforcement parity is proven.
- [x] Invalid-token bursts can produce detector notifications and a bounded TTL nft block.
- [ ] Valid-token high-rate abuse is rate-limited by credential/mechanism before considering IP blocking.
- [x] Outcomes continue through `cfm.detector.log`, reporting and Slack/mail notification paths.
- [x] XFF/effective-scheme regression tests cover edge, direct 6060 and direct 6061 entry points.
- [x] `[global]` `IGNORE_IPS`/`IGNORE_NETS`, loopback and refreshed self IPs are discarded before detector counting.
