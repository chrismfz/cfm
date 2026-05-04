# Challenge scope mapping and host binding

## Canonical derivation (shared model)

CFM now uses one canonical model across challenge token issuance (Go) and Lua validation:

- Web listeners derive scope as `web`.
- Panel listeners derive scope as `panel:<forwarded_port>`.
- Host identity is derived from trusted forwarded host (`X-Forwarded-Host`) and normalized (lowercase, no trailing dot, no port).

## Old behavior vs new behavior

### Old behavior
- `cfm_ok` was accepted as transitional solved marker and replay risk was higher across listener contexts.
- Challenge host/scope checks were less explicit about forwarded host/port guardrails in sensitive challenge endpoints.

### New host-bound model
- `cfm_clearance` is authoritative and bound to `ip + normalized_host + exact_scope`.
- `cfm_ok` remains migration-only and non-authoritative.
- Challenge/verify endpoints enforce forwarded-host presence and reject invalid/missing forwarded-port for panel scope contexts.

## Migration notes (`cfm_ok`)

- Legacy `cfm_ok` can still be issued for compatibility, but do not rely on it for cross-host or cross-scope pass state.
- Prefer validating behavior with `cfm_clearance` only.
- During rollout, monitor challenge logs for `host_mismatch` and `scope_mismatch` to identify stale or replayed cookies.

## Manual verification checklist

Use these commands from a test host (replace hostnames/ports):

```bash
# 1) Solve on web scope
curl -isk https://web-a.example.com/__cfm_challenge?next=%2F -c /tmp/web.cookies

# 2) Attempt replay on different web host (must fail with challenge / mismatch)
curl -isk https://web-b.example.com/ -b /tmp/web.cookies

# 3) Solve on panel scope (2083)
curl -isk https://panel-a.example.com:2083/__cfm_challenge?next=%2F -c /tmp/panel2083.cookies

# 4) Replay panel cookie to another panel port (2087) (must fail)
curl -isk https://panel-a.example.com:2087/ -b /tmp/panel2083.cookies

# 5) Replay panel cookie to web scope (443) (must fail)
curl -isk https://web-a.example.com/ -b /tmp/panel2083.cookies

# 6) Forwarded-header negative test: missing X-Forwarded-Host to verify endpoint (must be 400)
curl -isk https://challenge-backend.example.com/__cfm_verify -X POST
```
