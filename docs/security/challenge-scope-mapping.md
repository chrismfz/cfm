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
- The clearance cookie is authoritative and bound to `ip + normalized_host + exact_scope`.
- **The cookie name is per-scope** (edge-unification Phase 2a): web mints
  `cfm_clearance`, panel scopes mint `cfm_clearance_p<port>` (e.g.
  `cfm_clearance_p2087`). Browsers do not isolate cookies by port, so the
  previously shared name let a panel solve clobber the web token (and vice
  versa) — the per-scope name removes the clobber. `cfm_panel.lua` still
  accepts a panel-scoped token under the legacy shared name (upgrade lag)
  and migrates it to the scoped name on refresh; scope validation is
  HMAC-bound either way.
- `cfm_ok` remains migration-only and non-authoritative.
- Challenge/verify endpoints enforce forwarded-host presence and reject invalid/missing forwarded-port for panel scope contexts.

## Migration notes (`cfm_ok`)

- Legacy `cfm_ok` can still be issued for compatibility, but do not rely on it for cross-host or cross-scope pass state.
- Prefer validating behavior with the clearance cookie only (`cfm_clearance` on web, `cfm_clearance_p<port>` on panel).
- During rollout, monitor challenge logs for `host_mismatch` and `scope_mismatch` to identify stale or replayed cookies. Note: with per-scope names a cross-port replay usually never reaches the validator (the other port's cookie is simply not read), so `scope_mismatch` now mostly appears for tokens arriving via the legacy shared-name fallback; also watch `[cfm_panel_loop_break]` rates during the upgrade window.

## Validation-path carve-out (`/.well-known/`)

Certificate domain-control validation is fetched by the CA over **plain HTTP**
and must always reach the origin, never the challenge interstitial:

- Let's Encrypt / cPanel AutoSSL HTTP-01 → `/.well-known/acme-challenge/<token>`
- commercial CAs (Sectigo / DigiCert) HTTP DCV → `/.well-known/pki-validation/<file>`

Both Lua listeners exempt the whole `/.well-known/` prefix **before** any
challenge decision:

- main web listener — `cfm.lua` Step 0a1 routes `/.well-known/` to the origin
  (`X-CFM-Bypass: well-known`) ahead of the WAF, forced-challenge, and bridge
  vhost/per-IP challenge steps;
- panel listeners (2083/2087) — `cfm_panel.lua` `is_exempt_path`.

**Why this matters:** a forced/auto vhost challenge such as

```ini
# detectors.conf
CHALLENGE_VHOST = victim.com, cpanel.*, whm.*, webmail.*
```

would otherwise intercept the validation request on the very service
subdomains it targets (`cpanel.<domain>`, `webmail.<domain>`, …). The CA then
receives the CFM interstitial HTML instead of the token and AutoSSL reports:

```
403 urn:ietf:params:acme:error:unauthorized
Invalid response from http://cpanel.<domain>/__cfm_challenge?next=%2F.well-known%2Facme-challenge%2F...
```

The carve-out is `/.well-known/`-wide on purpose: it is the RFC 8615 reserved
namespace for validation/metadata (also `security.txt`, `mta-sts.txt`,
`apple-app-site-association`, …) and matches what cPanel / Imunify /
ModSecurity-CRS and `cfm_panel.lua` do. The ordering invariant is enforced by
`scripts/tests/cfm_well_known_carveout_test.lua` (run via `make test-lua`).

**Accepted trade-off:** the carve-out routes to the origin *before* the WAF
rule engine, so it skips WAF for the whole prefix, not only the challenge. A
few `/.well-known/` endpoints can be application-routed
(`/.well-known/webfinger`, `/.well-known/openid-configuration`) and therefore
lose WAF inspection. This is bounded — `uri` is decoded and dot-normalized so
there is no traversal-out-of-prefix evasion, and the request still reaches the
normal origin (a WAF-skip, not an auth bypass). If WAF coverage on app-routed
`.well-known` endpoints is needed, scope the carve-out to `acme-challenge/` +
`pki-validation/` only.

## Operator carve-out (Challenge Access-Control)

Where `/.well-known/` and the FCrDNS good-bot downgrade are *built-in* challenge
carve-outs, **Challenge Access-Control** is the operator-managed one: a
per-vhost/global allow-list (`internal/webdetector/challenge_access.go`, store
`/var/lib/cfm/webdetector_challenge_access.json`, CRUD under
`/api/v1/challenge/access/*`) whose entries EXEMPT matching requests from the
interactive challenge by country / URL-path / user-agent / IP-CIDR / ASN /
verified-crawler.

Its scope model is the same host-bound tenant boundary used everywhere else in
this doc:

- **Enforcement** is a challenge→allow downgrade in `nginx_bridge.go`
  `handleDecision`, applied *after* the good-bot downgrade and *before* the
  response is built. Like `goodBotDowngrade` it **never softens a per-IP block**
  and leaves the WAF / traffic-rule engine fully armed; unknown country/ASN
  **fail open** (never match), so a geo/enrich hiccup can neither grant nor deny
  an exemption.
- **Tenant isolation** reuses `scopeAllowsVhosts`/`scopeFilterChallengeAccess`
  (shared with `/api/v1/webdet/rules/*`): a scoped token may create the richer
  multi-dimension entries, but only pinned to vhosts inside its own allowlist —
  it can never author an exemption that reaches another tenant's vhost, and a
  vhost-less scoped token is denied. See
  `docs/endpoint_scope_inventory.md` and `docs/challenge-access-control.md`.
- **DNAT vs in-path:** the downgrade runs in the in-path decision, so
  path/UA/country/method dimensions apply in OpenResty/Angie mode only; in DNAT
  mode a flagged IP is redirected before the in-path decision, so only
  host/ASN/IP-level intent takes effect there (same class of caveat as the
  `/.well-known/` two-sided treatment).

Verify:

```bash
# Must return the token (or 404 from the origin), never the CFM interstitial,
# even while the host is under a forced vhost challenge.
curl -is "http://cpanel.<domain>/.well-known/acme-challenge/test-token" | head -n1
curl -is "http://cpanel.<domain>/.well-known/acme-challenge/test-token" | grep -i '^X-CFM-Bypass:'
```

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
