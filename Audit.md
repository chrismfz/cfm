# CFM external control-plane security audit / handoff

**Status:** planning / audit handoff — no behavioural code change in this document.

**Snapshot originally reviewed:** `main` at `df6586192754fc774b9049ba55f6658e304e8077` (`2026.08.23` release).

**Primary target surface:**

- `https://<hostname>/cfm-admin/` — Angie/OpenResty edge -> Go apiserver on loopback `:6060`.
- `http://<hostname>:6060/cfm-admin/` — direct Go HTTP listener.
- `https://<hostname>:6061/cfm-admin/` — direct Go TLS listener.
- `:9098` — challenge service transport; intended to remain loopback-only and be reused internally, not become a second public control plane.
- `/api/v1/*` plus related authenticated routes such as `/unblock`, `/search`, `/mcp`, etc.

This file preserves the reasoning, historical failures and the intended **small-step remediation order** so a dedicated security/audit session (including GSC/headless-browser tooling) can continue without rediscovering the architecture or repeating old mistakes.

---

## 0. Threat model and constraints

The current product direction is that `6060` / `6061` are not assumed to be hidden internal/debug ports. The Go apiserver is also the direct/fallback host for `cfm-admin`, and `cfm-web` reaches fleet nodes over the API (normally HTTPS `:6061`). The listeners therefore must be safe **when Internet-reachable**.

Existing first-class flows that must not be broken:

1. **Normal CFM admin browser session** — goauth session + MFA/CSRF.
2. **CFM Web / fleet controller** — admin bearer token.
3. **cPanel/hosting-panel plugin** — scoped bearer token and/or embedded bootstrap flow.
4. **Scoped embedded browser** — short-lived scoped embed cookie.
5. **MCP** — self-authenticated bearer/OAuth surface; it intentionally bypasses normal session/token middleware and applies its own auth gate.

The security model must distinguish **authentication mechanism + role/scope**, not split the product into artificial “browser APIs” and “machine APIs”. The same `/api/v1/*` endpoints are legitimately consumed by several mechanisms above.

### Non-goals for the first implementation pass

- Do not resurrect the retired per-IP challenge-DNAT machinery.
- Do not globally IP-allowlist `/api/v1/*`; that would break scoped/plugin/browser flows.
- Do not require challenge/PoW for machine bearer-token calls.
- Do not duplicate the challenge algorithm in the apiserver.
- Do not perform brute force, destructive writes, mass blocking, or high-rate load testing against production during the external audit.

---

# 1. Unify CFM Admin pre-auth challenge across edge, `:6060` and `:6061`

## Desired behaviour

The challenge should be a property of the **CFM control plane**, not a side effect of entering through Angie.

```text
https://host/cfm-admin/         -> CFM pre-auth challenge -> login -> admin
https://host:6061/cfm-admin/    -> CFM pre-auth challenge -> login -> admin
http://host:6060/cfm-admin/     -> redirect to :6061 when direct TLS is usable
                                -> otherwise degraded HTTP fallback, still challenge-gated
```

Machine/scoped traffic remains untouched:

```text
cfm-web + valid admin bearer       -> API directly, no PoW
cPanel scoped bearer               -> scoped API directly, no PoW
valid embed bootstrap cookie       -> scoped UI/API directly, no PoW
MCP bearer/OAuth                   -> MCP's own auth, no admin-login PoW
```

The challenge is a **pre-auth browser gate**, not an authorization mechanism. Password/session/token authorization remains authoritative.

## Preferred architecture: reuse the existing Go challenge implementation

`internal/webdetector/challenge_server.go` already owns PoW, verification, signed clearance, safe `next` normalization, rate limiting and post-solve redirect. Do **not** create a second implementation in `internal/apiserver`.

Refactor so one implementation can serve both transports:

```text
ChallengeServer
    |
    +-- Handler / RegisterHandlers
    |      +-- /__cfm_challenge
    |      `-- /__cfm_verify
    |
    `-- existing standalone Serve()
           `-- 127.0.0.1:9098 (edge compatibility)
```

The apiserver should mount the exact same challenge/verify handlers for direct `6060`/`6061`. Keep `9098` for the edge path if needed, but there must be one token format, one verifier and one set of safety rules.

### Clearance validation

The authoritative solved marker is the signed `cfm_clearance` cookie; legacy `cfm_ok` is transitional/non-authoritative. Existing tests bind clearance to:

- client IP,
- normalized hostname (port removed),
- clearance scope (`web` / panel scope),
- expiry,
- HMAC secret.

The new Go pre-auth gate should export/reuse the existing verifier.

**Pre-check:** confirm the bridge/clearance signing secret is always available when challenge service is enabled even without edge/DNAT. If not, fix secret lifecycle once; do not introduce a second “direct admin challenge secret”.

## Gate only the interactive login flow

Do not challenge every `/cfm-admin/*` request. The current auth flow already redirects an unauthenticated browser from protected admin UI routes to login, which gives a narrow pre-auth gate without touching API/assets/embed traffic.

Recommended semantics:

- `GET/HEAD /login` and `/cfm-admin/login`:
  - valid admin session -> normal flow,
  - valid clearance -> serve login,
  - no clearance -> redirect to `/__cfm_challenge?next=<original-login-url>`.
- Login POST and MFA/WebAuthn login sub-flow:
  - valid clearance -> normal handler,
  - missing/invalid clearance -> fail closed as `challenge_required`; **direct POST must not bypass PoW**.
- Assets, `/api/v1/*`, embed/bootstrap and machine bearer traffic are not challenge candidates.

```text
GET /cfm-admin/login
  -> 302 /__cfm_challenge?next=/cfm-admin/login
  -> solve
POST /__cfm_verify?next=/cfm-admin/login
  -> signed cfm_clearance
  -> 303 /cfm-admin/login
  -> normal Go login page
```

This deliberately avoids dynamically proxying the *login URI itself* to the challenge upstream — the design that previously caused prefix/redirect trouble.

### Placement in auth code

The old Go pre-auth gate ran early enough to exempt bearer/plugin/bootstrap flows. Reuse that **classification idea**, not the retired DNAT enforcer.

A clean implementation may be a narrow `maybeHandleAdminLoginChallenge()` adjacent to `TokenMiddleware`, or a pre-auth middleware after session loading that shares the existing auth classification helpers. Do not independently re-parse auth in several middleware layers.

Current mechanisms already have explicit identities:

- `session_cookie`
- `token_admin`
- `token_scoped`
- `embed_bootstrap_cookie`

---

## Historical warning: we already broke this once

Keep this history with the implementation. The current edge config still contains misleading/dead intent (`$cfm_force_challenge=1`), and it is easy to recreate the old bug.

### 2026-04-18 — PR #246: Go pre-auth challenge gate

PR `#246` (“Pre-auth challenge gate for interactive admin login flows”) added `internal/apiserver/login_challenge.go`.

Good ideas worth preserving:

- interactive browser login only,
- bearer/API/bootstrap/plugin exemptions,
- authenticated session bypass,
- integration tests proving embed/API calls stay unaffected.

Do **not** preserve its enforcement mechanism: it called firewall `AddChallenge()` and depended on the old per-IP challenge-DNAT path.

### 2026-04-20 — forced edge challenge

Commit `b041f9996fd27de40d157ef8d192ccd0e75a1daa` set `$cfm_force_challenge=1` for `/cfm-admin/login*`, and Lua could select `cfm_challenge`.

### Failure #1: Lua selected challenge, nginx still sent Go

Commit `dea270e29661b73c9bca7444c36577c2827cc9d3` documents the exact symptom:

> logs showed **`up=cfm_challenge` but `uaddr=127.0.0.1:6060`**.

The location had hardcoded `proxy_pass http://127.0.0.1:6060`, so the Lua upstream decision had no effect. A dynamic map was added to select Go vs challenge.

### Failure #2: redirect/prefix loops

Once login really reached challenge upstream, root-relative redirects escaped/interacted badly with the `/cfm-admin` mount.

- PR `#316`: tried to repair root redirects under `/cfm-admin`.
- PR `#317`: narrowed rewriting because the wider rewrite could loop.
- PR `#318` / commit `5a1fbabfd354651703f15a6e3fbe74ac1b750a75`: reverted login to direct Go to stop challenge/WAF proxy hops interfering with login.

Current config still says forced challenge should apply but also hardcodes Go, so the old `$cfm_force_challenge` cannot actually select challenge. Treat that as documentation/config drift, not active protection.

### 2026-08-11 — edge unification removed DNAT-era challenge gate

Commit `e40cce8fec293091f60d5ee3c48433a6b4a94a44` removed:

- per-IP challenge sets/redirect machinery,
- old `9099` daemon TLS challenge listener,
- `AddChallenge`/`RemoveChallenge` DNAT enforcement,
- the old `internal/apiserver/login_challenge.go` subsystem.

Do not revert this. New admin challenge is HTTP-level redirect/clearance backed by the existing ChallengeServer.

---

# 2. Direct `:6060/cfm-admin` -> `:6061` when TLS is actually usable

## Goal

`6061` is the preferred direct browser transport. `6060` remains because API deployments may explicitly use HTTP, it is the edge backend hop, and the product wants a browser fallback if TLS genuinely cannot operate.

Therefore **never globally redirect all requests on `6060`**.

### Critical distinction: direct HTTP vs edge backend HTTP

This is HTTPS to the user even though the final hop is HTTP:

```text
Browser -> HTTPS :443 -> Angie -> HTTP 127.0.0.1:6060 -> Go
```

It must **not** become a redirect from public `:443` to public `:6061`.

Only a direct external browser request is a candidate:

```text
Browser -> http://host:6060/cfm-admin/
```

Use immediate-peer trust, not spoofable forwarded headers, to distinguish these cases.

## “6061 exists” means runtime-ready, not configured

Do not redirect only because `TLS_PORT > 0`.

Preferred startup sequence:

1. Build auth/handler state.
2. Attempt the TLS listener bind first when configured and SSLCollector exists.
3. Mark `tlsListenerReady=true` only after successful bind.
4. Define/verify SNI certificate behaviour before redirecting that hostname.
5. Start HTTP listener with transport policy aware of runtime TLS readiness.
6. Serve TLS.

## Redirect semantics

For **direct** `6060` admin GET/HEAD while TLS is ready:

```text
http://host:6060/cfm-admin/... -> https://host:6061/cfm-admin/...
```

- Preserve request URI.
- Build/validate Host safely (`net.SplitHostPort`, `net.JoinHostPort` for IPv6).
- Do not trust forwarded host from a direct client.

For unsafe methods, do not process credentials and then redirect. If direct HTTP receives login/session-changing admin POST while TLS is healthy, reject with HTTPS-required semantics (optionally with `Location`). A credential body that already traversed HTTP cannot be made safe retroactively.

## Degraded fallback

If TLS did not bind / is genuinely unavailable, direct `6060/cfm-admin` may remain usable as an explicit degraded fallback, still protected by the same pre-auth challenge gate.

Log visibly, e.g.:

```text
event=admin_http_fallback reason=tls_listener_unavailable host=...
```

This is a resilience feature, not an assertion that HTTP equals TLS.

---

# 3. Trusted client identity and effective scheme (XFF/XFP hardening)

This section is a prerequisite for both challenge and automatic cookie security.

## Current XFF issue

CFM-admin proxy blocks currently use:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

and `realIPFromRequest()` trusts the whole XFF string when the immediate peer is loopback. An attacker can supply an XFF prefix and make Go use a chain string as rate/log identity.

This does not bypass auth, but weakens IP throttling/anomaly attribution and any future source-bound policy.

## Canonical edge -> Go contract

For **CFM control-plane proxy locations only**, Angie already owns real-IP normalization. Replace user-chain preservation with one canonical value:

```nginx
proxy_set_header X-Real-IP       $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
```

Do not blindly apply this to customer-origin proxy semantics without a separate review.

## Important current omission: CFM-admin does not forward scheme

The current `/cfm-admin/login`, `/cfm-admin/` and embed-bootstrap proxy blocks send Host/client-IP/prefix headers but do **not** send `X-Forwarded-Proto` to Go.

That becomes a bug as soon as cookie security is automatic: for

```text
Browser HTTPS -> Angie -> HTTP 127.0.0.1:6060 -> Go
```

`r.TLS` is nil in Go, but the **effective user-facing scheme is HTTPS**.

Add to every Angie/OpenResty -> Go CFM control-plane proxy block:

```nginx
proxy_set_header X-Forwarded-Proto $cf_xfp;
```

Use `$cf_xfp`, not raw `$http_x_forwarded_proto` and preferably not just `$scheme`. Commit `6ef61e8ada7734d5932a934ced51e12d6b4880fd` already hardened `$cf_xfp`: forwarded proto is honored only when the request came through the trusted real-ip proxy relationship; otherwise it falls back to the real edge `$scheme`. This also preserves an original HTTPS scheme behind a trusted TLS-terminating upstream where appropriate.

## One Go helper for client identity + effective scheme

Create one tested helper, conceptually:

```go
type RequestPeer struct {
    ImmediateIP  net.IP
    ClientIP     net.IP
    TrustedProxy bool
    Scheme       string // "http" or "https"
}
```

Rules:

1. Parse `RemoteAddr` first.
2. A direct request never trusts forwarded client/scheme headers.
3. Trusted proxy means the **immediate peer is explicitly trusted**. For the CFM Angie backend contract, loopback is the primary trusted peer. Additional proxy CIDRs must be explicit; do not silently trust all RFC1918/link-local sources.
4. Trusted edge client IP must resolve to exactly one parseable canonical IP; never use arbitrary comma-separated XFF text as identity.
5. Effective scheme:
   - direct `6061`: `r.TLS != nil` -> `https`;
   - direct `6060`: no TLS -> `http`, ignore spoofed `X-Forwarded-Proto`;
   - trusted proxy hop: accept exactly `http` or `https` from canonical `X-Forwarded-Proto`, otherwise fail safely to the immediate transport scheme.
6. Direct clients ignore `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`, etc.

Truth table:

```text
Direct :6061
  r.TLS != nil
  => effective scheme=https

Direct :6060
  non-trusted/non-loopback peer, r.TLS=nil
  => ignore XFP
  => effective scheme=http

Edge /cfm-admin/
  RemoteAddr=127.0.0.1:...
  X-Forwarded-Proto=https (set by our Angie from hardened $cf_xfp)
  => effective scheme=https
```

Use this single helper for:

- request logs,
- login limiter,
- future API limiter,
- challenge issue/verify IP binding,
- challenge cookie Secure decision,
- goauth session-cookie transport policy,
- CSRF origin/scheme comparisons where appropriate,
- future source binding.

## ChallengeServer direct-mount warning

Before mounting ChallengeServer on public `6060/6061`, remove assumptions that proxy headers are inherently trusted. Its current helper(s) historically accepted loopback/private/link-local proxy peers for old topologies. Public control-plane mounting requires the same explicit immediate-peer trust helper above.

---

# 4. Automatic request-aware session cookie policy

## Decision

**Do not make cookie security a permanent operator knob.** The CFM process knows whether the effective browser request is HTTP or HTTPS and should choose the correct cookie transport attributes automatically.

`AUTH_SECURE_COOKIE` should become **deprecated and ignored** after the automatic policy lands. Keep parsing it temporarily only so old fleet configs continue to load cleanly, and emit a one-time startup/config warning when present, for example:

```text
AUTH_SECURE_COOKIE is deprecated and ignored; CFM derives session-cookie security from the trusted effective request scheme
```

Later remove it from shipped examples and eventually from the parser after an appropriate compatibility window.

## Why naive `r.TLS` auto-detection would break `/cfm-admin/`

The public edge flow is:

```text
Browser -> https://host/cfm-admin/
        -> Angie
        -> http://127.0.0.1:6060
        -> Go
```

Go sees `r.TLS == nil` on the final hop. Therefore **`Secure = (r.TLS != nil)` is wrong** and would emit a non-Secure session cookie for the normal HTTPS admin URL.

The automatic policy must use `RequestPeer.Scheme` from section 3, where a trusted loopback proxy may carry canonical `X-Forwarded-Proto` and a direct client may not.

## Target HTTPS policy

```text
Effective scheme=https
    -> session cookie MUST be HttpOnly + Secure

Effective scheme=http, but TLS listener healthy and request is direct /cfm-admin
    -> do not accept browser login/session-changing traffic
    -> redirect GET/HEAD to :6061; reject unsafe methods

Effective scheme=http AND TLS genuinely unavailable
    -> explicit emergency/degraded browser fallback
```

## Important browser rule: do not reuse the same cookie name for HTTP fallback

A subtle downgrade case must be handled explicitly.

Suppose the browser already has:

```text
cfm-sid=<id>; Secure; Path=/
```

from an earlier HTTPS admin session. If TLS later fails completely, plain HTTP cannot safely replace that same-name/path Secure cookie with a non-Secure cookie. Modern cookie processing intentionally rejects a non-Secure cookie from an insecure origin when it would overlay an existing Secure cookie, as a cookie-fixing defense.

Therefore a robust emergency fallback should use a **separate cookie transport name**, for example:

```text
HTTPS / trusted-edge session:  cfm-sid
HTTP degraded fallback:        cfm-sid-http-fallback
```

The fallback cookie must never be accepted as an HTTPS “upgrade” credential automatically unless that behaviour is explicitly designed and proven safe. Prefer isolated transport names while sharing the same server-side session/auth store.

This also prevents an insecure-path session from downgrading/replacing a previously established Secure cookie.

## Current goauth limitation

CFM currently passes a static setting to the pinned `goauth` manager:

```go
SecureCookie: cfg.Debug.SecureCookie
```

and goauth configures SCS globally at construction:

```go
sm.Cookie.Name     = cfg.CookieName
sm.Cookie.HttpOnly = true
sm.Cookie.Secure   = cfg.SecureCookie
sm.Cookie.SameSite = cfg.SameSite
sm.Cookie.Path     = "/"
```

Do **not** mutate `sm.Cookie.Secure` or `sm.Cookie.Name` per request on one shared SessionManager; concurrent requests could race and leak one request's cookie transport policy into another.

Preferred solution: add a clean request-aware cookie transport capability to `goauth` using the same session DB/store, with two policy profiles if necessary:

```text
secure profile:
    name=cfm-sid
    Secure=true

http emergency profile:
    name=cfm-sid-http-fallback
    Secure=false
```

The implementation must avoid opening duplicate independent auth/session DB managers merely to get different cookie flags. If two SCS transport managers are used internally, they should share one underlying session store/DB lifecycle and be selected safely per request. Verify SCS context/session semantics with tests before choosing that implementation.

Do not use response-header regex/string rewriting as the first choice, and do not mutate a global cookie config under concurrency.

## Migration / deprecation plan

1. Add trusted effective-scheme helper and edge `X-Forwarded-Proto $cf_xfp` contract.
2. Add request-aware cookie transport support in `goauth` with tests.
3. Wire CFM:
   - HTTPS edge/direct 6061 -> secure profile;
   - direct 6060 while TLS healthy -> no interactive login;
   - TLS-unavailable HTTP fallback -> fallback profile.
4. Keep `AUTH_SECURE_COOKIE` accepted but **ignored**, with deprecation log.
5. Update `configs/cfm.conf` comment to explain automatic behaviour, then remove the key from new default configs after one compatibility period.
6. Eventually remove parser/config struct field after fleet migration.

## Cookie tests

Required regression matrix:

- edge HTTPS -> Go loopback HTTP still emits `cfm-sid; Secure`;
- direct `6061` -> Secure;
- direct `6061` with forged `X-Forwarded-Proto:http` -> still Secure;
- direct `6060` with forged `X-Forwarded-Proto:https` -> still treated HTTP;
- direct `6060` while TLS healthy -> login GET redirects, login POST rejected before auth body processing;
- controlled TLS-unavailable fallback -> `cfm-sid-http-fallback` works;
- pre-existing `cfm-sid; Secure` does not prevent fallback from creating its **different-name** HTTP session;
- fallback cookie is not confused with normal secure admin cookie;
- edge + direct `6061` can share the normal `cfm-sid` because cookies are host/path scoped, not port scoped;
- no raw forwarded header can influence cookie Secure state unless immediate peer is trusted.

### Later hardening

- Consider an `__Host-` secure cookie name only after the HTTP-fallback split is settled. `__Host-` requires Secure + `Path=/` + no Domain, and by definition cannot be the fallback cookie.
- Re-evaluate `SameSite=Lax` vs `Strict` only with explicit cPanel/embed/MFA testing; do not bundle that change into this audit step.

---

# 5. Per-authentication-mechanism API rate limiting

The existing login limiter is separate and should remain separate. It already has per-IP, account, tuple, adaptive backoff and lock behaviour.

The missing layer is bounded limiting for **already-authenticated** control-plane calls, differentiated by auth mechanism and route cost.

## Principles

1. Authenticate first, then identity-limit; invalid tokens still get normal `401` and must not leak validity through limiter classification.
2. Never key/log raw bearer secrets.
3. Stable identities:
   - `token_admin`: internal label or one-way fingerprint,
   - `token_scoped`: token-store ID/fingerprint,
   - `embed_bootstrap_cookie`: underlying scoped identity,
   - `session_cookie`: authenticated session/user + source where useful,
   - MCP: limiter remains with the MCP auth layer.
4. Account for **route cost**, not just request count.
5. Return `429` + `Retry-After`; emit mechanism/class/source audit event without secrets.
6. Bound/prune limiter memory.

Suggested classes:

| Class | Examples | Relative budget |
|---|---|---:|
| `cheap_read` | status, scoped summaries, UI refresh | high |
| `normal_read` | history, WAF tables | medium/high |
| `heavy_read` | logs, forensics, expensive aggregations | low |
| `write` | vhost/scoped controls | medium/low |
| `privileged_write` | block/unblock, tokens, DNAT/debug | low |
| `capture_stream` | pprof/debug captures | very low + concurrency cap |

Do not immediately hardcode product limits. Ship **shadow/observe** first and measure legitimate cfm-web fan-out, admin UI parallel requests and panel/plugin polling.

### Rollout

- Phase A: observe counters only.
- Phase B: enforce deliberately high ceilings above normal peaks.
- Phase C: tune heavy/write/debug families independently.

Tests must prove one scoped token cannot exhaust another, admin token traffic does not share scoped buckets, invalid bearer never falls back to session, no raw token is logged, state is pruned, and normal fleet fan-out remains under thresholds.

---

# 6. Exhaustive `/api/v1/*` authorization audit — dedicated next session

This is the large follow-up. Use a dedicated session with code + GSC/live probe tooling and this file as handoff.

Baseline document:

- `docs/endpoint_scope_inventory.md`

It is useful but **not proof of completeness**. Derive routes from current registration code and compare inventory to reality.

## 6.1 Generate route inventory from code

Search all registration paths:

- `http.NewServeMux`, `Handle`, `HandleFunc`, registration helpers,
- `internal/apiserver/*`,
- `internal/webdetector/*`,
- MySQL governor registrations,
- token/embed/cPanel routes,
- notifier/detector/debug/DNAT/system routes,
- MCP routes + OAuth discovery/consent/token endpoints,
- deferred `apiserver.Register(...)` users.

Prefer a machine-readable table:

```text
METHOD | PATH | HANDLER | AUTHN ALLOWED | ROLE/SCOPE | WRITE? | DATA SCOPE | NOTES
```

Every endpoint must appear exactly once or be intentionally grouped by a proven prefix handler.

## 6.2 Identities to test

For each endpoint/family:

1. anonymous,
2. invalid bearer,
3. admin bearer (`AUTH_TOKEN`) using controlled test credentials,
4. scoped token in-scope,
5. scoped token out-of-scope,
6. empty-vhost / DB-only scoped token,
7. normal admin browser session,
8. embed scoped cookie,
9. MCP bearer/OAuth where applicable,
10. cPanel actor assertion where applicable.

A supplied invalid token must **not** silently fall back to a valid browser session.

## 6.3 Authorization properties to prove

For every endpoint:

- public/self-auth/admin-only/scoped-allowed classification,
- omitted filters cannot return global data to scoped caller,
- host/vhost/user/db aliases, case, trailing dots, ports, encoding and duplicate params cannot escape scope,
- nil/empty scope never means admin,
- writes independently validate target scope server-side,
- no UI-only filtering,
- method confusion does not expose writes,
- session writes get CSRF protection,
- bearer/scoped writes are cookie-CSRF exempt but still authorized,
- errors do not leak host-wide data,
- caches vary safely by identity/scope,
- expensive endpoints have bounds.

## 6.4 Priority examples

### Admin/global

- `/api/v1/auth/token`
- `/api/v1/tokens/list`, `/api/v1/tokens/revoke`
- `/api/v1/firewall/block`, `/block/batch`, `/list`, `/counters`, `/selftest`
- `/unblock`
- `/search`
- `/api/v1/admin/authcheck`
- global MySQL state/process/history/cpu routes
- node-wide `/api/v1/system/*`
- debug capture / pprof
- notifier/detector administration

Prove scoped token -> `403`, not merely “auth present”.

### Scoped

- `/api/v1/mysql/user-summary|user-kills|user-history|user-kill`
- `/api/v1/tokens/me`
- webdet top/suspicious/drilldown/analyze-host/vhosts/history routes
- per-vhost challenge controls
- challenge/WAF exclude routes
- Clam override/sigignore/mode routes
- HTTP/3 per-host controls
- WAF hit rates
- mail DNS/traffic scoped views

Test in-scope success **and** out-of-scope denial.

### Public/self-auth special paths

- `/login*`, `/logout*`
- static `/assets/*` GET/HEAD
- `/api/v1/embed/bootstrap`
- `/api/v1/cpanel/user-info`
- `/mcp`, `/mcp/*` and OAuth discovery endpoints

Review them according to their own narrow contract; do not force them into normal bearer/session policy.

## 6.5 Pattern hunt from previous authz bugs

`/unblock` and `/search` were previously protected only by mux-wide authentication and later made explicitly admin-only. Use that as the pattern:

> Find every handler where “valid token/session” is enough but the handler never proves admin or scope before reading/writing host-wide state.

Search for direct `CtxScopeKey{}` reads, nil/empty-map ambiguity, handlers registered without admin/scoped wrappers, sibling read/write routes with inconsistent checks, and new endpoints missing from `endpoint_scope_inventory.md`.

---

# 7. GSC-MCP / live external audit plan

Run after/alongside static inventory; keep non-destructive and low-volume.

Primary test host discussed:

```text
titan.myip.gr
```

Surfaces:

```text
443   /cfm-admin/
6060  /cfm-admin/ + API
6061  /cfm-admin/ + API TLS
9098  challenge transport (expected loopback-only; verify externally)
```

## Recon

Use `app_recon`, `app_port_scan`, `app_http_probe`, `app_tls_probe`, headless browser equivalents to record:

- reachable ports,
- HTTP/TLS behaviour,
- 6061 certificate/SNI,
- redirects/canonical admin path,
- security headers,
- whether 9098 leaks externally,
- whether 6060 accepts browser credentials while 6061 is healthy.

Do not infer “closed” from a runtime with blocked outbound networking; use the external probe.

## Headless acceptance after challenge work

Fresh browser context per entry path.

### Edge 443

```text
GET https://titan.myip.gr/cfm-admin/
expected: PoW before credentials
solve once
expected: login loads, no loop
```

### Direct 6061

```text
GET https://titan.myip.gr:6061/cfm-admin/
expected: same PoW semantics
solve once
expected: login/session works
```

### Direct 6060 while TLS healthy

```text
GET http://titan.myip.gr:6060/cfm-admin/
expected: -> https://titan.myip.gr:6061/cfm-admin/
```

Verify edge backend loopback `6060` does **not** redirect the public `:443` browser to `:6061`.

Do not break production TLS just to test fallback; use unit/integration or staging for `TLS unavailable -> HTTP fallback`.

## Forwarded-header spoof regression

Direct `6061` request with forged:

```http
X-Forwarded-For: 8.8.8.8
X-Real-IP: 8.8.4.4
CF-Connecting-IP: 1.1.1.1
X-Forwarded-Proto: http
```

Expected: actual direct peer/TLS state wins.

Direct `6060` with `X-Forwarded-Proto:https` must remain HTTP.

Through trusted edge, inject XFF and verify Go sees one canonical edge-derived IP, not `attacker-value, real-ip`.

## Cookie checks

Inspect `Set-Cookie` on direct 6061, edge 443 and controlled HTTP fallback.

Expected:

- edge 443: normal session `Secure` despite backend hop being HTTP 6060;
- direct 6061: normal session `Secure`;
- direct healthy 6060: no credential-bearing session established;
- fallback 6060: separate degraded fallback cookie name, non-Secure by necessity, only when TLS unavailable;
- challenge clearance Secure on HTTPS and bound to expected IP/host/scope.

## API differential checks

Using short-lived/controlled credentials where possible compare:

```text
anonymous
invalid bearer
admin bearer
scoped bearer in-scope
scoped bearer out-of-scope
admin session
embed scoped cookie
```

Record status/minimal response shape, not sensitive payloads.

## Deferred GSC-MCP tooling for deeper audit

The current GSC-MCP application-audit workbench already has browser-backed identities/sessions, captured-request replay, `app_request_replay_as`, `app_authz_compare`, API discovery, audit ledger/evidence and OAST. Two additional bounded primitives would materially deepen the CFM pass without turning the auditor into a generic Internet scanner/fuzzer.

### Tool 1 — import API/bearer identities without a browser

Add a narrow tool, working name:

```text
app_identity_import_headers
```

Purpose: create/refresh a managed audit identity from explicitly supplied credential-shaped HTTP headers for APIs that do not naturally authenticate through a browser flow. This is primarily to let `app_authz_compare` exercise CFM's admin/scoped bearer boundaries directly.

Required safety/behaviour:

- origin must already be operator-approved/in scope;
- imported credentials are bound to the **exact scheme/host/port**;
- secret values remain ephemeral/in-memory and are never returned by identity/session/detail/list/evidence tools;
- outputs expose only non-secret metadata such as identity/role labels supplied by the tester, origin, credential header names and provenance;
- never log or hash raw bearer values into ordinary audit output;
- replacing an identity invalidates its previous imported session immediately;
- `app_request_replay_as` must remove inherited credential-shaped headers first, then inject only the selected managed identity credentials;
- do not support credential-bearing query parameters in the first version; headers are sufficient for CFM and avoid ambiguous URL-secret handling;
- no target request is sent merely by importing the identity.

Primary CFM identities for the deep pass:

```text
cfm-admin-bearer
cfm-scoped-vhost-test
cfm-scoped-db-only-test
```

Then use one retained baseline request with `app_authz_compare` rather than hand-building independent curls for every actor.

Required CFM test matrix after the tool exists:

- admin-only endpoint: admin bearer succeeds; scoped identities deny; anonymous/invalid bearer deny;
- scoped endpoint: in-scope scoped bearer succeeds; out-of-scope scoped bearer denies/returns no foreign data;
- DB-only scoped token cannot acquire vhost/global privileges through omitted parameters;
- omitted scope/filter never turns a scoped request into global data;
- an imported credential for `https://titan.myip.gr:6061` cannot be replayed automatically to `http://titan.myip.gr:6060` or `https://titan.myip.gr:443` merely because hostname matches;
- switching from admin to scoped identity never retains the admin Authorization/Cookie/API-key material from the parent request;
- response comparison records status/route/content type/body shape/hash evidence without copying sensitive payloads into the audit report.

The result should make the authorization pass reproducible as:

```text
route inventory
    -> capture one representative request per endpoint/family
    -> replay same request as named actors
    -> app_authz_compare
    -> attach request/response evidence to audit ledger
```

### Tool 2 — bounded raw HTTP edge-vs-backend differential probe

Add a separate explicit low-level primitive, working name:

```text
app_raw_http_probe
```

Purpose: compare request parsing/normalization at the public Angie/OpenResty edge versus the direct Go listener without Go's normal `net/http` client canonicalizing the test request first.

This is for **parser/normalization differential checks**, not high-rate fuzzing, request-smuggling campaigns or load testing.

Suggested bounds:

- one operator-approved host/IP + port per call;
- target re-authorized through the same app-audit scope/dial guard immediately before connect;
- one TCP connection, one bounded request and one bounded response;
- HTTP/1.0 or HTTP/1.1 only initially;
- strict request-byte ceiling (for example <= 8 KiB) and bounded response/header/body retention;
- explicit mode/effect gating; no hidden redirects/retries;
- secrets redacted in normal output and audit evidence;
- no automatic mutation corpus: the caller supplies the exact request being tested.

CFM differential suite should send the **same logical case** to edge `:443` where practical and direct Go `:6061`, then compare status/redirect/selected headers/body fingerprint and whether each layer reaches the expected route.

Low-volume cases worth retaining:

```text
normal canonical path
/cfm-admin/api/v1/...
/cfm-admin//api/v1/...
percent-encoded slash/dot segments where the URI is legal to transmit
trailing slash variants
mixed-case/port-bearing Host forms
absolute-form request target where accepted by HTTP/1.1
single vs duplicate benign query parameters
single vs duplicate forwarded headers
conflicting X-Forwarded-For / X-Real-IP / X-Forwarded-Proto values
```

Specific security assertions:

- edge and direct listener must not map two materially different raw paths onto different authorization semantics for the same protected operation;
- direct `6061` must ignore spoofed forwarded client/scheme headers regardless of duplicate/header ordering;
- edge must canonicalize client identity according to the trusted edge contract rather than preserve attacker-controlled XFF chains;
- encoded/path variants must not bypass `/cfm-admin` prefix handling, login challenge, admin-only wrappers or scoped filters;
- duplicate query/header forms must not make a scoped request global or select a more privileged interpretation in one layer;
- direct Go and edge may legitimately differ in rejection/canonicalization status, but any difference that changes **which handler/authz policy executes** is a finding candidate;
- keep production testing non-destructive and one-case-at-a-time; any ambiguous parser-desync/request-smuggling-style behaviour moves to disposable staging before further probing.

This primitive should remain separate from `app_request_send`/replay: ordinary application requests should continue using the safe structured HTTP transport, while raw HTTP is an explicit opt-in capability for edge/parser differential evidence.

---

# 8. Acceptance checklist / implementation order

## Step 1 — trusted request identity + effective scheme

- [ ] Replace CFM-admin `$proxy_add_x_forwarded_for` with canonical `$remote_addr` at Angie/OpenResty -> Go boundary.
- [ ] Add `X-Forwarded-Proto $cf_xfp` to **every** CFM control-plane proxy block that terminates at Go.
- [ ] Add one Go trusted-peer/client-IP/effective-scheme helper.
- [ ] `realIPFromRequest` returns one validated IP, never arbitrary XFF text.
- [ ] Direct `6060/6061` ignores forged forwarded client/scheme headers.
- [ ] Edge HTTPS -> loopback HTTP is still classified `scheme=https`.
- [ ] Login rate-limit tests include forged XFF regression.
- [ ] ChallengeServer consumes the same identity/scheme rules before direct mounting.

## Step 2 — reusable Go challenge handler + login gate

- [ ] Reuse ChallengeServer handler; no duplicate PoW.
- [ ] Keep loopback 9098 using same implementation.
- [ ] Mount `/__cfm_challenge` and `/__cfm_verify` in apiserver.
- [ ] Reuse signed clearance verification.
- [ ] Gate interactive login only.
- [ ] Bearer/scoped/embed flows not challenged.
- [ ] Missing clearance cannot bypass by direct login POST.
- [ ] No challenge nft sets / AddChallenge / DNAT challenge state returns.
- [ ] Test prefixed `next` paths; no lost/doubled `/cfm-admin`, no loop.
- [ ] Preserve regression coverage around historical `up=cfm_challenge` / `uaddr=127.0.0.1:6060` failure.

## Step 3 — direct 6060 transport policy

- [ ] Bind/check TLS listener before declaring ready.
- [ ] Direct GET/HEAD `6060/cfm-admin*` -> `:6061` only when TLS ready.
- [ ] Edge loopback backend requests stay on public `:443`.
- [ ] Unsafe direct HTTP admin methods are rejected when TLS healthy.
- [ ] Controlled TLS-unavailable fallback remains challenge-gated.
- [ ] Degraded fallback state logged.

## Step 4 — automatic session-cookie transport policy

- [ ] Add request-aware cookie transport support in goauth without global mutable cookie races.
- [ ] Use effective trusted scheme, **not raw `r.TLS`**.
- [ ] Edge HTTPS and direct 6061 use normal `cfm-sid; Secure`.
- [ ] Healthy 6060 never handles interactive login/session writes.
- [ ] TLS-unavailable HTTP fallback uses a **different cookie name** (e.g. `cfm-sid-http-fallback`) so an existing Secure cookie cannot block/overwrite it.
- [ ] Both profiles share one auth/session store lifecycle; do not duplicate DB managers casually.
- [ ] `AUTH_SECURE_COOKIE` becomes accepted-but-ignored/deprecated with one-time warning.
- [ ] Remove knob from new shipped configs after compatibility window; later remove parser field.
- [ ] Do not change SameSite/cookie prefix in same PR unless separately tested.

## Step 5 — per-auth-mechanism rate limiter

- [ ] Route-cost classification.
- [ ] Mechanism/identity classification without raw-token logging.
- [ ] Shadow mode first.
- [ ] Measure CFM Web, admin UI and scoped plugin traffic.
- [ ] Enforce high ceilings; tune heavy/write later.
- [ ] Memory pruning, `Retry-After`, audit/anomaly events.

## Step 6 — exhaustive endpoint audit

- [ ] Generate route inventory from code.
- [ ] Reconcile every route with `docs/endpoint_scope_inventory.md`.
- [ ] Static proof for every admin/scoped/public/self-auth route.
- [ ] Add GSC-MCP `app_identity_import_headers` (or equivalent exact-origin API identity import) before the credentialed differential pass.
- [ ] Run admin/scoped/DB-only identity matrices with `app_authz_compare` and attach evidence to the audit ledger.
- [ ] Add bounded GSC-MCP `app_raw_http_probe` before the edge-vs-direct parser/normalization pass.
- [ ] Run the retained low-volume edge `:443` vs direct `:6061` raw HTTP differential suite; move any parser-desync follow-up to disposable staging.
- [ ] Live low-volume differential checks with GSC-MCP.
- [ ] Add missing authz integration tests.
- [ ] Update this file with findings/fixes and exact commits/PRs.

---

# 9. Useful code/history references

Current code:

- `internal/apiserver/apiserver.go` — listeners, shared handler stack, `/cfm-admin/` prefix redispatch, goauth configuration.
- `internal/apiserver/middleware.go` — auth mechanism order/contexts and trusted prefix handling.
- `internal/apiserver/request_log.go` — current forwarded-IP handling.
- `internal/apiserver/login_rate_limit.go` — login-specific limiter.
- `internal/apiserver/csrf_middleware.go` — session CSRF policy.
- `internal/webdetector/challenge_server.go` — challenge/verify/clearance/rate limiting.
- `internal/webdetector/challenge_server_clearance_test.go` — signed clearance contract.
- `configs/angie.conf`, `configs/openresty.conf` — edge proxy and old forced-login challenge routing.
- `configs/cfm.conf` — 6060/6061 and historical `AUTH_SECURE_COOKIE` knob.
- `docs/endpoint_scope_inventory.md` — backend authz inventory baseline.
- `chrismfz/goauth` — session cookie implementation; currently static per-manager cookie attributes.
- `cfm-web/config/fleet.php` in `chrismfz/cfm-web` — fleet transport defaults to HTTPS 6061 / server_name for SNI.

History:

- PR `#246` — pre-auth login challenge concept; correct exemptions, obsolete DNAT enforcement.
- commit `b041f9996fd27de40d157ef8d192ccd0e75a1daa` — forced edge PoW on `/cfm-admin/login`.
- commit `dea270e29661b73c9bca7444c36577c2827cc9d3` — fixed hardcoded-Go routing; key symptom `up=cfm_challenge` but `uaddr=127.0.0.1:6060`.
- PR `#316` — challenge redirect prefix repair.
- PR `#317` — narrowed redirect rewrite after loop risk.
- PR `#318` / commit `5a1fbabfd354651703f15a6e3fbe74ac1b750a75` — reverted login to direct Go.
- commit `e40cce8fec293091f60d5ee3c48433a6b4a94a44` — removed legacy challenge-DNAT / old Go pre-auth DNAT gate.
- commit `6ef61e8ada7734d5932a934ced51e12d6b4880fd` — hardened edge `X-Forwarded-Proto` trust; precedent for fail-safe forwarded-header handling.

---

## Final design principle

> **The CFM admin/API should have the same authentication, scope enforcement, client-identity semantics and pre-auth browser protection regardless of whether a request enters through the edge or the direct Go listener. Transport security is derived from the trusted effective request scheme, not from a static config knob or blindly from the final backend hop.**

The edge may add WAF/transport benefits, but bypassing the edge must not bypass the CFM control-plane security model.