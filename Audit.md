# CFM external control-plane security audit / handoff

**Status:** planning / audit handoff — no behavioural code change in this document.

**Snapshot reviewed:** `main` at `df6586192754fc774b9049ba55f6658e304e8077` (`2026.08.23` release).

**Primary target surface:** the CFM control plane exposed through the normal edge path and the direct API listeners:

- `https://<hostname>/cfm-admin/` — Angie/OpenResty edge -> Go apiserver on loopback.
- `http://<hostname>:6060/cfm-admin/` — direct Go HTTP listener.
- `https://<hostname>:6061/cfm-admin/` — direct Go TLS listener.
- `:9098` — challenge service transport; intended to stay loopback-only and be reused internally, not become a second public control plane.
- `/api/v1/*` plus the related non-`/api/v1` authenticated routes (`/unblock`, `/search`, `/mcp`, etc.).

The purpose of this file is to preserve the reasoning, historical failures and the intended **small-step remediation order** so a dedicated security/audit session (including the GSC/headless-browser tooling) can continue without rediscovering the architecture or repeating old mistakes.

---

## 0. Threat model and constraints

The current product direction is that `6060` / `6061` are not assumed to be hidden internal/debug ports. The Go apiserver is also the direct/fallback host for `cfm-admin`, and `cfm-web` reaches fleet nodes over the API (normally HTTPS `:6061`). Therefore the listeners must be safe **when Internet-reachable**.

At the same time, the following existing flows are first-class and must not be broken:

1. **Normal CFM admin browser session** — goauth session + MFA/CSRF.
2. **CFM Web / fleet controller** — admin bearer token.
3. **cPanel/hosting-panel plugin** — scoped bearer token and/or embedded bootstrap flow.
4. **Scoped embedded browser** — short-lived scoped embed cookie.
5. **MCP** — self-authenticated bearer/OAuth surface; it intentionally bypasses normal session/token middleware and applies its own auth gate.

The security work below must therefore distinguish **authentication mechanism + role/scope**, not split the product into artificial “browser APIs” and “machine APIs”. The same `/api/v1/*` endpoints are legitimately consumed by several of the mechanisms above.

### Non-goals for the first implementation pass

- Do not resurrect the retired per-IP challenge-DNAT machinery.
- Do not globally IP-allowlist `/api/v1/*`; that would break scoped/plugin/browser use cases.
- Do not require challenge/PoW for machine bearer-token calls.
- Do not duplicate the challenge algorithm in the apiserver.
- Do not perform brute force, destructive writes, mass blocking, or high-rate load testing against production during the external audit.

---

# 1. Unify CFM Admin pre-auth challenge across edge, `:6060` and `:6061`

## Desired behaviour

The challenge should be a property of the **CFM control plane**, not a lucky side effect of entering through Angie.

Expected user-visible behaviour:

```text
https://host/cfm-admin/         -> CFM pre-auth challenge -> login -> admin
https://host:6061/cfm-admin/    -> CFM pre-auth challenge -> login -> admin
http://host:6060/cfm-admin/     -> redirect to :6061 when direct TLS is usable
                                -> otherwise degraded HTTP fallback, still challenge-gated
```

Machine/scoped traffic must remain untouched:

```text
cfm-web + valid admin bearer       -> API directly, no PoW
cPanel scoped bearer               -> scoped API directly, no PoW
valid embed bootstrap cookie       -> scoped UI/API directly, no PoW
MCP bearer/OAuth                   -> MCP's own auth, no admin-login PoW
```

The challenge is a **pre-auth browser gate**, not an authorization mechanism. Password/session/token authorization remains authoritative.

## Preferred architecture: reuse the existing Go challenge implementation

The existing `internal/webdetector/challenge_server.go` already owns the PoW challenge, verify endpoint, signed clearance token, safe `next` normalization, rate limiting and post-solve redirect. Do **not** create a second challenge implementation in `internal/apiserver`.

Refactor the challenge server so the same implementation can be mounted in two transports:

```text
ChallengeServer
    |
    +-- HTTP Handler / RegisterHandlers
    |      +-- /__cfm_challenge
    |      `-- /__cfm_verify
    |
    +-- existing standalone loopback Serve()
           `-- 127.0.0.1:9098 (Angie/OpenResty compatibility)
```

The apiserver (`6060`/`6061`) should register the exact challenge/verify handlers on its mux. Angie may continue to send its existing root challenge paths to `9098`; direct Go requests use the exact same handler in-process. There should be one token format, one verifier and one set of safety rules.

### Clearance validation

The current authoritative solved marker is the signed `cfm_clearance` cookie (the legacy `cfm_ok` marker is transitional/non-authoritative). Existing clearance tests prove the token is bound to:

- client IP,
- normalized host (port removed),
- clearance scope (`web` / panel scope),
- expiry,
- HMAC secret.

The new Go pre-auth gate should call/export the existing clearance verifier instead of introducing a new cookie.

**Pre-check before implementation:** confirm the bridge/clearance signing secret is always available when the webdetector challenge service is enabled even when edge/DNAT is disabled. If not, fix secret lifecycle once; do not fork a “direct-admin challenge secret”.

## Where to gate

The safest first version is to gate the **interactive login flow**, not every `/cfm-admin/*` request.

The current auth flow already redirects an unauthenticated interactive browser from protected `/cfm-admin/*` to the login route. That gives a narrow place to require clearance without touching API/assets/embed flows.

Recommended semantics:

- `GET/HEAD /login` and direct `/cfm-admin/login`:
  - valid admin session -> normal auth logic (normally user would not land here anyway),
  - valid CFM clearance -> serve login,
  - no clearance -> redirect to `/__cfm_challenge?next=<original-login-url>`.
- login POST and MFA/WebAuthn login sub-flow:
  - valid clearance -> normal login handler,
  - missing/invalid clearance -> fail closed as `challenge_required`; **do not let direct POST bypass the PoW**.
- assets, `/api/v1/*`, embed/bootstrap and machine bearer traffic are not challenge candidates.

For browser GETs the redirect flow should be explicit:

```text
GET /cfm-admin/login
  -> 302 /__cfm_challenge?next=/cfm-admin/login
  -> solve
POST /__cfm_verify?next=/cfm-admin/login
  -> signed cfm_clearance cookie
  -> 303 /cfm-admin/login
  -> normal Go login page
```

This avoids dynamically proxying the *login URI itself* to the challenge server, which is the exact design that previously created prefix/redirect trouble.

### Placement in auth code

The old pre-auth gate was called early from `TokenMiddleware`, because that location had enough knowledge to exempt bearer/plugin/bootstrap flows. Reuse that **classification idea**, but not the retired DNAT enforcer.

A clean implementation may either:

- add a narrow `maybeHandleAdminLoginChallenge()` inside/adjacent to `TokenMiddleware`, before public `/login` is passed through, or
- expose a small pre-auth middleware that runs after goauth session loading and uses shared helpers for token/embed detection.

Do not independently re-parse authentication in several middleware layers. The current mechanisms already have explicit identities:

- `session_cookie`
- `token_admin`
- `token_scoped`
- `embed_bootstrap_cookie`

The gate should remain aware that `/login` is public in the normal auth sense but **challenge-gated for interactive humans**.

---

## Historical warning: we already broke this once

This history must remain with the implementation because the current config contains misleading/dead intent (`$cfm_force_challenge=1`) and it is very easy to reintroduce the old bug.

### 2026-04-18 — PR #246: Go pre-auth challenge gate

PR `#246` (“Pre-auth challenge gate for interactive admin login flows”) added `internal/apiserver/login_challenge.go`.

Good ideas worth preserving:

- evaluate only interactive browser login entry points,
- do not challenge bearer/API/bootstrap/plugin flows,
- authenticated session bypass,
- integration tests proving embed/API calls stay unaffected.

The part **not** to preserve was the enforcement mechanism: it called firewall `AddChallenge()` and relied on the old per-IP challenge-DNAT system.

### 2026-04-20 — forced `/cfm-admin/login` challenge in edge config

Commit `b041f9996fd27de40d157ef8d192ccd0e75a1daa` added:

```nginx
location ^~ /cfm-admin/login {
    set $cfm_force_challenge "1";
    ...
}
```

and `cfm.lua` Step 2.5 set:

```text
$cfm_upstream = cfm_challenge
$cfm_pass     = http://cfm_challenge
```

### The first concrete failure: Lua selected challenge, nginx still sent Go

Commit `dea270e29661b73c9bca7444c36577c2827cc9d3` documents the exact failure:

> the location was hardcoded to `proxy_pass http://127.0.0.1:6060`, therefore the forced challenge had no visible effect; logs showed **`up=cfm_challenge` but `uaddr=127.0.0.1:6060`**.

The attempted fix introduced a map:

```nginx
map $cfm_upstream $cfm_admin_login_pass {
    default        http://127.0.0.1:6060;
    cfm_challenge  http://cfm_challenge;
}
```

and used `proxy_pass $cfm_admin_login_pass`.

### The second failure family: redirect/prefix behaviour

Once the login request really reached the challenge upstream, challenge/root-relative redirects escaped or interacted badly with the `/cfm-admin` mount.

- PR `#316`: rewrote root-relative redirects back under `/cfm-admin`.
- PR `#317`: narrowed the rewrite because the broader behaviour could create redirect loops.
- PR `#318`: finally reverted login to a direct Go upstream to prevent challenge/WAF hops from interfering with login flows.

The current config still says, in effect, “forced PoW applies” but also contains:

```nginx
proxy_pass http://127.0.0.1:6060;
```

so the old `$cfm_force_challenge` decision cannot actually select the challenge upstream. This is technical debt/documentation drift, not proof that challenge is active.

### 2026-08-11 — edge unification removed the old Go challenge-DNAT gate

Commit `e40cce8fec293091f60d5ee3c48433a6b4a94a44` (“delete challenge-DNAT machinery / Phase 1b”) intentionally removed:

- the legacy per-IP challenge sets/redirect machinery,
- the old `9099` daemon TLS challenge listener,
- `AddChallenge`/`RemoveChallenge` style DNAT enforcement,
- the DNAT-era `internal/apiserver/login_challenge.go` pre-auth subsystem.

The commit explicitly states the surviving enforcement model is **edge bridge + Lua clearance cookie**.

**Conclusion:** do not revert Phase 1b and do not re-add per-IP challenge DNAT. The new admin challenge should be an HTTP-level redirect/clearance gate backed by the existing ChallengeServer implementation.

---

# 2. Direct `:6060/cfm-admin` -> `:6061` when TLS is actually usable

## Goal

`6061` should be the preferred direct browser transport. `6060` remains available because:

- API deployments may still explicitly use HTTP,
- the product wants a browser fallback if the TLS listener cannot be started/used,
- Angie itself normally proxies `/cfm-admin/*` to loopback `6060` and must continue to do so.

Therefore this cannot be a global “all 6060 requests redirect” rule.

## Critical distinction: direct HTTP vs trusted reverse-proxy backend hop

This request:

```text
Browser -> https://host/cfm-admin/ -> Angie -> 127.0.0.1:6060
```

must **not** become:

```text
Angie -> 6060 -> redirect browser to https://host:6061/...
```

The public edge URL should remain on normal `:443`.

Only a direct external browser request such as:

```text
Browser -> http://host:6060/cfm-admin/
```

is a candidate for redirect to `:6061`.

The decision must use the **immediate peer**, not spoofable forwarded headers. A loopback peer plus the CFM proxy prefix headers may identify the Angie backend hop; a non-loopback direct peer must never be allowed to forge those headers into “trusted proxy” status.

## “6061 exists” must mean runtime-ready, not merely configured

Do not redirect based only on `TLS_PORT > 0`.

Preferred startup order:

1. Build handler/auth state.
2. If TLS is configured and SSLCollector is present, attempt to bind the `6061` listener first.
3. Record `tlsListenerReady = true` only after bind succeeds.
4. Ideally also confirm SSLCollector can serve the requested SNI/hostname before redirecting that host (or otherwise define the expected fallback-certificate behaviour explicitly).
5. Start the HTTP listener with direct-admin transport middleware that knows the runtime TLS readiness.
6. Start serving TLS.

This avoids a startup window where HTTP redirects to a listener that has already failed to bind.

## Redirect semantics

For **direct** `6060` admin navigation when TLS is ready:

- GET/HEAD `/cfm-admin` and `/cfm-admin/*` -> redirect to `https://<same-host>:6061<same-request-uri>`.
- Preserve IPv6/host parsing safely using `net.SplitHostPort` / `net.JoinHostPort`; never build the Location header by blindly concatenating attacker-controlled Host fragments.
- The current `Host` header is acceptable for a direct request only after normal host syntax validation; forwarded host headers are trusted only from an explicitly trusted reverse proxy.

For unsafe methods, a redirect is not enough security. A credential POST that already reached HTTP has already crossed the network in plaintext. Therefore when TLS is ready:

- do **not** accept login credentials/session-changing admin POSTs on direct `6060`,
- return a clear HTTPS-required error (and optionally a `Location`) rather than processing the body,
- normal users will have been redirected on the initial GET before any credential submission.

## Degraded fallback when TLS is not usable

If the TLS listener did not bind / is genuinely unavailable, direct `6060/cfm-admin` may remain usable as an explicit degraded fallback, but it must still use the **same pre-auth challenge gate**.

Log this state clearly, e.g.:

```text
event=admin_http_fallback reason=tls_listener_unavailable host=...
```

This is a resilience feature, not a claim that HTTP is equivalent to TLS.

---

# 3. Trusted client identity / XFF hardening

## Current issue

The CFM admin proxy locations currently use forms such as:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

`$proxy_add_x_forwarded_for` preserves a client-supplied `X-Forwarded-For` value and appends `$remote_addr`.

Meanwhile `internal/apiserver/request_log.go::realIPFromRequest()` currently does:

```go
if immediatePeer.IsLoopback() {
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        return xff
    }
}
```

That returns the **whole header string**, not one validated canonical IP. The same helper feeds login rate-limit keys and API anomaly/log attribution.

A request can therefore arrive as:

```text
attacker sends:   X-Forwarded-For: 8.8.8.8
Angie sees client real IP: 1.2.3.4
Go receives:      X-Forwarded-For: 8.8.8.8, 1.2.3.4
```

and the current Go identity becomes the attacker-controlled chain string.

This does not bypass password/token authorization, and the login account/tuple controls still provide protection, but it weakens IP-based throttling, anomaly correlation and any future source-bound policy.

## Recommended CFM-admin proxy contract

For the CFM-owned proxy hop, there is no need to preserve an arbitrary external XFF chain. Angie has already applied its trusted `real_ip` policy (including Cloudflare handling), so `$remote_addr` should be the canonical client identity at that boundary.

For CFM admin/internal control-plane proxy locations use:

```nginx
proxy_set_header X-Real-IP       $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
```

instead of `$proxy_add_x_forwarded_for`.

This recommendation is specifically about the CFM control-plane -> Go contract. Do not blindly change customer-origin proxy semantics without a separate compatibility review.

## One Go helper for all control-plane client identity

Create one tested helper, conceptually:

```go
type RequestPeer struct {
    ImmediateIP net.IP
    ClientIP    net.IP
    TrustedProxy bool
    Scheme      string
}
```

Rules:

1. Parse `RemoteAddr` first.
2. Forwarded client/scheme headers are considered **only** if the immediate peer is explicitly trusted.
3. For CFM's own Angie topology, loopback is the primary trusted peer. If configurable additional proxy CIDRs are wanted, make them explicit; do not silently treat every RFC1918/private client as a trusted proxy.
4. Accept exactly one parseable canonical client IP from the trusted proxy contract; never use an arbitrary comma-separated string as an identity/rate key.
5. Direct `6060`/`6061` clients ignore `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`, etc.

Use this helper for:

- request logs,
- login limiter,
- API rate limiter,
- challenge issue/verify IP binding,
- secure-scheme decision,
- any future source binding.

## Important before mounting ChallengeServer directly

`challenge_server.go` has code paths designed for its current reverse-proxied/legacy topology. In particular, `trustedForwardedProto()` currently accepts `X-Forwarded-Proto` when it is `http|https` before falling back to `r.TLS`, and some challenge logging/client-IP code reads proxy headers.

That is acceptable only under an already-trusted proxy boundary. Once the same handler is reachable directly on public `6060`/`6061`, a client must not be able to say:

```http
X-Forwarded-Proto: https
X-Real-IP: 203.0.113.123
CF-Connecting-IP: 203.0.113.123
```

and influence cookie security/IP binding.

Before in-process/direct mounting, refactor ChallengeServer to consume the same trusted request-identity helper above.

Also review `isTrustedProxyPeer()`: the challenge code currently treats loopback/private/link-local peers as trusted in some paths. For a public management listener, blanket `IsPrivate()` trust is broader than the CFM-owned Angie contract and should be narrowed or made explicit/configurable.

---

# 4. Session cookie `Secure` policy

## Current state and historical conclusion

Shipped `configs/cfm.conf` currently contains:

```ini
AUTH_SECURE_COOKIE = 0   # set 1 when serving over TLS only
```

The apiserver passes this directly into the pinned `goauth.Config`:

```go
SecureCookie: cfg.Debug.SecureCookie,
SameSite:     http.SameSiteLaxMode,
```

CFM currently pins `github.com/chrismfz/goauth` at `98a54bb7486b...`.

At that revision goauth configures SCS once at manager construction:

```go
sm.Cookie.HttpOnly = true
sm.Cookie.Secure   = cfg.SecureCookie
sm.Cookie.SameSite = cfg.SameSite
sm.Cookie.Path     = "/"
```

The goauth documentation itself says `SecureCookie=false` should be used only for local development over HTTP.

**History search result:** no commit/PR was found documenting a production breakage that forced CFM to set `AUTH_SECURE_COOKIE=0`. The current CFM config comment explicitly describes it as the compatibility setting for deployments that also serve HTTP. Treat this as a deliberate compatibility default, not a known bug workaround.

## Why simply changing the default to `1` is not enough

If the product requirement is:

> use `6061` when available, but allow `6060/cfm-admin` as an emergency browser fallback when TLS is unavailable,

then one static cookie flag cannot express the desired policy:

- `SecureCookie=true` is correct on HTTPS but the browser will not send that session cookie back over HTTP fallback.
- `SecureCookie=false` keeps HTTP fallback working but weakens the normal HTTPS session cookie.

Therefore do **not** blindly flip the shipped value until the fallback semantics are implemented.

## Target policy

Preferred behaviour:

```text
request is HTTPS (direct 6061 or trusted edge says original scheme=https)
    -> cfm-sid MUST be Secure

request is direct HTTP 6060 while TLS is healthy
    -> do not process interactive login; send user to HTTPS

request is direct HTTP 6060 AND TLS is genuinely unavailable
    -> explicit degraded fallback
    -> session may need non-Secure cookie to function
    -> log/security warning; never pretend this is equivalent to TLS
```

This likely needs a **request-aware cookie policy** in goauth/SCS or a carefully designed wrapper. Prefer a clean goauth capability over response-header string rewriting hacks.

Possible implementation direction in `goauth`:

- add an optional policy/callback for determining `Secure` from the request/effective trusted scheme, while preserving the existing fixed `SecureCookie` option for simple consumers, or
- expose a safe supported way for the application to provide cookie attributes per request.

Do not create two independent auth/session managers against the same session DB merely to get different cookie flags unless it is proven safe; CFM has already had SQLite/session contention issues and should not casually duplicate managers.

### Later hardening (not required in this baby step)

- Consider an `__Host-` session cookie name once compatibility is verified (goauth already recommends it). Requirements: `Secure`, `Path=/`, no `Domain`.
- Re-evaluate `SameSite=Lax` vs `Strict` only with explicit testing of cPanel/embed/MFA flows; do not change it casually as part of this audit.

---

# 5. Per-authentication-mechanism API rate limiting

## Current state

The login POST already has a strong application limiter in `internal/apiserver/login_rate_limit.go`:

- IP short/medium buckets,
- account short/medium buckets,
- IP+account tuple buckets,
- adaptive delay,
- account lock after repeated failures,
- audit/anomaly events.

Do not replace that with a generic API limiter.

The missing layer is a bounded limiter for **already authenticated** control-plane requests, differentiated by auth mechanism and route cost.

## Principles

1. **Authenticate first, then identity-limit.** Invalid tokens should still receive normal `401`, not a rate-limit response that leaks whether a candidate token is valid.
2. Keep a coarse pre-auth/IP abuse ceiling separately if needed for connection/CPU protection.
3. Never key on/log the raw bearer secret.
4. Use stable identity:
   - `token_admin`: fixed internal label or one-way token fingerprint (never raw token),
   - `token_scoped`: token-store ID/fingerprint,
   - `embed_bootstrap_cookie`: underlying scoped token/session identity,
   - `session_cookie`: authenticated session/user identity plus source IP where appropriate,
   - MCP: keep its limiter with/inside the MCP auth layer rather than pretending it is a normal CFM token mechanism.
5. Limits must also account for **route cost**, not just request count.
6. Return `429` with `Retry-After`; emit an audit/anomaly event with mechanism, route class and source IP, but no secret.
7. Bound/prune limiter memory.

## Suggested route cost classes

Do not immediately hardcode the example numbers below as product defaults. First ship **observe/shadow mode** and record real fleet usage, especially `cfm-web` fan-out.

Conceptual classes:

| Class | Examples | Relative limit |
|---|---|---:|
| `cheap_read` | status, scoped summaries, normal UI refresh | high |
| `normal_read` | history queries, WAF tables | medium/high |
| `heavy_read` | log tails, forensic aggregation, expensive history | low |
| `write` | vhost controls, scoped mode changes | medium/low |
| `privileged_write` | block/unblock, token management, DNAT/debug controls | low |
| `capture/stream` | pprof/debug capture | very low + explicit concurrency cap |

Mechanism profiles then scale those classes:

- `token_admin` / cfm-web: high read budget, but privileged writes/heavy reads remain bounded.
- `session_cookie`: normal interactive UI budget; enough for dashboard parallel fetches.
- `token_scoped`: normal plugin/UI budget; writes tighter than reads.
- `embed_bootstrap_cookie`: similar to scoped token, with its short lifetime.

## Rollout plan

### Phase A — shadow/observe

Record counters only:

```text
auth_mech=token_admin identity=<hash/id> class=heavy_read count=...
auth_mech=token_scoped identity=<token-id> class=normal_read count=...
```

Capture peaks for normal dashboard refreshes, cfm-web fleet fan-out, plugin polling and MCP separately.

### Phase B — enforce deliberately high ceilings

Start far above observed legitimate peaks. The first goal is to stop runaway/stolen-client loops and trivial resource exhaustion, not micro-throttle valid administration.

### Phase C — tighten expensive/sensitive families

Tune heavy logs/history/debug/write endpoints independently.

## Tests

- admin token burst does not affect unrelated scoped tokens,
- one scoped token cannot exhaust another token's bucket,
- one embed cookie cannot exhaust a normal admin session bucket,
- invalid bearer never falls back to session and is not classified as authenticated,
- retry-after is present and bounded,
- limiter state is pruned,
- no raw token appears in logs/metrics,
- cfm-web normal fan-out remains below the selected ceilings.

---

# 6. Exhaustive `/api/v1/*` authorization audit — dedicated next session

This is intentionally the large follow-up. Do it in a dedicated session with the code + GSC/live probe tooling and use this file as the handoff.

There is already a useful backend baseline in:

- `docs/endpoint_scope_inventory.md`

That document records many admin-only/scoped-allowed decisions and previous fixes. **It is a baseline, not proof of completeness.** The audit must derive the route inventory from the current mux/registration code and then compare the document to reality.

## 6.1 Build the route inventory from code

Search all current registration paths, not only `internal/apiserver/apiserver.go`:

- `http.NewServeMux`, `Handle`, `HandleFunc`, route registration helpers,
- `internal/apiserver/*`,
- `internal/webdetector/*`,
- MySQL governor registrations,
- token/embed/cPanel routes,
- notifier/detector/debug/DNAT/system routes,
- MCP mounted routes + OAuth discovery/consent/token endpoints,
- any deferred `apiserver.Register(...)` users.

Output a machine-readable table if practical:

```text
METHOD | PATH | HANDLER | AUTHN ALLOWED | ROLE/SCOPE | WRITE? | DATA SCOPE | NOTES
```

Every registered endpoint must appear exactly once or be intentionally grouped by a proven prefix handler.

## 6.2 Authentication identities to test

For every endpoint/family, reason and where safe live-test with these identities:

1. anonymous / no cookie / no token,
2. invalid bearer token,
3. valid admin bearer (`AUTH_TOKEN`) — use a controlled test credential; never paste production secrets into docs/logs,
4. valid scoped token with one known vhost/DB scope,
5. valid scoped token with a different/out-of-scope target,
6. scoped token with empty vhost scope / DB-only scope,
7. valid normal admin browser session,
8. valid embedded scoped cookie,
9. MCP bearer/OAuth where applicable,
10. cPanel actor assertion path where applicable.

A supplied invalid token must **not** silently fall back to a valid browser session.

## 6.3 Authorization properties to prove

For every endpoint:

- Is it genuinely public, self-authenticated, admin-only or scoped-allowed?
- Can a scoped token omit a query filter and accidentally receive global data?
- Can `host=`, `vhost=`, `user=`, `db=`, wildcard, aliases, case, trailing dot, port suffix, URL encoding or duplicate parameters escape scope?
- Does a nil/empty scope ever get mistaken for admin?
- For write endpoints, is the target independently scope-checked server-side?
- Does the handler trust UI filtering instead of backend filtering?
- Does method confusion (`GET` vs `POST`/`PUT`/`DELETE`) expose a write/read path unexpectedly?
- Does a browser-session write have CSRF protection?
- Are bearer/scoped token writes correctly exempt from cookie-CSRF while still authorized?
- Do errors leak host-wide information to scoped callers?
- Do response caches vary safely by auth/scope?
- Are expensive endpoints bounded by size/time/rate?

## 6.4 Known route families / priority examples

The existing inventory currently classifies, among others:

### High-priority admin-only/global examples

- `/api/v1/auth/token`
- `/api/v1/tokens/list`
- `/api/v1/tokens/revoke`
- `/api/v1/firewall/block`
- `/api/v1/firewall/block/batch`
- `/api/v1/firewall/list`
- `/api/v1/firewall/counters`
- `/api/v1/firewall/selftest`
- `/unblock` — global unblock + cross-plane allow state
- `/search` — host-wide multi-source IP lookup
- `/api/v1/admin/authcheck`
- global `/api/v1/mysql/state|processlist|top|locks|kills|history...|cpu`
- `/api/v1/system/*` node-wide health/log/DNAT/debug/SSL/process/service style endpoints
- `/api/v1/debug/*` / debug capture
- notifier/detector administration
- pprof (`/debug/pprof/*`) through normal auth stack

These deserve explicit proof that a scoped token gets `403`, not merely “some auth was present”.

### High-priority scoped examples

- `/api/v1/mysql/user-summary`
- `/api/v1/mysql/user-kills`
- `/api/v1/mysql/user-history`
- `/api/v1/mysql/user-kill` — especially verify target `(user, db)` scope on the write
- `/api/v1/tokens/me`
- `/api/v1/webdet/top-short|top|suspicious|long-top|drilldown|analyze-host|vhosts`
- scoped webdet history/overview routes
- `/api/v1/challenge/vhost*` / challenge per-vhost controls
- `/api/v1/challenge/exclude/*`
- `/api/v1/waf/exclude/*`
- `/api/v1/clam/override/*`
- `/api/v1/clam/sigignore/*`
- `/api/v1/clam/mode/*`
- `/api/v1/http3/enable|disable`
- `/api/v1/waf/hit-rates`
- `/api/v1/mail/dns`
- `/api/v1/mail/traffic`

For these, test **in-scope success and out-of-scope denial**, not just successful authentication.

### Special/public/self-authenticated paths

Review carefully rather than forcing them into the standard matrix:

- `/login*`, `/logout*` — public auth flow; future PoW pre-auth gate applies to interactive login.
- public static `/assets/*` GET/HEAD only.
- `/api/v1/embed/bootstrap` — intentionally public bootstrap handshake with its own constraints.
- `/api/v1/cpanel/user-info` — narrow actor-assertion/bearer self-service exception.
- `/mcp`, `/mcp/*`, OAuth discovery documents — normal TokenMiddleware treats them as public because the MCP server performs its own bearer/OAuth gate.

## 6.5 Regression cases from previous authz bugs

The current `docs/endpoint_scope_inventory.md` records endpoints that were previously only protected by the mux-wide “authenticated” middleware and later made explicitly admin-only, including `/unblock` and `/search`.

Use those as a pattern hunt:

> Find every handler where “valid token/session” is accepted but the handler never proves `admin` or scope before reading/writing host-wide state.

Search especially for:

- direct `CtxScopeKey{}` reads instead of the normalized scope helper,
- `nil` / empty-map logic,
- handlers registered directly on `m` without `adminOnlyHandler`, `RequireAdmin`, `RequireScopedOrAdmin` or an equivalent scoped validator,
- a list endpoint with filtering but a sibling write endpoint missing the same check,
- newly-added endpoints that were not added to `endpoint_scope_inventory.md`.

---

# 7. GSC-MCP / live external audit plan

Run this only after/alongside the static code inventory. Keep it non-destructive and low volume.

## Target

Primary test host currently discussed:

```text
titan.myip.gr
```

Ports/surfaces:

```text
443   /cfm-admin/
6060  /cfm-admin/ + API
6061  /cfm-admin/ + API TLS
9098  challenge transport (expected loopback-only; verify externally, do not assume)
```

## Recon / transport checks

Use the available GSC tooling equivalents (`app_recon`, `app_port_scan`, `app_http_probe`, `app_tls_probe`, headless browser) to record:

- externally reachable ports,
- HTTP vs TLS behaviour,
- certificate/SNI behaviour on `6061`,
- protocol versions/ciphers at a reasonable audit level,
- redirects and canonical admin entry point,
- security headers on login/admin/error responses,
- whether `9098` is externally reachable,
- whether `6060` accepts browser credentials when `6061` is healthy.

Do not infer “closed” from a local runtime that has no outbound connectivity; use the actual GSC external probe.

## Headless browser acceptance tests after challenge work

Use a fresh browser context (no cookies) for each entry path.

### Edge `443`

```text
GET https://titan.myip.gr/cfm-admin/
expected: unauthenticated flow reaches CFM PoW before login credentials
solve once
expected: login loads, no challenge loop
```

### Direct TLS `6061`

```text
GET https://titan.myip.gr:6061/cfm-admin/
expected: same CFM PoW semantics as edge
solve once
expected: login loads and session works
```

### Direct HTTP `6060` while TLS is healthy

```text
GET http://titan.myip.gr:6060/cfm-admin/
expected: redirected to https://titan.myip.gr:6061/cfm-admin/
```

Verify that an **edge backend hop** to loopback `6060` does not cause the public `:443` browser to be redirected to `:6061`.

Do not intentionally break production TLS merely to test fallback. Cover `TLS unavailable -> 6060 challenge fallback` with unit/integration tests or a controlled staging node.

## XFF/header-spoof regression checks

Low-volume requests only.

Direct `6061` request with attacker headers:

```http
X-Forwarded-For: 8.8.8.8
X-Real-IP: 8.8.4.4
CF-Connecting-IP: 1.1.1.1
X-Forwarded-Proto: http
```

Expected: direct listener uses the actual TCP peer/TLS state, not these values.

Through the trusted edge, inject an XFF value and verify the Go control plane sees **one canonical edge-derived client IP**, not `attacker-value, real-ip`.

## Cookie checks

Inspect `Set-Cookie` on:

- direct `6061`,
- edge `443`,
- controlled HTTP fallback.

Expected final policy:

- HTTPS admin session cookie: `HttpOnly`, `Secure`, intended `SameSite`, `Path=/`.
- challenge clearance: signed/host+IP-bound and `Secure` on HTTPS.
- direct healthy `6060`: no credential-bearing session should be established over HTTP.
- fallback `6060`: explicitly documented degraded behaviour only when TLS is unavailable.

## API differential tests

Use dedicated short-lived test/scoped credentials where possible. Never place real secrets in `Audit.md`, screenshots or captured logs.

For each selected endpoint compare:

```text
anonymous
invalid bearer
admin bearer
scoped bearer in-scope
scoped bearer out-of-scope
admin session
embed scoped cookie (where relevant)
```

Record status + minimal response shape, not sensitive payloads.

---

# 8. Acceptance checklist / implementation order

Keep the changes small enough that each step is independently reviewable and reversible.

## Step 1 — trusted request identity / XFF

- [ ] Replace CFM-admin `$proxy_add_x_forwarded_for` with canonical `$remote_addr` at the Angie/OpenResty -> Go boundary.
- [ ] Add one Go trusted-peer/client-IP/effective-scheme helper.
- [ ] `realIPFromRequest` returns one validated IP, never arbitrary XFF text.
- [ ] Direct `6060/6061` ignores spoofed forwarded client/scheme headers.
- [ ] Login rate-limit tests include forged XFF regression.
- [ ] ChallengeServer consumes the same identity rules before direct mounting.

## Step 2 — reusable Go challenge handler + admin login gate

- [ ] Extract/reuse ChallengeServer HTTP handler; no duplicate PoW implementation.
- [ ] Keep loopback `9098` using the same handler.
- [ ] Register `/__cfm_challenge` and `/__cfm_verify` on the apiserver for direct listeners.
- [ ] Export/reuse signed clearance validation.
- [ ] Gate interactive `/login` / `/cfm-admin/login` only.
- [ ] Valid admin/scoped bearer and embed flows are not challenged.
- [ ] Missing clearance cannot bypass PoW by direct login POST.
- [ ] No `AddChallenge`, challenge nft sets or legacy DNAT challenge state is reintroduced.
- [ ] Test edge-style prefixed `next` paths; no `/cfm-admin` loss/double prefix/redirect loop.
- [ ] Preserve the historical regression test corresponding to `up=cfm_challenge` / `uaddr=127.0.0.1:6060` so routing intent cannot silently become dead again.

## Step 3 — `6060` direct admin transport policy

- [ ] Bind/check TLS listener before declaring it ready.
- [ ] Direct GET/HEAD `6060/cfm-admin*` redirects to same host `:6061` only when TLS is ready.
- [ ] Angie loopback backend requests are not redirected away from public `:443`.
- [ ] Direct unsafe admin methods over `6060` are not processed when TLS is healthy.
- [ ] Controlled TLS-unavailable test proves `6060` fallback remains challenge-gated.
- [ ] Degraded fallback is logged visibly.

## Step 4 — request-aware Secure session cookie

- [ ] Confirm/implement goauth request-aware Secure policy (preferred) or another clean supported mechanism.
- [ ] HTTPS edge and direct `6061` always emit Secure session cookies.
- [ ] Healthy `6060` never processes browser login/session writes.
- [ ] Explicit HTTP fallback behaviour works only when TLS unavailable and is documented/logged as degraded.
- [ ] Do not change SameSite/cookie name in the same PR unless separately tested.

## Step 5 — per-auth-mechanism rate limiter

- [ ] Add route-cost classification.
- [ ] Add mechanism/identity classification without raw-token logging.
- [ ] Ship observe/shadow mode first.
- [ ] Measure normal CFM Web, admin UI and cPanel scoped traffic.
- [ ] Enforce high ceilings, then tune heavy/write families.
- [ ] Add memory pruning, `Retry-After`, audit/anomaly events.

## Step 6 — exhaustive endpoint audit

- [ ] Generate route inventory from code.
- [ ] Reconcile every route with `docs/endpoint_scope_inventory.md`.
- [ ] Static proof for every admin/scoped/public/self-auth route.
- [ ] Live low-volume differential checks with GSC-MCP.
- [ ] Add missing authz integration tests.
- [ ] Update this document with findings/fixes and exact commit/PR references.

---

# 9. Useful code/history references

Current code:

- `internal/apiserver/apiserver.go` — listeners, shared handler stack, `/cfm-admin/` prefix redispatch, goauth configuration.
- `internal/apiserver/middleware.go` — auth mechanism order and contexts.
- `internal/apiserver/request_log.go` — current forwarded-IP handling.
- `internal/apiserver/login_rate_limit.go` — existing login-specific rate limiter.
- `internal/apiserver/csrf_middleware.go` — session-only CSRF policy.
- `internal/webdetector/challenge_server.go` — challenge, verify, clearance issue/verify, rate limiting.
- `internal/webdetector/challenge_server_clearance_test.go` — signed clearance contract.
- `configs/angie.conf`, `configs/openresty.conf` — edge proxy and historical `/cfm-admin/login` `$cfm_force_challenge` routing.
- `configs/cfm.conf` — `6060`/`6061`, auth cookie defaults.
- `docs/endpoint_scope_inventory.md` — current backend authz inventory baseline.
- `cfm-web/config/fleet.php` in the separate `chrismfz/cfm-web` repo — normal fleet transport defaults to HTTPS `6061` and `server_name` for SNI.

History to preserve in review comments/tests:

- PR `#246` — pre-auth login challenge concept; correct exemptions, obsolete DNAT enforcement.
- commit `b041f9996fd27de40d157ef8d192ccd0e75a1daa` — forced edge PoW on `/cfm-admin/login`.
- commit `dea270e29661b73c9bca7444c36577c2827cc9d3` — fixed hardcoded-Go routing; key log symptom `up=cfm_challenge` but `uaddr=127.0.0.1:6060`.
- PR `#316` — `/cfm-admin` challenge redirect prefix repair.
- PR `#317` — narrowed redirect rewrite because of loop risk.
- PR `#318` / commit `5a1fbabfd354651703f15a6e3fbe74ac1b750a75` — reverted login to direct Go upstream to stop challenge/WAF routing from interfering with login.
- commit `e40cce8fec293091f60d5ee3c48433a6b4a94a44` — removed legacy per-IP challenge-DNAT and DNAT-era Go pre-auth gate during edge unification; do not resurrect that machinery.
- commit `6ef61e8ada7734d5932a934ced51e12d6b4880fd` — trusted-proxy hardening for edge `X-Forwarded-Proto`; useful precedent for fail-safe forwarded-header trust.

---

## Final design principle

The desired end state is not “hide 6060/6061”. It is:

> **The CFM admin/API has the same authentication, scope enforcement, client-identity semantics and pre-auth browser protection regardless of whether the request entered through the edge or the direct Go listener.**

The edge may add WAF/transport benefits, but bypassing the edge must not bypass the CFM control-plane security model.
