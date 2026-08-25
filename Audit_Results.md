# CFM Live Audit Results

This file tracks confirmed live findings, source-confirmed concerns, and remaining live verification work for the CFM control-plane audit. It complements `Audit.md` and `Improvements.md`.

Target used for the first live pass: `titan.myip.gr`

Primary surfaces:

- `http://titan.myip.gr:6060`
- `https://titan.myip.gr:6061`
- `https://titan.myip.gr/cfm-admin/`
- external reachability check of `:9098`

Audit mode: active, low-volume, non-destructive. Production state must not be changed during verification unless separately approved.

## Status legend

- **CONFIRMED LIVE** — reproduced against the deployed service.
- **SOURCE CONFIRMED / LIVE PENDING** — current code demonstrates the issue or missing guard, but credentialed/live reproduction is still pending.
- **PASS** — tested and behaved as intended.
- **UNTESTED** — still needs live verification.

---

## R01 — Plaintext control plane on TCP/6060

**Severity:** HIGH  
**Status:** ✅ SOURCE FIXED (defence in depth) / ✅ LIVE VERIFIED 2026-08-25 (see third-pass addendum)  
**Priority:** P0/P1

**Fix:** (1) The plaintext `:6060` listener is now loopback-only by default —
**code-enforced**: `httpBindAddr` resolves an unset `LISTEN_ADDRESS` to `127.0.0.1` at
the bind site (not just the reference `cfm.conf` value), so no config binds the wildcard
implicitly; an explicit `0.0.0.0` stays the opt-in escape hatch. Edge + CLI both reach
`:6060` over loopback; `:6061` stays public via `TLS_LISTEN_ADDRESS` (keep it `0.0.0.0` —
`:6061` inherits `LISTEN_ADDRESS` when that key is unset). So there is no Internet-reachable
plaintext admin plane by default. (2) A new pre-auth `AdminTransportRedirect` middleware
(`internal/apiserver/transport_redirect.go`, wired in `Start()` outside `TokenMiddleware`)
upgrades direct external `:6060` browser GET/HEAD admin routes to `:6061` once a
bind-verified `tlsReady` is set, refuses state-changing plaintext admin requests with `403`
(never processed-then-redirected), and serves a logged degraded fallback when TLS is
genuinely down. Edge/`:6061`/loopback CLI/machine-`/api/v1` are untouched. **Residuals
(tracked):** machine-`/api/v1` writes on a re-exposed `:6060` stay plaintext (R01 closure
for them rests on the loopback bind, not this middleware), and the TLS-down degraded window
is **read-only** (writes are refused with `403` regardless of TLS state) with challenge-gating
of the remaining GET/HEAD traffic deferred to Step 4 — both realistic only with an explicit
`0.0.0.0`.
Tests: `transport_redirect_test.go`. Design + operator decisions:
`docs/security/direct-6060-transport-policy.md`. Live retest (§below) rolls up to Step 10.

`84.54.49.200:6060` is Internet reachable and serves the real CFM HTTP handler over plaintext.

Observed flow:

```text
GET http://titan.myip.gr:6060/cfm-admin/
  -> 303 /cfm-admin/login?next=...
  -> 200 CFM login page
```

The flow remains on HTTP/6060. No HTTPS upgrade to `:6061` occurs.

Security impact:

- browser credentials may be submitted over plaintext if an operator follows the direct 6060 URL;
- Bearer/admin/scoped tokens can also be sent to the same handler over plaintext;
- Secure-cookie hardening alone is insufficient because credentials/tokens travel before a cookie exists.

Affected design/source:

- `internal/apiserver/apiserver.go::Start`
- HTTP and TLS listeners currently share the same application handler.

Planned remediation is already documented in `Audit.md`:

- direct browser `/cfm-admin/*` on 6060 should redirect to 6061 when the TLS listener is available;
- requests arriving from the trusted local edge proxy to loopback:6060 must NOT be redirected externally;
- if 6061 is genuinely unavailable, 6060 may provide an explicit degraded fallback with challenge and a separate HTTP-fallback session-cookie strategy;
- API compatibility on 6060 must be decided explicitly rather than accidentally inherited from the shared handler.

### Retest after fix

- [x] direct `http://host:6060/cfm-admin/` redirects to `https://host:6061/cfm-admin/` while 6061 is healthy (2026-08-25: `302 → https://titan.myip.gr:6061/cfm-admin/`, with `:6060` deliberately left on `0.0.0.0` as an explicit deployment exception to exercise the redirect);
- [ ] edge `https://host/cfm-admin/ -> loopback:6060` does not redirect to external `:6061`;
- [ ] degraded fallback behavior works only when intentionally active;
- [ ] no credential or Bearer token is silently accepted over unintended plaintext browser flow.

---

## R02 — pprof lacks an explicit admin-only role gate

**Severity:** HIGH  
**Status:** ✅ SOURCE FIXED / ✅ LIVE VERIFIED 2026-08-25 (scoped→403, anon→401; see third-pass addendum)  
**Priority:** P0/P1

**Fix (source):** every pprof handler is now wrapped with `adminOnlyHandler` in
`internal/apiserver/apiserver_debug.go::registerPprofHandlers`, mirroring the gate
already used for `/api/v1/debug/*`, `/unblock` and `/search`. A regression test
(`internal/apiserver/apiserver_pprof_authz_test.go`) asserts scoped→403,
anonymous→403 and admin→200 at the handler, so the profiler never runs for a
non-admin. The `/cfm-admin/debug/pprof/` prefix re-dispatches onto the same mux,
so it inherits the same gate. Live credentialed scoped→403 proof is still pending
(no scoped token was available in the audit environment — see Step 10).

Original finding (pre-fix): registration attached:

```text
/debug/pprof/
/debug/pprof/cmdline
/debug/pprof/profile
/debug/pprof/symbol
/debug/pprof/trace
```

to the shared mux without `adminOnlyHandler` / `RequireAdmin` around the pprof handlers.

The global authentication middleware accepts both admin and valid scoped tokens. Therefore a scoped token appeared able to reach pprof even though pprof exposes host-global debugging/process information.

Live results so far:

- anonymous `/debug/pprof/` -> 401
- invalid Bearer -> 401
- anonymous over 6060 -> 401
- anonymous through `/cfm-admin/debug/pprof/` -> 401
- anonymous `/debug/pprof/cmdline` -> 401

No valid scoped credential was available in the first audit pass, so scoped -> 200/403 remains to be measured.

Affected source:

- `internal/apiserver/apiserver.go`
- `internal/apiserver/apiserver_debug.go::registerPprofHandlers`

Expected policy:

```text
anonymous -> 401
invalid   -> 401
scoped    -> 403
admin     -> 200
```

### Tests

- [x] source unit test: scoped→403, anonymous→403, admin→200 at the handler (`apiserver_pprof_authz_test.go`)
- [x] live: valid scoped token against `GET /debug/pprof/heap` → 403 (2026-08-25, titan); anonymous → 401
- [ ] live: valid scoped token against `/cfm-admin/debug/pprof/` where applicable → 403
- [ ] live: admin token confirms intended access (no admin token was supplied in the scoped-only retest)

Do NOT execute CPU profile or trace during production verification.

---

## R03 — Mutating GET / CSRF method-confusion gap

**Severity:** HIGH  
**Status:** ✅ SOURCE FIXED / ✅ LIVE VERIFIED 2026-08-25 (GET mutator → 405 + `Allow: POST`; see third-pass addendum)  
**Fix:** the 13 state-changing challenge/waf/clam endpoints are wrapped with `requirePOST` in the route table (`internal/webdetector/http_api.go`) — non-POST → `405` + `Allow: POST` before any auth/param/state work, so a state-changing GET can no longer slip past the session-CSRF boundary. Read siblings stay GET; `ingest-source` confirmed a read. The HTTP/3 opt-in mutators (`/api/v1/http3/{enable,disable}`) were the original "correct reference" for POST-only but returned `405` **without** `Allow: POST` (handler-local check); the 2026-08-25 live retest flagged that inconsistency and it is now fixed — both routes go through the same `requirePOST` wrapper and are in the regression set. Regression: `internal/webdetector/post_only_test.go`. Live authenticated-session repro (GET a mutator with a valid admin session → expect 405) rolls up to Step 10.  

**Priority:** P0/P1

Several handlers documented as POST mutators do not enforce `r.Method == POST` before mutation logic.

Confirmed affected families include:

```text
/api/v1/challenge/vhost/add
/api/v1/challenge/vhost/remove
/api/v1/challenge/vhost/attack

/api/v1/challenge/exclude/add
/api/v1/challenge/exclude/remove

/api/v1/waf/exclude/add
/api/v1/waf/exclude/remove

/api/v1/clam/override/add
/api/v1/clam/override/remove

/api/v1/clam/mode/add
/api/v1/clam/mode/remove

/api/v1/clam/sigignore/add
/api/v1/clam/sigignore/remove
```

Why this matters:

- CFM CSRF middleware correctly treats POST/PUT/PATCH/DELETE as unsafe;
- GET is excluded as expected;
- therefore a mutation handler that accepts GET bypasses the browser-session CSRF boundary.

Correct reference implementation already exists:

```text
/api/v1/http3/enable
/api/v1/http3/disable
```

These explicitly reject non-POST with 405.

### Safe live verification

Use an authenticated browser/session but do not supply a valid production target. A GET with missing/invalid parameters should still return 405 if the method boundary is correct.

For example:

```text
GET /api/v1/challenge/vhost/add
```

Expected after fix:

```text
405 Method Not Allowed
```

If current production reaches parameter validation (`400 missing host`, etc.), that confirms the GET reached a mutating handler without actually changing state.

### Remaining tests

- [ ] authenticated-session GET with no valid target against every listed mutator
- [ ] representative `Origin: https://evil.example` browser-session requests
- [ ] HEAD/OPTIONS/PUT/PATCH/DELETE method matrix for representative mutators
- [ ] audit every other write route for the same missing-method class

---

## R04 — Forwarded-header / effective client identity hardening

**Severity:** MEDIUM / HARDENING  
**Status:** SOURCE CONFIRMED / PARTIAL LIVE  
**Priority:** P1

Current request identity handling trusts forwarded values when the immediate peer is loopback. `realIPFromRequest()` can return the raw `X-Forwarded-For` value rather than one validated canonical address.

Risk:

- if the edge appends an attacker-supplied XFF rather than replacing it, Go-side logs/rate limits/anomaly attribution can receive a malformed or attacker-influenced chain;
- the same trusted-request problem affects effective forwarded host/scheme handling.

Live direct-6061 spoof tests with:

```text
X-Forwarded-For: 8.8.8.8
X-Real-IP: 8.8.4.4
CF-Connecting-IP: 1.1.1.1
X-Forwarded-Proto: http
```

did not change authentication behavior. This is expected because the direct peer is not loopback.

Edge requests also retained the expected authentication/self-IP behavior, but the first pass could not correlate the request with Titan's `cfm.api.log`, so Go-side attribution remains unverified live.

Planned architecture:

- edge overwrites forwarded identity using canonical trusted values;
- one Go trusted-request helper derives `peer_ip`, one canonical `client_ip`, effective scheme, effective host and entry point;
- forwarded headers are honored only for an explicitly trusted immediate peer;
- the same helper feeds auth logs, rate limits, CSRF, detector events and self-protection.

### Remaining tests

- [ ] correlate controlled edge request with `cfm.api.log`
- [ ] verify `src_ip` is canonical and not a raw XFF chain
- [ ] verify effective scheme is HTTPS for edge -> loopback:6060
- [ ] verify direct 6061 ignores spoofed XFF/XFP/XFH
- [ ] verify direct 6060 ignores spoofed forwarded identity unless intentionally trusted

---

## R05 — 6061 direct Internet exposure

**Severity:** HARDENING / architectural  
**Status:** CONFIRMED LIVE

TCP/6061 is externally reachable and serves the authenticated CFM API/UI directly.

This is intentional/supported product surface, not itself an authentication bypass. It means all CFM security controls must work on direct 6061 and must not exist only in the edge proxy.

Observed TLS:

- TLS 1.3 negotiated;
- ALPN h2;
- certificate SAN contains `titan.myip.gr`;
- hostname validation passed.

### Remaining tests

- [x] unknown/wrong/absent SNI behavior — now **defined**: `:6061` serves a
      lazily-generated self-signed fallback cert when the real-cert path has nothing
      (no discovered cert, or no SNI on a by-IP client), so the handshake always
      completes instead of aborting (Step 6 prerequisite; CHANGELOG Unreleased). A
      real discovered cert is still always preferred. Never paired with HSTS.
- [ ] TLS 1.2 minimum / legacy protocol rejection
- [ ] direct `:6061/cfm-admin/` challenge behavior after challenge work is implemented
- [ ] headers/cookie policy after automatic effective-scheme work lands

---

## R06 — Challenge service external exposure

**Status:** PASS

`9098/tcp` was externally closed / connection refused during the first live pass.

This matches the intended local-only challenge service model.

### Regression

- [ ] keep 9098 externally unavailable after challenge handler refactor/mounting changes

---

## R07 — Anonymous/invalid-token baseline

**Status:** PARTIAL PASS

Representative protected routes correctly rejected anonymous and malformed/invalid credentials.

Observed examples:

```text
/api/v1/system/processes -> 401 anonymous / 401 invalid Bearer
/api/v1/webdet/top-short -> 401 anonymous / 401 invalid Bearer
/api/v1/tokens/me -> 401 anonymous
/debug/pprof/ -> 401 anonymous / 401 invalid Bearer
```

Malformed examples also remained denied:

```text
Authorization: Bearer
Authorization: Bearer invalid
Authorization: Basic ...
X-CFM-Token: invalid
```

No unauthenticated sensitive read or write was observed in this pass.

---

## R08 — Embed bootstrap baseline

**Status:** PASS for anonymous-invalid cases

Observed:

```text
random/expired/reused-looking code -> 401
external absolute next -> 400
```

No real production bootstrap code was consumed.

### Remaining tests

- [ ] controlled one-time code issuance + successful bootstrap
- [ ] replay same code -> rejected
- [ ] resulting scoped cookie cannot escape its scope
- [ ] expected-origin handling/postMessage boundary if tested via browser

---

## R09 — MCP baseline

**Status:** PARTIAL PASS

Observed:

```text
/mcp anonymous -> 401 with OAuth resource metadata
/mcp invalid MCP bearer -> 401
OAuth/OpenID discovery endpoints -> 200 public metadata only
```

### Remaining tests

- [ ] valid MCP credential can use only MCP read-only surface
- [ ] MCP credential cannot authenticate directly to `/api/v1/*`
- [ ] OAuth access token is audience-bound and inert against `/api/v1/*`
- [ ] direct 6061 MCP and edge `/cfm-admin/mcp` behave consistently where intended

---

# Next live pass — highest value tests

The first pass established transport and anonymous boundaries. The highest-value remaining work requires controlled credentials.

## 1. Scoped-token authorization matrix — highest priority

Obtain or create a dedicated short-lived test scoped token with:

- one known test vhost;
- optionally one DB user/database;
- no unrelated production scope.

Then verify:

```text
scoped -> admin-only endpoint = 403
scoped -> own vhost endpoint = allowed
scoped -> unrelated vhost = 403 / no rows
scoped with omitted host/global aggregation = never leaks global data
```

Start with the highest-risk admin-only routes:

```text
/debug/pprof/
/api/v1/tokens/list
/api/v1/auth/token
/api/v1/firewall/list
/api/v1/firewall/counters
/api/v1/system/processes
/api/v1/system/listeners
/api/v1/system/cfm-log
/api/v1/system/journal
/api/v1/debug/live
/api/v1/detectors/config
/api/v1/notifier/config
/api/v1/mysql/processlist
/api/v1/webdet/access-recent
/api/v1/webdet/force-unblock-ip
/api/v1/webdet/summary
/api/v1/webdet/ingest-source
/api/v1/webdet/hot-ips
/api/v1/webdet/ip-drilldown
/api/v1/webdet/analyze-ip
/api/v1/clam/health
```

Then scoped-capable routes:

```text
/api/v1/tokens/me
/api/v1/webdet/top-short
/api/v1/webdet/drilldown
/api/v1/webdet/analyze-host
/api/v1/webdet/vhosts
/api/v1/webdet/rules*
/api/v1/webdet/history/* scoped views
/api/v1/challenge/vhost*
/api/v1/challenge/exclude/*
/api/v1/waf/exclude/*
/api/v1/clam/override/*
/api/v1/clam/mode/*
/api/v1/clam/sigignore/*
/api/v1/http3/*
/api/v1/waf/engine/summary
/api/v1/waf/rules
/api/v1/waf/hit-rates
/api/v1/mysql/user-*
/api/v1/mail/dns
/api/v1/mail/traffic
```

Scope-escape variations:

```text
host omitted / empty
vhosts omitted / empty
mixed in-scope,out-of-scope
uppercase
trailing dot
host:443
apex vs www
wildcard
URL encoded host
duplicate query parameters
completely unrelated domain
DB-only scoped token with no vhost scope
vhost-only scoped token with no DB scope
```

## 2. Browser-session CSRF/method pass

With a dedicated admin test session:

- prove listed mutators reject GET after remediation or currently reach validation before remediation;
- test `Origin: https://evil.example` for unsafe methods;
- check HEAD/OPTIONS/PUT/PATCH/DELETE method confusion;
- do not supply production-valid mutation targets.

## 3. Auth logging / detector telemetry

Now that `cfm_endpoints` + one-line auth logging is planned, capture the current baseline first:

- one failed login;
- one successful controlled login;
- one invalid Bearer;
- one valid admin Bearer;
- one valid scoped Bearer;
- one scoped authorization denial;
- one rate-limit response only if it can be generated safely without approaching block thresholds.

Correlate each with `cfm.api.log` and detector/anomaly output. Record missing fields so implementation can be tested against a real baseline.

## 4. Admin-token API consistency: edge vs direct 6061

For read-only admin endpoints compare:

```text
https://titan.myip.gr:6061/api/v1/...
https://titan.myip.gr/cfm-admin/api/v1/...
```

Expected data/auth semantics should match except for transport/entry metadata.

Good read-only samples:

```text
/api/v1/system/listeners
/api/v1/firewall/counters
/api/v1/detectors/status
/api/v1/notifier/status
/api/v1/health/snapshot
```

Do not copy sensitive response bodies into the audit; status/schema/minimal metadata is enough.

## 5. MCP credential boundary

With a controlled MCP credential:

```text
MCP token -> /mcp = allowed
MCP token -> /api/v1/system/status-like route = 401/denied
OAuth MCP access token -> /api/v1/* = denied
AUTH_TOKEN -> /mcp may behave according to documented compatibility policy
```

This verifies that read-only MCP credentials cannot become general API credentials.

## 6. TLS / host-routing edge cases

Low-volume checks:

- wrong/unknown SNI on 6061;
- Host header mismatch while SNI is correct;
- TLS 1.0/1.1 rejection;
- TLS 1.2 acceptance if intentionally supported;
- absolute-form requests / unusual Host formatting only if tooling supports them safely;
- confirm no alternate hostname accidentally receives an unrelated certificate/control-plane identity.

## 7. Response hardening / cache identity

For authentication endpoints and identity-sensitive routes compare headers on edge and direct 6061:

```text
/api/v1/tokens/me
/api/v1/admin/authcheck
/login
/login/verify
/api/v1/embed/bootstrap
```

Check:

- `Cache-Control: no-store` where identity/security sensitive;
- `Vary: Authorization, Cookie` where appropriate;
- no auth-dependent response caching;
- no token/session material in redirects, URLs or response headers.

## 8. Challenge coverage — after implementation

Do not judge current deployment against future design. Once Go challenge gating lands, run a dedicated regression across:

```text
edge https://host/cfm-admin/
direct https://host:6061/cfm-admin/
direct http://host:6060/cfm-admin/ when 6061 available
direct http://host:6060/cfm-admin/ degraded fallback
```

Verify:

- same pre-auth browser challenge policy at every supported entry point;
- API Bearer/scoped/embed traffic is not challenged;
- direct POST login cannot bypass challenge clearance;
- successful clearance works across same hostname/ports as intended;
- challenge service remains non-public on 9098.

---

# Current audit summary

Confirmed live:

1. **HIGH:** functional plaintext CFM control plane on public 6060 with no TLS redirect.
2. **HARDENING:** public 6061 is a first-class direct Internet control-plane entry point.
3. **PASS:** 9098 externally unavailable.
4. **PASS/PARTIAL:** anonymous and invalid-token samples are denied.
5. **PASS/PARTIAL:** invalid embed bootstrap/open-redirect attempts are rejected.
6. **PASS/PARTIAL:** MCP anonymous/invalid authentication boundaries behave as expected.

Source-confirmed, live credentialed proof still pending:

1. **HIGH — SOURCE FIXED:** scoped-token access to pprof now blocked by an explicit
   `adminOnlyHandler` gate on every pprof handler, with a scoped→403 / admin→200
   regression test. Live credentialed scoped→403 proof still pending.
2. **HIGH:** multiple mutating handlers accept GET at the handler level, bypassing unsafe-method CSRF protection.
3. **MEDIUM/HARDENING:** forwarded identity needs one canonical trusted-proxy implementation and live log correlation.

The next most valuable audit activity is therefore **not more anonymous endpoint enumeration**. It is a controlled scoped/admin credential matrix plus browser-session method/CSRF checks and log correlation.

---

# Second live pass addendum — 2026-08-23

Source snapshot reviewed before this pass: `main` at `2599147d2617a10e10a6e219350e96fa57326df4`.

Audit mode remained active, low-volume and non-destructive. No production firewall, token, detector/notifier, history, MySQL, challenge, WAF, ClamAV or HTTP/3 state was changed; no pprof profile or trace was requested.

## R04 second-live-pass update — forwarded XFF poisoning confirmed

**Severity:** MEDIUM / HARDENING  
**Status update:** CONFIRMED LIVE for proxied client-IP attribution  
**Priority:** P1

A controlled unauthenticated request was sent through the edge to:

```text
GET https://titan.myip.gr/cfm-admin/api/v1/system/processes
X-Forwarded-For: 8.8.8.8
X-Real-IP: 8.8.4.4
CF-Connecting-IP: 1.1.1.1
X-Forwarded-Proto: http
```

The request returned `401` as expected, but Titan's `cfm.api.log` recorded:

```text
2026-08-23 21:16:41 [apiserver] GET /api/v1/system/processes 401 ... ip=8.8.8.8, 84.54.49.6
```

The immediately following direct request to `https://titan.myip.gr:6061/api/v1/system/processes` with the same spoofed forwarding headers returned `401` and logged:

```text
2026-08-23 21:16:46 [apiserver] GET /api/v1/system/processes 401 ... ip=84.54.49.6
```

This closes the first-pass uncertainty: the edge path appends an attacker-supplied XFF value and Go's `realIPFromRequest()` consumes the complete comma-separated XFF string as the effective log/rate-limit identity when the immediate peer is loopback. Direct `:6061` correctly ignores the spoofed forwarding headers.

No authentication bypass was observed. The confirmed impact is attacker influence over proxied client identity used by request logging and any limiter/anomaly path that reuses `realIPFromRequest()`.

Affected source/design:

- `internal/apiserver/request_log.go::realIPFromRequest`
- CFM-admin edge proxy contract currently using append-style `X-Forwarded-For`

Recommended remediation remains the design already documented in `Audit.md`: overwrite CFM control-plane XFF with the canonical edge client address and replace raw forwarded-header consumption with one trusted-immediate-peer helper that yields exactly one parseable client IP.

Still unverified for R04:

- effective scheme on edge -> loopback:6060, because current `cfm.api.log` records do not include scheme;
- direct 6060 forwarded-header behavior.

---

## R10 — Authentication/cache response-header hardening gaps

**Severity:** HARDENING  
**Status:** ✅ SOURCE FIXED (safe subset) / CSP+frame+HSTS ⛔ DECLINED (too risky for P2) / ✅ LIVE VERIFIED 2026-08-25 (nosniff + Referrer-Policy direct & edge; `no-store` on anon 401; see third-pass addendum)  
**Priority:** P2

**Fix (Step 9):** a new `SecurityHeadersMiddleware` (`internal/apiserver/security_headers.go`,
wired outside `AdminTransportRedirect`, inside `RequestLog`) sets `X-Content-Type-Options:
nosniff` and `Referrer-Policy: strict-origin-when-cross-origin` on **every** direct
`:6060`/`:6061` response, so the direct control plane no longer depends on edge-only headers
(closes the `/login`-missing-`nosniff` gap; `strict-origin-when-cross-origin` chosen over
`no-referrer` so `CSRFMiddleware`'s `Referer` fallback keeps working). Separately,
`setAuthIdentityNoCacheHeaders()` is now called at the `TokenMiddleware` auth-failure points
(`rejectTokenAuth` + the two inline `401`s), so anonymous/invalid `401`s carry
`Cache-Control: no-store` + `Vary` — they were previously rejected before the endpoint
headers ran. **CSP + frame policy + HSTS: ⛔ DECLINED** (operator decision — too risky
for a P2 gain): a full `script-src` CSP breaks the inline-script admin UI; a blanket
`frame-ancestors`/`DENY` breaks the cPanel iframe embed (and the panel origin is
client-provided, so it cannot be trust-derived); and HSTS is host-wide so a `:6061`
HSTS would force HTTPS on the supported plaintext `:6060` and break the self-signed
`:6061` bootstrap. An operator who wants these adds them at their own edge/reverse
proxy where the trusted origins + TLS posture are known. Full rationale + the safe
opt-in shape (if ever revisited): `docs/security/control-plane-csp-frame-hsts.md`.
Tests: `security_headers_test.go`. Live retest (direct-vs-edge parity with a
credentialed session) → Step 10.

Low-volume header-only checks found different hardening behavior between direct `:6061` and the edge.

Observed direct `:6061`:

- `GET /login` -> `200`, `Cache-Control: no-store`, `Vary: Cookie`;
- `GET /login/verify` -> `200`, `Cache-Control: no-store`, `Vary: Cookie`;
- anonymous `GET /api/v1/tokens/me` -> `401`, `Vary: Cookie`, but no `Cache-Control: no-store`;
- anonymous `GET /api/v1/admin/authcheck` -> `401`, `Vary: Cookie`, but no `Cache-Control: no-store`;
- invalid `GET /api/v1/embed/bootstrap?...` -> `401`, `Vary: Cookie`, but no `Cache-Control: no-store`.

Observed through `/cfm-admin` edge:

- the same anonymous API/bootstrap `401` responses received `Cache-Control: no-store` from the edge;
- `/login` and `/login/verify` also returned `Cache-Control: no-store` (duplicated on the proxied login responses).

The sampled login responses did not expose `Content-Security-Policy`, `X-Frame-Options`, `Referrer-Policy`, `Strict-Transport-Security` or `X-Content-Type-Options`. The sampled API `401` responses did include `X-Content-Type-Options: nosniff`.

Source explains the direct identity-response cache discrepancy: `setAuthIdentityNoCacheHeaders()` is called inside `/api/v1/tokens/me` and `/api/v1/admin/authcheck`, but anonymous requests are rejected earlier by `TokenMiddleware`, before those endpoint-specific headers run.

No concrete sensitive-response cache leak or cookie-attribute vulnerability was proven in this pass, so this remains hardening rather than a vulnerability.

Recommended remediation:

- set conservative no-store/cache identity headers on authentication failures at the outer auth middleware as well as successful identity handlers;
- centralize browser security headers for both direct `:6061` and edge entry points so the direct control plane does not depend on edge-only policy;
- add HSTS only where the intended direct/edge transport policy is finalized, especially while plaintext `:6060` remains a supported/degraded surface.

---

## Second-pass credential/tooling coverage notes

No valid scoped token, admin bearer or authenticated admin browser session was available in the authorized audit environment. The persistent browser profile landed at the CFM sign-in page, and the managed identity store was empty. Consequently:

- R02 scoped -> pprof was **SOURCE CONFIRMED / LIVE PENDING** at this pass; at the time, main still mounted pprof without an explicit admin gate. _[update: source-fixed after this pass — every pprof handler now behind `adminOnlyHandler` with a scoped→403 regression test; live scoped proof still pending]_
- R03 mutating-GET/CSRF remains **SOURCE CONFIRMED / LIVE AUTHENTICATED REPRO PENDING**; current main still lacks method guards on the listed Challenge/WAF/Clam mutators while HTTP/3 controls enforce POST;
- scoped admin-only and in-scope/out-of-scope matrices remain live-unverified;
- admin-token edge-vs-direct response equivalence remains live-unverified;
- MCP-only and OAuth credential separation remains live-unverified, although current source keeps MCP client credentials separate from `/api/v1` authentication and the node's MCP read surface is operational;
- TLS 1.3 with correct `titan.myip.gr` SNI remains confirmed, but the available scoped TLS probe could not force TLS 1.0/1.1/1.2 or arbitrary/no-SNI handshakes without widening target scope.

---

# Third live pass addendum — 2026-08-25 (credentialed scoped retest)

Target: `titan.myip.gr`, running `cfm-2026.08.25-1.214653.el10.x86_64` (the audit
fixes deployed). A throwaway **viewer-scoped** token (`--vhosts vol2.gr`, `--label
audit-retest`, short TTL) was minted on the box via `cfm webtop tokens create` — the
read-only MCP cannot mint or POST, so this closes the scoped-credential gap the first
two passes flagged. Mode stayed active, low-volume, non-destructive: reads, rejected
writes, and one throwaway token. Every credential was carried only in request headers.

## Verified live

- **R02 (pprof admin-only) — ✅ PASS.** `GET /debug/pprof/heap` with the **scoped**
  token → `403` (denied, as required); anonymous → `401`. The scoped→403 boundary that
  was source-only through the first two passes is now reproduced against the deployed
  service. (Admin→200 not exercised — no admin token was supplied in this scoped-only
  retest; it stays covered by the source regression test.)
- **R03 (mutating-GET / method boundary) — ✅ PASS.** `GET /api/v1/challenge/vhost/add`
  → `405` + `Allow: POST` before any param/state work. During this pass the HTTP/3
  opt-in mutators were found to return the correct `405` but **without** `Allow: POST`
  (a handler-local check diverging from the shared `requirePOST` wrapper) — a
  consistency LOW, not a security issue. **Now fixed**: `/api/v1/http3/{enable,disable}`
  go through `requirePOST` and are in the `post_only_test.go` regression set.
- **R01 (direct `:6060` transport) — ✅ PASS.** `GET http://titan.myip.gr:6060/cfm-admin/`
  → `302` to `https://titan.myip.gr:6061/cfm-admin/`. Note: for this retest `:6060` was
  **deliberately left bound to `0.0.0.0`** (an explicit deployment exception) so the
  direct-external redirect path could be exercised at all — by default the R01 fix binds
  `:6060` to loopback, where this browser-upgrade path never applies.
- **R10 (security/cache headers) — ✅ PASS, direct and edge.** Direct `:6061` responses
  now carry `X-Content-Type-Options: nosniff` + `Referrer-Policy:
  strict-origin-when-cross-origin` (before→after confirmed against the pre-deploy
  baseline that lacked them), and anonymous `401`s carry `Cache-Control: no-store`. The
  same headers are present on the edge `/cfm-admin/login` path (443 via OpenResty), so
  the direct control plane no longer depends on edge-only policy — direct-vs-edge parity
  holds.

## Scoped authorization matrix — ✅ PASS (clean)

The scoped viewer token showed no admin escape and no cross-vhost leakage: admin-only
endpoints returned `403` (not served), in-scope vhost reads were allowed, unrelated
vhosts returned `403`/no rows, omitted/empty host did not fall back to global
aggregation, `merge_www` behaved fail-closed, and host-access history was scope-correct.

## Still pending (not findings — verification leftovers)

- Admin-positive paths (pprof admin→200, admin edge-vs-direct read parity) — no admin
  token was supplied in the scoped-only retest.
- No-SNI `:6061` self-signed fallback cert — the audit transport auto-sets SNI to the
  hostname, so a genuine by-IP/no-SNI handshake couldn't be forced from it; covered by
  source (`tls_fallback.go`) and the Step 10 `openssl s_client` one-liner for on-box run.

## Overall

Verdict of this pass: **PASS with low/hardening notes** — no REQUIRES-FIX item. The one
actionable code nit (http3 `Allow: POST`) is resolved. R04 remains the standing
MEDIUM/HARDENING item (edge XFF attribution — see second-pass addendum), tracked for the
trusted-proxy helper work.
