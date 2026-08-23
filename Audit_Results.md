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
**Status:** CONFIRMED LIVE  
**Priority:** P0/P1

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

- [ ] direct `http://host:6060/cfm-admin/` redirects to `https://host:6061/cfm-admin/` while 6061 is healthy;
- [ ] edge `https://host/cfm-admin/ -> loopback:6060` does not redirect to external `:6061`;
- [ ] degraded fallback behavior works only when intentionally active;
- [ ] no credential or Bearer token is silently accepted over unintended plaintext browser flow.

---

## R02 — pprof lacks an explicit admin-only role gate

**Severity:** HIGH  
**Status:** SOURCE CONFIRMED / LIVE SCOPED TEST PENDING  
**Priority:** P0/P1

Current registration attaches:

```text
/debug/pprof/
/debug/pprof/cmdline
/debug/pprof/profile
/debug/pprof/symbol
/debug/pprof/trace
```

to the shared mux without `adminOnlyHandler` / `RequireAdmin` around the pprof handlers.

The global authentication middleware accepts both admin and valid scoped tokens. Therefore a scoped token appears able to reach pprof even though pprof exposes host-global debugging/process information.

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

### Remaining test

- [ ] valid scoped token against `GET /debug/pprof/`
- [ ] valid scoped token against `/cfm-admin/debug/pprof/` where applicable
- [ ] admin token confirms intended access

Do NOT execute CPU profile or trace during production verification.

---

## R03 — Mutating GET / CSRF method-confusion gap

**Severity:** HIGH  
**Status:** SOURCE CONFIRMED / LIVE AUTHENTICATED REPRO PENDING  
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

- [ ] unknown/wrong SNI behavior
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

1. **HIGH:** scoped-token access to pprof likely lacks admin-role enforcement.
2. **HIGH:** multiple mutating handlers accept GET at the handler level, bypassing unsafe-method CSRF protection.
3. **MEDIUM/HARDENING:** forwarded identity needs one canonical trusted-proxy implementation and live log correlation.

The next most valuable audit activity is therefore **not more anonymous endpoint enumeration**. It is a controlled scoped/admin credential matrix plus browser-session method/CSRF checks and log correlation.
