# CFM control-plane audit — canonical fix execution order

**Purpose:** single execution source-of-truth for the remediation work discovered in `Audit.md` and confirmed/triaged in `Audit_Results.md`.

**Use this file for implementation order.**

- `Audit.md` keeps architecture, historical context and detailed design rationale.
- `Audit_Results.md` keeps live/static evidence and retest status.
- `Improvements.md` keeps longer-term product improvements (`cfm_endpoints`, logging, detector integration, etc.).
- This file answers: **what do we fix next, in what order, what exactly changes, and how do we prove each step is complete?**

Do not skip dependency steps merely because a later change looks small. In particular, trusted client identity/effective scheme is a prerequisite for challenge IP binding, automatic Secure-cookie policy, auth logging and rate limiting.

---

# Execution order at a glance

```text
1.  ✅ Trusted request identity + effective scheme (XFF/XFP)   — apiserver done (#1338); challenge item 8 declined
2.  ✅ pprof explicit admin-only authorization                 — done (#1341); live scoped proof -> Step 10
3.  ✅ POST-only enforcement for every mutating endpoint       — done (this change)
4.  ☐  Reusable Go pre-auth challenge + interactive login gate
5.  ☐  Direct :6060 browser transport policy -> :6061 when TLS ready
6.  ☐  Automatic request-aware session-cookie transport policy
7.  ✅ cfm.api.log auth-attempt schema + api_abuse -> cfm_endpoints default-on  — done (#1338); auth_autoblock.go removal pending
8.  ☐  Per-auth-mechanism / route-cost API rate limiting
9.  ☐  Direct control-plane response/cache/security-header hardening
10. ☐  Controlled credentialed regression + close Audit_Results findings
```

Status legend: ✅ source-complete · ☐ open. Live credentialed verification for the
done items (R02 scoped→403, etc.) rolls up to Step 10.

The first three are intentionally small, separately reviewable security fixes. Steps 4-6 are the interconnected browser transport/challenge/session work. Steps 7-9 harden abuse detection and response policy after identity/transport semantics are trustworthy. Step 10 proves the final boundaries live.

---

# Step 1 — trusted request identity + effective scheme

**Priority:** P1 prerequisite  
**Findings:** `Audit_Results.md` R04, CONFIRMED LIVE  
**Status:** ✅ SOURCE COMPLETE (this section's "Done when" met) — canonical identity/scheme
helper `internal/apiserver/request_identity.go` (`requestPeer`), edge configs forward
`$remote_addr` + `$cf_xfp` on every apiserver `:6060` control-plane block (both engines),
and regression tests cover all three entry topologies (`TestRequestPeerEntryTopologies`)
plus the login forged-XFF path (`TestLoginLimiterIgnoresForgedXFFForPerIPBucket`). Landed
via #1338 + this branch. The broader Step-1 acceptance list in `Audit.md` keeps ONE box
open — ChallengeServer identity/scheme unification — the challenge upstream still forwards
`$scheme` and uses its own `clientIP()`. A loopback-only unification of that helper was
attempted and **deliberately declined** (PR #1342 closed unmerged, 2026-08-25): narrowing the
challenge server to loopback-only trust removed its tolerance for non-loopback front-ends and
was judged too risky fleet-wide. Any future challenge direct-mount (Step 4 below) must handle
identity with an **explicit per-listener trust policy**, not a fleet-wide narrowing — see the
decision note under item 8 in `Audit.md`.

## Problem

The edge currently appends client-supplied XFF. A live Titan request with:

```text
X-Forwarded-For: 8.8.8.8
```

was logged by Go as a chain equivalent to:

```text
8.8.8.8, <real-client-ip>
```

whereas the same spoof against direct `:6061` correctly used the actual socket peer.

`realIPFromRequest()` must not treat arbitrary comma-separated XFF text as one client identity. This affects logging, login throttling, anomaly attribution, challenge clearance binding, future API rate limits and any source-bound policy.

## Change

For **CFM control-plane proxy locations only** in both Angie/OpenResty configs:

```nginx
proxy_set_header X-Real-IP        $remote_addr;
proxy_set_header X-Forwarded-For  $remote_addr;
proxy_set_header X-Forwarded-Proto $cf_xfp;
```

Do not globally change customer-origin proxy XFF semantics as part of this patch.

Create one Go helper, conceptually:

```go
type RequestPeer struct {
    ImmediateIP  net.IP
    ClientIP     net.IP
    TrustedProxy bool
    Scheme       string // http|https
}
```

Rules:

1. Parse `RemoteAddr` first.
2. Direct requests never trust forwarded identity/scheme/host headers.
3. Trusted proxy means the **immediate peer** is explicitly trusted; loopback is the primary Angie/OpenResty backend trust relationship.
4. Do not silently trust every RFC1918/private/link-local source.
5. A trusted forwarded client address must become **exactly one parsed canonical IP**.
6. Direct `:6061` derives HTTPS from `r.TLS`, ignoring forged XFP.
7. Direct `:6060` remains HTTP, ignoring forged XFP.
8. Edge HTTPS -> loopback HTTP accepts canonical `X-Forwarded-Proto=https` from the trusted edge.

Use this helper everywhere identity/scheme matters:

- request logging;
- login limiter/account lock/autoblock attribution;
- API anomaly events;
- challenge issue/verify and clearance IP binding;
- session-cookie transport policy;
- CSRF host/scheme reasoning where applicable;
- `cfm_endpoints` and later API limiter;
- future source binding.

## Done when

- edge spoofed XFF no longer produces a comma-separated identity;
- `cfm.api.log` has one canonical client IP;
- direct 6060/6061 ignore forwarded spoof headers;
- edge HTTPS is classified as effective `https` despite Go receiving the final hop over loopback HTTP;
- regression tests cover all three entry topologies.

---

# Step 2 — make pprof explicitly admin-only

**Priority:** P0/P1  
**Finding:** `Audit_Results.md` R02, HIGH source-confirmed / scoped live proof pending  
**Status:** ✅ SOURCE FIXED — every pprof handler now wrapped with `adminOnlyHandler`
(`internal/apiserver/apiserver_debug.go`); scoped→403 / admin→200 regression test
added (`internal/apiserver/apiserver_pprof_authz_test.go`). Live credentialed
scoped→403 proof still pending (Step 10) — no scoped token was available in the
audit environment.

## Problem

`/debug/pprof/*` is registered on the shared mux without an explicit `adminOnlyHandler` / `RequireAdmin` role gate. Global authentication accepts scoped credentials as valid authentication, so host-global debug information must not rely on authentication alone.

Affected surface:

```text
/debug/pprof/
/debug/pprof/cmdline
/debug/pprof/profile
/debug/pprof/symbol
/debug/pprof/trace
```

## Change

Wrap **every pprof handler** with the same explicit admin-role enforcement used by other node-global endpoints.

Do not merely hide links in the UI.

Keep the existing pprof write-timeout/capture protections.

## Done when

```text
anonymous -> 401   (TokenMiddleware, unchanged)
invalid   -> 401   (TokenMiddleware, unchanged)
scoped    -> 403   (adminOnlyHandler)   ✅ source + unit test
admin     -> expected handler response  ✅ source + unit test
```

- [x] every pprof handler wrapped with the shared admin-role gate (`adminOnlyHandler`)
- [x] scoped→403 / anonymous→403 / admin→200 regression test (`apiserver_pprof_authz_test.go`)
- [x] existing pprof write-timeout/capture protections kept (`PprofWriteTimeoutMiddleware` unchanged)
- [ ] live credentialed scoped→403 proof (deferred to Step 10; needs a scoped token in the audit env)

The unit test asserts scoped→403 at the handler, so the profiler never runs for a
non-admin. Production regression must never execute `profile` or `trace`; `GET
/debug/pprof/` is enough to verify the role boundary.

---

# Step 3 — POST-only enforcement for every mutating endpoint

**Priority:** P0/P1  
**Finding:** `Audit_Results.md` R03, HIGH source-confirmed  
**Status:** ✅ SOURCE FIXED — the 13 state-changing challenge/waf/clam endpoints
(`{challenge/vhost,challenge/exclude,waf/exclude,clam/override,clam/mode,clam/sigignore}/…`)
are wrapped with `requirePOST` in the single-source-of-truth route table
(`internal/webdetector/http_api.go`): non-POST → `405` + `Allow: POST` before any
auth/param/state work. Read siblings (`list`/`status`) stay GET; the already-guarded
mutators (`webdet/rules/*`, `history/{prune,truncate}`, `ua-emergency`,
`force-unblock-ip`, `http3/{enable,disable}`) were verified and left as-is; `ingest-source`
is a read despite its name. Regression tests: `internal/webdetector/post_only_test.go`
(reject non-POST / allow POST / reads stay GET). Live authenticated-session repro of a
state-changing GET rolls up to Step 10.

## Problem

Several handlers described as POST mutators do not reject GET. Since CSRF middleware correctly treats GET as safe, a state-changing GET bypasses the browser-session unsafe-method CSRF boundary.

Known affected families include:

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

`/api/v1/http3/enable|disable` and `force-unblock-ip` are useful correct references because they enforce POST.

## Change

For every mutator, reject the wrong method **before parsing targets or touching state**:

```go
if r.Method != http.MethodPost {
    // Allow: POST where useful
    // 405 Method Not Allowed
    return
}
```

Then perform a source-wide method audit of every mutator family:

```text
Add / Remove / Update / Delete
Enable / Disable
Truncate / Prune
Reload / Restore
Revoke
Block / Unblock
Kill
Refresh
Ingest
Attack
```

Prefer method-aware mux registration where practical, but do not make that refactor a prerequisite for adding explicit guards.

## Done when

- all state-changing endpoints have an explicit intended verb;
- GET/HEAD/OPTIONS/PUT/PATCH/DELETE cannot reach mutation logic unless intentionally supported;
- browser-session unsafe requests still pass CSRF checks;
- authenticated GET with missing parameters returns 405, not `400 missing host/value`;
- integration tests enumerate the known mutator table.

---

# Step 4 — reusable Go pre-auth challenge + interactive login gate

**Priority:** P1  
**Dependency:** Step 1 first

> **Identity constraint (2026-08-25).** Mounting the challenge handlers on the public
> `:6060`/`:6061` control plane needs the challenge server to resolve client identity/scheme
> safely on a public listener. The obvious route — unifying it onto the apiserver's fleet-wide
> loopback-only rule — was attempted and **declined** (PR #1342, closed unmerged) because it
> removed the challenge server's tolerance for non-loopback front-ends. Do this instead with an
> **explicit per-listener trust policy**: the loopback-only rule applies to the request only
> when it arrived on the direct `:6060`/`:6061` mount, while the existing `9098` edge path keeps
> its current behavior. See the item-8 decision note in `Audit.md`.

## Goal

The same pre-auth browser challenge must protect:

```text
https://host/cfm-admin/
https://host:6061/cfm-admin/
http://host:6060/cfm-admin/   # only in genuine degraded fallback
```

without challenging machine/scoped traffic.

## Change

Refactor the existing `internal/webdetector/challenge_server.go` implementation so it exposes reusable handlers, for example:

```text
ChallengeServer
  +-- Handler/RegisterHandlers
  |    +-- /__cfm_challenge
  |    `-- /__cfm_verify
  `-- existing loopback Serve() on :9098
```

There must be one PoW implementation, one signed clearance format and one verifier.

Mount the same handlers in the apiserver.

Gate **interactive login only**:

- unauthenticated browser GET/HEAD login without clearance -> challenge;
- valid clearance -> login page;
- login POST/MFA/WebAuthn continuation without clearance -> fail closed;
- valid admin session -> no challenge;
- admin bearer -> no challenge;
- scoped bearer -> no challenge;
- embed bootstrap cookie -> no challenge;
- MCP -> own auth, no admin-login challenge.

Do not resurrect:

- `AddChallenge()`;
- nft challenge sets;
- DNAT-era challenge enforcement;
- the old 9099 listener.

Preserve regression coverage for the historical failures where Lua selected challenge but nginx still proxied 6060, and for `/cfm-admin` redirect-prefix loops.

## Done when

- edge and direct 6061 get identical interactive challenge semantics;
- direct login POST cannot bypass clearance;
- bearer/scoped/embed/API calls remain unaffected;
- `/cfm-admin` prefix is neither lost nor doubled;
- 9098 remains externally unreachable;
- signed clearance is bound to canonical client IP/host/scope/expiry.

---

# Step 5 — direct :6060 browser transport policy

**Priority:** P0/P1  
**Finding:** `Audit_Results.md` R01, HIGH CONFIRMED LIVE  
**Dependencies:** Step 1; integrates with Step 4  
**Status:** ✅ SOURCE FIXED (defence in depth) — `docs/security/direct-6060-transport-policy.md`.
Two defences shipped: (1) `:6060` is loopback-only by default — **code-enforced** (`httpBindAddr`
resolves an unset `LISTEN_ADDRESS` to `127.0.0.1`, not just the reference-conf value; explicit
`0.0.0.0` stays the opt-in), edge + CLI both loopback, `:6061` stays public (keep
`TLS_LISTEN_ADDRESS=0.0.0.0` — it inherits `LISTEN_ADDRESS` when unset), so no
Internet-reachable plaintext admin plane by default; (2) pre-auth `AdminTransportRedirect`
(`internal/apiserver/transport_redirect.go`, outside `TokenMiddleware`) upgrades direct
external `:6060` browser GET/HEAD → `:6061` once a bind-verified `tlsReady` is set, refuses
state-changing plaintext admin (`403`, not processed-then-redirected), and logs a degraded
HTTP fallback when TLS is down. Edge/`:6061`/loopback-CLI/machine-`/api/v1` untouched.
**Residuals (tracked, → Step 4):** machine-`/api/v1` writes on a re-exposed `:6060` stay
plaintext (their R01 closure rests on the loopback bind); challenge-gating the TLS-down
degraded window is deferred to Step 4 — both realistic only under an explicit `0.0.0.0`.
Tests: `transport_redirect_test.go` (incl. all-unsafe-methods `403`, machine-API write
pass-through, edge write pass-through, `httpBindAddr` default). Live retest → Step 10. The
`## Update` glance list and `Audit_Results.md` R01 reflect this.

## Problem

Titan currently serves the real CFM login/API handler over Internet-reachable plaintext `:6060`. A browser can reach the login form without any HTTPS upgrade.

## Change

Do **not** globally redirect every 6060 request, because the normal public edge path is:

```text
browser HTTPS :443 -> Angie/OpenResty -> HTTP 127.0.0.1:6060 -> Go
```

That trusted loopback backend request must stay on `:443` from the browser's point of view.

For direct external browser admin traffic:

1. Build/bind TLS listener first where configured.
2. Mark `tlsReady` only after successful runtime bind/readiness, not merely because `TLS_PORT > 0`.
3. If TLS is ready:
   - GET/HEAD `http://host:6060/cfm-admin/...` -> equivalent `https://host:6061/cfm-admin/...`;
   - preserve URI safely;
   - build Host/port with proper IPv4/IPv6 handling;
   - do not trust forwarded Host from the direct client.
4. Unsafe direct HTTP admin methods while TLS is healthy must be **rejected**, not processed and then redirected.
5. If TLS genuinely cannot operate, direct 6060 may act as an explicit degraded browser fallback, still challenge-gated.
6. Log degraded mode clearly, e.g. `event=admin_http_fallback`.

Machine/API compatibility on plaintext 6060 must be an explicit product decision; do not accidentally inherit it merely because both listeners share the same handler.

## Done when

- direct 6060 browser admin GET/HEAD upgrades to 6061 while TLS is ready;
- edge -> loopback:6060 never sends the public :443 browser to :6061;
- no login/session-changing credentials are accepted over direct HTTP while TLS is healthy;
- controlled TLS-down fallback works and is visibly logged;
- R01 retest is closed in `Audit_Results.md`.

---

# Step 6 — automatic request-aware session-cookie transport policy

**Priority:** P1  
**Dependencies:** Steps 1 and 5

## Decision

Cookie security becomes automatic. `AUTH_SECURE_COOKIE` is not a permanent operator decision.

Use **effective trusted scheme**, never only `r.TLS`:

```text
edge HTTPS -> loopback HTTP     => https
Direct :6061 TLS               => https
Direct :6060                    => http
```

## Target behavior

```text
effective https
    -> cfm-sid; HttpOnly; Secure

direct 6060 + TLS healthy
    -> no interactive browser login/session writes

TLS unavailable degraded HTTP fallback
    -> separate fallback cookie, e.g. cfm-sid-http-fallback
    -> non-Secure by necessity
```

Use a different cookie name for the HTTP fallback. A browser with an existing `cfm-sid; Secure` must not need to overwrite/downgrade the same cookie over plaintext.

## goauth change

The current goauth/SCS cookie config is manager-global. Do not mutate global `Cookie.Secure` or `Cookie.Name` per request: that creates request races.

Add clean request-aware cookie transport support while sharing one auth/session-store lifecycle. Do not casually open two independent auth/session DB managers merely to obtain different cookie flags.

## Deprecation

After automatic policy lands:

```text
AUTH_SECURE_COOKIE
  -> still parsed temporarily for fleet compatibility
  -> ignored
  -> one-time deprecation warning
  -> removed from new shipped configs after compatibility window
  -> parser/config field removed later
```

Do not bundle SameSite changes or `__Host-` conversion into this step.

## Done when

- edge HTTPS emits Secure normal session cookie;
- direct 6061 emits Secure normal session cookie;
- direct spoofed XFP cannot alter Secure state;
- healthy 6060 cannot establish normal browser session;
- degraded fallback uses distinct fallback cookie and shared server-side auth/session state;
- no global mutable-cookie race exists.

---

# Step 7 — `cfm.api.log` auth trail + `api_abuse` -> `cfm_endpoints`

**Priority:** P1/P2  
**Dependencies:** Step 1

Detailed design lives in `Improvements.md`.

## Detector decision

Evolve/rename the existing `api_abuse` detector into **`cfm_endpoints`**.

It is a built-in safety feature and must be **ON by default even when no `[cfm_endpoints]` section exists**.

Semantics:

```text
no section
    -> instantiate built-in cfm_endpoints defaults

[cfm_endpoints]
    -> built-in defaults + operator overrides

[api_abuse]
    -> temporary deprecated compatibility alias
    -> never run both against the same events
```

Enforcement input remains structured in-process security events, not log tailing.

Normal path:

```text
CFM control-plane event
 -> cfm_endpoints
 -> detector policy
 -> global ignore/leniency
 -> challenge and/or nft block
 -> reporting
 -> cfm.detector.log
 -> Slack/mail
```

Preserve login throttle/account-lock behavior. Remove `auth_autoblock.go` only after detector parity is proven.

## `cfm.api.log`

Keep `cfm.api.log` as the canonical control-plane audit trail.

Require **one physical parse-friendly line per authentication attempt**, success or failure:

- login;
- token admin/scoped;
- MFA/TOTP/passkey/recovery where useful;
- authorization denial/rate-limit significant events.

Common fields should include:

```text
event
kind
result/reason
src_ip
peer_ip
entry=edge|6060|6061|other
scheme=http|https
auth_mech
safe user/token_id if applicable
method
path
status
request_id
```

Never log:

- password;
- raw token/bearer;
- MFA/recovery code;
- WebAuthn assertion;
- session ID;
- clearance cookie value;
- request body merely for auth telemetry.

Signals for `cfm_endpoints` should include login failures/locks, invalid/malformed tokens, scope violations, endpoint fuzz/probing, API rate-limit events, challenge abuse and CSRF/origin rejects.

## Done when

- `cfm_endpoints` exists and runs with no config section;
- old `[api_abuse]` migrates without duplicate counting;
- login/token attempts produce exactly one safe auth line each;
- canonical Step-1 identity fields are used;
- structured events reach normal detector sink/notify/nft path;
- invalid-token bursts can produce bounded enforcement/notification;
- valid admin/scoped credential abuse does not blindly nft-block trusted fleet sources.

---

# Step 8 — per-auth-mechanism / route-cost API rate limiting

**Priority:** P2  
**Dependencies:** Steps 1 and preferably 7

## Goal

Bound already-authenticated control-plane abuse without treating every caller equally.

Identity classes:

```text
token_admin
token_scoped
embed_bootstrap_cookie
session_cookie
MCP handled in MCP auth layer
```

Never key buckets by raw credential material.

Route classes:

```text
cheap_read
normal_read
heavy_read
write
privileged_write
capture_stream
```

## Rollout

1. Authenticate first.
2. Ship **shadow/observe only**.
3. Measure legitimate CFM Web fan-out, admin UI concurrency and panel/plugin polling.
4. Introduce deliberately high safe ceilings.
5. Tune heavy/write/debug/capture separately.
6. Return 429 + Retry-After.
7. Bound/prune limiter memory.
8. Emit safe audit/anomaly events into `cfm_endpoints`.

Important policy:

- invalid Bearer still gets normal 401 and must not reveal credential validity through limiter behavior;
- one scoped token must not exhaust another token's bucket;
- valid admin token runaway should normally produce credential-level throttling + high-severity alert, not automatic nft blocking of the fleet controller's source IP.

## Done when

- no raw secrets in keys/logs;
- identities do not share unintended buckets;
- normal fleet/UI traffic stays below limits;
- heavy/debug routes have tighter budgets/concurrency caps;
- limiter state is bounded and observable.

---

# Step 9 — direct control-plane response/cache/security-header hardening

**Priority:** P2  
**Finding:** `Audit_Results.md` R10, CONFIRMED LIVE hardening gap

## Problem

Direct `:6061` anonymous auth failures are weaker than the edge for cache/security headers. Handler-level helpers may set `no-store`, but anonymous rejection can occur earlier in `TokenMiddleware`.

## Change

Apply conservative identity/auth response headers at an outer common layer so both direct listeners and edge-proxied requests receive consistent policy.

At minimum review/standardize:

```text
Cache-Control: no-store
Pragma / Expires where desired
Vary: Authorization, Cookie where identity can alter representation
X-Content-Type-Options: nosniff
Content-Security-Policy for browser HTML
frame policy (CSP frame-ancestors and/or X-Frame-Options as appropriate)
Referrer-Policy
```

Do not depend on the edge to supply the direct control-plane security model.

### HSTS ordering rule

Do **not** blindly add HSTS while the `:6060` browser transport behavior is unresolved. Finalize Step 5 first and then decide the intended hostname-wide HSTS policy deliberately.

## Done when

- direct 6061 and edge return consistent no-store behavior for auth/identity-sensitive responses;
- browser HTML has centralized direct+edge security-header policy;
- authenticated and rejected identity responses cannot be cached as another identity;
- HSTS is introduced only after transport semantics are compatible with it.

---

# Step 10 — controlled credentialed regression and audit closure

**Priority:** required before declaring the audit remediation complete

Use dedicated/short-lived controlled credentials where necessary:

```text
admin bearer
scoped token with one known test vhost
optionally one DB user/database scope
admin browser session
MCP-only credential / OAuth access token where available
```

Never print credential values in audit output.

## Obtaining the test credentials (prerequisite — read before Step 10)

The scoped token is **not** a missing capability — CFM can already mint one. The
read-only MCP cannot (it only observes), so the authorization probes run over
curl/HTTP with a token minted here:

- **Admin bearer:** the node's `AUTH_TOKEN` from `/etc/cfm/cfm.conf`. The `cfm`
  CLI reads it automatically when run locally as root.
- **Scoped viewer token — CLI (on the node):**
  `cfm webtop tokens create --vhosts <host[,host2]> --label audit-scoped --ttl 1h`
  → prints the token value (role defaults to `viewer` = scoped). List/clean up with
  `cfm webtop tokens` and `cfm webtop tokens revoke <id>`.
- **Scoped viewer token — API (admin-only):**
  `POST /api/v1/auth/token` with
  `{"vhosts":["example.com"],"role":"viewer","ttl":"1h","label":"audit-scoped"}`
  → returns `{id, token, …}`. Revoke via `POST /api/v1/tokens/revoke`.

Prefer a short TTL so test tokens self-expire. Prior audit passes stalled at this
step only because they ran from **outside** the node with no admin credential —
with the admin token (or a root shell on the node) the scoped token is one
command. This is the concrete unblock for the R02/R03/R04 "live scoped /
authenticated proof pending" items.

## Authorization regression

Prove:

```text
scoped -> /debug/pprof/ = 403
scoped -> admin/global endpoint = 403
scoped -> own vhost endpoint = allowed
scoped -> unrelated vhost = 403 / zero data
scoped omitted/global filter = never global data
DB-only scoped token with no vhost scope = owns no vhosts, never admin
```

Test hostname/filter edge cases:

```text
uppercase
trailing dot
host:port
www/apex
wildcard
URL encoding
duplicate query parameters
mixed in-scope,out-of-scope
empty/omitted filters
```

## Method/CSRF regression

All known mutators:

```text
GET -> 405
wrong unsafe verb -> 405 unless intentionally supported
proper session POST with evil Origin -> CSRF reject
Bearer/scoped write -> CSRF-exempt but still authorization/scope checked
```

Do not perform destructive production mutations merely to prove the boundary.

## Transport/challenge/cookie regression

```text
edge https://host/cfm-admin/
    -> challenge before credentials
    -> solve -> login, no loop

https://host:6061/cfm-admin/
    -> same challenge semantics

http://host:6060/cfm-admin/ + TLS ready
    -> redirect to :6061

edge -> loopback:6060
    -> remains on public :443, no redirect to :6061
```

Controlled/staging TLS-unavailable test:

```text
6060 degraded fallback
    -> challenge-gated
    -> distinct fallback cookie
    -> explicit degraded log event
```

Verify 9098 remains externally unavailable.

## Credential separation

```text
MCP_TOKEN -> /mcp = allowed
MCP_TOKEN -> /api/v1/* = denied
MCP OAuth token -> /api/v1/* = denied
AUTH_TOKEN -> normal admin API = allowed
```

## Edge/direct parity

For read-only admin routes compare edge vs direct 6061:

- auth role;
- status;
- response schema;
- cache/security headers;
- no data-scope discrepancy.

## Closeout

Update `Audit_Results.md` for each Rxx finding with:

```text
FIXED / RETEST PASS
commit / PR
exact regression performed
date/node
remaining caveat if any
```

Do not delete historical evidence; append remediation/retest status.

---

# Immediate implementation batches

The recommended first development sequence is deliberately small:

```text
PR/commit batch 1
  Step 1 — trusted request identity + XFF/XFP/effective scheme

PR/commit batch 2
  Step 2 — pprof admin-only

PR/commit batch 3
  Step 3 — POST-only mutators + source-wide verb audit
```

After those independent fixes:

```text
Step 4 challenge
  -> Step 5 6060 transport
  -> Step 6 automatic cookies
  -> Step 7 cfm_endpoints/logging
  -> Step 8 authenticated rate limits
  -> Step 9 response/header hardening
  -> Step 10 credentialed regression
```

Do not combine the first three into one large behavioral rewrite unless there is a strong implementation reason; separate changes make regressions and rollback much easier to reason about.

---

# Definition of done for the control-plane remediation

The control-plane work is complete only when all of the following are true:

- one trusted-request identity/scheme model is used everywhere;
- no attacker-supplied forwarded chain becomes CFM identity;
- pprof and all host-global surfaces explicitly prove admin role;
- every state-changing endpoint has an enforced HTTP verb and scope check;
- interactive admin login receives the same pre-auth challenge regardless of edge/direct TLS entry;
- direct healthy 6060 does not accept browser credentials when 6061 is available;
- session cookie Secure behavior is derived automatically from trusted effective scheme;
- `AUTH_SECURE_COOKIE` is deprecated/ignored as planned;
- CFM's own endpoints feed the normal detector/sink/notification/blocking pipeline through default-on `cfm_endpoints`;
- login/token attempts are safely and consistently auditable in `cfm.api.log`;
- authenticated API abuse is bounded per mechanism/identity/route cost;
- direct 6061 does not rely on edge-only cache/security policy;
- scoped/admin/MCP/session boundaries pass controlled live regression;
- `Audit_Results.md` records retest evidence for every relevant Rxx finding.
