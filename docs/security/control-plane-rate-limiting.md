# Control-plane rate limiting (audit Step 8)

**Status:** ✅ IMPLEMENTED — `internal/apiserver/ratelimit.go` + `withAuthnSubject`
threading. Ships **enforcing by default** (`429`) with **honestly high ceilings** +
full log/API observability. Tests: `ratelimit_test.go`. Live verification → Step 10.

Finding/spec: `Audit_Fix_Order.md` Step 8 (P2). Goal: bound already-authenticated
control-plane abuse without treating every caller equally, keyed by identity class
× route class, never by raw credential material.

**Rollout note (operator decision, 2026-08-25):** the audit's "shadow/observe
first, measure, then enforce" rollout is **deliberately compressed**. Measurement on
this fleet is impractical, and a `RATE_LIMIT_MODE=shadow` that must be flipped to
`enforce` later is a protection that never turns on (it gets forgotten). So we ship
**enforce by default** with ceilings set honestly high — above realistic legitimate
fan-out — so nothing legitimate trips, and **every trip is logged + API-visible** so
the operator tunes from real signal instead of a measurement pass. `shadow` and
`off` remain available (§5). The one hard safety line from the spec is kept exactly:
a runaway trip is a self-healing `429` (credential-level throttle) + alert, **never**
an nft block of the caller's IP (§6).

## 1. What already exists (reuse, don't reinvent)

- **Identity classes are already classified.** `middleware.go` sets an
  `authnMechanism` into the request context for every authenticated request:
  `token_admin`, `token_scoped`, `embed_bootstrap_cookie`, `embed_admin_cookie`,
  `session_cookie`
  (MCP is authenticated in its own layer and is out of scope here). Phase 1 reads
  this straight from context — no new auth logic.
- **A token-bucket limiter already exists.** `login_rate_limit.go` has
  `tokenBucket` (capacity/rate/refill), `bucketPair` (short+medium windows) and a
  `lastSeen` field for idle pruning. Step 8 reuses these types for the per-identity
  × per-route buckets rather than inventing a second limiter.
- **An anomaly-event bus already exists.** `publishRequestAnomaly` /
  `SubscribeAPIAnomalyEvents` feed the `cfm_endpoints` detector. Phase 1 does NOT
  wire rate-limit events into it (see §6) — it only logs.

## 2. Identity key (never a raw secret)

Bucket key = `identityClass "|" identitySubkey "|" routeClass`. The subkey keeps
one caller from draining another's bucket, and is always a stable non-secret:

| Class | Subkey | Source |
|---|---|---|
| `token_admin` | `""` (one shared admin bucket) | there is a single admin token; a runaway admin is throttled + alerted, **not** nft-blocked (§6) |
| `token_scoped` | the token **ID** (`TokenStore` `st.ID`) | already the non-secret id used in `auth_attempt` audit; must be threaded into context (small add) |
| `embed_bootstrap_cookie` | the embed session id | the embed context already carries a stable non-secret id |
| `embed_admin_cookie` | `admin` (shared admin bucket) | the admin SSO cookie authenticates the full-admin role; it shares the single `token_admin` bucket and is a **trusted**-tier identity, not scoped |
| `session_cookie` | `user:<username>` | the authenticated goauth username (non-secret; never the session cookie); `key_kind=session_user` in the log |

Raw tokens/cookies never appear in a key or a log line. IP is **not** the primary
key for authenticated callers (the fleet controller and the admin UI share IPs);
it is recorded in the shadow log only as context.

## 3. Route classes

A small pure classifier `routeClass(method, path) -> class` (table-driven, no
per-request allocation). Initial mapping (tunable):

| Class | Examples | Rationale |
|---|---|---|
| `cheap_read` | `/healthz`, `/api/v1/system/status` | health/poll; very high ceiling |
| `normal_read` | most `GET /api/v1/*` | default read |
| `heavy_read` | `/api/v1/search`, `…/history`, large aggregations | expensive; tighter |
| `write` | state-changing `POST/PUT/DELETE` (non-privileged) | moderate |
| `privileged_write` | firewall block/unblock, config/token mutation | admin-only; tighter, always alert on trip |
| `capture_stream` | `/debug/pprof/*`, capture/stream endpoints | tightest + concurrency cap (these are already admin-only after R02) |

Unknown routes default to `normal_read`.

## 4. Ceilings (honest, high, code-default)

**Secure-fleet principle:** ceilings live in **code** and default **on**, so a CFM
upgrade protects the control plane without anyone editing `cfm.conf` (same posture as
R01's code-enforced loopback bind). They are set **honestly high** — above realistic
legitimate fan-out (cfm-web multi-node polling, the admin UI's auto-refresh,
panel/plugin polling) with generous margin — so a normal upgrade never starts
`429`-ing real traffic; only genuine runaway (orders of magnitude above normal) trips
them. `token_admin`/`session_cookie`/`embed_admin_cookie` (interactive admin + the
fleet controller + admin SSO sessions) get
**much** higher ceilings than `token_scoped`/`embed_bootstrap_cookie`;
`capture_stream` also gets a small concurrency cap. Per-route-class overrides are
**optional** `cfm.conf` knobs (§5) — documented but never required.

## 5. Middleware & mode

- New `RateLimitMiddleware`, wired **inside** `TokenMiddleware` (so the identity
  context is populated) and skipping MCP + public/health paths. Execution order:
  `… → TokenMiddleware → CSRF → RateLimit → MFARollout → mux`.
- **Enforce by default, in code** — no `cfm.conf` entry required (secure-fleet
  default). An optional `RATE_LIMIT_MODE` selects:
  - `enforce` (**default**): over-ceiling → `429` + `Retry-After` (from the bucket
    refill), small JSON body. A self-healing throttle, not a ban.
  - `shadow`: log/emit only, serve normally — a diagnostic for watching one ceiling
    before tightening it, not the steady state.
  - `off`: kill switch.
- **Credential-validity must not leak.** An invalid/absent credential is still
  rejected by `TokenMiddleware` with the normal `401` *before* this middleware runs,
  so limiter behaviour never distinguishes a valid-but-throttled token from an
  invalid one.

## 6. Observability & the one hard safety line

Every trip (enforced `429` or a `shadow` would-block) is written to the API log —
`event=ratelimit_trip identity_class=… route_class=… key_kind=… mode=… ip=…` — so it
surfaces in `cfm.api.log` and the MCP/API views the operator already uses. That IS
the "log/API" signal they tune ceilings from (the operator's stated substitute for a
measurement pass): a legitimate caller that ever trips shows up immediately and its
ceiling gets raised. Trips are rate-limited in the log too (no log flood).

**The one hard line from the spec, kept exactly:** a runaway trip is
**credential-level throttling** (a self-healing `429`) plus a high-severity signal —
today that signal is the `severity=high` line in `cfm.api.log` (a real notifier
event is the deferred operator follow-up) — and is **never** turned into an nft block
of the caller's IP. The admin token is the
fleet controller (cfm-web); nft-banning its IP would take out fleet management. So
rate-limit trips are **deliberately NOT wired into the `cfm_endpoints`/wafsec → nft
path** — they log and alert only. (This is also why admin ceilings are the most
generous and an admin trip is high-severity: it should be rare and loud.)

## 7. Memory bounds

Buckets live in a mutex-guarded map keyed as §2. A background prune (reusing the
`lastSeen` pattern) drops buckets idle beyond the medium window; the map is also
hard-capped (evict oldest) so a spray of distinct scoped-token ids or session ids
cannot grow it without bound.

## 8. Done-when (from the spec)

- no raw secrets in keys/logs (§2);
- identities do not share unintended buckets (per-subkey, §2);
- normal fleet/UI traffic stays below limits (honest-high code-default ceilings, and
  any legitimate trip is immediately visible in the log/API to raise, §4/§6);
- heavy/debug routes have tighter budgets/concurrency caps (§3–4);
- limiter state is bounded and observable (§7 + shadow log).

## 9. Deliverable (this PR)

`ratelimit.go` (classifier + buckets + middleware, reusing `tokenBucket`), the
`st.ID`→context thread, optional config plumbing for `RATE_LIMIT_MODE` + per-route
ceiling overrides (all **defaulted in code**, none required), `RateLimitMiddleware`
wired **enforce-by-default**, and unit tests: identity-keying isolation (one scoped
token can't drain another's bucket), route classification, enforce-returns-429
+Retry-After, shadow-logs-not-blocks, `off` disables, no-secret-in-key/log,
prune/cap bounds, and generous-ceiling headroom (a realistic admin/controller burst
stays under). A commented, optional knob block is added to the reference `cfm.conf`
(documentation only — behaviour is code-default). Later, operator-driven: tune
individual ceilings from log/API signal; an alert-only (never-nft) detector event.
