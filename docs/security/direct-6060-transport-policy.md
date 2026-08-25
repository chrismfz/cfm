# Direct `:6060` browser transport policy (Audit Step 5 / R01)

**Status:** ✅ IMPLEMENTED (Phase 5a). Operator decisions below resolved
(2026-08-25): **both** defences — loopback-bind `:6060` by default **and** the
`AdminTransportRedirect` safety net; machine `/api/v1` left as-is; redirect status
`302`. Code: `internal/apiserver/transport_redirect.go` + `Start()` wiring +
`configs/cfm.conf` `LISTEN_ADDRESS=127.0.0.1`; tests `transport_redirect_test.go`.
**Finding:** `Audit_Results.md` R01 (HIGH, CONFIRMED LIVE) · **Spec:**
`Audit_Fix_Order.md` Step 5 · `Audit.md` §2.

---

## 1. Problem

The apiserver runs an HTTP listener on `:6060` and a TLS listener on `:6061`,
**both serving the identical handler stack** (`internal/apiserver/apiserver.go`
`Start()`, `:334-390`). Both bind `0.0.0.0` by default (`configs/cfm.conf`
`PORT=6060`, `TLS_PORT=6061`, `LISTEN_ADDRESS=0.0.0.0`). So a direct external
`http://host:6060/cfm-admin/` serves the real admin login/UI/API **in
plaintext** — a browser can reach the login form and submit credentials, and
Bearer tokens can be sent, over cleartext, before any Secure cookie exists. No
HTTPS upgrade to `:6061` happens today (confirmed: the only Go redirects are
same-origin, path-only `303`s; there is no `http→https` / `6060→6061` redirect
anywhere).

## 2. The hard constraint — why we can't just redirect everything on `:6060`

`:6060` carries **three different kinds of traffic**, and only one of them
should be upgraded:

| traffic | how it reaches `:6060` | `requestPeer(r).Entry` | must we redirect? |
|---|---|---|---|
| **Public browser via the edge** | `browser HTTPS :443 → OpenResty/Angie → proxy_bind 127.0.0.1 → :6060` (XFP=https) | `"edge"` | **NO** — the browser is already on HTTPS; redirecting would bounce the normal public path |
| **Local machine (CLI)** | `cfm` CLI → `127.0.0.1:6060` plaintext, Bearer | `"6060"` (loopback peer, no forwarded id) | **NO** — loopback plaintext never touches the wire |
| **Direct external browser** | `http://host:6060/cfm-admin/` straight to the listener | `"6060"` (non-loopback peer) | **YES** — this is R01 |

The audit is explicit (`Audit.md` §2): *"never globally redirect every request on
6060."* The signal that separates these is already built: `requestPeer(r).Entry`
distinguishes `edge` from `6060`/`6061`, and `requestPeer(r).ImmediateIP.IsLoopback()`
distinguishes the loopback CLI from an external browser.

**Note the ambiguity that must be handled:** `Entry=="6060"` is *the same* for the
loopback CLI and an external browser — `requestListenerEntry` keys only on the
local listener port. They are separable because the CLI **only** hits `/api/v1/*`
and `/debug/*` (never `/cfm-admin/*`) and sends **no** `Accept: text/html`. So the
policy keys on **`Entry=="6060"` + non-loopback peer + browser admin route**, not
on the port alone.

## 3. Signals the policy uses

- `requestPeer(r).Entry` — `"edge"` | `"6060"` | `"6061"` | `"other"` (existing).
- `requestPeer(r).ImmediateIP.IsLoopback()` — local vs external (existing).
- **`tlsReady`** — a NEW runtime flag. It must be true **only after the `:6061`
  listener actually binds**, not merely because `TLS_PORT > 0` (`Audit.md`
  §2 is explicit). No such signal exists today (`tlsSrv` is a local var, never
  published; SSLCollector readiness is per-SNI-host, not global). See §7.
- **Browser-admin-route predicate** — path under `/cfm-admin/` (before the
  prefix rewriter) **or** an HTML UI/login route with `Accept: text/html`.

## 4. Policy

A new **pre-auth** transport middleware, `AdminTransportRedirect`, placed
**outside `TokenMiddleware`** so a doomed request is redirected/rejected **before
any credential is processed** (§8). It touches only requests that arrived on the
`:6060` HTTP listener and are **not** the edge hop; everything else passes through
untouched.

| # | condition (all on top of `Entry=="6060"`) | action |
|---|---|---|
| 0 | `Entry != "6060"` (edge / 6061 / other) | **pass through** — no transport action |
| 1 | immediate peer is **loopback** (local CLI/curl) | **pass through** — loopback plaintext is not a wire risk |
| 2 | external, **not** a browser admin route (`/api/v1/*`, `/debug/*`, `/mcp`, assets) | **pass through** (default) — see §6a machine-API decision |
| 3 | external, browser admin route, **GET/HEAD**, `tlsReady` | **redirect** → `https://<host>:<TLSPort><uri>` (§5) |
| 4 | external, browser admin route, **unsafe method** (POST/PUT/PATCH/DELETE), `tlsReady` | **reject** — `HTTPS required`, *not* processed then redirected (`Audit.md` §2, spec pt 4) |
| 5 | external, browser admin route, **`tlsReady == false`** | **degraded**: pass through over HTTP, log `event=admin_http_fallback` (§6b) |

Rows 3 and 4 are the R01 fix. Row 4 matters because a plain redirect on a login
`POST` would have **accepted the credential body over plaintext first**; the
request must be refused so the browser re-submits over HTTPS.

## 5. Redirect-target construction

There is **no public-hostname config** for this daemon (only `API_URL`, which is
the *upstream cfm-web* endpoint, not this node's name). So the target host can
only come from the client-supplied `Host`:

```
host  = hostOnly(r.Host)                 // net.SplitHostPort; IPv4/IPv6-aware; if no port, use as-is
target = "https://" + net.JoinHostPort(host, tlsPortStr) + r.URL.RequestURI()
```

- **Preserve the URI** (path + query) verbatim via `r.URL.RequestURI()`.
- **Do not trust `X-Forwarded-Host`** — this is a direct client; use `r.Host` only
  (a direct client's `Host` is what they connected to, which is the correct
  upgrade target).
- **Validate `TLSPort` (1..65535) before use** — `TLS_PORT` has *no* range check
  in config parsing (unlike `PORT`), so a garbage value must not be echoed into a
  `Location`. If `TLSPort` is invalid, treat as `tlsReady == false` (degraded).
- **Status code:** recommend **`302 Found`** (or `307`) over `301` — `301` is
  aggressively cached by browsers and the target port `:6061` is non-standard and
  policy-dependent; a sticky permanent redirect to a non-standard port is a
  foot-gun if the deployment changes. (Open decision §12.)

## 6. Explicit decisions — surfaced, not silently chosen

### 6a. Machine `/api/v1/*` over direct external plaintext `:6060`

The CLI is loopback (exempt); cfm-web uses `:6061`; so external plaintext
`/api/v1` should not exist in normal operation — but `Audit.md` §2 notes *"API
deployments may explicitly use HTTP."* Options:

- **(A) Leave `/api/v1` on `:6060` as-is** (row 2 pass-through). Least disruption;
  machine clients own their transport risk. **Recommended for Step 5** — scope
  the transport policy to *browser* admin routes.
- (B) Also reject/redirect external plaintext `/api/v1`. Stricter, but risks
  breaking a machine client that deliberately uses HTTP, and needs its own
  compatibility decision.

Recommendation: **(A)**; a stricter machine-API stance is a separate, explicit
follow-up, not smuggled into Step 5.

### 6b. TLS-down degraded fallback & the Step 4 dependency

The spec says the degraded fallback stays **challenge-gated**. The challenge gate
is **Step 4** (reusable pre-auth challenge + login gate), which is **on hold**
after the item-8 decision (challenge identity unification was declined, PR #1342).
Therefore Step 5 ships:

- redirect (TLS ready) + reject-unsafe (TLS ready) + **degraded pass-through with
  `event=admin_http_fallback` logging** (TLS down).

The **challenge-gating** of the degraded fallback is **deferred to Step 4**. The
degraded state is rare (TLS genuinely unavailable); serving HTTP + a visible log
is the Step-5 deliverable, and full challenge-gating waits for Step 4. This keeps
Step 5 independent of the on-hold challenge work.

### 6c. Alternative / complementary hardening — bind `:6060` to loopback

The **simplest and strongest** R01 fix, if external `:6060` is not actually
required, is to bind the HTTP listener to `127.0.0.1` (`LISTEN_ADDRESS`), so there
is **no external plaintext at all** — the edge (loopback) and CLI (loopback) still
work, and only `:6061` is public. The redirect approach is only necessary if
`:6060` **must** stay externally reachable as a fallback. The threat model
(`Audit.md` §0) treats `:6060` as an intended Internet-reachable fallback, so this
design implements the redirect — but the operator should confirm whether external
`:6060` is needed; loopback-binding is a cleaner fix if not, and the two are
complementary (loopback-bind removes the attack surface; the redirect handles the
case where it stays public).

## 7. `tlsReady` plumbing

Introduce an `atomic.Bool` (package-level in `apiserver`, or a field on a shared
struct the middleware can read). In `Start()`:

- default `false`;
- set `true` **immediately after** `net.Listen("tcp", fullTLSAddr)` succeeds
  (`apiserver.go:367`), before the serve goroutine;
- stays `false` when `TLSPort <= 0`, `ssl == nil`, or the listen fails.

This matches `Audit.md` §2 ("mark ready only after successful runtime
bind/readiness"). A bound-but-no-cert-for-this-SNI case still fails the TLS
handshake on `:6061` — but that is a **cert-provisioning** issue, not a
transport-policy bug; redirecting a browser to `:6061` is still correct (it would
otherwise stay on plaintext). We do **not** try to gate on per-SNI cert
availability (SSLCollector has no clean global "cert ready" signal).

## 8. Middleware placement (exact)

Current stack, outer→inner (`apiserver.go:322-331`; the file-header comment there
is stale — trust the code):

```
RequestLog → APISecurityAnomaly → PprofWriteTimeout → LoadAndSave → Token → CSRF → MFARollout → mux
```

Insert `AdminTransportRedirect` **outside `TokenMiddleware`** (pre-auth) and
**inside `RequestLogMiddleware`** (so redirects/rejections are logged):

```
handler = AdminTransportRedirect(handler)   // right before the RequestLog wrap
handler = RequestLogMiddleware(handler)
```

→ effective order: `RequestLog → AdminTransportRedirect → APISecurityAnomaly → … →
Token → …`. It only reads `requestPeer(r)` (no auth needed), so it is safe this
early.

## 9. What must NOT break (regression checklist)

- **Edge** (`Entry=="edge"`) GET/POST `/cfm-admin/*` → served, never redirected.
- **CLI** loopback `/api/v1/*`, `/debug/*` → served (loopback exempt, not a browser route).
- **cfm-web** on `:6061` (`Entry=="6061"`) → served.
- **MCP** `/mcp` (bypasses middleware via `isMCPPublicPath`) → exempt.
- **Embed bootstrap** (via edge, `Entry=="edge"`) → served.
- **Direct `:6061` browser** → served (already HTTPS).
- **Loopback direct `:6060`** (local admin curl) → served (loopback exempt).

## 10. Test matrix

Use the existing `withLocalAddr(r, "0.0.0.0:6060")` helper to simulate "which
listener served this", set `RemoteAddr` for loopback vs external, and drive the
middleware directly (pattern: `auth_redirect_test.go`).

| listener/peer | forwarded | method | path | Accept | tlsReady | expect |
|---|---|---|---|---|---|---|
| 6060, external | none | GET | `/cfm-admin/` | text/html | true | `302 https://host:6061/cfm-admin/` |
| 6060, external | none | HEAD | `/cfm-admin/x?q=1` | text/html | true | `302 …:6061/cfm-admin/x?q=1` (URI preserved) |
| 6060, external | none | POST | `/cfm-admin/login` | text/html | true | **reject** (not 3xx, not processed) |
| 6060, external | none | GET | `/cfm-admin/` | text/html | **false** | pass-through + `admin_http_fallback` log |
| 6060, external | none | GET | `/api/v1/system/status` | — | true | pass-through (§6a) |
| 6060, **loopback** | none | GET | `/cfm-admin/` | text/html | true | pass-through (loopback exempt) |
| **edge** (loopback + XFP=https) | X-Real-IP,XFP | GET | `/cfm-admin/` | text/html | true | pass-through (served) |
| 6061, external | none | GET | `/cfm-admin/` | text/html | true | pass-through (already HTTPS) |
| 6060, external | forged `X-Forwarded-Host: evil` | GET | `/cfm-admin/` | text/html | true | redirect host from `r.Host`, **not** the forged header |

## 11. Phased plan

- **Phase 5a (this change):** `tlsReady` plumbing + `AdminTransportRedirect`
  (redirect GET/HEAD, reject unsafe, degraded log) scoped to external direct-6060
  **browser** admin routes, + the test matrix. Independent of Step 4.
- **Phase 5b (with Step 6):** distinct HTTP-fallback session cookie
  (`cfm-sid-http-fallback`) for the degraded state.
- **Phase 5c (with Step 4):** challenge-gate the degraded fallback.
- **Separate follow-up:** machine-API-on-plaintext-`:6060` stance (§6a); and/or
  the loopback-bind hardening (§6c).

## 12. Operator decisions — RESOLVED (2026-08-25)

1. **§6a** — machine `/api/v1` over external plaintext `:6060`: **leave as-is**. The
   transport policy is scoped to browser admin routes; a stricter machine stance stays
   a separate follow-up.
2. **§6c** — is external `:6060` required? **No by default → both defences shipped:**
   `LISTEN_ADDRESS` defaults to `127.0.0.1` (no external plaintext), AND the redirect
   middleware remains as a safety net for anyone who deliberately re-exposes `:6060`.
3. **§5** — redirect status code: **`302 Found`** (avoids `301`'s sticky caching of a
   non-standard port).

## 13. Done when (from the spec, mapped)

- direct external `:6060` browser admin GET/HEAD upgrades to `:6061` while TLS ready ✔ (row 3);
- edge → loopback `:6060` never sent to `:6061` ✔ (row 0);
- no login/session-changing credential accepted over direct HTTP while TLS healthy ✔ (row 4);
- controlled TLS-down fallback works and is visibly logged ✔ (row 5); challenge-gating deferred to Step 4;
- R01 retest closed in `Audit_Results.md` after live verification (Step 10).
