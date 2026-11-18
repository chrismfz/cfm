# CFM control plane: who reaches it, how it authenticates, why it is built this way

The control plane is the daemon's own HTTP surface: the API (`/api/v1/*`), the
admin UI (`/cfm-admin/`), `/mcp`, `/debug/pprof`. This page is the current
picture (checked against the code on 2026-11-18). Code: `internal/apiserver`,
the port rules in `internal/firewall/ports_policy.go`, the knobs in
`configs/cfm.conf`. When the code changes, change this page in the same PR.

Most of it came out of the 2026-08 control-plane audit. The audit documents
were deleted: the code has moved on since, and they read as current.

---

## 1. The three ways in

| Door | Listener | Who uses it | What guards it at L3/L4 |
|---|---|---|---|
| **Edge** | browser → `:443` → OpenResty/Angie → loopback `:6060` | operators, cPanel users (iframe), cfm-web SSO redirect | nothing (it arrives from loopback). The daemon trusts `X-Real-IP` / `X-Forwarded-Proto` only from a loopback peer, one hop (`request_identity.go`) |
| **Direct TLS** | `:6061` (`TLS_PORT`, `TLS_LISTEN_ADDRESS="0.0.0.0"`) | cfm-web, server to server | nft: see below |
| **Direct HTTP** | `:6060` (`PORT`) | the local CLI, the WHM plugin, the edge hop | **loopback-bound**: an unset `LISTEN_ADDRESS` binds `127.0.0.1` in code (`HTTPBindAddr`), not only in the reference conf |

**nft on `PORT` / `TLS_PORT`.** Both ports are taken out of `TCP_IN` even if
an operator lists them there (`NewPortsPolicy`), and get their own accepts
above the catch-all drop (`debugPortRules`): new connections only from this
host's own IPs (`@self_v4/v6`) and from the resolved `API_URL` host
(`@debug_api_v4/v6`, refreshed with a 5-minute DNS cache). The global early
accepts still let in everything on `cfm.allow`, `cfm.dyndns` and the fleet
whitelist feed. So `:6061` answers cfm-web, this host, and the allow lists.

That gate disappears with `cfm disable`, and the edge door never passes it.
That is why the app layer below must hold on its own.

**`:6061` inherits `LISTEN_ADDRESS` when `TLS_LISTEN_ADDRESS` is unset.** An
install that sets only `LISTEN_ADDRESS=127.0.0.1` makes `:6061` loopback too.
Keep `TLS_LISTEN_ADDRESS="0.0.0.0"` (the reference conf does) for cfm-web.
`:6061` always completes a handshake, with a self-signed fallback when no
certificate matches (`tls_fallback.go`), so a fresh or by-IP box is reachable.

## 2. Credentials

| Credential | Presented by | From | Notes |
|---|---|---|---|
| **`AUTH_TOKEN`** (admin bearer) | cfm-web; the WHM plugin / `panelauth` | cfm-web's egress (= the `API_URL` A record), loopback | never by a browser. `ADMIN_TOKEN_IP_BINDING` (§4) |
| **Admin SSO code** | minted by an admin-token caller, redeemed by the operator's browser | mint: cfm-web / loopback; redeem: anywhere | 160-bit, single use, 45 s |
| **`cfm-embed-admin` cookie** | operator browser after SSO | anywhere | HMAC with a **random per-node key** (`/var/lib/cfm/embed-admin-cookie.key`, 0600, never sent to cfm-web), host + UA bound, 10 min with renewal at half-life, `SameSite=Lax`, honoured only under `/cfm-admin` and only without a bearer header |
| **Scoped viewer token / `cfm-embed-scope` cookie** | cPanel user's browser (iframe) | anywhere | viewer role, vhost/db scope, out of scope → 403. Cookie is `SameSite=None` (cross-site iframe) |
| **goauth session `cfm-sid`** | username/password login + MFA | anywhere | always `Secure`; see §5 |
| **`MCP_TOKEN`** | MCP clients (cfm-web) | cfm-web | auto-generated, ≥ 24 chars. `/mcp` bypasses `TokenMiddleware` and **also accepts `AUTH_TOKEN`** (`mcp_wire.go`), read-only |

**Admin SSO flow** (`embed_admin_bootstrap.go`). The controller calls
`GET /api/v1/embed/admin-code?next=/cfm-admin/` with the admin bearer (any
non-admin role → 403) and hands the browser a top-level link to
`https://<host>/cfm-admin/api/v1/embed/admin-bootstrap?code=…`. The redemption
sets `cfm-embed-admin` and 303s to `next`. The code store is process-global,
so a code minted on `:6061` redeems on `:443`. Consumers: cfm-web's Agents
"Login" (super_admin only on the cfm-web side) and the WHM plugin
(`plugins/cfm-plugin-cpanel/lib/bootstrap.php`, loopback, falls back to a bare
`/cfm-admin/` redirect when the mint is unavailable). Every mint and redemption
logs `src_ip` and `next`.

**Known residual: the scoped embed cookie key still derives from
`AUTH_TOKEN`** (HKDF, public salt, `embed_bootstrap.go`). A cfm-web database
leak can forge a scoped viewer cookie for any vhost/db scope. The admin
cookie had the same flaw and moved to a random per-node key; the scoped one
has not yet (`docs/ROADMAP.md` §6).

## 3. Handler stack

Outermost first (`apiserver.go`, the comment above the stack is the source):

```
RequestLog → SecurityHeaders → AdminTransportRedirect → APISecurityAnomaly
→ PprofWriteTimeout → SessionCookieTransport → LoadAndSave (goauth)
→ TokenMiddleware → CSRF → RateLimit → mux
```

Both listeners serve this same stack. Order that matters:
`AdminTransportRedirect` runs before any credential is read;
`SessionCookieTransport` wraps goauth from outside; `RateLimit` runs inside
`TokenMiddleware` so it keys on the authenticated identity.

## 4. Admin-token source-IP binding

`ADMIN_TOKEN_IP_BINDING = off | logonly | enforce` (default `off`,
`admin_token_ip_binding.go`). Applies **only** to the `token_admin` branch of
`TokenMiddleware`: the presented admin token must come from loopback ∪ this
host's IPs ∪ `cfm.allow` / `cfm.dyndns` ∪ the `API_URL` host, keyed on the
forwarded client IP, never `RemoteAddr`. `enforce` → 403, an audit line and an
`ADMIN_TOKEN_FOREIGN_IP` anomaly; `logonly` logs `would_block`.

Why per-credential and not a gate over the whole mux: the browser never
carries the admin token (it uses the SSO cookie, a session or a scoped token
from arbitrary IPs), so binding only the token touches no interactive access.

It covers all three doors, including the edge (where nft cannot help), and
holds when the firewall is off. Rollout: enforce on one node, test cfm-web SSO
and API, then the fleet. Caveats:

- The `API_URL` host is resolved per request; a DNS failure drops cfm-web out
  of the set until it recovers. Add cfm-web's IP to `cfm.allow` to make
  `enforce` DNS-independent. Re-check if cfm-web's egress ever differs from
  the `API_URL` A record.
- The allowlist is rebuilt per request for a valid admin token from a
  non-loopback IP (no cache). Bounded: it needs the valid token.
- Only as good as the edge's `real_ip` trust.
- Loopback is the floor: a local process or an SSRF on the node that reaches
  `:6060` is trusted. Hardening the node itself is out of scope here.

## 5. Plaintext `:6060`

`:6060` carries three kinds of traffic: the edge hop (already HTTPS at the
browser), the local CLI (loopback, never on the wire), and a direct external
browser. Only the last must be upgraded, so **never redirect all of `:6060`**.
With the loopback bind the third kind does not exist by default;
`AdminTransportRedirect` (`transport_redirect.go`) is the safety net for an
operator who re-exposes it. On `:6060`, non-loopback peer, browser admin
route (`/cfm-admin/…` or HTML):

- **Unsafe method** (POST/PUT/…) → refused, whatever the TLS state. A
  redirect would have accepted the login body over plaintext first.
- **GET/HEAD with `:6061` bound** (`tlsReady`, set after the listen
  succeeds) → `302` to `https://<Host>:<TLS_PORT><uri>`. `302`, not `301`: a
  cached permanent redirect to a non-standard port is a trap. The host comes
  from `r.Host`, never `X-Forwarded-Host`.
- **GET/HEAD with TLS down** → served read-only, logged
  `event=admin_http_fallback`.

Machine `/api/v1/*` on a re-exposed `:6060` stays plaintext by decision
(machine clients own their transport); its protection is the loopback bind.

**Session cookie** (`session_cookie_transport.go`). goauth sets cookie
attributes once at startup, and mutating them per request would race, so the
manager is always `Secure` (`cfm-sid`). On an effective-http `:6060` session
(a TLS-down window, or an SSH tunnel to `127.0.0.1:6060`) a wrapper renames
it on the wire to a non-Secure `cfm-sid-http-fallback`, over the same
server-side session. A plaintext `cfm-sid` arriving there is dropped (only an
injected one could), so it cannot shadow the real session.
`AUTH_SECURE_COOKIE` is parsed and ignored, with a one-time warning.

## 6. Rate limiting

`RATE_LIMIT_MODE = enforce | shadow | off` (default enforce, `ratelimit.go`),
`RATE_LIMIT_SCALE` multiplies every ceiling (default 1.0). Buckets are keyed
`tier | route class | subject`, never by a raw credential:

- tier `trusted` (admin token, admin SSO cookie, session) or `scoped` (scoped
  token, scoped embed cookie), each with its own ceilings in code;
- route class: `cheap_read`, `normal_read`, `heavy_read`, `write`,
  `privileged_write`, `capture_stream` (pprof / capture: a small bucket, no
  concurrency cap);
- subject: the scoped token ID, the session user, and so on.

Shipped enforcing with honestly high ceilings, because a "shadow first"
switch is the one that never gets flipped. A trip is a self-healing `429` +
`Retry-After` and an `event=ratelimit_trip` line in `cfm.api.log`. **It is
never an nft ban**: the admin token is cfm-web, and banning its IP would take
fleet management down. An invalid credential is rejected with 401 before the
limiter runs, so a throttled answer never reveals that a token is valid.

## 7. Response headers

`SecurityHeadersMiddleware` sets, only if absent, on every response of both
listeners: `X-Content-Type-Options: nosniff` and
`Referrer-Policy: strict-origin-when-cross-origin` (not `no-referrer`: the
CSRF check falls back to the same-origin `Referer` when `Origin` is missing).
Every `TokenMiddleware` 401 carries `Cache-Control: no-store` + `Vary:
Authorization, Cookie`, so a rejected identity response cannot be cached and
replayed.

**Declined (2026-08-25), do not re-add without a new reason:**

- **CSP**: the admin UI's 22 `index.html` pages use inline scripts; a useful
  CSP needs a per-response nonce in each.
- **`X-Frame-Options` / `frame-ancestors`**: the UI is framed by cPanel/WHM
  from a per-install origin; a constant breaks the plugin.
- **HSTS**: browsers apply it per host, not per port, so HSTS from `:6061`
  would also hit the plain-HTTP surfaces on the same host (a re-exposed
  `:6060`, any HTTP site on the hostname).

An operator who wants them adds them at their own reverse proxy.
