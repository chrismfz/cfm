# Admin SSO bootstrap (`cfm-embed-admin`)

**Status:** ✅ IMPLEMENTED — `internal/apiserver/embed_admin_bootstrap.go`
(+ `embed_admin_bootstrap_test.go`), wired in `middleware.go` and `apiserver.go`.

## Problem

Opening the CFM admin UI from a trusted controller used to require an existing
admin session on the node:

- The **WHM plugin** (`plugins/cfm-plugin-cpanel`, `whm` mode) just meta-refreshed
  the root operator to `https://<host>/cfm-admin/`. With no live session that
  lands on the login page — "worked the first time" only because a session
  already existed.
- **cfm-web** (the fleet controller) holds each node's admin bearer token and
  already drives the node API as admin, but a bearer token cannot become a
  browser session, so its Agents page had no way to log an operator straight in.

The scoped cPanel embed flow (`embed_bootstrap.go`) already solves the analogous
problem for **scoped** users (socket assertion → scoped token → `/embed/code` →
iframe `/embed/bootstrap` → `cfm-embed-scope` cookie). There was no **admin**
equivalent — `embed/bootstrap` only ever mints scoped-role cookies.

## Flow

```
controller (holds admin token)                 browser                         node daemon
  │  GET /api/v1/embed/admin-code?next=/cfm-admin/                              │
  │  Authorization: Bearer <admin token>   ───────────────────────────────────▶│  (:6060/:6061 direct)
  │◀── {"code": <160-bit>, "expires_in": 45} ──────────────────────────────────│  role==admin required
  │                                                                             │
  │  hand the browser a top-level link to:                                      │
  │     https://<host>/cfm-admin/api/v1/embed/admin-bootstrap?code=…&next=/cfm-admin/
  │                                       ──(new tab)──▶  GET admin-bootstrap ──▶│  (:443 via edge)
  │                                                     ◀── 303 /cfm-admin/ ─────│  Set-Cookie: cfm-embed-admin
  │                                                        GET /cfm-admin/  ─────▶│  cookie → CtxRoleAdmin
```

- The **code mint** is server-to-server on the direct control plane (`:6061`),
  authenticated by the admin bearer token.
- The **redemption** is a top-level browser navigation to the public
  `/cfm-admin/` origin (`:443` via the edge proxy) — that is where cookies,
  Host binding and same-origin API calls work. The in-memory exchange store is
  process-global, so a code minted on `:6061` is redeemable on `:443`.

## Security model

Turning an admin bearer token into a browser session grants **nothing the
caller did not already hold** — the admin token already authorizes the full
admin API. The guardrails mirror the scoped flow:

- `/api/v1/embed/admin-code` is **not** a public path. The auth middleware
  requires a valid credential to reach it, and the handler additionally rejects
  any non-admin role (a scoped token or scoped embed cookie → `403`). A scoped
  identity can never mint an admin session.
- The exchange code is 160-bit random, **single-use** (`LoadAndDelete`) and
  expires in `embedExchangeCodeTTL` (45s). Rate-limited before redemption so a
  burst can neither burn a valid code nor run cookie crypto under a flood.
- The `cfm-embed-admin` cookie is HMAC-signed with a key **HKDF-derived from
  `AUTH_TOKEN` under a distinct info/salt** from the scoped cookie, so neither
  cookie can be replayed as the other. Claims are `typ=admin`, `exp`, `pfx`,
  host (`hst`) and UA-hash (`uah`); all are verified on every request. Honored
  only when the effective base is `/cfm-admin` (`cfmBase(r)`), and only when no
  bearer header is present.
- TTL 10 min with rolling renewal at half-life (`embedAdminBootstrapTTL`), so an
  active session stays alive and an idle one expires. `HttpOnly`, `Secure`,
  `SameSite=Lax` — Lax (not the scoped cookie's `None`) because the admin
  session is a top-level navigation and same-origin thereafter, which shrinks
  the CSRF surface of the higher-privilege cookie.
- Audited: every mint and redemption logs `src_ip` + `next`; the identity is a
  distinct `embed_admin_cookie` authn mechanism that keys the **trusted**
  rate-limit tier (see `docs/security/control-plane-rate-limiting.md`).

## Consumers

- **cfm-web** — the Agents page "Login" action (table row + per-agent Health
  page) opens a cfm-web SSO route that mints a code against the node and 302s the
  browser to the node's `admin-bootstrap`. cfm-web restricts that action to its
  **super_admin** role (it yields a full-admin node session), independent of the
  node-side guardrails here.
- **WHM plugin** (future) — the `whm` mode can mint a code against the local
  admin API and redirect instead of the bare `/cfm-admin/` meta-refresh.
