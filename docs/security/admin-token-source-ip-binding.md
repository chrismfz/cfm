# Admin-token source-IP binding (control-plane hardening)

**Status:** design / not implemented. Effort ≈ M.
**Scope:** CFM daemon apiserver (`internal/apiserver`). No cfm-web change required
(but see the egress-IP caveat below).

## Problem / threat model

`cfm-web` holds every node's **long-lived admin token** (`AUTH_TOKEN` / `TOKEN`,
`internal/config/config.go:643-644`) so it can drive each node's control plane
(SSO code minting, `node_call`, scoped-token minting). The WHM plugin holds the
same secret to reach the local daemon.

If `cfm-web`'s database leaks, **every node's admin token leaks with it**, and an
attacker could drive the admin API of the whole fleet from anywhere. Token
at-rest hashing on the cfm-web side reduces the leak's value; this document is
the complementary daemon-side control: **make a leaked admin token unusable from
any IP that is not us.**

### Live exposure (verified 2026-08-26, node `orion.myip.gr`)

- `6060/tcp` (admin HTTP) → `cfm`, bound to `*` (0.0.0.0) — **internet-facing**.
- `6061/tcp` (admin TLS) → `cfm`, bound to `*` — **internet-facing**.
- `9098/tcp` (edge challenge) → `cfm`, bound to `127.0.0.1`/`::1` — loopback only.
- `netfilter_path` (input, dport 6060/6061): base chain `inet cfm input`
  (priority -50, policy accept) exists; **no per-port allowlist rule**, findings 0.
- No committed CFM nft rule gates 6060/6061 to selfIPs/`cfm.allow`/`cfm.dyndns`.

So today the admin plane is Internet-reachable and protected **only** by
app-layer auth (as `Audit.md` acknowledges: "listeners must be safe when
Internet-reachable"). Both the app-layer binding below and any L3/L4 nft port
lock are currently **absent**.

## Why this is safe to do (the key insight)

The long-lived admin token is **never presented by an end-user's browser.** It is
presented only:

- by `cfm-web`, server-to-server, from its egress IP; and
- by the WHM plugin / `panelauth`, over **loopback** (`127.0.0.1:6060`).

Browser SSO uses **ephemeral** credentials instead, so restricting the token does
not touch anyone's interactive access:

| Credential | Who presents it | Source IP | Restrict? |
|---|---|---|---|
| **Long-lived admin token** (`token_admin`, `middleware.go:379-388`) | cfm-web (server→node); WHM/panelauth (loopback) | cfm-web egress **or** loopback | ✅ **yes** |
| One-time admin SSO code (45s, single-use, `embed_admin_bootstrap.go`) | minted server-side; **redeemed by operator browser** | mint: known; redeem: arbitrary | ❌ leave |
| `cfm-embed-admin` cookie (600s, HKDF from AUTH_TOKEN) | operator browser | arbitrary | ❌ leave |
| Scoped viewer token / `cfm-embed-scope` cookie | cPanel user's browser | arbitrary | ❌ leave |
| goauth session (`cfm-sid`) | operator browser | arbitrary | ❌ leave |
| `MCP_TOKEN` (separate namespace, bypasses `TokenMiddleware`) | MCP clients (cfm-web) | known | separate policy |

Because the operator/cPanel browser authenticates with a **cookie / scoped token
/ session** — not the admin token — binding the admin token to known IPs leaves
all interactive access untouched. This is why the check must be **per-credential**
(only the `token_admin` branch), NOT a blanket gate over the mux (a blanket gate
would break scoped, SSO-browser and login flows).

## The three doors (and what guards each)

The admin API is reachable three ways; a leaked token can be tried on each:

1. **Direct `:6060`** — HTTP. (Loopback-only by config default, but live nodes
   bind `*`.) Attacker token here → app-layer `token_admin` IP check rejects.
2. **Direct `:6061`** — TLS; what cfm-web uses server-to-server. Attacker token
   here → app-layer check rejects; an nft port-lock would also drop the packet.
3. **Public edge `:443` → `/cfm-admin/` → loopback → `:6060`** — the browser
   front door, reachable from everywhere. nft cannot help (arrives from
   loopback), but the daemon sees the real client IP in `X-Real-IP` (trusted only
   across the loopback hop, multi-hop rejected — `request_identity.go:106-121`),
   so the app-layer check still rejects a token presented from a non-allowlisted
   IP.

The app-layer check covers **all three** because both listeners share the same
`TokenMiddleware` (`apiserver.go`). It is the **fail-safe** control: it lives in
the API itself, so it holds even if the firewall is disabled (`cfm disable`), the
port is opened later, or the nft ruleset drifts. An nft port lock on `:6061` is a
good **bonus** L3/L4 layer, but not the thing to rely on.

## Live evidence (2026-08-27)

Two real SSO logins, captured from `cfm.api.log`, confirm the model end to end.

**Login to `orion` from the cfm-web "Login" button** (`cfm-admin`):

```
event=auth_attempt kind=token result=success src_ip=84.54.49.4 peer_ip=84.54.49.4 \
  entry=6061 scheme=https auth_mech=token_admin path=/api/v1/embed/admin-code status=200
embed admin-code minted   src_ip=84.54.49.4        next=/cfm-admin/
embed admin bootstrap ok  src_ip=94.68.121.123     next=/cfm-admin/
auth_source=embed_admin_cookie src_ip=94.68.121.123 path="/api/v1/system/dnat" ua="…Firefox/154.0"
```

**Login to `earth` from the WHM plugin:**

```
event=auth_attempt kind=token result=success src_ip=127.0.0.1 peer_ip=127.0.0.1 \
  entry=6060 scheme=http auth_mech=token_admin path=/api/v1/embed/admin-code status=200
embed admin-code minted   src_ip=127.0.0.1         next=/cfm-admin/
embed admin bootstrap ok  src_ip=94.68.121.123     next=/cfm-admin/
auth_source=embed_admin_cookie src_ip=94.68.121.123 path="/" ua="…Firefox/154.0"
```

Reading:

- The **admin token** (`auth_mech=token_admin`) is presented only from
  **`84.54.49.4`** (cfm-web, direct `:6061`) or **`127.0.0.1`** (WHM plugin,
  loopback `:6060`) — never from the operator's browser.
- The operator's browser (**`94.68.121.123`**, an arbitrary home IP) redeems the
  one-time code and then drives every `/cfm-admin/` call with the
  `embed_admin_cookie` — **not** the token.
- So the allowlist `{ loopback, selfIPs, 84.54.49.4 }` admits every legitimate
  token presentation and blocks a leaked token from any other IP, while the
  browser session (different IP, different credential) is untouched.

## Design

Add a source-IP gate **only** at the admin-token branch of `TokenMiddleware`
(`internal/apiserver/middleware.go:379-388`): when the presented credential
matches the admin token, additionally require

```
requestPeer(r).ClientIP ∈ allowlist
allowlist = { loopback, selfIPs, cfm.allow, cfm.dyndns, cfm-web egress IP }
```

else return 403. Key on `requestPeer(r).ClientIP` (the forwarded real IP behind
the edge), **never** `r.RemoteAddr` (which is loopback behind the edge and would
make everything "trusted").

Scoped tokens, embed cookies, sessions and MCP stay on their current IP-agnostic
path — no collateral.

### Reuse (already written, currently unwired)

- `internal/apiserver/ip_allow_middleware.go` — `IPAllowMiddleware` already
  composes loopback ∪ selfIPs ∪ `cfm.allow`/`cfm.dyndns` ∪ API_URL-host, keyed on
  `requestPeer().ClientIP`, unit-tested — but **not mounted**. Lift its allowlist
  logic into the admin-token branch (do **not** mount it blanket).
- `internal/detectors/core/selfip.go:74` — `IsSelfIP`.
- `allowlist.BuildSnapshot` / `ipAllowed()` — exact-IP + CIDR + hostname resolve.

## Necessary companion: the embed cookie is forgeable from a leaked token

The `token_admin` IP gate alone does **not** fully neutralize a leaked
`AUTH_TOKEN`. A leaked token grants three capabilities; the IP gate closes two:

1. Direct API (`Authorization: Bearer`) → `token_admin` branch → **gated**.
2. Mint an SSO code (`/api/v1/embed/admin-code` requires admin role) →
   `token_admin` → **gated**.
3. **Forge a session cookie → NOT gated.** Both embed cookies are HMAC-signed
   with a key HKDF-derived **solely from `AUTH_TOKEN`** with in-code (public)
   salt/info:
   - `deriveEmbedAdminCookieSigningKey` (`embed_admin_bootstrap.go:391-404`) —
     `hkdf.Key(sha256, AUTH_TOKEN, "…admin-cookie-salt-v1", "…admin-cookie-v1")`.
   - `deriveEmbedCookieSigningKey` (`embed_bootstrap.go:597-605`) — same, scoped.

   So an attacker who leaked `AUTH_TOKEN` can derive the key offline, mint a valid
   `cfm-embed-admin` cookie (`typ=admin`, fresh `exp`, own UA-hash) and present it
   to `/cfm-admin/` **from any IP**. That is the `embed_admin_cookie` mechanism,
   not `token_admin`, so the IP gate above misses it — and it **cannot** be
   IP-gated, because the legitimate operator presents that same cookie from an
   arbitrary browser IP.

To make a leaked `AUTH_TOKEN` truly useless without credentials, pair the IP gate
with **decoupling the cookie signing key from `AUTH_TOKEN`**:

- **(B1)** Sign embed cookies with a **separate per-node secret** generated on the
  node and never stored in cfm-web's DB. Smallest change (swap the HKDF input);
  a cfm-web DB leak then cannot forge cookies.
- **(B2)** Make the admin cookie **stateful** — a random session id stored on the
  node, created only by redeeming an IP-gated mint — so forgery is impossible
  regardless of any leaked secret. Cleaner, needs session storage.

Root cause: `AUTH_TOKEN` is overloaded — it is simultaneously the API bearer, the
SSO-mint credential, and the seed for cookie-signing keys, so one leak exposes all
three. The durable direction is a **separate secret per job** (same rationale as
splitting out a dedicated `MCP_TOKEN`).

The username/password login path (`session_cookie` / goauth) is inherently
token-leak-safe — it needs the password, not the token — provided the password
store is hashed.

## Caveats / must-verify before enforcing

1. **cfm-web egress IP vs API_URL host — VERIFIED (2026-08-27), covered.** The
   concern was that `API_URL` names cfm-web's *ingress*, while its *egress* source
   IP (when it calls back into a node) could differ under NAT. The live trace
   above shows cfm-web's egress is **`84.54.49.4`**, and `cfm.myip.gr` (the
   `API_URL` host) resolves to **`84.54.49.4`** — they match, so the
   `apiURLHost(API_URL)` allowlist entry admits cfm-web automatically; no extra
   `cfm.allow` line is needed today. Re-verify if cfm-web moves or becomes
   multi-homed (egress ≠ the A record); the check is the `src_ip` on
   `/api/v1/embed/admin-code` mints (`embed_admin_bootstrap.go:164`).
2. **Lock-out risk → dry-run first.** A wrong allowlist locks cfm-web out of the
   whole admin plane. Ship behind a config toggle **default-off**, with a
   **logonly/dry-run** phase (log would-be-blocked admin-token requests with
   `src_ip`) for burn-in, then enforce — the same `logonly → block` promotion the
   WAF uses. Always keep loopback + selfIPs in the set.
3. **Edge real_ip trust.** The bound IP is only as trustworthy as the edge's
   `real_ip` config; on Cloudflare-fronted vhosts `X-Real-IP` is forgeable via
   `CF-Connecting-IP` unless CF is the genuine edge (`configs/openresty.conf`).
4. **MCP is separate.** `MCP_TOKEN` auth bypasses `TokenMiddleware`, so this
   change does not cover the MCP surface. Introducing a dedicated `MCP_TOKEN` on
   the cfm-web side (so `auth_token` stops being an MCP fallback credential) is
   the clean complementary fix.

## Optional companion: nft port-lock on `:6061`

An `inet cfm input` rule that accepts `:6061` (and direct `:6060`) only from
{selfIPs, loopback, `cfm.allow`, `cfm.dyndns`} drops attacker packets at L3/L4
before auth. It does **not** cover the `:443`→loopback→`:6060` edge path (that is
the app-layer check's job), and it can be disabled — so it is defence-in-depth,
not the primary control. Currently absent (see live exposure above).

## Relationship to other work

- **Complementary to cfm-web token-at-rest hashing:** hashing protects the token
  *at rest*; this makes a leaked token unusable *in use* from the wrong IP.
- References: `docs/security/admin-sso-bootstrap.md`,
  `docs/security/direct-6060-transport-policy.md`, `Audit.md`.
