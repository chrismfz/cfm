# Step 4 — pre-auth admin-login challenge gate (DESIGN)

**Status:** 🎨 DESIGNED, ready to implement (was ON HOLD after the item-8 decline).
This is the agreed approach; no code is written yet. Implement design-first, staged,
and run `docs/challenge-waf-release-checklist.md` before shipping. **Test in BOTH
edge and DNAT mode.**

**One-line principle:** *Unify the challenge algorithm, not the topology assumptions.*
Almost every past failure here was not a bad PoW — it was **two authorities** for
routing, identity, clearance, secret, or release state. The design is single-source
for the challenge logic and **explicit per-listener trust boundaries**.

## 1. Goal

The same pre-auth browser challenge that already fronts the edge must also protect the
**interactive admin login** on the direct control plane:

```
https://host/cfm-admin/         (edge)
https://host:6061/cfm-admin/    (direct TLS)
http://host:6060/cfm-admin/     (only in genuine loopback/degraded fallback)
```

**Only interactive browser login is gated.** No PoW for: valid admin session, admin
bearer, scoped bearer, embed/bootstrap cookie, MCP (own auth). Machine/scoped traffic
is never challenged.

## 2. The history this design must NOT repeat (why each broke)

| Class | PRs | Root cause | How this design avoids it |
|---|---|---|---|
| **Routing ≠ policy** | #246, forced-edge-challenge | Lua chose `up=cfm_challenge` but the nginx location had a hardcoded `proxy_pass 127.0.0.1:6060` — logs showed `up=cfm_challenge` / `uaddr=127.0.0.1:6060`. Policy decision and routing decision were two different things. | **Login stays a Go route.** No dynamic "proxy to Go vs ChallengeServer". The gate is a redirect, not an upstream switch. |
| **Redirect/prefix loops** | #316 → #317 → #318 | Once `/cfm-admin/login` really proxied to the challenge upstream, the ChallengeServer emitted **root-relative redirects** while admin is mounted under `/cfm-admin`. Rewrite → narrow rewrite → revert-to-direct-Go. | Never proxy `/cfm-admin/login`. Challenge is a separate `/__cfm_challenge` mounted on the **same** control plane; `next` is validated to control-plane paths only (§5). |
| **Endless "Checking your browser" (Orion, 11 Aug)** | #1222 → #1225 | Dual-path residue: `/__cfm_verify` called `RemoveChallenge(ip)` on the firewall backend; the shared nftlib socket wedged (1–234s), the browser 499'd before `Set-Cookie`, so it re-challenged forever. | **Already fixed in current code** (`challenge_server.go:308-322`): solve calls **only** `bridge.ClearIP()`, **never** the firewall backend on the release path. #1225 deleted the legacy per-IP challenge-DNAT/9099 machinery (edge is the only mode). The mount inherits this. |
| **Shared clearance cookie collisions** | #1227 | One `cfm_clearance` cookie made web and panel step on each other — cookies aren't isolated per port → "solved but still challenged" loops. Fixed with per-scope names (`cfm_clearance_p2087`, …). | **Already in current code**: `clearanceCookieName(scope)`. The apiserver mount uses a **distinct scope** so it never collides with edge/panel/`:9098` (§5). |
| **Signing-secret mismatch** | #659 | Go ChallengeServer signed clearance from the challenge-secret chain while the Lua panel validator verified with the OpenResty bridge token → valid solve → invalid clearance → loop. | **One signed clearance format, one verifier** shared by every mount (handler registration, not a second impl). No second "truth" for the secret. |
| **Identity trust narrowing (near-miss)** | #1342 (closed), #1345 (constraint) | Unifying the apiserver `RequestPeer` (fleet-wide loopback-only trust) onto the ChallengeServer removed its tolerance for **non-loopback trusted front-ends** — in a non-standard topology the real client would collapse to the proxy IP. | **Explicit per-listener trust policy** (§4). The loopback-only rule applies only on the direct `:6060`/`:6061` mount; `:9098` keeps its own front-end trust. No global narrowing. |

## 3. Architecture — reuse, don't re-implement

Refactor `internal/webdetector/challenge_server.go` to expose its **existing** handlers
for registration on any mux (they already exist on an internal `http.NewServeMux()`),
without creating a second challenge implementation inside the apiserver (per `Audit.md`).

```
ChallengeServer
  ├── RegisterHandlers(mux, trustPolicy)      ← reusable
  │     ├── /__cfm_challenge                   (one PoW impl)
  │     └── /__cfm_verify                      (one signed clearance format, one verifier, one safe-next)
  ├── standalone :9098   → listener-specific trust policy (its own front-end trust)
  └── mounted in apiserver :6060/:6061 → different listener-specific trust policy
```

One PoW implementation, one token format, one verifier, one safe-next — but **no global
assumption** about which proxy header to trust.

## 4. Per-listener trust policy (the #1342 lesson, now explicit)

Trust is a **parameter of the mount**, never a global:

```
:6061 direct        → RemoteAddr authoritative; ignore forged forwarded headers.
:6060 from local edge → explicit edge trust policy; accept canonical XRI/XFF/XFP.
:9098 standalone    → its OWN explicit front-end trust policy; do NOT silently
                      inherit :6060's loopback-only assumption.
```

The apiserver mount reuses the Step 1 `requestPeer` effective-scheme/identity model,
which is already the direct-listener policy; `:9098` keeps its current behaviour.

## 5. Login flow — login stays Go, challenge is a redirect gate

```
GET /cfm-admin/login
      │ no clearance
      ▼
302 /__cfm_challenge?next=/cfm-admin/login
      │
      ▼
challenge handler (mounted on the SAME control plane)
      │  POST /__cfm_verify
      │  signed clearance cookie (distinct control-plane scope)
      ▼
303 /cfm-admin/login
      │  valid clearance
      ▼
normal Go login handler   (unchanged)
```

- `/__cfm_challenge` and `/__cfm_verify` are **public** (self-exempt from the gate) —
  else you loop forever needing clearance to reach the page that grants it.
- **safe-next:** `next` is validated to same-origin control-plane paths only (anti
  open-redirect, anti-loop); never a root-relative redirect that ignores `/cfm-admin`.
- **Distinct clearance scope** for the apiserver mount via `clearanceCookieName(scope)`,
  isolated from edge/panel/`:9098`.
- **Continuation is fail-closed:** a login `POST`/MFA/WebAuthn continuation without
  valid clearance is refused (not silently allowed).

## 6. Integration with the NEW middleware stack — the one genuinely new risk

None of the historical attempts faced today's apiserver stack. The gate must slot in
cleanly (this is where to be most careful):

- **Pre-auth:** the gate runs before `TokenMiddleware` (it fronts *unauthenticated*
  browser login). The `/__cfm_challenge` / `/__cfm_verify` endpoints must be treated as
  public paths (bypass `TokenMiddleware`, `CSRFMiddleware`, and Step 8 `RateLimit`
  keys — or be rate-limited by IP, never by an identity they don't have yet).
- **AdminTransportRedirect (Step 5):** already redirects a direct-external `:6060`
  browser GET to `:6061`, so the challenge normally runs on `:6061`. The gate must not
  double-act or fight the redirect — order them so transport is resolved first, then
  the challenge gate on the effective HTTPS listener.
- **SessionCookieTransport (Step 6):** unrelated cookie; ensure the clearance cookie is
  not caught by the session-cookie rewrite (different name, so it isn't — verify).
- **Only browser routes:** bearer/scoped/embed/MCP short-circuit before the gate (same
  predicate the auth layer already uses).

## 7. Abuse-self-protection firewall path

The ChallengeServer still has an abuse path (`rlFirewallBlock → AddBlock`) for `:9098`.
On the control-plane mount it must be **disabled or scoped** so a challenge abuse
heuristic can never nft-block an admin/controller IP — the same never-nft-the-controller
principle as Step 8's rate limiter.

## 8. Non-goals (do NOT resurrect)

- No second challenge implementation inside the apiserver.
- No `proxy_pass` of `/cfm-admin/login` to the ChallengeServer / a new proxy to `:9098`.
- No legacy per-IP challenge-DNAT / `:9099` machinery (deleted in #1225).
- No global trust narrowing (#1342).
- No PoW for machine/scoped/bearer/embed/MCP traffic.

## 9. Done-when

- one PoW/verifier/secret/safe-next, registered on both `:9098` and the apiserver mount;
- interactive admin-login GET without clearance → challenge → solve → back to the Go
  login handler, on edge, direct `:6061`, and loopback `:6060`;
- per-listener trust: direct `:6061` ignores forged forwarded headers; `:9098` keeps
  its front-end trust; no fleet-wide narrowing;
- clearance cookie scoped so web/panel/`:9098` never collide;
- no firewall-backend call on the solve path; abuse path can't nft-block the mount;
- bearer/scoped/embed/MCP never challenged;
- release checklist passed; verified in edge AND DNAT mode.
