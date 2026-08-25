# Direct control-plane response headers (audit R10 / Step 9)

**Status:** ✅ IMPLEMENTED (safe subset) — `internal/apiserver/security_headers.go`
+ `no-store` on auth failures in `internal/apiserver/middleware.go`. CSP / frame
policy and HSTS are **deliberately deferred** (see §4). Live retest → Step 10.

Finding: `Audit_Results.md` R10 (HARDENING, CONFIRMED LIVE, P2).

## 1. Problem

The direct listeners — plaintext `:6060` and TLS `:6061` — serve the real CFM
API/UI without passing through the OpenResty/Angie edge. Any hardening header that
only the edge added is therefore **absent** on a request that reaches `:6061`
straight from the Internet. R10's low-volume probes found exactly that asymmetry:

- anonymous `GET /api/v1/tokens/me` / `…/admin/authcheck` → `401` **without**
  `Cache-Control: no-store` (the edge added it; direct did not). The endpoint's own
  `setAuthIdentityNoCacheHeaders()` never runs because `TokenMiddleware` rejects the
  anonymous request first;
- `/login` HTML exposed **no** `X-Content-Type-Options` / `Referrer-Policy` /
  CSP / frame headers on the direct listener.

Principle: **the direct control plane must carry its own security model** and not
depend on edge-only policy.

## 2. What shipped

Both changes live on the shared apiserver handler stack, so `:6060` and `:6061`
get identical treatment.

**`SecurityHeadersMiddleware`** (outer stack, just inside `RequestLog` and outside
`AdminTransportRedirect`, so redirects/refusals carry the headers too). On every
response, set-only-if-absent:

| Header | Value | Why safe everywhere |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | `http.Error` already emits it on API JSON errors; this extends it to handler-rendered HTML (`/login`) and static assets. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | The modern browser default (no behaviour change), made explicit. **Not** `no-referrer`: `CSRFMiddleware` falls back to the `Referer` header when `Origin` is absent, and `no-referrer` would strip the same-origin `Referer` it needs. |

Set-only-if-absent lets a specific handler pick a stricter policy for its own response.

**`no-store` on auth failures** — `setAuthIdentityNoCacheHeaders(w)` (which sets
`Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma`, `Expires`,
`Vary: Authorization, Cookie`) is now called at the `TokenMiddleware` rejection
points (`rejectTokenAuth` for malformed/invalid, and the two inline `401`s for
embedded-missing and missing-token), matching what the success handlers already do.

## 3. What this closes

- direct `:6061` and edge now return consistent `no-store` on auth/identity `401`s;
- `nosniff` + `Referrer-Policy` are present on every direct response, including
  `/login` HTML;
- a rejected identity response can no longer be cached and replayed as another
  identity.

## 4. CSP + frame policy + HSTS — ⛔ DECLINED (not shipping)

**Decision (2026-08-25):** these are **not** added to CFM's default control plane —
the P2 hardening isn't worth the fleet-wide breakage risk. Full rationale and the safe
opt-in shape (if ever revisited) are in `docs/security/control-plane-csp-frame-hsts.md`;
operators who want them add them at their own edge/reverse proxy. The reasons, in
brief (they were originally "deferred", now consciously declined):

- **CSP + frame policy (`X-Frame-Options` / `frame-ancestors`).** CFM's admin UI is
  embedded in the **cPanel iframe** (CLAUDE.md §6), whose origin is per-install and
  derived from panel-auth config. A blanket `DENY`/`SAMEORIGIN` — or a
  `frame-ancestors` that omits the panel origin — would break that integration. A
  correct policy must derive allowed ancestors from the panel origin and be verified
  against the real UI's script/style usage (a config-aware change with its own
  review, not a header constant). Until then framing is left unrestricted, exactly as
  before — no regression, but no clickjacking protection added.
- **HSTS.** `Strict-Transport-Security` is **host-wide** — browsers apply it per
  host, ignoring the port. An HSTS emitted on `:6061` would force the browser to
  HTTPS for the whole host, **including the plaintext `:6060`** that remains a
  supported/degraded admin surface after audit R01 / Step 5. Adding HSTS is a
  deliberate decision for once `:6060`'s transport end-state is settled (e.g. `:6060`
  retired or firewalled), and if adopted it needs a scope that cannot strand the
  degraded path.

## 5. Verification

- `internal/apiserver/security_headers_test.go`: baseline headers present on
  HTML/200 and on error responses; a handler's own stricter `Referrer-Policy` is
  preserved; anonymous and invalid-token `401`s carry `no-store` + `Vary: Cookie`.
- Live (Step 10): re-run the R10 direct-vs-edge header probes with a credentialed
  session and confirm parity on `:6061` for the identity `401`s and `/login`.
