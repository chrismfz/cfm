# Automatic request-aware session-cookie transport (audit Step 6)

**Status:** 🎨 DESIGN — awaiting review before implementation.

Finding/spec: `Audit_Fix_Order.md` Step 6 (P1). Make the session cookie's `Secure`
flag automatic from the **effective trusted scheme** (not `AUTH_SECURE_COOKIE`, not
raw `r.TLS`), and give the TLS-down degraded HTTP window its own **distinct**
non-Secure cookie so a real `cfm-sid; Secure` is never downgraded over plaintext —
all **without** mutating goauth's manager-global cookie config per request (a race).

## 1. The constraint

goauth wraps SCS; its cookie attributes are set **once** at manager creation
(`goauth.go:170-174`: `sm.Cookie.Name/Secure/SameSite/Path`). There is no
per-request cookie hook, and mutating `sm.Cookie.*` per request races across
concurrent requests. So per-request behaviour must live **outside** goauth, on the
wire, while goauth keeps one manager + one session store.

The effective scheme is already computed and spoof-safe: `requestPeer(r).Scheme`
(Step 1) is `https` for the edge hop (loopback peer + trusted `X-Forwarded-Proto`)
and direct `:6061` (TLS), and `http` only for direct `:6060`. A direct client cannot
forge it (XFP is trusted only from a loopback peer), which satisfies "direct spoofed
XFP cannot alter Secure state".

## 2. Key insight — one Secure cookie + a translated fallback

Every **non-degraded** path already carries an effective-`https` scheme (edge or
`:6061`), and after Step 5 a healthy `:6060` browser login is redirected to `:6061`
before any session is written. So the **only** time a session cookie is written over
real plaintext is the TLS-down degraded `:6060` window. Therefore:

- **goauth global becomes always-`Secure`**, name `cfm-sid` — the production cookie.
  Correct for every real (https) path; no per-request flag.
- A thin **`SessionCookieTransportMiddleware`** wraps goauth's `LoadAndSave` and acts
  **only** when the effective scheme is `http` on the `:6060` listener (the degraded
  window). There it translates between the wire name `cfm-sid-http-fallback`
  (non-Secure) and goauth's internal `cfm-sid`:
  - **request in:** rename a `cfm-sid-http-fallback` request cookie to `cfm-sid` so
    goauth reads the shared session;
  - **response out:** rewrite goauth's `Set-Cookie: cfm-sid; Secure` to
    `cfm-sid-http-fallback` with `Secure` stripped.
  On every non-degraded request it is a pure pass-through (no rewrite).

One goauth manager, one session store, **no global mutation, no race**. A browser
holding `cfm-sid; Secure` never sends it over http (Secure), so the fallback cookie
is a separate credential — the `Secure` cookie is never overwritten/downgraded.

## 3. Middleware mechanics

- **Placement:** outside `LoadAndSave` (must rewrite the request before goauth reads
  and the response after goauth writes): `… → SessionCookieTransport → LoadAndSave →
  Token → …`.
- **Response rewrite** needs a `http.ResponseWriter` wrapper that post-processes the
  `Set-Cookie` header(s) at `WriteHeader`/first `Write` time: find the session
  cookie by name, rename it, strip `; Secure`. Only touches the one cookie; all other
  headers pass untouched.
- **Guard:** rewrite only when `peer.Entry == "6060"` && `peer.Scheme == "http"` &&
  the peer is non-loopback external (a local CLI on `:6060` doesn't do browser
  sessions). Everywhere else: pass through, goauth's native `cfm-sid; Secure` stands.

## 4. `AUTH_SECURE_COOKIE` deprecation (staged, per spec)

- Parse it still (fleet compatibility) but **ignore** it for the Secure decision.
- Emit a **one-time** deprecation warning at startup when it is present.
- Leave the config field + parser in place this step; remove from newly shipped
  `cfm.conf` and drop the field in a later compatibility-window step.

Explicitly **out of scope** (spec): SameSite changes and `__Host-` conversion — not
bundled here. (Note goauth's own default name is `__Host-sid`; CFM overrides to
`cfm-sid`, which we keep, because `__Host-` forbids a `Domain` and pins `Path=/` and
would itself be a separate, deliberate change.)

## 5. Done-when (from the spec)

- edge HTTPS → `cfm-sid; HttpOnly; Secure` (goauth native);
- direct `:6061` → `cfm-sid; HttpOnly; Secure` (goauth native);
- direct spoofed XFP cannot alter Secure state (`requestPeer` trust model, Step 1);
- healthy `:6060` cannot establish a normal browser session (Step 5 redirect/refuse);
- degraded fallback uses a distinct `cfm-sid-http-fallback` (non-Secure) over shared
  server-side session state (the translation middleware);
- no global mutable-cookie race (translation is per-request on the wire, goauth
  config is immutable after startup).

## 6. Deliverable (this PR, if approved)

`session_cookie_transport.go` (the middleware + Set-Cookie-rewriting ResponseWriter),
flip the goauth manager to always-`Secure` in `Start()`, deprecate `AUTH_SECURE_COOKIE`
(ignore + one-time warn), wire the middleware outside `LoadAndSave`, and unit tests:
edge/`:6061` → Secure `cfm-sid`; degraded `:6060` → `cfm-sid-http-fallback` non-Secure
+ request-cookie rename round-trips the session; spoofed XFP on `:6060` stays http;
non-degraded paths untouched; the `Secure` cookie is never emitted over http.
