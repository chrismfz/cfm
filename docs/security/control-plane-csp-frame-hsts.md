# Control-plane CSP, frame policy, and HSTS (audit Step 9, deferred bits)

**Status:** ⛔ DECLINED — **not shipping** (operator decision, 2026-08-25). Evaluated
and consciously left out: the benefit is P2 hardening, but each piece risks breaking
real fleet traffic (inline-script UI, the cPanel iframe embed, the self-signed `:6061`
+ plaintext `:6060` bootstrap). CFM's own default control plane keeps only the safe
headers already shipped in `docs/security/control-plane-headers.md` (`nosniff` +
`Referrer-Policy` + `no-store` on auth failures). This file is the **decision record**:
why it was declined, and what a *safe opt-in* would look like if ever revisited (so
nobody re-attempts a naive blanket CSP/frame/HSTS and breaks the fleet). Any operator
who wants these can add them at their edge/reverse proxy, where they control the exact
origins and TLS posture.

## 1. The constraints (why these were deferred)

- **The admin UI uses inline scripts.** Every `internal/webui/static/**/index.html`
  carries an inline `<script>` theme-init and inline `<script type="module">`. A
  strict `script-src 'self'` CSP would break the UI; allowing it needs either
  `'unsafe-inline'` (which defeats the point) or a per-response nonce/hash injected
  into every inline script — i.e. templating ~15 embedded static files. That is a
  separate, larger change, not a header tweak.
- **The cPanel iframe embed is the most painful area (CLAUDE.md §6).** The cPanel
  plugin (parent) embeds the CFM admin UI (child) cross-origin. A blanket
  `frame-ancestors 'self'` / `X-Frame-Options: DENY` on the CFM response would
  **break that embed on upgrade**. And the parent origin the daemon sees
  (`cfmExpectedOrigin`) is **client-provided and only format-validated**
  (`sanitizeExpectedParentOrigin`) — it is NOT a trusted allowlist, so it must never
  drive `frame-ancestors` (an attacker could set it to their own origin).
- **HSTS is host-wide and CFM runs a self-signed `:6061` fallback + a supported
  plaintext `:6060`.** HSTS pinned for the host would (a) force HTTPS on `:6060`, and
  (b) forbid the click-through on the self-signed `:6061` bootstrap — the exact
  fresh-box path Step 6's prerequisite (#1356) keeps open.

## 2. If ever revisited — what a safe opt-in would look like (NOT shipping)

The analysis below is preserved so a future attempt starts from the safe shape, not a
fleet-breaking blanket policy. It is **not** implemented. Would extend
`SecurityHeadersMiddleware` (which already sets `nosniff` + `Referrer-Policy`).

### 2a. Minimal CSP — default ON, breaks nothing

Every control-plane response gains a small CSP that touches **no** script/style/frame
directive, so the inline-script UI and the cPanel embed are unaffected:

```
Content-Security-Policy: object-src 'none'; base-uri 'self'; form-action 'self'
```

- `object-src 'none'` — no `<object>/<embed>/<applet>` injection.
- `base-uri 'self'` — no `<base>`-tag hijack of relative URLs.
- `form-action 'self'` — forms post only same-origin (CFM's own forms all do).

Set only if the handler hasn't set its own `Content-Security-Policy` (the challenge
engine sets its own; this is the apiserver control plane).

### 2b. `frame-ancestors` — opt-in via config (default = current behaviour)

New optional `ADMIN_FRAME_ANCESTORS` (space-separated source list). Default **unset**
→ **no** `frame-ancestors` emitted → framing unrestricted, exactly as today, so cPanel
installs keep working with no config change. When set, it is appended to the CSP:

```
Content-Security-Policy: object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors <value>
```

- Direct-only install wanting clickjacking protection: `ADMIN_FRAME_ANCESTORS = "'self'"`.
- cPanel install: `ADMIN_FRAME_ANCESTORS = "'self' https://panel.example.com:2083"`
  (the operator supplies the **trusted** panel origin — never derived from the
  request). Auto-detection is impossible: the initial cross-origin iframe HTML load
  carries no embed token yet, so a default `'self'` would block the frame before it
  can bootstrap.

No `X-Frame-Options` (legacy, cannot express an allowlist; `frame-ancestors`
supersedes it).

### 2c. HSTS — opt-in via config, HTTPS-only, default OFF

New optional `HSTS_MAX_AGE` seconds. Default **0** → **no** HSTS (keeps the self-signed
`:6061` click-through and plaintext `:6060` working). When > 0, emit
`Strict-Transport-Security: max-age=<n>` **only** on an effective-`https` response
(`requestPeer(r).Scheme == "https"`) — never over plaintext `:6060`, so it can't be
sent over a cleartext hop. Docs carry the loud warnings: host-wide (affects every port
incl. `:6060`), breaks the self-signed `:6061` click-through, and only enable once a
**real** cert is in place fleet-wide. `includeSubDomains`/`preload` are intentionally
NOT offered here.

## 3. Deliberately still deferred

A full `script-src`/`style-src`/`frame-src` CSP that constrains code execution — it
requires nonce/hash templating of the inline scripts across the embedded static UI (a
UI build change), tracked separately.

## 4. Why declined rather than shipped as opt-in-off

Even the "minimal CSP default-on" (§2a) is not worth a fleet-wide upgrade risk for a
P2 gain: `form-action 'self'` and `object-src 'none'` are low-risk but non-zero across
the whole embedded UI + cPanel embed, and shipping the config knobs invites operators
to enable `frame-ancestors`/HSTS without the full context and lock themselves out (the
self-signed `:6061` + plaintext `:6060` interplay is subtle). The safe home for these
is the operator's own edge/reverse proxy, per-install, where the trusted panel origin
and TLS posture are known. If CFM ever revisits this, the full `script-src` CSP would
also need nonce/hash templating of the inline scripts across the static UI (a UI build
change) to be meaningful — another reason this is a project, not a header tweak.

## 5. Status

Not implemented. No `security_headers.go` change, no new config keys, no `cfm.conf`
change. `docs/security/control-plane-headers.md` already records the safe subset that
IS shipped and points to this decision for the rest.
