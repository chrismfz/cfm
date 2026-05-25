# CFM — Security Headers (Response Policies) Roadmap

**Status:** Design — v1 scope decided, schema and hot-path sketched, open questions tracked below
**Scope:** New module `cfm_policies.lua`, SQLite tables `vhost_policies` + `policy_templates`, control plane via apiserver/cfm-admin/cli
**Goal:** Let operators define response-side browser policies (CSP, HSTS, CORS, Permissions-Policy, Referrer-Policy, X-Frame-Options, X-Content-Type-Options, COOP/COEP/CORP) per vhost, portable across panels (cPanel/DA/LiteSpeed/Plesk) and stacks (Apache/nginx/LiteSpeed/mixed), with templates that survive customer migrations

---

## Table of Contents

1. [Why this matters](#1-why-this-matters)
2. [Naming & terminology](#2-naming--terminology)
3. [Architecture overview](#3-architecture-overview)
4. [Data model — v1](#4-data-model--v1)
5. [Collision modes](#5-collision-modes)
6. [Scope of targeting — v1 vs v2](#6-scope-of-targeting--v1-vs-v2)
7. [V1 feature set](#7-v1-feature-set)
8. [Templates shipped in v1](#8-templates-shipped-in-v1)
9. [CORS preflight handling](#9-cors-preflight-handling)
10. [HSTS — the one-way door](#10-hsts--the-one-way-door)
11. [Hot-path performance plan](#11-hot-path-performance-plan)
12. [Control plane](#12-control-plane)
13. [Phase plan](#13-phase-plan)
14. [Open questions](#14-open-questions)
15. [Out of scope](#15-out-of-scope)

---

## 1. Why this matters

CFM sits as a transparent reverse proxy in front of any web stack the customer happens to run (cPanel-Apache, DA-LiteSpeed, plain nginx, nginx+Apache, etc.). Today CFM does **not touch response headers from the origin** on normal traffic — the only `proxy_hide_header` calls are `Upgrade` and `Alt-Svc` (`configs/angie.conf:447`, `configs/openresty.conf:452`), and `header_filter_by_lua*` is not used anywhere on the customer path.

That's correct as a default, but it means every "we need a CSP for an audit", "we need CORS for our SPA", "we need to set HSTS" ticket today gets answered with stack-specific instructions:

- cPanel-Apache → `.htaccess` Header directive
- DA-LiteSpeed → vhost.conf or `.htaccess` (LiteSpeed reads them differently)
- Plesk-nginx-in-front-of-Apache → both layers
- Raw nginx → server block edit

When the customer migrates panels, the config doesn't follow. When they upgrade LiteSpeed, the directives sometimes change. When CFM is in front of all of them anyway, **CFM is the right place to own browser policy declarations once**.

This roadmap describes how to ship that, reusing the same `Lua + SQLite + apiserver + cfm-admin + cli` shape as WAF/rules.

---

## 2. Naming & terminology

**Q: What do we call these in code, in the DB, and in the UI?**

**Decision:**
- Code: module `cfm_policies.lua`, package noun `policies`
- DB: tables `vhost_policies`, `policy_templates`
- UI tab and customer-facing copy: **"Security Headers"**
- CLI subcommand: `cfm policy ...`

**Why two names?** Engineers see "policy" everywhere in standards (Content-Security-Policy, Permissions-Policy, Referrer-Policy, Cross-Origin-*-Policy) and in this codebase's response-side intent. Customers Google "security headers scanner" and want a tab that matches. Same split CFM already uses for `cfm_clearance` (code) vs "Challenge" (UI).

**Q: Doesn't "policy" collide with existing CFM terms (WAF policy, rule policy)?**

A bit. Rule of thumb to keep them straight:
- `rules` = request-side decisions (block / throttle / challenge)
- `policies` = response-side declarations (headers the browser obeys)

If a contributor ever writes "WAF policy" in new code, prefer "WAF profile" or "ruleset" to avoid the collision.

---

## 3. Architecture overview

```
                                   client
                                     │
                                     ▼
        ┌──────────────────────────────────────────────────────┐
        │                Angie / OpenResty                      │
        │                                                       │
        │  server { listen 9043 ssl ... }                       │
        │    location / {                                       │
        │      access_by_lua_file  cfm.lua    ◄── existing      │
        │      access_by_lua_block {                            │
        │        require("cfm_policies").preflight()            │
        │      }                              ◄── NEW (CORS)    │
        │      proxy_pass $cfm_pass;                            │
        │      header_filter_by_lua_block {                     │
        │        require("cfm_policies").apply()                │
        │      }                              ◄── NEW (headers) │
        │    }                                                  │
        └──────────────────────────────────────────────────────┘
                                     │
                                     ▼
                              origin (Apache/LSWS/...)
```

**Two hook points, both new:**

1. **`access_by_lua_block` for CORS preflight** — must run *before* `proxy_pass`. If method is `OPTIONS` and the vhost has a CORS policy with a matching `Origin`, short-circuit with 204 + ACAO/ACAM/ACAH/ACMA + `Vary: Origin`. Never hits the origin.

2. **`header_filter_by_lua_block` for response headers** — runs after `proxy_pass` returns, before bytes go to the client. Reads vhost policy from per-worker cache, applies collision mode (`add_if_missing` default, `replace` opt-in), sets `ngx.header[...]`.

**Where it gets wired:** the single proxy `location /` block in both `configs/angie.conf` (around line 807 for HTTP, 1188 for HTTPS) and `configs/openresty.conf` (around line 824). **Not** wired into:
- `__cfm_challenge` locations (they set their own headers, see angie.conf:487-492)
- `/cfm-admin` locations (panel has its own header policy)
- Panel listeners in `cfm-panel-listeners.conf.in` (already opinionated, e.g. their own HSTS)

---

## 4. Data model — v1

Two SQLite tables, living alongside the existing rules tables in the CFM state DB.

### 4a. `policy_templates`

Built-in templates ship in code (a Lua table loaded at startup); operator-defined or operator-customized templates live in this table.

| column | type | notes |
|---|---|---|
| `name` | TEXT PK | e.g. `baseline-safe`, `cors-allowlist`, `csp-report-only` |
| `version` | INTEGER | bump when template definition changes |
| `source` | TEXT | `builtin` \| `custom` |
| `headers_json` | TEXT | array of `{header, value, mode, condition?}` |
| `options_json` | TEXT | template-specific knobs (e.g. CORS allowed origins, HSTS max-age) |
| `created_at` | INTEGER | unix epoch |
| `updated_at` | INTEGER | unix epoch |

A built-in template's row is auto-inserted on startup if missing, and refreshed if `version` differs. Customers can `cfm policy clone baseline-safe my-baseline` to fork it.

### 4b. `vhost_policies`

| column | type | notes |
|---|---|---|
| `vhost` | TEXT PK | e.g. `example.com` (lowercase, no port) |
| `template` | TEXT | FK → `policy_templates.name`, nullable if `overrides_json` carries everything |
| `overrides_json` | TEXT | per-vhost overrides on top of template (e.g. site-specific CSP additions) |
| `enabled` | INTEGER | 0/1 |
| `updated_at` | INTEGER | unix epoch, drives cache invalidation |

**Why this shape:** templates are the reusable thing; vhost rows are just (template + small overrides). A customer with 50 vhosts wanting baseline + HSTS-1d picks the template once, applies it 50 times, and each row is tiny.

**v1 keeps path scoping out of the schema.** When v2 adds path-prefix targeting, the migration is `ALTER TABLE vhost_policies ADD COLUMN path_prefix TEXT DEFAULT '';` + composite PK. Acceptable trade.

---

## 5. Collision modes

**Q: When the origin emits a header CFM is also configured to set, what wins?**

**Decision: default `add_if_missing`. Operators must opt into `replace` per header.**

Modes supported per header in a template definition:

| mode | behavior |
|---|---|
| `add_if_missing` *(default)* | If origin already sent this header, leave it alone. CFM only fills gaps. |
| `replace` | Strip origin's value, set CFM's value. Use for headers the operator wants to *enforce* regardless of what the app does. |
| `append` | For comma-separated headers (`Vary`, `Permissions-Policy` directives, some CSP fragments). Merges values without duplicating. |
| `strip` | Remove the header entirely (no replacement). Useful for leaky `Server: Apache/2.4.x ...` style cases. |

**Why this default:** zero blast radius. A customer applies `baseline-safe` and any app that already sets a sane CSP is untouched. The "scary" cases (overriding what the app emits) require deliberate opt-in.

**Duplicate-header trap to remember when writing the apply function:** browsers handle multi-valued headers differently:
- Two `Access-Control-Allow-Origin` → CORS fails (malformed)
- Two `Content-Security-Policy` → intersection (most restrictive wins)
- Two `Strict-Transport-Security` → first wins (usually)

So `add_if_missing` must actually check `ngx.header[name]` before setting. Don't trust nginx to dedupe.

---

## 6. Scope of targeting — v1 vs v2

**Decision: v1 is per-vhost only. Per-path-prefix targeting deferred to v2.**

**v1 covers cleanly:**
- Baseline headers on a whole vhost (X-Content-Type-Options, Referrer-Policy, X-Frame-Options)
- HSTS on a whole vhost
- A single CSP (typically report-only) on a whole vhost
- A single CORS policy on a whole vhost

**v1 does *not* cover:**
- Different CSP for `/wp-admin` vs front-end
- CORS only on `/api`, denied elsewhere
- Per-path Permissions-Policy

Operators who need that today still have to do it at the origin in v1. v2 adds `path_prefix` to `vhost_policies` and a longest-prefix-wins match in `apply()`.

**Why defer:** path scoping is where customers will demand precise behavior matching their old `.htaccess`, which means more bugs, more edge cases (regex vs prefix, case sensitivity, trailing slash), and more test surface. Shipping v1 without it gets the portability win sooner.

---

## 7. V1 feature set

**Decision: Conservative baseline + HSTS ramp + CSP report-only + CORS allowlist with preflight.**

Explicitly **in** for v1:
- `header_filter_by_lua` apply with `add_if_missing` / `replace` / `append` / `strip` modes
- `access_by_lua` CORS preflight handler (handles `OPTIONS` short-circuit)
- Templates: see §8
- Per-vhost enable/disable
- CLI + apiserver + cfm-admin UI tab

Explicitly **out** for v1:
- CSP-enforce templates per app (WordPress/WHMCS/Magento). Only `csp-report-only-*` ships. CSP-enforce comes after we have report data and per-path scoping.
- Per-path targeting (v2)
- CSP report receiver endpoint (v2 — for now operators can point `report-uri` at their own collector)
- COOP/COEP/CORP templates (v2 — these break embeds and we want path scoping first)
- Automatic origin sniffing / suggested baseline ("scan this site, suggest a CSP") — v3 at earliest

---

## 8. Templates shipped in v1

All built-in. All ship with `source = 'builtin'` in `policy_templates`. Customers can clone+edit.

| template | headers | notes |
|---|---|---|
| `baseline-safe` | `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: SAMEORIGIN` | All `add_if_missing`. Zero-risk starting point. |
| `hsts-ramp-5m` | `Strict-Transport-Security: max-age=300` | Testing only. Reversible within minutes. |
| `hsts-ramp-1d` | `Strict-Transport-Security: max-age=86400` | Same value as the panel listeners use. Safe production "we mean it" tier. |
| `hsts-ramp-1y` | `Strict-Transport-Security: max-age=31536000; includeSubDomains` | Commitment. UI must warn. |
| `hsts-ramp-preload` | `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` | One-way. UI must require explicit confirm + show preload-list submission link. |
| `cors-allowlist` | dynamic; options carry `origins[]`, `methods[]`, `headers[]`, `credentials`, `max_age` | Activates the preflight handler. See §9. |
| `csp-report-only` | `Content-Security-Policy-Report-Only: default-src 'self'; report-uri <operator-supplied>` | Observability only. Doesn't break anything. |
| `embed-friendly` | `X-Frame-Options: ` *(strip)* + nothing else | For customers whose iframe customers complain. Uses `strip` mode. |
| `pci-audit-baseline` | Combines `baseline-safe` + `hsts-ramp-1y` + `csp-report-only` | The "auditor checklist" bundle. |

All templates' `options_json` is documented in `docs/security_headers_templates.md` (to be written alongside v1 implementation).

---

## 9. CORS preflight handling

The reason `cors-allowlist` is harder than the others: real CORS needs CFM to **answer** `OPTIONS` requests, not just decorate responses.

**The flow:**

1. Browser sends `OPTIONS /api/whatever` with `Origin: https://app.example` + `Access-Control-Request-Method: POST` + `Access-Control-Request-Headers: content-type,authorization`.
2. `access_by_lua_block { require("cfm_policies").preflight() }` runs.
3. If vhost has no CORS policy → fall through (origin handles or 404s).
4. If vhost has a CORS policy, look up the `Origin` in the allowlist:
   - **No match** → fall through (do not return CORS headers; browser will fail the actual request). Don't 403 here — let the origin decide.
   - **Match** → respond 204 with:
     - `Access-Control-Allow-Origin: <echoed origin>` (never `*` when credentials are involved)
     - `Access-Control-Allow-Methods: <from template>`
     - `Access-Control-Allow-Headers: <from template, or echo of ACRH>`
     - `Access-Control-Max-Age: <from template>`
     - `Access-Control-Allow-Credentials: true` *(if template enables it)*
     - `Vary: Origin` (always, when echoing origin)
5. `ngx.exit(204)`. Never touches `proxy_pass`.

For non-preflight requests (GET/POST/etc with `Origin`), `header_filter_by_lua` adds the same ACAO + `Vary: Origin` to the upstream response **in `add_if_missing` mode by default** — so apps that already do CORS correctly don't get clobbered.

**Allowlist syntax for v1:**
- Exact match: `https://app.example.com`
- Wildcard subdomain: `https://*.example.com` (matches `https://foo.example.com`, not `https://example.com`)
- Special: `null` (for sandboxed iframes / file://)
- No regex. No glob. Keep parsing predictable.

**Open Q on preflight:** see §14.

---

## 10. HSTS — the one-way door

HSTS deserves its own section because it is the only header in this set where a wrong value **cannot be fixed by deploying a new value**. Browsers remember.

**Hard requirements for the UI when an operator applies an HSTS template:**

1. Show the current effective `max-age` and `includeSubDomains` / `preload` flags before the change.
2. For `hsts-ramp-1y` and `hsts-ramp-preload`: require typing the vhost name to confirm.
3. For `hsts-ramp-preload`: also show a link to https://hstspreload.org/ and remind the operator that preload submission is separate and also one-way.
4. Never auto-upgrade between ramp tiers. The operator picks each tier deliberately.
5. Removing an HSTS policy from CFM **does not undo** existing browsers' memory. Document this in the UI.

**Recommended customer flow:** apply `hsts-ramp-5m`, verify with curl + a real browser, apply `hsts-ramp-1d`, leave for a week, apply `hsts-ramp-1y`. Only after weeks of clean operation consider `hsts-ramp-preload`.

---

## 11. Hot-path performance plan

`header_filter_by_lua` runs on **every response** through the proxy. It has to be cheap.

**Cache shape (mirrors `cfm_rules.lua`):**

- Per-worker LRU keyed by `vhost` (lowercased server_name).
- Value: prebuilt list of `{name, value, mode}` tuples (no JSON parse at request time).
- Invalidation: `updated_at` epoch comparison against an in-shared-dict version counter that the apiserver bumps on policy write.
- Cold miss: SQLite read + template merge + cache insert. Bounded to ~ms.

**Per-request cost target:** < 50µs P99 in cache-hit path. Achieved by:
- One `ngx.var.host` read (already cached by nginx).
- One LRU lookup.
- For each header in the policy: one `ngx.header[name]` read (cheap), one assignment.
- No allocations in steady state (preallocate the assignment buffers).

**Preflight cost:** more expensive (origin match, building the response) but only fires on `OPTIONS`, which is rare.

---

## 12. Control plane

### 12a. CLI

```
cfm policy list-templates
cfm policy show <vhost>
cfm policy apply <template> <vhost> [--override key=val ...]
cfm policy clone <template> <new-name>
cfm policy diff <vhost> <template>
cfm policy clear <vhost>
cfm policy test <vhost>          # curl -I against the vhost, show observed headers vs configured
```

`cfm policy test` is the killer debug tool — operator-friendly verification that the configured policy matches what the wire actually returns.

### 12b. apiserver

REST endpoints under `/api/v1/policy/`:

- `GET /api/v1/policy/templates`
- `GET /api/v1/policy/templates/{name}`
- `POST /api/v1/policy/templates` (custom)
- `GET /api/v1/policy/vhosts`
- `GET /api/v1/policy/vhost/{host}`
- `PUT /api/v1/policy/vhost/{host}` (template + overrides + enabled)
- `DELETE /api/v1/policy/vhost/{host}`
- `POST /api/v1/policy/vhost/{host}/test` (synthetic curl, returns observed vs configured)

Audit-logged the same way rule writes are.

### 12c. cfm-admin UI

New left-nav entry: **"Security Headers"**. Per-vhost detail page:
- Current applied template + last-modified
- Template picker with previews of headers each would set
- Per-header override grid (header / value / mode)
- "Test against live" button (calls `/test`)
- HSTS confirmation modal (per §10)
- CSP "report mode" toggle (switches between `csp-report-only-*` and `csp-enforce-*` template families — v1 only ships report-only, toggle exists for v2 readiness)

---

## 13. Phase plan

**Phase 1 — schema + Lua skeleton (no UI):**
- Add `vhost_policies` and `policy_templates` tables + migrations
- Seed built-in templates at startup
- Implement `cfm_policies.apply()` with `add_if_missing` / `replace` / `append` / `strip`
- Wire `header_filter_by_lua_block` into the main proxy `location /` in both `angie.conf` and `openresty.conf`
- CLI: `cfm policy list-templates`, `apply`, `show`, `clear`
- Smoke tests: apply `baseline-safe`, verify with curl

**Phase 2 — CORS:**
- `cors-allowlist` template + `options_json` parser
- `cfm_policies.preflight()` + `access_by_lua_block` wiring
- Vary-Origin handling in `apply()` when CORS is active
- Tests: preflight match, preflight miss-fallthrough, simple-request flow

**Phase 3 — apiserver + cfm-admin:**
- REST endpoints
- UI tab and per-vhost editor
- `cfm policy test` (CLI + API endpoint)
- HSTS confirm UX

**Phase 4 — hardening:**
- Cache invalidation pub/sub via shared dict
- Audit logging for all policy writes
- Docs: `docs/security_headers_templates.md` (per-template reference)

**Phase 5 (v2, separate roadmap once v1 settles):**
- Per-path-prefix scoping
- CSP report receiver endpoint
- CSP-enforce templates per app
- COOP/COEP/CORP templates
- Suggested-baseline scanner

---

## 14. Open questions

These need answers before Phase 1 ships. Tracking them here so they don't get lost.

### 14a. CSP report-uri destination

Where does `report-uri` point in the shipped `csp-report-only` template? Options:
- Force operator to fill it in (template carries `__OPERATOR_REPORT_URI__` placeholder).
- Ship a CFM-hosted receiver endpoint that logs to `/var/log/cfm/csp-reports/`.
- Leave empty, operator adds via override.

**Default position:** placeholder + UI validation that flags an unconfigured report-uri as a non-fatal warning. CFM-hosted receiver is a v2 feature (storage, rotation, panel UI for reading reports — all non-trivial).

### 14b. CORS preflight fallthrough vs reject

When a vhost has a CORS policy but the `Origin` is not in the allowlist, do we:
- (a) Fall through to origin (current §9 design — let the app decide).
- (b) Return 403 with no CORS headers (browser will fail the actual request anyway, this just makes it faster).

**Leaning:** (a) for safety. (b) might surprise an app that has its own CORS allowlist that differs.

### 14c. Wildcard handling

Should `https://*.example.com` match the apex `https://example.com`?

**Standards-aligned answer:** no. `*` means "one or more subdomain labels". If the customer wants both, they list both. Document loudly.

### 14d. Template version drift

When CFM ships an update that bumps `baseline-safe` from v1 to v2 (e.g. tightens `Referrer-Policy`), what happens to vhosts pinned to that template?

Options:
- Auto-upgrade silently.
- Auto-upgrade but log + show banner in UI.
- Pin vhost to the template version it was applied with; require explicit re-apply to take the new version.

**Leaning:** pin to version. Surfaces a "X vhosts have policy updates available" badge in the UI. Operators stay in control.

### 14e. Interaction with Cloudflare in front of CFM

If a customer is on Cloudflare → CFM → origin, CF may add/strip some of these headers (e.g. CF always sets `Server: cloudflare`, sometimes injects its own HSTS). Need to verify that what CFM emits actually reaches the browser unchanged on CF-fronted sites.

Action: add a manual test pass to the Phase 4 hardening list — apply each template behind a CF-fronted test domain, observe the wire at the browser.

### 14f. Should the policy apply to non-2xx responses?

E.g. should `X-Content-Type-Options: nosniff` be added to 500 pages from the origin? Probably yes — error pages can be HTML and need the same hardening. Current `header_filter_by_lua_block` runs regardless of status. Confirm this is the intended default and document.

### 14g. What about `Server` and `X-Powered-By`?

These aren't security headers strictly, but customers often want them stripped for "security through obscurity" audit checkboxes. Add a `strip-leaky-headers` template? Or out of scope?

**Leaning:** ship it. One template, three lines, makes auditors happy.

### 14h. Reload latency target

When operator changes a policy via API, how fast does it have to take effect across all workers? Same approach as rules (shared-dict version counter + per-worker LRU TTL) gives ~5s worst case. Acceptable?

---

## 15. Out of scope

Explicitly **not** part of this roadmap, to keep v1 shippable:

- **WAF interaction.** Policies do not gate WAF decisions. WAF still runs on the request side; policies decorate the response side. They are independent.
- **Request-side headers.** This is all response-direction. Modifying request headers to upstream stays in `proxy_set_header` directives.
- **HTTP/2 server push, Early Hints (103).** Different mechanisms, different ticket.
- **Origin-suggested policies.** No "scan a site, propose a CSP" automation in v1.
- **Cookie policies (`Secure`, `SameSite`, `HttpOnly`).** Cookies are set by the origin; CFM rewriting them risks breaking session state. Out of scope unless a future ticket really demands it.
- **CSP nonces / hashes.** Requires per-response body inspection and is app-specific. Not a fit for a generic proxy.
