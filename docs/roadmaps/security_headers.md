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
16. [CSP composition packs for common third-party integrations](#16-csp-composition-packs-for-common-third-party-integrations)
    - [16a. Composition model](#16a-composition-model)
    - [16b. Built-in packs — international (by category)](#16b-built-in-packs--international-by-category)
    - [16c. Built-in packs — Greek banks (vPOS) + IRIS](#16c-built-in-packs--greek-banks-vpos--iris)
    - [16d. Built-in packs — Greek shipping & last-mile](#16d-built-in-packs--greek-shipping--last-mile)
    - [16e. Built-in packs — Greek marketplaces & comparison](#16e-built-in-packs--greek-marketplaces--comparison)
    - [16f. Bundled templates — common stacks](#16f-bundled-templates--common-stacks)
    - [16g. Honest note on `'unsafe-inline'` and `'unsafe-eval'`](#16g-honest-note-on-unsafe-inline-and-unsafe-eval)
    - [16h. Open questions for packs](#16h-open-questions-for-packs)
17. [Policy probing & auto-suggest](#17-policy-probing--auto-suggest)
    - [17a. Why this exists](#17a-why-this-exists)
    - [17b. Two probe modes — passive body scan + CSP report-only](#17b-two-probe-modes--passive-body-scan--csp-report-only)
    - [17c. CLI surface](#17c-cli-surface)
    - [17d. Data model](#17d-data-model)
    - [17e. CSP report receiver](#17e-csp-report-receiver)
    - [17f. Body scanner](#17f-body-scanner)
    - [17g. Suggestion engine](#17g-suggestion-engine)
    - [17h. Privacy & performance bounds](#17h-privacy--performance-bounds)
    - [17i. Open questions for probing](#17i-open-questions-for-probing)
18. [Permissions-Policy packs](#18-permissions-policy-packs)
    - [18a. Why Permissions-Policy](#18a-why-permissions-policy)
    - [18b. Syntax and composition model](#18b-syntax-and-composition-model)
    - [18c. Baseline & built-in packs](#18c-baseline--built-in-packs)
    - [18d. Bundled Permissions-Policy templates](#18d-bundled-permissions-policy-templates)
    - [18e. Cross-Origin policies (COOP, COEP, CORP)](#18e-cross-origin-policies-coop-coep-corp)
19. [Reporting-Endpoints — the modern reporting API](#19-reporting-endpoints--the-modern-reporting-api)
    - [19a. Why this replaces `report-uri`](#19a-why-this-replaces-report-uri)
    - [19b. Dual-shipping strategy](#19b-dual-shipping-strategy)
    - [19c. Generalised receiver `/__cfm_reports/<token>`](#19c-generalised-receiver-__cfm_reportstoken)
    - [19d. Report types CFM ingests](#19d-report-types-cfm-ingests)
20. [Network Error Logging (NEL)](#20-network-error-logging-nel)
21. [Rollout playbook for operators](#21-rollout-playbook-for-operators)
    - [21a. CSP migration timeline (RO → enforce, ~4 weeks)](#21a-csp-migration-timeline-ro--enforce-4-weeks)
    - [21b. HSTS rollout (4-step ramp)](#21b-hsts-rollout-4-step-ramp)
    - [21c. CORS rollout](#21c-cors-rollout)
    - [21d. Rollback procedure](#21d-rollback-procedure)
22. [Metrics & observability](#22-metrics--observability)
    - [22a. Per-vhost counters](#22a-per-vhost-counters)
    - [22b. Global counters](#22b-global-counters)
    - [22c. Dashboard & alerts](#22c-dashboard--alerts)

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

---

## 16. CSP composition packs for common third-party integrations

The single CSP directive list a real customer needs is the **union of every external service their site loads**. Hand-writing that string is the #1 reason CSP rollouts get abandoned. Rather than ship one monolithic permissive template, v1 ships **composition packs**: small, named bundles, one per integration. The vhost's effective CSP is the union of the base template + every enabled pack, deduped and emitted as a single header.

### 16a. Composition model

Each pack contributes a small set of `(directive, source)` entries, e.g.:

```
script-src   https://js.stripe.com
frame-src    https://js.stripe.com https://hooks.stripe.com
connect-src  https://api.stripe.com
```

At apply time, `cfm_policies.lua` merges every enabled pack by directive name, dedupes sources, and emits one `Content-Security-Policy[-Report-Only]` header. Keywords (`'self'`, `'unsafe-inline'`, `'unsafe-eval'`, `'none'`, `data:`, `blob:`) are preserved verbatim and ordered first within each directive.

**UI shape:** per vhost, the operator sees a checklist of packs and a live preview of the effective header:

```
Enabled packs:
  [x] csp-pack-google-fonts            (style-src, font-src)
  [x] csp-pack-google-analytics        (script-src, img-src, connect-src)
  [x] csp-pack-recaptcha               (script-src, frame-src)
  [x] csp-pack-gr-vpos-cardlink        (form-action, frame-src)
  [ ] csp-pack-stripe                  (script-src, frame-src, connect-src)

Effective CSP (report-only):
  default-src 'self';
  script-src  'self' 'unsafe-inline' https://www.googletagmanager.com ...
  form-action 'self' https://*.cardlink.gr;
  frame-ancestors 'self';
  ...
```

**Storage:** packs live in their own table `policy_csp_packs(name, version, source, directives_json)`. `vhost_policies.overrides_json` gains an `enabled_packs: [...]` array. The composition step happens at cache-build time, not per request.

> **Critical for vPOS:** Greek bank gateways redirect via HTML form `POST`. The directive that gates this is **`form-action`**, not `connect-src` and not `frame-src`. Forget `form-action` and the browser silently blocks checkout submission. Every bank pack below sets it.

### 16b. Built-in packs — international (by category)

Wildcard host forms (`*.example.com`) are used throughout to survive vendor CDN-hostname drift, matching the convention in the example you pasted. This catalog is a **starter set** — packs are versioned and shipped via the same channel as WAF signatures (see §16h).

#### Fonts & icon CDNs

**`csp-pack-google-fonts`**
```
style-src   https://fonts.googleapis.com
font-src    https://fonts.gstatic.com
```

**`csp-pack-bunny-fonts`** *(GDPR-friendly Google Fonts mirror, hosted in EU)*
```
style-src   https://fonts.bunny.net
font-src    https://fonts.bunny.net
```

**`csp-pack-adobe-fonts`** *(Typekit)*
```
script-src  https://use.typekit.net
style-src   https://use.typekit.net
font-src    https://use.typekit.net https://p.typekit.net
img-src     https://p.typekit.net
```

**`csp-pack-font-awesome`** *(Kit-hosted)*
```
script-src  https://kit.fontawesome.com
style-src   https://*.fontawesome.com
font-src    https://*.fontawesome.com
connect-src https://ka-f.fontawesome.com
```

#### Generic script/style CDNs

**`csp-pack-jsdelivr`**
```
script-src  https://cdn.jsdelivr.net
style-src   https://cdn.jsdelivr.net
font-src    https://cdn.jsdelivr.net
```

**`csp-pack-unpkg`**
```
script-src  https://unpkg.com
style-src   https://unpkg.com
```

**`csp-pack-cdnjs`** *(Cloudflare CDNJS)*
```
script-src  https://cdnjs.cloudflare.com
style-src   https://cdnjs.cloudflare.com
font-src    https://cdnjs.cloudflare.com
```

**`csp-pack-bunnycdn`** *(generic *.b-cdn.net hosting — site-specific, often disabled by default)*
```
script-src  https://*.b-cdn.net
style-src   https://*.b-cdn.net
img-src     https://*.b-cdn.net
font-src    https://*.b-cdn.net
media-src   https://*.b-cdn.net
```

#### Image CDNs / optimizers

**`csp-pack-cloudinary`**
```
img-src     https://*.cloudinary.com
script-src  https://*.cloudinary.com
```

**`csp-pack-imgix`**
```
img-src     https://*.imgix.net
```

#### Analytics, RUM, session replay

**`csp-pack-google-analytics`** *(GA4 + GTM)*
```
script-src  https://*.googletagmanager.com https://*.google-analytics.com
img-src     https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com
connect-src https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com
```

**`csp-pack-microsoft-clarity`**
```
script-src  https://*.clarity.ms
connect-src https://*.clarity.ms
```

**`csp-pack-hotjar`**
```
script-src  https://*.hotjar.com https://*.hotjar.io
connect-src https://*.hotjar.com https://*.hotjar.io wss://*.hotjar.com
img-src     https://*.hotjar.com
font-src    https://*.hotjar.com
frame-src   https://*.hotjar.com
```

**`csp-pack-fullstory`**
```
script-src  https://*.fullstory.com
connect-src https://*.fullstory.com
img-src     https://*.fullstory.com
```

**`csp-pack-matomo-cloud`** *(InnoCraft hosted)*
```
script-src  https://*.matomo.cloud
connect-src https://*.matomo.cloud
img-src     https://*.matomo.cloud
```

**`csp-pack-plausible-cloud`**
```
script-src  https://plausible.io
connect-src https://plausible.io
```

#### Error & performance monitoring

**`csp-pack-sentry`**
```
script-src  https://*.sentry.io
connect-src https://*.sentry.io https://*.ingest.sentry.io
```

**`csp-pack-datadog-rum`**
```
script-src  https://www.datadoghq-browser-agent.com
connect-src https://*.browser-intake-datadoghq.com https://*.datadoghq.com https://*.datadoghq.eu
```

**`csp-pack-new-relic-browser`**
```
script-src  https://js-agent.newrelic.com
connect-src https://bam.nr-data.net https://*.nr-data.net
```

**`csp-pack-logrocket`**
```
script-src  https://*.logrocket.com https://*.lr-ingest.io
connect-src https://*.lr-ingest.io https://*.logr-ingest.com
img-src     https://*.logrocket.com
```

#### A/B testing & personalization

**`csp-pack-optimizely`**
```
script-src  https://cdn.optimizely.com
connect-src https://*.optimizely.com
```

**`csp-pack-vwo`** *(Visual Website Optimizer / Wingify)*
```
script-src  https://dev.visualwebsiteoptimizer.com https://*.visualwebsiteoptimizer.com https://*.wingify.com
connect-src https://*.visualwebsiteoptimizer.com https://*.wingify.com
img-src     https://*.visualwebsiteoptimizer.com
```

#### Cookie consent (GDPR)

**`csp-pack-cookiebot`**
```
script-src  https://consent.cookiebot.com https://consentcdn.cookiebot.com
img-src     https://imgsct.cookiebot.com
connect-src https://consent.cookiebot.com https://consentcdn.cookiebot.com
```

**`csp-pack-onetrust`**
```
script-src  https://*.onetrust.com https://cdn.cookielaw.org
connect-src https://*.onetrust.com https://geolocation.onetrust.com
img-src     https://*.onetrust.com
```

**`csp-pack-iubenda`**
```
script-src  https://*.iubenda.com https://cdn.iubenda.com
connect-src https://*.iubenda.com
img-src     https://*.iubenda.com
```

#### Maps

**`csp-pack-google-maps`**
```
script-src  https://maps.googleapis.com https://maps.gstatic.com
img-src     https://maps.googleapis.com https://maps.gstatic.com https://*.googleusercontent.com
style-src   https://fonts.googleapis.com
font-src    https://fonts.gstatic.com
frame-src   https://www.google.com
```

**`csp-pack-mapbox`**
```
script-src  https://api.mapbox.com
style-src   https://api.mapbox.com
img-src     https://*.tiles.mapbox.com https://api.mapbox.com
connect-src https://*.tiles.mapbox.com https://api.mapbox.com https://events.mapbox.com
worker-src  blob:
```

**`csp-pack-openstreetmap`** *(Leaflet + OSM tile servers)*
```
img-src     https://*.tile.openstreetmap.org https://*.openstreetmap.org
script-src  https://unpkg.com
style-src   https://unpkg.com
```

#### CAPTCHA & bot challenges

**`csp-pack-recaptcha`** *(v2 / v3 / Enterprise)*
```
script-src  https://www.google.com https://www.gstatic.com https://www.recaptcha.net
frame-src   https://www.google.com https://www.recaptcha.net
```

**`csp-pack-hcaptcha`**
```
script-src  https://*.hcaptcha.com
style-src   https://*.hcaptcha.com
frame-src   https://*.hcaptcha.com
connect-src https://*.hcaptcha.com
```

**`csp-pack-cloudflare-turnstile`**
```
script-src  https://challenges.cloudflare.com
frame-src   https://challenges.cloudflare.com
```

**`csp-pack-cloudflare-insights`** *(RUM beacon)*
```
script-src  https://static.cloudflareinsights.com
connect-src https://cloudflareinsights.com
```

#### Video & audio embeds

**`csp-pack-youtube`**
```
frame-src   https://*.youtube.com https://*.youtube-nocookie.com https://*.youtu.be
img-src     https://*.ytimg.com
```

**`csp-pack-vimeo`**
```
frame-src   https://player.vimeo.com https://*.vimeo.com
img-src     https://*.vimeocdn.com
script-src  https://player.vimeo.com
```

**`csp-pack-spotify`** *(embedded player)*
```
frame-src   https://open.spotify.com
img-src     https://*.scdn.co
```

#### Social pixels & embeds

**`csp-pack-facebook-pixel`** *(FB Pixel + SDK)*
```
script-src  https://*.facebook.net
img-src     https://*.facebook.com
connect-src https://*.facebook.com
frame-src   https://*.facebook.com
```

**`csp-pack-instagram-embed`**
```
script-src  https://*.instagram.com
frame-src   https://*.instagram.com
img-src     https://*.cdninstagram.com
```

**`csp-pack-twitter-x`** *(formerly Twitter widgets/embeds)*
```
script-src  https://platform.twitter.com https://*.twimg.com
frame-src   https://platform.twitter.com https://*.twitter.com https://*.x.com
img-src     https://*.twimg.com
```

**`csp-pack-tiktok-pixel`**
```
script-src  https://*.tiktok.com
connect-src https://*.tiktok.com
img-src     https://*.tiktokcdn.com
```

**`csp-pack-linkedin-insight`**
```
script-src  https://snap.licdn.com
img-src     https://px.ads.linkedin.com
connect-src https://px.ads.linkedin.com
```

**`csp-pack-pinterest-tag`**
```
script-src  https://*.pinimg.com
img-src     https://*.pinimg.com
```

**`csp-pack-snap-pixel`**
```
script-src  https://sc-static.net
img-src     https://tr.snapchat.com
connect-src https://tr.snapchat.com
```

**`csp-pack-reddit-pixel`**
```
script-src  https://www.redditstatic.com
img-src     https://www.redditstatic.com
```

**`csp-pack-bing-uet`** *(Microsoft Ads UET)*
```
script-src  https://bat.bing.com
img-src     https://bat.bing.com
```

#### Live chat & support widgets

**`csp-pack-tawk`**
```
script-src  https://*.tawk.to
style-src   https://*.tawk.to
img-src     https://*.tawk.to
font-src    https://*.tawk.to
connect-src https://*.tawk.to wss://*.tawk.to
frame-src   https://*.tawk.to
```

**`csp-pack-intercom`**
```
script-src  https://*.intercomcdn.com https://*.intercom.io https://js.intercomcdn.com
style-src   https://*.intercomcdn.com
img-src     https://*.intercomcdn.com https://*.intercom-mail.com
font-src    https://*.intercomcdn.com
connect-src https://*.intercom.io https://*.intercom.com wss://*.intercom.io
frame-src   https://*.intercom.io https://*.intercom.com
```

**`csp-pack-crisp`**
```
script-src  https://client.crisp.chat
style-src   https://client.crisp.chat
img-src     https://image.crisp.chat https://client.crisp.chat
font-src    https://client.crisp.chat
connect-src https://client.crisp.chat wss://client.relay.crisp.chat
frame-src   https://game.crisp.chat
```

**`csp-pack-livechat`** *(LiveChat Inc.)*
```
script-src  https://*.livechatinc.com
style-src   https://*.livechatinc.com
img-src     https://*.livechatinc.com
connect-src https://*.livechatinc.com wss://*.livechatinc.com
frame-src   https://*.livechatinc.com
```

**`csp-pack-zendesk-widget`**
```
script-src  https://*.zendesk.com https://*.zdassets.com https://static.zdassets.com
style-src   https://*.zendesk.com https://*.zdassets.com
img-src     https://*.zendesk.com https://*.zdassets.com
font-src    https://*.zdassets.com
connect-src https://*.zendesk.com https://*.zdassets.com wss://*.zendesk.com
frame-src   https://*.zendesk.com
```

**`csp-pack-drift`**
```
script-src  https://js.driftt.com https://widget.drift.com
style-src   https://js.driftt.com
img-src     https://*.drift.com
connect-src https://*.drift.com wss://*.drift.com
frame-src   https://js.driftt.com
```

**`csp-pack-hubspot-chat`**
```
script-src  https://js.hs-scripts.com https://js.hs-banner.com https://js.usemessages.com
style-src   https://*.hubspot.com
img-src     https://*.hubspot.com
connect-src https://*.hubspot.com wss://*.hubspot.com
frame-src   https://*.hubspot.com
```

#### Email marketing & CRM

**`csp-pack-mailchimp`**
```
script-src  https://*.list-manage.com https://*.mailchimp.com https://chimpstatic.com
img-src     https://*.list-manage.com https://*.mailchimp.com
connect-src https://*.list-manage.com
form-action https://*.list-manage.com
```

**`csp-pack-klaviyo`**
```
script-src  https://*.klaviyo.com https://static.klaviyo.com
connect-src https://*.klaviyo.com
img-src     https://*.klaviyo.com
```

**`csp-pack-brevo`** *(formerly Sendinblue)*
```
script-src  https://*.brevo.com https://sibautomation.com
img-src     https://*.brevo.com
connect-src https://*.brevo.com
```

**`csp-pack-hubspot-tracking`**
```
script-src  https://js.hs-analytics.net https://js.hs-scripts.com
img-src     https://track.hubspot.com
connect-src https://*.hubspot.com
```

**`csp-pack-activecampaign`**
```
script-src  https://*.activehosted.com https://*.activecampaign.com
connect-src https://*.activehosted.com https://*.activecampaign.com
```

#### Reviews, loyalty, on-site search

**`csp-pack-trustpilot`**
```
script-src  https://*.trustpilot.com
img-src     https://*.trustpilot.com
frame-src   https://*.trustpilot.com
connect-src https://*.trustpilot.com
```

**`csp-pack-yotpo`**
```
script-src  https://*.yotpo.com
img-src     https://*.yotpo.com
connect-src https://*.yotpo.com
```

**`csp-pack-stamped`**
```
script-src  https://*.stamped.io
img-src     https://*.stamped.io
connect-src https://*.stamped.io
```

**`csp-pack-algolia`** *(InstantSearch / autocomplete)*
```
script-src  https://cdn.jsdelivr.net
connect-src https://*.algolia.net https://*.algolianet.com https://*.algolia.io
```

#### Forms & scheduling

**`csp-pack-typeform`**
```
script-src  https://embed.typeform.com
frame-src   https://*.typeform.com
```

**`csp-pack-calendly`**
```
script-src  https://assets.calendly.com
style-src   https://assets.calendly.com
frame-src   https://calendly.com https://*.calendly.com
```

#### SSO / social login

**`csp-pack-google-signin`** *(Google Identity Services)*
```
script-src  https://accounts.google.com https://apis.google.com
frame-src   https://accounts.google.com
connect-src https://accounts.google.com
```

**`csp-pack-apple-signin`**
```
script-src  https://appleid.cdn-apple.com
frame-src   https://appleid.apple.com
connect-src https://appleid.apple.com
form-action https://appleid.apple.com
```

**`csp-pack-microsoft-signin`** *(MSAL.js / Entra ID)*
```
script-src  https://alcdn.msauth.net
frame-src   https://login.microsoftonline.com
connect-src https://login.microsoftonline.com https://*.b2clogin.com
form-action https://login.microsoftonline.com
```

#### Payments — international

**`csp-pack-stripe`**
```
script-src  https://js.stripe.com https://*.stripe.com
frame-src   https://js.stripe.com https://hooks.stripe.com https://*.stripe.com
connect-src https://api.stripe.com https://*.stripe.com
```

**`csp-pack-paypal`**
```
script-src  https://*.paypal.com https://*.paypalobjects.com
frame-src   https://*.paypal.com
img-src     https://*.paypal.com https://*.paypalobjects.com
connect-src https://*.paypal.com
form-action https://www.paypal.com
```

**`csp-pack-klarna`**
```
script-src  https://*.klarna.com https://*.klarnacdn.net
frame-src   https://*.klarna.com
img-src     https://*.klarnacdn.net
connect-src https://*.klarna.com
form-action https://*.klarna.com
```

**`csp-pack-adyen`**
```
script-src  https://*.adyen.com
frame-src   https://*.adyen.com
img-src     https://*.adyen.com
connect-src https://*.adyen.com
form-action https://*.adyen.com
```

**`csp-pack-mollie`**
```
script-src  https://js.mollie.com
frame-src   https://*.mollie.com
connect-src https://api.mollie.com
form-action https://*.mollie.com
```

**`csp-pack-applepay`** *(only when used as native ApplePayJS, not via Stripe/Adyen)*
```
connect-src https://apple-pay-gateway.apple.com
frame-src   https://apple-pay-gateway.apple.com
```

#### WordPress ecosystem

**`csp-pack-wp-jetpack`** *(WordPress.com services + Gravatar)*
```
script-src  https://*.wp.com
img-src     https://*.wp.com https://*.gravatar.com https://secure.gravatar.com
style-src   https://*.wp.com
```

**`csp-pack-disqus`** *(comment widget)*
```
script-src  https://*.disqus.com https://*.disquscdn.com
img-src     https://*.disquscdn.com
style-src   https://*.disquscdn.com
frame-src   https://disqus.com
connect-src https://*.disqus.com
```

### 16c. Built-in packs — Greek banks (vPOS) + IRIS

Each pack below sets **`form-action`** in addition to `frame-src` (the latter only matters when the bank's hosted form is iframed instead of redirected — most are redirect-flow, but a few support both).

#### `csp-pack-gr-vpos-cardlink` (Alpha Bank + Eurobank Cards + NBG cards via Cardlink)
```
form-action https://*.cardlink.gr
frame-src   https://*.cardlink.gr
```

#### `csp-pack-gr-vpos-eurocommerce` (Eurobank direct vPOS)
```
form-action https://*.eurocommerce.gr
frame-src   https://*.eurocommerce.gr
```

#### `csp-pack-gr-vpos-alpha` (Alpha Bank direct, when not via Cardlink)
```
form-action https://*.alphae-commerce.gr https://*.alpha-bank.gr
frame-src   https://*.alphae-commerce.gr
```

#### `csp-pack-gr-vpos-piraeus` (Piraeus PayCenter)
```
form-action https://paycenter.piraeusbank.gr
frame-src   https://paycenter.piraeusbank.gr
```

#### `csp-pack-gr-vpos-nbg` (Εθνική Τράπεζα PayCenter)
```
form-action https://paycenter.nbg.gr
frame-src   https://paycenter.nbg.gr
```

#### `csp-pack-gr-vpos-viva` (Viva Wallet / Viva.com)
```
script-src  https://*.vivapayments.com https://*.vivawallet.com https://*.viva.com
form-action https://*.vivapayments.com https://*.vivawallet.com https://*.viva.com
frame-src   https://*.vivapayments.com https://*.vivawallet.com https://*.viva.com
connect-src https://*.vivapayments.com https://*.vivawallet.com
```

#### `csp-pack-gr-vpos-everypay`
```
script-src  https://*.everypay.gr
form-action https://*.everypay.gr
frame-src   https://*.everypay.gr
```

#### `csp-pack-gr-iris` (IRIS Online Payments — DIAS account-to-account)

State-pushed alternative to card payments; integrated either via the customer's bank vPOS (in which case the relevant bank pack covers it) or directly via the IRIS gateway. Direct-integration domains:
```
script-src  https://*.iris.gr
form-action https://*.iris.gr https://*.dias.com.gr
frame-src   https://*.iris.gr https://*.dias.com.gr
connect-src https://*.iris.gr
```

#### `csp-pack-gr-myip` (myip.gr utility — CFM-internal customer convenience)
```
script-src  https://*.myip.gr
connect-src https://*.myip.gr
img-src     https://*.myip.gr
```

### 16d. Built-in packs — Greek shipping & last-mile

These widgets typically embed a JS picker on checkout (locker selection, address autocomplete) and/or a tracking iframe on the order-status page. For most carriers `script-src` + `frame-src` + `connect-src` is enough; `form-action` rarely applies because shipping selection is client-side state, not a redirect.

#### `csp-pack-gr-shipping-boxnow` (BoxNow lockers — the dominant locker network in GR)

Embedded locker map/picker on checkout. Increasingly mandatory for shops competing on delivery options.
```
script-src  https://*.boxnow.gr
style-src   https://*.boxnow.gr
img-src     https://*.boxnow.gr
connect-src https://*.boxnow.gr
frame-src   https://*.boxnow.gr
```

#### `csp-pack-gr-shipping-skroutz-last-mile` (Skroutz Last Mile / SLM — locker + courier)
```
script-src  https://*.skroutz.gr
style-src   https://*.skroutz.gr
img-src     https://*.skroutz.gr
connect-src https://*.skroutz.gr
frame-src   https://*.skroutz.gr
```

#### `csp-pack-gr-shipping-acs` (ACS Courier — tracking widget / address validation)
```
script-src  https://*.acscourier.net https://*.acscourier.gr
connect-src https://*.acscourier.net https://*.acscourier.gr
frame-src   https://*.acscourier.net https://*.acscourier.gr
img-src     https://*.acscourier.net https://*.acscourier.gr
```

#### `csp-pack-gr-shipping-geniki-taxydromiki` (Geniki Taxydromiki / General Post)
```
script-src  https://*.taxydromiki.com
connect-src https://*.taxydromiki.com
frame-src   https://*.taxydromiki.com
```

#### `csp-pack-gr-shipping-speedex`
```
script-src  https://*.speedex.gr
connect-src https://*.speedex.gr
frame-src   https://*.speedex.gr
img-src     https://*.speedex.gr
```

#### `csp-pack-gr-shipping-elta-courier` (ELTA Courier — ΕΛΤΑ Courier)
```
script-src  https://*.elta-courier.gr https://*.elta.gr
connect-src https://*.elta-courier.gr https://*.elta.gr
frame-src   https://*.elta-courier.gr https://*.elta.gr
img-src     https://*.elta-courier.gr https://*.elta.gr
```

#### `csp-pack-gr-shipping-sendx` (SendX — third-party fulfillment, used by many small GR shops)
```
script-src  https://*.sendx.gr
connect-src https://*.sendx.gr
frame-src   https://*.sendx.gr
```

### 16e. Built-in packs — Greek marketplaces & comparison

#### `csp-pack-gr-skroutz` (Skroutz Analytics + Smart Cart + reviews + affiliate)

Skroutz embeds appear on most GR e-commerce sites for at least one of: analytics conversion tracking, Smart Cart unified checkout, product reviews import, affiliate link tracking. One wildcard pack covers all of them.
```
script-src  https://*.skroutz.gr
style-src   https://*.skroutz.gr
img-src     https://*.skroutz.gr
connect-src https://*.skroutz.gr
frame-src   https://*.skroutz.gr
form-action https://*.skroutz.gr
```

> Note: `csp-pack-gr-skroutz` and `csp-pack-gr-shipping-skroutz-last-mile` overlap entirely (`*.skroutz.gr` covers both). They're kept as separate packs so the UI can show *intent* — "this site uses Skroutz comparison/analytics" vs "this site uses Skroutz Last Mile shipping" — even though the merged directive list is identical. The composition step dedupes.

#### `csp-pack-gr-bestprice` (BestPrice price comparison — analytics + affiliate)
```
script-src  https://*.bestprice.gr
img-src     https://*.bestprice.gr
connect-src https://*.bestprice.gr
```

### 16f. Bundled templates — common stacks

Pre-composed templates for "I just want it to work" customers. Each bundle is a regular template whose `options_json` carries `enabled_packs: [...]`. Operators can clone and customize.

#### `csp-bundle-gr-ecommerce-typical`

The typical Greek shop: GA + reCAPTCHA + at least one bank gateway + at least one international processor + Skroutz + BoxNow.

```
base:           csp-report-only
enabled_packs:
  - csp-pack-google-fonts
  - csp-pack-google-analytics
  - csp-pack-recaptcha
  - csp-pack-gr-vpos-cardlink
  - csp-pack-gr-vpos-eurocommerce
  - csp-pack-stripe
  - csp-pack-paypal
  - csp-pack-youtube
  - csp-pack-gr-skroutz
  - csp-pack-gr-shipping-boxnow
  - csp-pack-cookiebot
extra_directives:
  default-src     'self'
  object-src      'none'
  base-uri        'self'
  frame-ancestors 'self'
```

#### `csp-bundle-gr-ecommerce-viva-everypay`

The same shape but for shops using Viva + Everypay instead of Cardlink/Eurocommerce.

```
base:           csp-report-only
enabled_packs:
  - csp-pack-google-fonts
  - csp-pack-google-analytics
  - csp-pack-recaptcha
  - csp-pack-gr-vpos-viva
  - csp-pack-gr-vpos-everypay
  - csp-pack-stripe
  - csp-pack-gr-skroutz
  - csp-pack-gr-shipping-boxnow
  - csp-pack-cookiebot
extra_directives:
  default-src     'self'
  object-src      'none'
  base-uri        'self'
  frame-ancestors 'self'
```

#### `csp-bundle-gr-ecommerce-skroutz-stack`

For shops fully on the Skroutz ecosystem (Smart Cart checkout + Skroutz Pay + SLM shipping).

```
base:           csp-report-only
enabled_packs:
  - csp-pack-google-fonts
  - csp-pack-google-analytics
  - csp-pack-recaptcha
  - csp-pack-gr-skroutz
  - csp-pack-gr-shipping-skroutz-last-mile
  - csp-pack-gr-vpos-cardlink
  - csp-pack-stripe
  - csp-pack-cookiebot
extra_directives:
  default-src     'self'
  object-src      'none'
  base-uri        'self'
  frame-ancestors 'self'
```

#### `csp-bundle-gr-ecommerce-full-shipping`

Maximal shipping coverage — useful for shops that let the customer pick *any* carrier at checkout.

```
base:           csp-report-only
enabled_packs:
  - csp-pack-google-fonts
  - csp-pack-google-analytics
  - csp-pack-recaptcha
  - csp-pack-gr-vpos-cardlink
  - csp-pack-gr-vpos-eurocommerce
  - csp-pack-stripe
  - csp-pack-paypal
  - csp-pack-gr-shipping-boxnow
  - csp-pack-gr-shipping-skroutz-last-mile
  - csp-pack-gr-shipping-acs
  - csp-pack-gr-shipping-geniki-taxydromiki
  - csp-pack-gr-shipping-speedex
  - csp-pack-gr-shipping-elta-courier
  - csp-pack-cookiebot
  - csp-pack-gr-skroutz
  - csp-pack-trustpilot
extra_directives:
  default-src     'self'
  object-src      'none'
  base-uri        'self'
  frame-ancestors 'self'
```

#### `csp-bundle-wp-typical`

WordPress site with Jetpack, fonts, analytics, embedded YouTube.

```
base:           csp-report-only
enabled_packs:
  - csp-pack-google-fonts
  - csp-pack-google-analytics
  - csp-pack-wp-jetpack
  - csp-pack-youtube
extra_directives:
  default-src     'self'
  script-src      'self' 'unsafe-inline' 'unsafe-eval'
  style-src       'self' 'unsafe-inline'
  object-src      'none'
  base-uri        'self'
  frame-ancestors 'self'
```

Includes `'unsafe-inline'` and `'unsafe-eval'` as a documented compromise — see §16e.

#### `csp-bundle-whmcs-typical`

Same `'unsafe-inline' / 'unsafe-eval'` compromise as WP, plus payment packs WHMCS shops typically wire up.

```
base:           csp-report-only
enabled_packs:
  - csp-pack-stripe
  - csp-pack-paypal
  - csp-pack-recaptcha
extra_directives:
  default-src     'self'
  script-src      'self' 'unsafe-inline' 'unsafe-eval'
  style-src       'self' 'unsafe-inline'
  object-src      'none'
  base-uri        'self'
  frame-ancestors 'self'
```

### 16g. Honest note on `'unsafe-inline'` and `'unsafe-eval'`

WordPress (core, most themes, most plugins), WHMCS, and many legacy panels rely on inline `<script>`/`<style>` and inline event handlers. Removing `'unsafe-inline'` and `'unsafe-eval'` from `script-src` will break them, and the only standards-compliant alternative — per-script nonces or hashes — requires response-body rewriting, which is **out of scope** (see §15).

Realistic positions for these stacks:

1. **CSP enforce with `'unsafe-inline' 'unsafe-eval'` permitted.** Reduced XSS protection on `script-src`, but **still real value from the other directives**: `form-action 'self' <vpos>` (anti-phishing-redirect), `frame-ancestors 'self'` (clickjacking), `object-src 'none'` (no Flash/embed exploits), `base-uri 'self'` (anti-base-tag injection). Audit auditors get their "yes we send a CSP" checkbox; site keeps working.

2. **CSP report-only with `'unsafe-inline' 'unsafe-eval'` permitted.** Zero blocking, observability only. Useful as a pre-flight: leave it on for a week, look at violation reports, see what the site actually loads, then decide if a stricter enforce policy is feasible.

The UI must label both modes clearly so an operator picking `csp-bundle-wp-typical` doesn't believe the CSP is fully blocking XSS — it isn't. Mark `'unsafe-*'` directives with a warning icon and a hover-tooltip explaining the trade.

### 16h. Open questions for packs

- **Pack-URL drift.** Vendors quietly add CDN hostnames (Facebook split into `facebook.net` / `fbcdn.net` / `connect.facebook.net` over the years; Google moves analytics endpoints; banks add new gateway domains). Treat packs like WAF signatures — version them, ship updates via the same channel — or treat them as user-editable config from day one?
- **`cfm policy test` per pack.** Should the test command probe each enabled pack's primary host (`HEAD https://js.stripe.com/v3/`, etc.) and confirm it's reachable from the server? Useful sanity check before enabling, especially for vPOS hosts that some upstream networks block.
- **"Suggest packs" tool.** Given a vhost, fetch the homepage + a sample checkout page from the proxy host itself, parse `<script src>`, `<iframe src>`, `<link href>`, `<form action>`, and propose matching packs. v2 feature, but worth designing the pack catalog now with this in mind (every pack should declare a `signature_hosts` list used for detection).
- **Per-pack `report-uri` override.** Does a customer ever want different report endpoints per integration? Probably no — keep one report-uri at the bundle level.
- **Packs for non-CSP headers.** Same composition pattern could apply to `Permissions-Policy` (e.g. "allow geolocation for Google Maps pack"). Out of v1 scope but the table shape should accommodate `directive_family: 'csp' | 'permissions-policy'` from day one to avoid a v2 migration.
- **Auto-suggest from observed traffic.** Picked up properly in §17 — every pack declares a `signature_hosts: [...]` list so the probe/suggest engine can map observed external hostnames back to packs.

---

## 17. Policy probing & auto-suggest

> **Note:** purely design-phase exploration. This section is captured to clarify what *would* be needed if/when CFM grows a "tell me what packs this site needs" feature. It is not part of the v1 commitment in §13.

### 17a. Why this exists

Picking packs by hand is fine when the operator knows the site. For:
- migrated customers whose site config the operator has never seen,
- WordPress sites with 30+ plugins each pulling its own CDN,
- legacy shops where nobody remembers what's wired up,

…it's a guessing game, and a wrong guess means either a broken site (over-strict CSP) or a useless CSP (everything permitted). Since CFM sits transparently in front of all of these, it can **observe what the site actually loads** for 24–48 hours and propose the matching packs.

This is the §16h "suggest packs" open question, designed out.

The operator workflow is:

```
$ cfm policy probe shop.example.gr --hours 48
[ok] probe started for shop.example.gr
     mode:      passive + csp-report-only
     started:   2026-05-25T14:00:00Z
     expires:   2026-05-27T14:00:00Z
     token:     b3f1a9c2  (CSP report path: /__cfm_csp_report/b3f1a9c2)

# … 48h later, or any time during the window …

$ cfm policy probe-status shop.example.gr
     observations: 1,847 requests sampled, 142 CSP reports received
     unique hosts seen: 27
     known packs matched: 9
     unmatched hosts:    3

$ cfm policy probe-suggest shop.example.gr
Suggested packs (would set csp-report-only):
  csp-pack-google-fonts          ← seen: fonts.googleapis.com, fonts.gstatic.com
  csp-pack-google-analytics      ← seen: googletagmanager.com, www.google-analytics.com
  csp-pack-recaptcha             ← seen: www.google.com/recaptcha, gstatic.com
  csp-pack-gr-vpos-cardlink      ← seen (form-action!): ecommerce.cardlink.gr
  csp-pack-stripe                ← seen: js.stripe.com, api.stripe.com (connect-src)
  csp-pack-gr-skroutz            ← seen: analytics.skroutz.gr
  csp-pack-gr-shipping-boxnow    ← seen: locker-map.boxnow.gr
  csp-pack-cookiebot             ← seen: consent.cookiebot.com
  csp-pack-youtube               ← seen (frame-src): www.youtube.com

Unmatched hosts (not in pack catalog — operator review):
  cdn.shop-internal.example.gr   ← seen 1,247x as script-src
  static.partner-tool.io         ← seen 14x as script-src
  s3.eu-central-1.amazonaws.com  ← seen 89x as img-src

To apply:
  $ cfm policy apply csp-bundle-suggested shop.example.gr   # auto-built from above
```

### 17b. Two probe modes — passive body scan + CSP report-only

Both run concurrently when a probe is active. They are complementary:

| | Passive body scan | CSP report-only |
|---|---|---|
| What it sees | External hosts in HTML/CSS sources (`<script src>`, `<link href>`, `<iframe src>`, `<form action>`, `@import`) | Anything the browser actually blocked / would have blocked |
| Catches dynamic JS loads? | No | **Yes** — `fetch()`, dynamic `<script>` injection, `import()` |
| Catches `<form action>` for vPOS? | **Yes** — directly | Yes, via `form-action` violation |
| Cost | Per-response, sampled, ~tens of µs | Per-violation report, ingress only |
| Privacy surface | Reads response body | Receives client-reported URLs (subject to browser sanitisation) |
| Coverage of low-traffic vhosts | Slow (need traffic) | Slow (need traffic) |

**Run both** — single observations table feeds the same suggestion engine.

### 17c. CLI surface

```
cfm policy probe <vhost> [--hours N=24] [--mode passive|csp-ro|both=both] [--sample 1/N=100]
cfm policy probe-status <vhost>
cfm policy probe-suggest <vhost> [--accept-unmatched]
cfm policy probe-stop <vhost>
cfm policy probe-clear <vhost>           # discard observations
cfm policy probe-list                    # all active probes
```

`probe-suggest --accept-unmatched` writes the unmatched hostnames into a per-vhost `csp-custom-additions` override so the operator can ship "everything observed" without manual edits — useful for one-off legacy sites where the operator just wants something working.

### 17d. Data model

Two new tables, both auto-trim by `expires_at`.

#### `policy_probes`

| column | type | notes |
|---|---|---|
| `vhost` | TEXT PK | |
| `token` | TEXT | random 8-char hex, used in CSP `report-uri` path |
| `mode` | TEXT | `passive` \| `csp-ro` \| `both` |
| `sample_rate` | INTEGER | 1-in-N for body scanner |
| `started_at` | INTEGER | unix epoch |
| `expires_at` | INTEGER | unix epoch — workers stop collecting at this point |
| `status` | TEXT | `active` \| `expired` \| `stopped` |
| `csp_template_was` | TEXT | nullable — captures the policy that was active before probe started, so we can restore |

#### `policy_observations`

Aggregated, never per-request. Keyed `(vhost, host, directive)` to bound table size.

| column | type | notes |
|---|---|---|
| `vhost` | TEXT | |
| `host` | TEXT | observed external hostname (no path, no query) |
| `directive` | TEXT | `script-src` \| `style-src` \| `img-src` \| `font-src` \| `connect-src` \| `frame-src` \| `form-action` \| `media-src` |
| `source` | TEXT | `body-scan` \| `csp-report` |
| `count` | INTEGER | bumped per observation |
| `first_seen` | INTEGER | unix epoch |
| `last_seen` | INTEGER | unix epoch |

PK: `(vhost, host, directive)`. A single `UPSERT ... ON CONFLICT(...) DO UPDATE SET count = count+1, last_seen = ?` per observation.

Bound: cap at ~10k rows per vhost; if exceeded, drop low-count entries.

### 17e. CSP report receiver

A new endpoint mounted in the proxy:

```nginx
location ~ ^/__cfm_csp_report/([a-f0-9]{8})$ {
    access_by_lua_block { return; }            # bypass WAF/clearance/etc.
    content_by_lua_block {
        require("cfm_policies_probe").ingest_csp_report(ngx.var[1])
    }
}
```

**Implementation notes:**

- Accepts both `Content-Type: application/csp-report` (legacy) and `application/reports+json` (Reporting API). Body parse must tolerate both.
- **Rate limits per token**: 100 req/s, 8 KB body max. Excess silently dropped — one bad page can flood the receiver with thousands of identical reports.
- **Aggregate at ingest, not at query.** Extract `blocked-uri`, parse its host, find the directive, `UPSERT` into `policy_observations`. Don't store the raw report.
- **Noise filters** (drop without recording):
  - `blocked-uri` schemes `chrome-extension://`, `moz-extension://`, `safari-extension://`, `ms-browser-extension://` — browser extensions injecting scripts. **This is by far the biggest source of CSP report noise; without this filter the dashboard is unusable.**
  - `blocked-uri` values `inline`, `eval`, `data` (these tell you about `'unsafe-inline'`/`'unsafe-eval'` needs but don't map to packs — record under a separate counter, surface in suggest output as "site uses inline scripts/eval — pick a `*-typical` bundle").
  - `blocked-uri` of `about`, `null`, empty — meaningless.
  - User-agent regex for in-app browsers / Translate proxies if it becomes a problem.
- **Token validation**: token must exist in `policy_probes` with `status='active'` and `expires_at > now`. Otherwise 410 Gone.

### 17f. Body scanner

A `body_filter_by_lua_block` on the proxy `location /`, gated by:

1. `policy_probes[vhost].status == 'active'` (per-worker cached).
2. `ngx.header["Content-Type"]` starts with `text/html` or `text/css`.
3. `math.random(sample_rate) == 1` (1-in-N sampling — default 1-in-100).
4. Response size < 256 KB (don't buffer huge pages — most CDN-listing happens in the `<head>`).

**Extraction** uses cheap pattern matches, not a real HTML parser:

```lua
-- script src
for url in body:gmatch('<script[^>]+src=["\']([^"\']+)["\']') do ... end
-- iframe src
for url in body:gmatch('<iframe[^>]+src=["\']([^"\']+)["\']') do ... end
-- link href
for url in body:gmatch('<link[^>]+href=["\']([^"\']+)["\']') do ... end
-- form action (vPOS!)
for url in body:gmatch('<form[^>]+action=["\']([^"\']+)["\']') do ... end
-- img src
for url in body:gmatch('<img[^>]+src=["\']([^"\']+)["\']') do ... end
-- CSS @import
for url in body:gmatch('@import[^;]+["\']([^"\']+)["\']') do ... end
```

For each match: parse `host`, skip if same as vhost (`'self'`), skip if scheme is `data:` / `blob:` / `javascript:`, dedupe via per-worker LRU keyed `(vhost, host, directive)`. Insert via batched UPSERT every N seconds, not per-request.

**Per-response cost target:** ~10 µs in the steady-state cache-hit path (LRU says "already recorded"), ~100 µs on cold miss.

**Limitations to document:** body scanner sees only what's in the initial HTML/CSS. It will not see:
- Scripts loaded by other scripts (need CSP-RO)
- Resources behind login (sampled traffic might not include logged-in pages)
- Resources fetched via `fetch()` / `XHR` (need CSP-RO via `connect-src` violations)

That's why both modes run together.

### 17g. Suggestion engine

Pack catalog gains a per-pack `signature_hosts` field:

```yaml
csp-pack-stripe:
  signature_hosts:
    - js.stripe.com
    - api.stripe.com
    - "*.stripe.com"
  directives:
    script-src:  ["https://js.stripe.com", "https://*.stripe.com"]
    frame-src:   ["https://js.stripe.com", "https://hooks.stripe.com", "https://*.stripe.com"]
    connect-src: ["https://api.stripe.com", "https://*.stripe.com"]
```

`probe-suggest` algorithm:

1. Read all rows from `policy_observations` for the vhost.
2. For each unique observed host: look up matching packs via `signature_hosts` (suffix/wildcard match).
3. For each matched pack: count the directives it covers vs. directives the host was observed under. Score = (directives matched) / (directives observed).
4. Emit a ranked list. Default threshold: include pack if it covers ≥1 observed directive for its host.
5. Unmatched hosts: report separately with their observed directive + count.
6. Detect inline/eval needs: if `inline`/`eval` counters > N, recommend a `*-typical` bundle (the WP/WHMCS-flavored ones that permit `'unsafe-inline' 'unsafe-eval'`).

Output is human-readable (the CLI example in §17a) and machine-readable (`--json` flag) so cfm-admin can render it as a checklist.

### 17h. Privacy & performance bounds

Body scanning means CFM is now reading response bodies on a vhost-by-vhost opt-in basis. Defensive defaults:

- **Opt-in per vhost.** No global "scan everything" mode. The operator runs `cfm policy probe <vhost>` for each vhost they want analysed.
- **Time-boxed.** Probes auto-expire at `expires_at`. No accumulation past 48h by default. CLI hard-caps at `--hours 168` (one week).
- **No content captured.** Only external host names are stored. Never paths, never query strings, never response bodies. Audit-log the fact that scanning is active but not what was scanned.
- **No request bodies.** Only response bodies. POST payloads from the client are never read.
- **No logged-in detection magic.** Don't try to be clever about "scan logged-in pages too" — just sample.
- **Sample rate bounded.** Default 1-in-100. Below 1-in-10 requires `--unsafe-high-sampling` flag (rate-limit on operator slowdown more than privacy).
- **CSP report receiver rate-limited** per §17e.

Performance bounds:

- Body scan adds ~10 µs P99 on sampled responses (cache-hit), ~100 µs on cold miss. Sampled at 1%, so amortised ~0.1–1 µs per response.
- CSP report ingest is off the proxy hot path (separate location). Capped at 100 req/s/token.
- `policy_observations` capped per vhost (see §17d).

### 17i. Open questions for probing

- **Persistent vs. session probes.** Should the operator's "auto-suggest" survive across CFM restarts and pack-catalog updates? Probably yes — observations are valuable data, don't lose them. But document the staleness risk (a host seen 60 days ago may no longer be live).
- **Re-probe diff.** When the operator re-runs `probe` on a vhost that already has a policy applied, should the suggestion show only *new* hosts (those not covered by the current policy)? This is the natural maintenance loop — apply, leave it on, re-probe periodically to catch drift.
- **Cross-vhost rollup.** "Show me which packs are most-applied across all my probed vhosts" — useful for operators with hundreds of customers, lets them spot the long tail (e.g. "5 customers are using a payment processor we don't have a pack for, time to write one").
- **Active probe vs. live policy.** While a probe is active, do we also enforce the current policy (if any)? Default: yes, current policy still enforces; probe-RO is added on top in report-only mode. Operator can override with `--detach-policy` to probe a blank slate.
- **Headless-browser warm-up.** Optional `--warm-up` flag fires a headless Chromium against a few canonical paths (`/`, `/checkout`, `/wp-admin` if accessible) to bootstrap observations without waiting for organic traffic. Adds a chromium dependency; defer until v2 of probing.
- **Signature drift.** When a vendor adds a new CDN host (e.g. Facebook starts using `fbcdn-static.net` alongside `fbcdn.net`), suggest output flags it as "unmatched" until the pack catalog is updated. Worth a dashboard view: "unmatched hosts seen across multiple vhosts — candidates for new packs or pack-host additions".

---

## 18. Permissions-Policy packs

> Design-phase. Same composition pattern as §16, applied to the `Permissions-Policy` header (formerly `Feature-Policy`). Foreshadowed in §16h ("Packs for non-CSP headers").

### 18a. Why Permissions-Policy

`Permissions-Policy` controls browser feature gating: which features (camera, microphone, geolocation, payment, fullscreen, autoplay, clipboard, USB, MIDI, etc.) the page and its iframes are allowed to use. Two reasons it matters:

1. **Audit checkbox.** Modern security scanners (Mozilla Observatory, securityheaders.com, PCI tooling) check for its presence and complain if absent or too permissive (`*`).
2. **Real defence.** A locked-down `Permissions-Policy` blocks a compromised third-party iframe from silently requesting camera/microphone/geolocation. CSP doesn't cover this — different header, different attack surface.

The default browser behaviour is *not* "deny everything" — it's mostly "allow same-origin". So the policy matters even on sites that "don't use" these features.

### 18b. Syntax and composition model

Syntax differs from CSP. Per-feature allowlist with explicit `()` form:

```
Permissions-Policy: camera=(), microphone=(), geolocation=(self "https://maps.example.com"),
                    payment=(self), fullscreen=(self), autoplay=(self "https://*.youtube.com")
```

Each feature gets one allowlist:
- `()` — deny entirely (no origin can use this feature, including the page itself)
- `(self)` — allow same-origin only
- `(self "https://x.com")` — same-origin + named third parties
- `(*)` — allow everywhere (avoid)

**Composition shape** mirrors §16a:

Each `pp-pack-*` contributes feature entries like:
```yaml
pp-pack-google-maps:
  features:
    geolocation: ["self", "https://maps.googleapis.com"]
```

At apply time, `cfm_policies.lua` per-feature-merges every enabled pack, deduplicates, and emits a single `Permissions-Policy` header. Features not mentioned by any pack inherit from the **baseline** (default deny — see §18c).

Storage: same `policy_csp_packs` table with `directive_family='permissions-policy'` column (the foresight from §16h).

UI: the cfm-admin "Security Headers" tab gains a second sub-section "Permissions" with the same checkbox UX as CSP packs.

### 18c. Baseline & built-in packs

#### Baseline templates

**`pp-template-baseline-strict`** — denies everything except the bare minimum same-origin features. Recommended default for almost all sites.

```
accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(),
camera=(), clipboard-read=(), clipboard-write=(self), display-capture=(),
document-domain=(), encrypted-media=(), execution-while-not-rendered=(),
execution-while-out-of-viewport=(), fullscreen=(self), gamepad=(),
geolocation=(), gyroscope=(), hid=(), idle-detection=(),
keyboard-map=(), local-fonts=(), magnetometer=(), microphone=(),
midi=(), navigation-override=(), payment=(), picture-in-picture=(),
publickey-credentials-get=(), screen-wake-lock=(), serial=(),
speaker-selection=(), storage-access=(), usb=(), web-share=(),
window-management=(), xr-spatial-tracking=()
```

**`pp-template-baseline-permissive`** — allows `self` for features a generic CMS might need (fullscreen, clipboard-write, autoplay for embedded media). Compromise for WordPress-flavoured sites.

#### Feature-enabling packs (additive)

**`pp-pack-payments`** *(any payment processor — Stripe, PayPal, Apple Pay, Google Pay)*
```yaml
features:
  payment:                     [self]
  publickey-credentials-get:   [self]  # WebAuthn / passkeys, used by 3DS2
```

**`pp-pack-google-maps`**
```yaml
features:
  geolocation: [self, "https://*.googleapis.com"]
```

**`pp-pack-mapbox`**
```yaml
features:
  geolocation: [self]
```

**`pp-pack-video-embed`** *(YouTube/Vimeo/Spotify embeds)*
```yaml
features:
  fullscreen:           [self, "https://*.youtube.com", "https://*.vimeo.com", "https://open.spotify.com"]
  autoplay:             [self, "https://*.youtube.com", "https://*.vimeo.com"]
  encrypted-media:      [self, "https://*.youtube.com", "https://*.vimeo.com"]
  picture-in-picture:   [self, "https://*.youtube.com", "https://*.vimeo.com"]
```

**`pp-pack-video-conferencing`** *(in-app calls, support widgets with video)*
```yaml
features:
  camera:          [self]
  microphone:      [self]
  display-capture: [self]
  speaker-selection: [self]
```

**`pp-pack-clipboard-rw`** *(sites with "copy code" buttons, share helpers)*
```yaml
features:
  clipboard-read:  [self]
  clipboard-write: [self]
```

**`pp-pack-webauthn`** *(passkey/security-key login)*
```yaml
features:
  publickey-credentials-get:    [self]
  publickey-credentials-create: [self]
```

**`pp-pack-pwa-install-prompts`**
```yaml
features:
  web-share:        [self]
  screen-wake-lock: [self]
```

**`pp-pack-recaptcha-pp`** *(reCAPTCHA needs ambient-light/gyro/accel access on some platforms — well-documented Google requirement)*
```yaml
features:
  accelerometer: [self, "https://www.google.com"]
  gyroscope:     [self, "https://www.google.com"]
  magnetometer:  [self, "https://www.google.com"]
```

**`pp-pack-google-signin-pp`** *(Google Identity Services needs FedCM for newer flows)*
```yaml
features:
  identity-credentials-get: [self, "https://accounts.google.com"]
```

> **Note on naming:** `pp-pack-*` not `csp-pack-*`. They're distinct namespaces so an operator (or the suggest engine) can enable a CSP pack without also enabling a Permissions-Policy pack of the same name. Where the two overlap conceptually (e.g. Stripe needs `csp-pack-stripe` *and* `pp-pack-payments`), the bundles in §18d enable both together.

### 18d. Bundled Permissions-Policy templates

#### `pp-bundle-strict-with-payments`

Baseline strict + payment + WebAuthn. Recommended for any e-commerce site that doesn't embed video.

```
base:           pp-template-baseline-strict
enabled_packs:
  - pp-pack-payments
  - pp-pack-webauthn
```

#### `pp-bundle-ecommerce-typical`

What the Greek e-commerce bundle in §16f needs on the Permissions-Policy side.

```
base:           pp-template-baseline-strict
enabled_packs:
  - pp-pack-payments
  - pp-pack-webauthn
  - pp-pack-google-maps
  - pp-pack-recaptcha-pp
  - pp-pack-clipboard-rw
  - pp-pack-video-embed       # for product video tours
```

#### `pp-bundle-wp-typical`

Baseline permissive + extras most WP sites need.

```
base:           pp-template-baseline-permissive
enabled_packs:
  - pp-pack-video-embed
  - pp-pack-clipboard-rw
  - pp-pack-pwa-install-prompts
```

#### `pp-bundle-content-only-locked-down`

Maximum lockdown for static/content sites. Nothing extra enabled.

```
base:           pp-template-baseline-strict
enabled_packs: []
```

### 18e. Cross-Origin policies (COOP, COEP, CORP)

The three Cross-Origin-* headers fit the same pack/bundle shape but **must be deferred to v2** because they break embeds in subtle ways.

- `Cross-Origin-Opener-Policy: same-origin` — protects against `window.opener` cross-origin attacks. Breaks popup-based OAuth (Stripe checkout popup, PayPal popup, Google Sign-In popup) → must use `same-origin-allow-popups` or omit.
- `Cross-Origin-Embedder-Policy: require-corp` — required for `SharedArrayBuffer` (only relevant if the site uses high-perf wasm). Breaks every iframe/image that doesn't send `CORP` headers — most third-party content.
- `Cross-Origin-Resource-Policy: same-origin` — only relevant on assets the site itself emits. Not a per-vhost browser-side gate.

CFM should ship `coop-coep-corp` packs **off by default**, with very loud UI warnings:

- `pp-pack-coop-popup-friendly` — `Cross-Origin-Opener-Policy: same-origin-allow-popups` (the only safe COOP value for any site doing third-party auth/payments)
- `pp-pack-coep-credentialless` — `Cross-Origin-Embedder-Policy: credentialless` (less breakage than `require-corp` but still risky)

Both deferred to v2-of-v2. Document existence so operators asking "where's my COOP?" find the answer.

---

## 19. Reporting-Endpoints — the modern reporting API

> Design-phase. Replaces the `report-uri` design in §17e with the modern `Reporting-Endpoints` header + `report-to` directive (Reporting API). CFM ships both for browser-compat.

### 19a. Why this replaces `report-uri`

`report-uri` (used in §17e) is **deprecated** in the CSP spec. It has been gradually superseded by the Reporting API since ~2019, and modern browsers ship a unified path:

```
Reporting-Endpoints: csp-endpoint="https://example.com/__cfm_reports/abc123",
                     default="https://example.com/__cfm_reports/abc123"

Content-Security-Policy-Report-Only: default-src 'self'; report-to csp-endpoint
```

Advantages over `report-uri`:
- One receiver for **all** report types — CSP, COEP, COOP, Document-Policy, deprecation, intervention, NEL, crash. No need to write five endpoints.
- Reports are **batched** by the browser (`application/reports+json` is an array, not a single report). Lower request volume.
- Includes report metadata (`age` ms, `type`, `url`, `user_agent`) that `report-uri` doesn't carry.
- Browsers retry delivery on transient failures.

### 19b. Dual-shipping strategy

Real-world CSP deployments **send both** during the transition years, because:
- Safari has been laggy on Reporting API adoption (some versions ignore `report-to`).
- A meaningful share of in-the-wild Chromiums (in-app browsers, embedded WebViews) still favour `report-uri`.
- Coverage matters when probing — you don't want to miss the iOS Safari users.

CFM emits both directives when a probe is active or a vhost has `report-to` configured:

```
Reporting-Endpoints: csp-endpoint="https://shop.example.gr/__cfm_reports/abc123"

Content-Security-Policy-Report-Only:
  default-src 'self';
  ... pack contributions ...;
  report-uri /__cfm_reports/abc123;
  report-to  csp-endpoint
```

The path is the **same** for both — the receiver in §19c handles both request shapes.

### 19c. Generalised receiver `/__cfm_reports/<token>`

Generalisation of §17e. Same nginx location, same token-validates-against-`policy_probes` rule, but parses both ingest formats:

| `Content-Type` | Body shape | Source |
|---|---|---|
| `application/csp-report` | `{"csp-report": {...}}` (one report) | legacy `report-uri` |
| `application/reports+json` | `[{...}, {...}, ...]` (array of reports, may mix types) | modern `report-to` |

**Parser dispatch (Lua sketch):**

```lua
local ct = ngx.req.get_headers()["content-type"] or ""
local body = ngx.req.get_body_data()
if ct:find("application/reports+json") then
    -- modern: array of {type, age, url, user_agent, body}
    local reports = cjson.decode(body)
    for _, r in ipairs(reports) do dispatch_by_type(r.type, r) end
elseif ct:find("application/csp-report") then
    -- legacy: single CSP report
    local r = cjson.decode(body)
    dispatch_csp(r["csp-report"])
end
```

`dispatch_by_type` routes:
- `csp-violation` → existing §17e CSP logic
- `coep`, `coop` → §18e violation logging (no aggregation yet, just count)
- `network-error` → §20 NEL ingestion
- `deprecation`, `intervention`, `crash` → log + count, surface in UI ("your site uses N deprecated APIs across M reports last 7d")

### 19d. Report types CFM ingests

Single receiver, multiple aggregation tables (or a single `report_observations` with a `type` column). Recommended split because the keying is different:

| Report type | Aggregation key | Purpose |
|---|---|---|
| `csp-violation` | `(vhost, host, directive)` | suggest engine (§17g) |
| `coep`, `coop` | `(vhost, blocked-url, type)` | "what cross-origin embeds are you blocking?" |
| `deprecation` | `(vhost, feature-id)` | "this site uses N deprecated browser APIs" |
| `intervention` | `(vhost, feature-id, reason)` | browser-applied interventions (e.g. slow-iframe-throttle) |
| `network-error` | per §20 | DNS/TCP/TLS/HTTP errors clients hit |
| `crash` | `(vhost, reason)` | very rare; renderer crashes |

All inherit the per-vhost rate limit and noise-filter logic from §17e.

---

## 20. Network Error Logging (NEL)

> Design-phase. Adjacent to CSP/Reporting — different goal: tell the operator when *clients* can't reach the site.

NEL is a client-side reporting mechanism: when a browser fails to fetch a resource (DNS failure, TCP RST, TLS handshake error, HTTP 5xx, abandoned navigation), it queues a network-error report and POSTs it to the configured Reporting endpoint when it next can. The operator gets observability into failures that **never reached** the server logs.

**Header shape:**

```
NEL: {"report_to":"default","max_age":2592000,"include_subdomains":false,
       "success_fraction":0.001,"failure_fraction":1.0}
```

Reads as: send 100% of failure reports and 0.1% of successes (for baseline calibration) to the `default` endpoint named in `Reporting-Endpoints`, with a 30-day client-side memory.

**CFM template:**

`nel-template-default`:
```
max_age:          2592000      # 30d
include_subdomains: false
success_fraction: 0.0001       # 0.01% — keep volume sane
failure_fraction: 1.0
```

Aggregated into `network_error_observations(vhost, error_type, host, count, last_seen)` where `error_type` is one of NEL's enum (`dns.unreachable`, `tcp.refused`, `tls.protocol.error`, `http.error`, etc.). Surfaced in the cfm-admin "Security Headers" tab as a small panel: "Last 7d client-side failures".

**Why it matters in CFM's context:**
- The operator gets early warning of upstream cert problems before customers complain.
- Geographic outages become visible ("0.4% of EU clients are TLS-failing — your cert chain may be broken on some path").
- DNS issues at the *client's* resolver show up here.

**Scope note:** ship as an opt-in template, not a default. Volume from a busy site can be non-trivial; rate-limit aggressively on the receiver (same path/token as §19).

---

## 21. Rollout playbook for operators

> Operational guide — the recommended way to migrate a real customer site without breaking it. This belongs in the doc because the technology is only half the story; getting the rollout sequence wrong is the most common cause of CSP/HSTS regret.

### 21a. CSP migration timeline (RO → enforce, ~4 weeks)

A safe rollout is gradual. Each step has a "this should be true before moving on" gate.

**Day 0 — Baseline-safe.**
```
$ cfm policy apply baseline-safe shop.example.gr
$ cfm policy test shop.example.gr     # verify X-Content-Type-Options, Referrer-Policy, X-Frame-Options visible
```
Zero risk. If anything breaks, it wasn't this.

**Days 0–2 — Start CSP probe.**
```
$ cfm policy probe shop.example.gr --hours 48
```
Probe runs both modes (§17b). Browser CSP-RO sends violations; passive scan extracts static resources.

**Day 2 — Review and apply suggested packs in report-only.**
```
$ cfm policy probe-suggest shop.example.gr
[suggestion list as in §17a]

$ cfm policy apply csp-bundle-suggested shop.example.gr --report-only
```
At this point the site is in **CSP-report-only** mode. Browsers report violations but don't block. The operator's job for the next 2 weeks: watch the receiver, fix unmatched hosts.

**Days 2–14 — Soak period.**
- Re-run `probe-status` every couple of days.
- Look for new unmatched hosts. Add to overrides or wait for organic pack updates.
- Visit edge flows manually (checkout, account page, password reset) — these may load resources not seen in normal traffic.
- Have the customer place at least one test order using each enabled payment method (this is where `form-action` violations show up for vPOS!).

**Gate to move forward:** zero unmatched non-extension hosts for 7 consecutive days. If a real new host appears, restart the gate clock.

**Day 14+ — Switch to enforce.**
```
$ cfm policy apply csp-bundle-suggested shop.example.gr --enforce
```
Same effective directives, but now CSP blocks instead of reporting. Tell the customer: "watch the site for 24h; ping us if anything looks off."

**Day 14+ — Watch first 24h.**
Keep the report endpoint live (`report-to` still sends violations even in enforce mode for the directives that violate). Aggregated violations in the first 24h tell you what you missed.

**Ongoing — periodic re-probe.**
Every 90 days: `cfm policy probe --hours 24` again. If the site added a new integration, you'll see it in the diff. The §17i "re-probe diff" feature surfaces *only the new* hosts so the operator isn't re-reviewing the whole list.

### 21b. HSTS rollout (4-step ramp)

HSTS is one-way (§10). Never auto-upgrade.

| Day | Action | What it means |
|---|---|---|
| 0 | `cfm policy apply hsts-ramp-5m shop.example.gr` | Browser remembers HTTPS for 5 minutes. Mistakes are reversible. |
| 1 | Verify HTTPS works on every entry-point. Then `cfm policy apply hsts-ramp-1d`. | 1-day commitment. Still recoverable in worst case. |
| 8 | `cfm policy apply hsts-ramp-1y` | 1-year commitment. Browsers will refuse HTTP for a year. **Do not do this if any subdomain still serves HTTP only.** |
| 38+ | `cfm policy apply hsts-ramp-preload` (optional) | Bake into the HSTS preload list. **Permanent.** Operator must also submit to https://hstspreload.org/. |

The CLI must require typing the vhost name to confirm for `hsts-ramp-1y` and `hsts-ramp-preload`. The cfm-admin UI shows the current effective `max-age` and date the policy was applied, so the operator can see "we've been at 1d for 30 days, safe to go to 1y."

### 21c. CORS rollout

CORS is the most ticket-prone of the headers because it interacts with browser caching and credentials.

**Step 1: enumerate current origins.**
If the operator has a logs source for `Origin:` headers on the vhost, dump distinct values:

```
$ awk '/^Origin:/ {print $2}' /var/log/cfm/access.log | sort -u
https://app.example.gr
https://admin.example.gr
https://mobile-app.example.gr
```

If no logs are available, ask the customer for the list of allowed origins.

**Step 2: configure allowlist.**
```
$ cfm policy apply cors-allowlist shop.example.gr \
    --origins https://app.example.gr,https://admin.example.gr,https://mobile-app.example.gr \
    --methods GET,POST,PUT,DELETE \
    --credentials true \
    --max-age 600
```

**Step 3: verify preflight.**
```
$ curl -X OPTIONS -H "Origin: https://app.example.gr" \
       -H "Access-Control-Request-Method: POST" \
       -H "Access-Control-Request-Headers: content-type,authorization" \
       -i https://shop.example.gr/api/whatever
```
Expect 204 with `Access-Control-Allow-Origin`, `-Methods`, `-Headers`, `-Max-Age`, `Vary: Origin`. Verify a *non-allowlisted* origin produces no CORS headers (browser would block).

**Step 4: roll out to one path first.**
If the schema supports per-path (v2), enable CORS on `/api/*` only initially. v1 = whole vhost, so the rollout is binary — verify with a real client app before flipping.

### 21d. Rollback procedure

For all policy types, the rollback is `cfm policy clear <vhost>`. It removes the row from `vhost_policies`, the cache invalidates within 5s (§14h), and CFM stops emitting CFM-managed headers on that vhost — origin's headers (if any) pass through untouched.

**Exception: HSTS is not rolled back.** Browsers remember the previous `max-age`. To genuinely undo:

1. `cfm policy clear` removes CFM's HSTS header.
2. To accelerate browser forgetting, the operator can apply `hsts-ramp-5m` (which actively sends `max-age=300`, overwriting the browser memory with a short TTL).
3. After 5 minutes, `cfm policy clear` again.

This is the only safe HSTS rollback. Document loudly.

---

## 22. Metrics & observability

> Design-phase. What counters and dashboards the policy subsystem exposes via existing `cfm_stats`/Prometheus paths.

### 22a. Per-vhost counters

All counters are labelled `vhost=<host>`. Cardinality bounded by the number of vhosts × number of header types.

```
cfm_policies_header_set_total{vhost, header, mode}
    # incremented in header_filter_by_lua for each header CFM emits.
    # mode = add_if_missing | replace | append | strip
cfm_policies_header_kept_origin_total{vhost, header}
    # incremented when add_if_missing skipped because origin already sent the header.
cfm_policies_preflight_total{vhost, result}
    # result = match | miss | error
cfm_policies_preflight_duration_seconds{vhost} (histogram)
cfm_policies_apply_duration_seconds{vhost}    (histogram)
    # cost of the header_filter step per response
cfm_policies_cache_total{vhost, result}
    # result = hit | miss | reload (LRU per worker)
cfm_policies_csp_reports_total{vhost, type, source}
    # type = csp-violation | coep | coop | deprecation | network-error | ...
    # source = report-uri | report-to
cfm_policies_csp_reports_dropped_total{vhost, reason}
    # reason = rate-limit | extension-noise | invalid-token | body-too-large | malformed
cfm_policies_observations_recorded_total{vhost, source}
    # source = body-scan | csp-report
cfm_policies_observations_skipped_total{vhost, reason}
    # reason = lru-hit | wrong-content-type | sampled-out | size-cap
```

### 22b. Global counters

```
cfm_policies_probes_active                  (gauge)
cfm_policies_probes_expired_total           (counter)
cfm_policies_templates_loaded               (gauge)
cfm_policies_packs_loaded{family}           (gauge, family=csp|permissions-policy|cross-origin)
cfm_policies_db_writes_total{table}         (counter)
cfm_policies_db_write_errors_total{table}   (counter)
```

### 22c. Dashboard & alerts

**cfm-admin "Security Headers" tab gains a metrics sub-panel per vhost showing:**

- Last 24h: headers set, reports received, observations recorded.
- Top 5 unmatched hosts seen this week (link to suggest engine).
- Apply-duration p99 (alert if > 1ms — something is wrong with the cache).
- Preflight match rate (low = misconfigured allowlist).

**Recommended alerts** (operator-configurable; opt-in):

- **`policies-apply-duration-high`** — apply step taking > 1ms p99 for > 5 min. Indicates cache thrash or pack-catalog corruption.
- **`policies-csp-reports-flood`** — single vhost receiving > 1000 reports/min for > 5 min. Either an attacker probing or a bad pack causing legitimate violations.
- **`policies-cors-preflight-miss-spike`** — preflight miss rate > 50% for > 10 min. Likely a frontend deploy with a new origin that wasn't added to the allowlist.
- **`policies-nel-failure-spike`** — NEL failure-report rate suddenly tripled. Possible cert / DNS / network issue.

**What we explicitly don't do:**
- No per-report exporting to external sinks (Splunk, Loki, etc.) in v1 — bounded counters only. Heavy log forwarding is its own feature.
- No real-time stream of CSP violations. Aggregated only. Operator who needs raw stream points `report-to` at their own collector.
