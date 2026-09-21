# Site Cache (per-vhost edge caching) — design & plan of record

Status: **Proposal / design.** Nothing built yet. This is the ONE design doc for
per-vhost edge caching in CFM; we follow it. Scope: the edge configs
(`configs/openresty.conf`, `configs/angie.conf`), a new decision module in
`configs/lua/`, a new per-vhost store + API + CLI in `internal/webdetector`, a
new `/cfm-admin` page under `internal/webui/static/`, and the daemon↔edge
bridge in `internal/webdetector/nginx_bridge.go`.

The feature lets an operator (and a scoped cPanel user, for their own domains)
turn caching **on per vhost** — static-asset cache and/or short micro-cache of
HTML — pick a **recipe** (lean → aggressive) or a custom TTL, **purge** (global
or per-vhost), and see per-vhost state in cfm-admin (filter/sort) and via the
CLI (`cfm webtop site-cache list`). Managed identically from three surfaces —
API, CLI, cfm-admin — exactly like WAF excludes / Challenge Access.

---

## 0. The governing principle (why this exists and how it stays safe)

CFM shipped **global, unconditional** caching once (hardwired in
`nginx.conf`/`angie.conf`). It broke customer pages, **redirects**, webmail,
cPanel and **SSO**, and had to be ripped out entirely. The remnants are still
in the tree (see §2).

Everything in this design is a reaction to that one failure mode. The
invariants, in priority order:

1. **Master default OFF.** The feature can be installed and cache *nothing*
   anywhere. `[webdetector] SITE_CACHE = 0` by default; `SITE_CACHE = 0` also
   removes all per-request edge cost (kill-switch mirrored to the edge like
   `FP_POLICY`).
2. **Opt-in per vhost, exact-host.** `myip.gr` and `www.myip.gr` are two
   explicit entries; there is **no** implicit `*.myip.gr`. Wildcards are an
   advanced opt-in, never a default.
3. **Bypass-by-default at the edge.** The Lua sets `$cfm_cache_skip = 1` (do
   not cache) at the start of every request and flips it to `0` **only** when
   every safety gate in §4 passes. A regression that drops the gate fails
   closed (no caching), never open.
4. **Caching lives *behind* enforcement.** WAF, Challenge, IP-block, traffic
   rules all run in the `access` phase; the cache is consulted in the upstream
   phase. **A cache HIT never bypasses WAF, a challenge, or an IP block** — the
   request still runs the full `cfm.lua` before any cached body is served.
5. **The safety rails (§4) are absolute.** They do not depend on the recipe,
   the TTL, or who armed the vhost. "Full power" (§9) means freedom over TTL
   and recipe — **never** freedom to disable a rail.

The key correctness argument that makes "full power" safe: **TTL controls
staleness, not who-sees-what.** Because we never cache a response that carries
`Set-Cookie`, never cache a request that carries an auth/session cookie, and
never cache redirects or panel traffic (§4), the worst outcome of an aggressive
TTL is *stale anonymous content* — which the operator opted into and can Purge
(§10). It can never serve user A's session to user B. So we can be generous
with TTL and recipes as long as the rails hold.

---

## 1. Non-goals

- **Not** a CDN / not multi-node cache sharing. Each node caches its own
  origin locally. (A future cross-node story is out of scope.)
- **Not** DNAT-mode caching in Phase 1. The teeth are in-path edge only
  (OpenResty/Angie), same as WAF/rules. DNAT clients hit origin directly.
- **Not** integration with the `ngm1` MCP `site_cache_*` tools — that is a
  separate product surface. Per decision, we ignore it and build CFM-native.
- **Not** arbitrary per-request TTL down to the second (nginx constraint, see
  §5.4) — we offer a rich, extensible **menu of TTL buckets** instead.

---

## 2. Leftover inventory (build-on vs delete vs leave-alone)

There is **no** prior cache *design doc* — this is the first. There is only
leftover **code** from the ripped-out global caching. Verdicts:

| Leftover | What it is | Verdict |
|---|---|---|
| `configs/lua/cfm_cache_log.lua` | Ready HIT/MISS/BYPASS/EXPIRED/STALE/… counter, `log_by_lua_block`-only, no I/O. **Orphaned** (not `require`d anywhere). | **Keep & wire** — this is our observability layer (§11). |
| `ngx.shared.cfm_cache_stats` | Read by `cfm_stats.lua:398-399`, **never declared** in `lua_shared_dict` → silent no-op. | **Declare it** (§11). |
| Commented "Future caching" recipe, `openresty.conf:841-849` + `:868` (angie `:828-834`) | A deliberate note left for exactly this work; sketches `proxy_cache_path` + per-vhost `set $cfm_static_cache`. | **Implement** as Tier A (§3, §5). |
| Cache dirs `/var/cache/nginx/cfm_static`, `/var/cache/nginx/cfm_micro` | Already created by the daemon (`cmd/cfm/main.go:628-629`). | **Use these canonical paths.** Note the stale conf comment says `/var/cache/cfm/static` — **fix the comment** in the same change. |
| `configs/lua/cfm_pcw.lua` | **NOT a cache remnant.** It is the live *post-clearance nav-cadence* shadow counter (B2 challenge-score, `docs/challenge-score-b2.md`), wired at `cfm.lua` Step 2b. | **Do not touch.** |
| `configs/lua/cfm_purge.lua` + `nginx_bridge_purge.go` | Existing purge plumbing (currently purge-ip). | **Extend** for cache purge (§10). |

---

## 3. Architecture at a glance

Two tiers, one management model.

```
                         ┌───────────────────────── EDGE (OpenResty/Angie) ─────────────────────────┐
  client ──HTTPS/QUIC──► │  server{}                                                                 │
                         │    set $cfm_cache_skip 1;  set $cfm_cache_zone "";  set $cfm_cache_ttl 0; │
                         │                                                                           │
                         │  ┌ static-asset location (css/js/img/…) ──────────┐                       │
                         │  │ minimal access_by_lua: cache-gate lookup only  │  TIER A: static cache │
                         │  │ proxy_cache $cfm_cache_zone;                    │  (cfm_static_*)       │
                         │  └────────────────────────────────────────────────┘                       │
                         │  ┌ catch-all location (/) ───────────────────────┐                        │
                         │  │ access_by_lua_file cfm.lua  (full enforcement) │  TIER B: micro-cache  │
                         │  │   Step 2b / Step 4 allow → cache-policy lookup │  of anonymous HTML    │
                         │  │ proxy_cache $cfm_cache_zone;                    │  (cfm_micro_*)        │
                         │  └────────────────────────────────────────────────┘                       │
                         │                    │ every N s: GET /nginx/cache/config (edge-pull)        │
                         └────────────────────┼──────────────────────────────────────────────────────┘
                                              ▼ unix socket, token-gated
                         ┌──────────────────── DAEMON (internal/webdetector) ───────────────────────┐
                         │  siteCacheStore  ←→  /var/lib/cfm/webdetector_site_cache.json             │
                         │  API /api/v1/site-cache/*   CLI cfm webtop site-cache   cfm-admin page    │
                         └──────────────────────────────────────────────────────────────────────────┘
```

- **Tier A — static asset cache** (low risk). Caches `css/js/woff/img/…` by
  extension, in the existing static-asset location that already skips the heavy
  `cfm.lua`. Safe because assets carry no `Set-Cookie` and are not per-user.
- **Tier B — micro-cache of HTML** (high risk — this is what broke before).
  Very short TTL, **anonymous traffic only**, hard gated (§4). Absorbs bursts
  on heavy pages (the `myip.gr` case).

A vhost may enable **Tier A, Tier B, or both** (per decision).

---

## 4. Safety rails — the never-cache table (absolute, layered)

Enforced on **every** request regardless of the vhost's recipe/TTL. Two layers:
request-time (Lua, `access` phase) and response-time (nginx-native + a thin
`header_filter`).

| Rail | Enforced where | Prevents |
|---|---|---|
| `GET`/`HEAD` only | `proxy_cache_methods` (default) | POST / logins cached |
| Status: micro `200` only; static `200` (opt. `301/404`) | status gate + `proxy_cache_valid` | **3xx redirect / SSO loop cached** |
| Response has `Set-Cookie` → never store | nginx default (we **never** add `Set-Cookie` to `proxy_ignore_headers`) | user A's session served to user B |
| Request has an **auth/session cookie** → `$cfm_cache_skip=1` | Lua, cookie-name allowlist: `PHPSESSID`, `wordpress_logged_in_*`, `wordpress_sec_*`, `cpsession`, `roundcube_sessid`, roundcube/webmail, panel sessions, … | **logged-in users get stale/foreign content** |
| Origin `Cache-Control: private\|no-store\|no-cache` → respect | nginx default (not ignored) | origin keeps the final say |
| Panel hosts/ports (`:2083/:2087/:2096`), webmail hosts, `/.well-known/`, `/acctxfer*`, cPanel/webmail bypass paths → never | Lua gate, sits **after** `cfm.lua` Step 0a1 | **cPanel / webmail / SSO / AutoSSL broken** |
| Cache key excludes cookies | `proxy_cache_key "$scheme$host$request_uri"` | per-user fragmentation / leakage |
| `cfm_clearance` is edge-set, not origin | see §5.5 open item | edge cookie poisoning the cache |

`cfm_clearance`-cookie holders (cleared visitors) are still *anonymous* to the
app, so they **may** be served micro-cache; the cache key never varies on the
clearance cookie, and the clearance cookie is refreshed per-response by the edge
(§5.5 flags the ordering item to verify in implementation).

---

## 5. Edge mechanics

### 5.1 Cache zones — declared once, inert until used

`proxy_cache_path` must live in `http{}`. Declaring a zone caches nothing; a
zone only bites when a location activates `proxy_cache` **and** the bypass gate
allows it. Declared identically in **both** confs, under
`/var/cache/nginx/cfm_*` (the paths the daemon already creates):

```nginx
# TTL buckets (see §5.4) — a small, admin-extensible menu, one zone per bucket.
proxy_cache_path /var/cache/nginx/cfm_static_1h  levels=1:2 keys_zone=cfm_static_1h:20m  max_size=5g  inactive=2h  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_static_7d  levels=1:2 keys_zone=cfm_static_7d:20m  max_size=10g inactive=8d  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_static_30d levels=1:2 keys_zone=cfm_static_30d:20m max_size=20g inactive=31d use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_1s   levels=1:2 keys_zone=cfm_micro_1s:10m   max_size=1g  inactive=60s use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_10s  levels=1:2 keys_zone=cfm_micro_10s:10m  max_size=1g  inactive=120s use_temp_path=off;
```

### 5.2 Per-request decision transport: edge-pull → shared dict → local lookup

This is the **WAF/Clam/H3-exclude** model, **not** the fppolicy per-key RPC
model — chosen deliberately:

- fppolicy does an **RPC per key** because fingerprints are **high-cardinality**
  (thousands) → it needs an RPC budget.
- Cache policy is **per vhost → low cardinality** (the number of domains). So
  the edge **polls the whole table** every `CFG.cache_cfg_refresh_sec` via
  `GET /nginx/cache/config`, stashes it in a dedicated shared dict + a
  `require`d per-worker module (mirrors `refresh_waf_excludes_if_needed()`,
  `cfm.lua:876`), and **each request does a local map lookup** — zero RPC on the
  hot path, no budget to tune.

New module `configs/lua/cfm_cache.lua` (mirrors `cfm_waf_excl.lua`): parses the
config into host→policy, exposes `policy_for(host, uri, is_static)` returning
`{skip, zone, ttl}`. Must be a `require`d module, not a file-local — an
`access_by_lua_file` resets file-locals per request (the WAF-excl PITFALL).

### 5.3 Insertion points in `cfm.lua`

Micro-cache (Tier B) is decided at the **allow-returns**, after all enforcement:

- **Step 2b** (`cfm.lua:1502`, the dominant real-traffic clearance path) and
- **Step 4** (`cfm.lua:1632`, the plain allow).

Both are **after** Step 0a1 (`/.well-known/` carve-out, `:1202`), so ACME/DCV is
never cached. At those points `host`, `uri`, `method`, `scheme` and clearance
state are already computed (`cfm.lua:1048-1054`). The Lua calls
`cfm_cache.policy_for(...)`, applies the §4 rails, and on success sets:

```lua
ngx.var.cfm_cache_skip = "0"
ngx.var.cfm_cache_zone = pol.zone   -- e.g. "cfm_micro_1s"
ngx.var.cfm_cache_ttl  = pol.ttl    -- informational / stats
```

Static (Tier A) is decided in the static-asset location. That location currently
does `access_by_lua_block { return; }` (skips *all* of `cfm.lua`, including WAF —
correct for assets). We replace the bare `return` with a **minimal**
`access_by_lua_block` that does **only** the `cfm_cache` shdict lookup and sets
the three vars — no WAF, no decision RPC. Cost is one shared-dict `get`
(microseconds); when `SITE_CACHE=0` it short-circuits immediately.

### 5.4 TTL model (honest nginx constraint → TTL buckets)

nginx computes a cached entry's validity from the **upstream** response headers
during upstream-header processing, which is **before** any Lua `header_filter`
runs — so `X-Accel-Expires` set from Lua is **too late** and cannot drive TTL,
and `proxy_cache_valid` is not variablizable. Truly arbitrary per-request TTL is
therefore not natively supported.

Resolution: **`proxy_cache` accepts a variable zone name.** We define a small,
admin-extensible **menu of TTL buckets**, one cheap zone each (§5.1), and the
Lua picks the zone by setting `$cfm_cache_zone`. Each zone carries its own
`proxy_cache_valid`.

- Per-vhost bucket choice is **reload-free** (it is just a policy value the edge
  pulls).
- "Custom TTL" = pick any bucket. If an admin needs a value not in the menu,
  that adds a bucket = a rare zone-list regen + reload (not a per-vhost event).
- Suggested starting buckets — micro: `1s, 5s, 30s`; static: `1h, 7d, 30d`.
  Aggressive static also adds `Cache-Control: public, immutable` via `add_header`
  on HIT for the asset location. Final bucket set is a Phase 3/4 tuning detail.

### 5.5 Open edge items to validate during implementation

1. **Clearance-cookie ordering.** Confirm the edge-set `cfm_clearance`
   `Set-Cookie` (Step 2b refresh) does **not** mark the upstream response
   uncacheable, and that every cache HIT still gets a fresh clearance cookie
   in the header phase. If there is any interaction, micro-cache serves only the
   Step 4 (uncleared-but-allowed) path in Phase 4 and Step 2b is added later.
2. **Origin keepalive.** Caching sits in front of the origin regardless of the
   `ORIGIN_KEEPALIVE` pools; 443 `proxy_ssl_session_reuse off` is unaffected.
   Verify HIT/MISS accounting with KA armed.
3. **`Vary`.** Respect only a safe subset (e.g. `Accept-Encoding`); a
   `Vary: Cookie` from origin must force bypass, not key-fragment.

---

## 6. Data model (the per-vhost store)

New `siteCacheStore` in `internal/webdetector/site_cache.go`, JSON at
`/var/lib/cfm/webdetector_site_cache.json` (knob `SITE_CACHE_STORE_PATH`),
write-through source of truth with atomic save + forward-compat `frozen` map —
same mechanics as `http3_overrides_store.go` / `traffic_rules.go`. One entry per
vhost, holding **independent per-tier sub-policies** so a vhost can run static
and micro together:

```jsonc
{
  "host": "myip.gr",
  "scope_hosts": ["myip.gr"],          // audit + scoped-token gating; caller's own scope
  "generation": 3,                       // bumped by Purge (§10); part of the cache key
  "static": { "enabled": true,  "recipe": "static_aggressive", "ttl": "7d" },
  "micro":  { "enabled": false, "recipe": "micro_safe",        "ttl": "1s" },
  "created_at": "2026-09-21T...", "updated_at": "2026-09-21T..."
}
```

`generation` is folded into the cache key (`"$scheme$host$request_uri"` becomes
`"g<gen>|$scheme$host$request_uri"` via a Lua-set `$cfm_cache_gen`), so a Purge
is a counter bump — old keys become unreachable and age out under `inactive`,
with no filesystem walking.

---

## 7. Management surfaces

### 7.1 HTTP API (`/api/v1`, rows added to `apiRoutes()` in `http_api.go:44-127`)

| Method | Path | Notes |
|---|---|---|
| GET  | `/api/v1/site-cache/list` | scope-filtered; supports `?host=` and sort params |
| GET  | `/api/v1/site-cache/get?host=` | one vhost |
| POST | `/api/v1/site-cache/add` | `requirePOST`; scoped→own host only |
| POST | `/api/v1/site-cache/update` | scope-checks existing **and** new vhosts |
| POST | `/api/v1/site-cache/remove` | i.e. OFF for a vhost |
| POST | `/api/v1/site-cache/purge` | `?host=` (per-vhost) or `?all=1` (global, admin) |
| GET  | `/api/v1/site-cache/simulate?host=&uri=&method=&cookie=` | would-cache? which tier/recipe/TTL? why bypass? (read-only) |

Prefix `site-cache` added to `SharedAPIPrefixes()` so the shared apiserver
proxies it to the engine mux. Never a bare `mux.HandleFunc` (a prefix-coverage
test walks the table). Every add/remove/purge routes through one
`logExcludeChange`-style choke point for lifecycle audit.

### 7.2 CLI (`cfm webtop site-cache …`)

New `case "site-cache":` in the `webtop` dispatch (`cli.go`), implemented in
`internal/webdetector/cli_site_cache.go`, mirroring `cli_challenge_access.go`
over the JSON API (through `internal/clihttp`, per the transport guardrail):

```
cfm webtop site-cache list [--host H] [--sort host|updated]
cfm webtop site-cache get <host>
cfm webtop site-cache add <host> [--static RECIPE|--micro RECIPE] [--ttl D]
cfm webtop site-cache off <host>          # remove / disable
cfm webtop site-cache purge <host>        # or: purge --all
cfm webtop site-cache simulate <host> <uri> [--method GET] [--cookie ...]
```

### 7.3 cfm-admin page "Site Cache"

Multi-page app, directory-routed (`internal/webui/embed.go`). Template =
**Challenge-Access** (per-vhost + scoped + recipes). Files to add:
`static/webdetector/site-cache/index.html`, `assets/webdet/pages/site-cache.js`,
`assets/webdet/feature-site-cache.js`, `assets/webdet/site-cache-model.js`
(+`.test.js`), `assets/webdet/site-cache-recipes.js` (+`.test.js`). One
`MENU_GROUPS` item in `nav.js` under "Rules & engine". The page has:

- a vhost table with **filter + sort** (host, tier(s) on, recipe, TTL, gen,
  updated, HIT-ratio), a per-row **OFF** and **Purge**, and a top-level
  **Purge all** (admin);
- a **Recipes** panel (§8) and a **Simulate** panel (§8).

Scoped filtering: leave `site-cache` **out** of `ADMIN_ONLY_NAV_PATHS`
(`controller-bootstrap.js`) so scoped cPanel users keep the link, and add
`v1/site-cache/` to `isScopedSelfServiceWrite` (`core.js`). Backends still
fail-closed regardless of the UI.

### 7.4 Bridge (daemon↔edge, `nginx_bridge.go`)

- `GET /nginx/cache/config` → `{ "entries": [ {host, static{…}, micro{…}, gen}, … ] }`,
  token-gated, **explicit Content-Length** (the minimal Lua parser needs it —
  the Clam handler gotcha). Backed by a `ListCachePolicy` engine hook.
- Purge is a **push** (like `/nginx/vhost`): daemon → edge. Phase 1 realizes
  purge purely via the `generation` bump in the pulled config (no push needed);
  an explicit per-URL purge push is a later extension of `cfm_purge.lua`.

---

## 8. Recipes + "start-disabled / Simulate"

Recipes are a **front-end-only catalog** (each `build(vars)` emits ordinary CRUD
payloads), exactly like `CA_RECIPES` (`challenge-access-recipes.js`). Catalog:

| Key | Tier | TTL | Ships | For |
|---|---|---|---|---|
| `static_lean` | static | 1h | enabled | the safe default for most sites |
| `static_aggressive` | static | 7–30d + `immutable` | enabled | asset-heavy sites |
| `micro_safe` | micro | 1s, `use_stale updating` | enabled | heavy pages / bursts (`myip.gr`) |
| `micro_aggressive` | micro | 10–30s, stale-while-revalidate | enabled | near-static pages |
| `micro_custom` | micro | operator TTL (bucket) | enabled | full control |
| `fullpage_advanced` | micro-zone, long TTL | hours | **DISABLED** | advanced, purge-aware only |

A vhost can combine **one static + one micro** recipe. Per the repo's history
(the `Simulate`-ignored-`Enabled` bug, CLAUDE.md §6), risky recipes are
**built disabled** and there is a **Simulate** that answers, for a given
`host + uri + method + cookie-state`: *would this be cached? which tier/recipe?
what TTL? if bypassed, which rail bypassed it?* — so an operator (or tenant)
**validates their login/redirect paths before arming**. Simulate is the direct
answer to "how do I know it won't break my site."

The Simulate contract mirrors traffic-rules `disabled_match`: a disabled tier's
would-be decision is returned for the UI but never enforced.

---

## 9. Scope model (scoped cPanel self-service — full power, fenced)

Per decision, scoped users get the **same power** as admins **over their own
vhosts**: enable any recipe (incl. aggressive), set custom TTL, turn OFF, and
Purge — but only for hosts in their token scope, fail-closed otherwise. This
reuses the tested precedent verbatim:

- `RequireScopedOrAdmin` + `scopeAllowsVhosts(r, vhosts)` on every write
  (`challenge_access_api_handlers.go` shape): nil scope = admin (unrestricted);
  empty scope = deny; else every target host must be in the token allowlist.
- Update re-checks **both** the existing entry's and the new host set (no
  re-scoping escalation). Remove/Purge re-fetch and scope-check first.
- List/simulate are scope-filtered (`scopeFilterChallengeAccess` shape),
  cross-tenant hosts redacted.
- **Purge-all** (`?all=1`) is **admin-only**; a scoped `purge` is implicitly
  scoped to the caller's own vhosts.

Because the §4 rails are absolute, a tenant's "aggressive" choice can still only
ever cache their own anonymous, cookieless, non-redirect 200s — so full
self-service power carries no cross-tenant or correctness risk.

Update `docs/endpoint_scope_inventory.md` in the same change (hard rule,
CLAUDE.md §5): site-cache list/get/simulate = scoped-allowed (own host);
add/update/remove/purge = scoped-allowed (own host); purge-all = admin-only.

---

## 10. Purge / invalidation

- **Micro-cache is self-healing** (1–30s TTL) — rarely needs an explicit purge.
- **Static (long TTL) needs purge.** Mechanism: **generation bump.** Each
  vhost entry carries `generation`; the cache key includes it
  (`g<gen>|$scheme$host$request_uri`). Purge = `generation++` in the store →
  new key space → old entries age out under `inactive`. No filesystem walking,
  no `proxy_cache_purge` (commercial) dependency, works on both OpenResty and
  Angie.
- **Surfaces:** `POST /api/v1/site-cache/purge?host=` (per-vhost; admin or the
  owning scoped user) and `?all=1` (global; admin). CLI `purge <host>` /
  `purge --all`. cfm-admin per-row **Purge** + top **Purge all**.
- **Per-URL purge** (delete a single path) is a later extension building on
  `cfm_purge.lua`; not in Phase 1.

---

## 11. Observability

Revive the orphaned plumbing instead of writing new:

- Declare `lua_shared_dict cfm_cache_stats` (both confs).
- Wire `cfm_cache_log.lua` in a `log_by_lua_block` keyed on
  `$upstream_cache_status` (HIT/MISS/BYPASS/EXPIRED/STALE/UPDATING/REVALIDATED)
  per zone. `cfm_stats.lua:398-399` already reads this dict → the stats/dashboard
  endpoint lights up for free.
- Response header `X-CFM-Cache: HIT|MISS|BYPASS` (behind a debug flag) so an
  operator can `curl` and verify a specific URL's decision.
- cfm-admin per-vhost HIT-ratio column from the stats dict.

---

## 12. Config knobs (`[webdetector]` in `detectors.conf`)

| Knob | Default | Meaning |
|---|---|---|
| `SITE_CACHE` | `0` (OFF) | master gate; `0` = no caching + no edge cost (mirrored to edge via `manager.go`, like `FP_POLICY`) |
| `SITE_CACHE_STORE_PATH` | `/var/lib/cfm/webdetector_site_cache.json` | per-vhost store |
| `SITE_CACHE_SCOPED` | `1` | allow scoped cPanel self-service (§9) |
| `SITE_CACHE_CFG_REFRESH_SEC` | `10` | edge config-pull cadence |

Add the `SITE_CACHE` doc block to `configs/detectors.conf` under `[webdetector]`
(mirror the `FP_POLICY` block), the `Config` fields + `FillDefaults` in
`webdetector_config.go`, the read in `webdetector_register.go` (Config build +
a `ConfigureSiteCache(kvBool(kv,"SITE_CACHE",false), …)` in the reload block for
the package-level gate), and the edge kill-switch mirror in `manager.go`.
`TestWAFSecurityFamilyCoverage`-style coverage test for the knobs.

---

## 13. CI guardrails (turn the lesson into an enforced rule)

New `scripts/tests/check_site_cache_config.sh` (in the spirit of
`check_origin_ka_config.sh`), wired into `security.yml` and §3 of CLAUDE.md:

1. **Bypass-by-default:** every location that names `proxy_cache` must also
   carry `proxy_cache_bypass $cfm_cache_skip;` **and** `proxy_no_cache
   $cfm_cache_skip;`. Fails the build otherwise — **unconditional caching can
   never be reintroduced.**
2. **Set-Cookie safety:** assert `Set-Cookie` is never added to
   `proxy_ignore_headers` in a cache location.
3. **OpenResty↔Angie parity:** the two confs declare the same zones and the same
   cache locations.
4. **Lua↔Go parity** for any cache-policy identifiers (recipe keys), mirroring
   `TestWAFRuleIDs_LuaParity`.
5. **Logrotate:** if any new `/var/log/cfm/…` cache log path is added, it needs a
   rotation entry (`check_logrotate_coverage.sh`). (Stats live in a shdict, so
   likely none.)

---

## 14. Phased PR plan (small, single-concern, each with adversarial self-review)

1. **Store + API + CLI + scope** (daemon-only; no edge). Tests: scope
   (`scope_enforcement_test.go` shape), store round-trip. No behaviour on the
   edge yet.
2. **Bridge `/nginx/cache/config` + `cfm_cache.lua`** (edge-pull → shdict), and
   set `$cfm_cache_*` vars + `X-CFM-Cache` header **without** activating
   `proxy_cache` (observe-only). Lets us watch decisions in prod before any body
   is cached.
3. **Tier A (static)** activation in both confs + `cfm_cache_stats` +
   `cfm_cache_log` wiring + the new CI guard. Lowest-risk caching first.
4. **Tier B (micro-cache)** + the full §4 rails + Simulate. Validate §5.5 items
   on a live box (the `myip.gr` case) per the challenge/WAF release checklist.
5. **cfm-admin page + Recipes** (+ `make test-js`), filter/sort, per-row + global
   Purge UI.
6. **Purge generation-bump** end-to-end (if not already folded into 3/4).

Each edge-affecting PR runs `docs/challenge-waf-release-checklist.md`. Each
runtime PR adds a `CHANGELOG.md [Unreleased]` entry.

---

## 15. Files to add / touch (map)

**Add (Go):** `internal/webdetector/site_cache.go` (store + model + policy
resolve), `internal/webdetector/site_cache_api_handlers.go`,
`internal/webdetector/cli_site_cache.go`.
**Touch (Go):** `http_api.go` (`apiRoutes()` + `SharedAPIPrefixes()`),
`cli.go` (dispatch + help), `nginx_bridge.go` (route + `handleCachePolicy` +
`ListCachePolicy` hook), `engine.go` (construct store + wire hook),
`webdetector_config.go` + `webdetector_register.go` + `manager.go` (knobs),
`cmd/cfm/main.go` (canonical cache dirs already exist — reconcile bucket dirs).

**Add (Lua):** `configs/lua/cfm_cache.lua`.
**Touch (Lua/conf):** `configs/lua/cfm.lua` (Steps 2b/4 + static-location
mini-gate + `$cfm_cache_*` var decls), `configs/openresty.conf` +
`configs/angie.conf` (zones, `lua_shared_dict`, cache locations, fix stale
comment), wire `cfm_cache_log.lua`.

**Add (UI):** the six files in §7.3.
**Touch (UI):** `nav.js`, `core.js`, (leave `controller-bootstrap.js`'s
admin-only set unchanged).

**Add (CI):** `scripts/tests/check_site_cache_config.sh` + `security.yml` wiring
+ CLAUDE.md §3 line.
**Docs:** this file, `docs/endpoint_scope_inventory.md`, CLAUDE.md §7 pointer
row, `CHANGELOG.md`.

---

## 16. References

- `configs/lua/cfm.lua` (decision flow: Steps 0a1 / 2b / 4), `cfm_decision.lua`,
  `cfm_fppolicy.lua` (per-key lookup template), `cfm_waf_excl.lua` +
  `refresh_waf_excludes_if_needed()` (edge-pull template), `cfm_filecache.lua`,
  `cfm_cache_log.lua` (observability), `cfm_purge.lua`.
- `internal/webdetector/`: `exclude_store.go`, `http3_overrides_store.go`,
  `traffic_rules.go` (store + `Simulate` = enforcement), `nginx_bridge.go`
  (bridge + WAF/Clam pull handlers), `challenge_access_api_handlers.go` (scoped
  write precedent), `vhost_filter.go` / `authz.go` (scope helpers),
  `fppolicy.go` (package-level policy store + `manager.go` kill-switch mirror).
- `internal/webui/static/`: `webdetector/challenge-access/` (page template),
  `assets/webdet/challenge-access-recipes.js` (recipe template),
  `assets/shared/nav.js`, `assets/webdet/core.js`,
  `assets/shared/controller-bootstrap.js`.
- Docs: `docs/traffic-rules-ux-proposal.md` (recipes/Simulate UX),
  `docs/challenge-access-control.md`, `docs/endpoint_scope_inventory.md`,
  `docs/proxy-performance.md` (origin keepalive / proxy_ssl),
  `docs/challenge-waf-release-checklist.md` (edge release gate).
