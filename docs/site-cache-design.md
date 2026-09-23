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

1. **Safe by default via per-vhost opt-in — not a global default-off.** The
   per-vhost policy store is empty by default, so the feature can be installed
   and cache *nothing* anywhere until an operator arms a vhost. The master
   `[webdetector] SITE_CACHE` is therefore a **kill switch, default ON (1)** — a
   default-*off* master would just be a redundant second opt-in. It is not what
   makes the feature safe; the empty per-vhost store is. `SITE_CACHE = 0` is the
   panic button: it removes all per-request edge cost (`cfm_cache.lua` → full
   no-op, mirrored to the edge like `FP_POLICY`) fleet-wide in ~10s **without**
   disarming any vhost, so re-arming is instant.
2. **Arming a vhost is the single opt-in — exact-host.** `myip.gr` and
   `www.myip.gr` are two explicit entries; there is **no** implicit `*.myip.gr`.
   Wildcards are an advanced opt-in, never a default.
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
| Cache dirs `/var/cache/nginx/cfm_static`, `/var/cache/nginx/cfm_micro` | Created by the daemon (`cmd/cfm/site_cache_dirs.go`) and by `scripts/cfm-cache-dirs.sh` (packaging + installers). | **Use these canonical paths.** Note the stale conf comment says `/var/cache/cfm/static` — **fix the comment** in the same change. |
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
| Status: **only `200` is stored** (as-built Tier A — dropped the optional `301/404`) | `map $upstream_status $cfm_cache_non200` → `proxy_no_cache` (hard block, beats any origin `Cache-Control`), not just `proxy_cache_valid` | **3xx redirect / SSO loop cached** (the incident that removed CFM's global cache) |
| Response has `Set-Cookie` → never store | nginx default (we **never** add `Set-Cookie` to `proxy_ignore_headers`) | user A's session served to user B |
| Request carries a **named app-session cookie** → `$cfm_cache_skip=1` (see §4.1 — **allowlist by name**, NOT "any cookie") | Lua cookie-name allowlist | **logged-in users get stale/foreign content** |
| Origin `Cache-Control: private\|no-store\|no-cache` → respect | nginx default (not ignored) | origin keeps the final say |
| Panel hosts/ports (`:2083/:2087/:2096`), webmail hosts, `/.well-known/`, `/acctxfer*`, cPanel/webmail bypass paths → never | Lua gate, sits **after** `cfm.lua` Step 0a1 | **cPanel / webmail / SSO / AutoSSL broken** |
| Cache key excludes cookies; carries purge generation, **destination IP**, the **listener scheme** and the **scheme the origin is told** (as-built) | `proxy_cache_key "g$cfm_cache_gen\|$server_addr\|$scheme\|$cf_xfp://$host$request_uri"` | per-user fragmentation / leakage; **multi-IP poisoning** — the origin is chosen by `$server_addr`, so without it a request to IP B with `Host: victim` stores B's default vhost under victim's key. **Both** schemes, not either: `$scheme` is the listener (:9080 → origin :80, :9043 → origin :443, which Apache may answer from different vhosts — e.g. a domain with no SSL vhost falls back to the IP's default SSL site), `$cf_xfp` is what the origin is told (differs from `$scheme` only behind a trusted peer such as Cloudflare Flexible SSL). Keying on `$cf_xfp` alone let a direct HTTPS client fill an entry that a Cloudflare visitor on :80 then hit (reproduced) |
| Request carries **`Authorization`** → never read, never store (as-built) | `map $http_authorization $cfm_req_auth` (any non-empty value → `"1"`; a raw predicate would read `Authorization: 0` as false) on `proxy_cache_bypass` **and** `proxy_no_cache` in every cache location; Tier B `micro_decision` also reports `bypass:authorization` and does not route | **basic-auth (cPanel Directory Privacy) / bearer response served to anonymous visitors** — nginx does not bypass on `Authorization` by itself |
| **Forwarded headers pinned** in cache locations (as-built) | `proxy_set_header X-Forwarded-Host $host;` and `""` (not sent) for `X-Forwarded-Server/-Port/-Scheme/-Protocol/-Prefix/-Ssl/-Uri/-Path`, `X-Host`, `X-Original-Host`, `X-Original-URL`, `X-Original-Uri`, `X-Rewrite-URL`, `Forwarded`, `Front-End-Https`, `X-Url-Scheme`, `X-Scheme`, `X-HTTP-Method(-Override)`, `X-Method-Override`. Applies to **every** request through a cache location, armed vhost or not (all vhosts' static assets use the Tier A location) | cache poisoning — an app building absolute URLs / routes from these writes attacker input into a page cached for everyone. A denylist of the known URL-building headers, not a proof |
| Lock wait set **per tier** (as-built) | `proxy_cache_lock_timeout 1s` (Tier A) / `5s` (Tier B) | the timeout must outlast the fill, or a cold-key burst all reaches the origin (when it expires every waiter is sent upstream and nothing is stored); yet on an uncacheable key (Set-Cookie / no-store / non-200) waiters queue at 500 ms steps until it expires — nginx has no hit-for-pass. Static files fill in well under 1 s and a popular 404 is the usual uncacheable key → 1 s. HTML can take seconds to render → 5 s, paying the uncacheable queue until a remembered-uncacheable skip lands (Tier B hardening) |
| `cfm_clearance` is edge-set, not origin | see §5.5 open item | edge cookie poisoning the cache |

**Residuals (cannot be seen at the edge).** An origin that varies a `200` on
something outside the key **without sending `Vary`** fills the cache with
whatever the first client got — and on a cold key an attacker can choose to be
that client:
- the **client IP** (`Require ip`, cPanel IP Blocker, a per-IP throttle that
  answers 200) or **`Referer`** (hotlink protection);
- **`User-Agent` / `Accept` / `Accept-Language`** (mobile themes, WebP
  negotiation by `.htaccess`, language auto-detect) — safe only when the origin
  sends `Vary` (nginx then stores one copy per variant);
- on Tier B, a credential in a **custom header** (`X-Api-Key`, `X-Auth-Token`)
  rather than `Authorization`; on Tier A, request cookies are not consulted
  at all (§14 3b — static assets rely on the response-side rails).

Non-200 answers are safe (only-200 rail), so the classic cached-throttle
(`429`/`503`) incident cannot recur; a 200 that depends on who asked can. Do not
arm a vhost whose pages are gated or negotiated that way.

Collateral of the header pinning: behind a proxy that rewrites `Host` and
supplies its own `X-Forwarded-Host`, a micro-armed vhost's cached (anonymous)
pages build absolute URLs from `$host`, while uncached requests through
`location /` still see the proxy's value.

`check_site_cache_config.sh` pins the conf-side rails above in every
`proxy_cache` location of both confs: bypass-by-default, only-200, the
`$cfm_req_auth` map + predicates, the full key, the per-tier lock timeout, the
forwarded-header pins, buffering, `internal` + access override on micro — and,
file-wide, that `proxy_ignore_headers` never lists `Set-Cookie`, `Vary` or
`Cache-Control` and `proxy_cache_methods` never lists a non-GET/HEAD method.

`cfm_clearance`-cookie holders (cleared visitors) are still *anonymous* to the
app, so they **may** be served micro-cache; the cache key never varies on the
clearance cookie, and the clearance cookie is refreshed per-response by the edge
(§5.5 flags the ordering item to verify in implementation).

### 4.1 Cookie handling — why the challenge cookie does **not** block caching

This is the single easiest way to accidentally neuter micro-cache, so it is a
first-class rail, not a detail. The bypass is **not** "the request has a
`Cookie` header." It is a **positive allowlist of app-session cookie names**,
plus an explicit **ignore-list** that caching treats as anonymous:

- **Auth allowlist (bypass → do not cache):** the cPanel-ecosystem session
  cookies — `PHPSESSID`, `wordpress_logged_in_*`, `wordpress_sec_*`,
  `wp-postpass_*`, `comment_author_*`, `woocommerce_*` / `wp_woocommerce_session_*`,
  `cpsession`, `whmsession`, `roundcube_sessid` / `roundcube_sessauth`,
  `horde_*`, `PrestaShop-*`, `laravel_session`, `ci_session`, `XSRF-TOKEN`
  (session-bound), … — **operator/tenant-extensible** per vhost.
- **Ignore-list (never bypass, treated as anonymous):** **`cfm_clearance` and
  every `cfm_*` CFM-set cookie**, plus common non-session cookies (`_ga`,
  `_gid`, `_gcl_*`, `_fbp`, consent/CMP cookies, …). A visitor whose **only**
  cookies are these **IS cached.**

So the answer to "won't our own challenge-solve cookie stop caching?" is **no**:
`cfm_clearance` is on the ignore-list. A visitor who is *anonymous but cleared*
(solved the challenge, no app login) is exactly the burst traffic micro-cache
exists to absorb on a heavy page — and they get cached. Only a **named app
session** bypasses.

**The allowlist's blind spot** is an app using an unknown session-cookie name.
Two layers cover it: (1) the **response-side rails** — a page that renders
per-user almost always emits `Set-Cookie` and/or `Cache-Control:
private|no-cache` (WordPress, Woo, Laravel, Roundcube all do), and both force
"do not store"; (2) an **optional per-vhost `strict_cookies` flag** (advanced)
that inverts the logic to *bypass on any cookie not on the ignore-list* — max
safety at the cost of caching visitors who carry a stray analytics/consent
cookie. Default is the allowlist (effective); `strict_cookies` is opt-in for a
site the operator wants to be paranoid about. This is the same trade-off the
classic nginx WordPress micro-cache recipe makes, tuned for the cPanel fleet.

The §11 **BYPASS counter is how you validate this in production**: if a vhost
shows high BYPASS + low HIT, the cookie allowlist (or `strict_cookies`) is
bypassing traffic you expected to cache — tune it there, don't guess.

> **As-built (Tier A / 3b):** this request-cookie allowlist is **not** wired on
> the Tier A static path — `static_gate` does not read
> `strict_cookies`/`auth_cookies`. Tier A relies on the response-side rails
> (`Set-Cookie` / `Cache-Control: private` → never stored) plus the public nature
> of static assets. Decision + residual: §14 item 3b.
>
> **As-built (Tier B / B2, observe-only):** the built-in allowlist/ignore-list
> machinery now ships in `cfm_cache.lua` (`micro_cookie_verdict` + `micro_decision`),
> exercised by the header-filter `observe()` for a micro-armed vhost. It is the
> full request-side model — auth allowlist (built-in names + per-vhost
> `auth_cookies`), the `cfm_*`/analytics ignore-list, `strict_cookies`, the
> GET/HEAD rail and the `/acctxfer*` never-cache path — but **nothing caches**:
> the verdict is surfaced only on the debug-gated `X-CFM-Cache` header
> (`microcache=would/<n>s` | `microcache=bypass:<reason>`) so the cookie logic
> burns in on real traffic before B3 activates `proxy_cache`. The **response**-side
> rails (Set-Cookie / `Cache-Control: private|no-store|no-cache` → never stored)
> stay nginx-native and are enforced at store time in B3, not here.

---

## 5. Edge mechanics

### 5.1 Cache zones — declared once, inert until used

`proxy_cache_path` must live in `http{}`. Declaring a zone caches nothing; a
zone only bites when a location activates `proxy_cache` **and** the bypass gate
allows it. Declared identically in **both** confs, under
`/var/cache/nginx/cfm_*` (the paths the daemon already creates):

```nginx
# TTL buckets (see §5.4) — an admin-extensible menu, one zone per bucket.
# Static (disk): 1h / 7d / 30d
proxy_cache_path /var/cache/nginx/cfm_static_1h  levels=1:2 keys_zone=cfm_static_1h:20m  max_size=5g  inactive=2h  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_static_7d  levels=1:2 keys_zone=cfm_static_7d:20m  max_size=10g inactive=8d  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_static_30d levels=1:2 keys_zone=cfm_static_30d:20m max_size=20g inactive=31d use_temp_path=off;
# Micro (tiny, short-lived; may live on tmpfs — see §5.6): 1/2/5/10/30/60s
proxy_cache_path /var/cache/nginx/cfm_micro_1s   levels=1:2 keys_zone=cfm_micro_1s:10m  max_size=512m inactive=30s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_2s   levels=1:2 keys_zone=cfm_micro_2s:10m  max_size=512m inactive=30s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_5s   levels=1:2 keys_zone=cfm_micro_5s:10m  max_size=512m inactive=60s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_10s  levels=1:2 keys_zone=cfm_micro_10s:10m max_size=512m inactive=60s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_30s  levels=1:2 keys_zone=cfm_micro_30s:10m max_size=1g   inactive=120s use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_60s  levels=1:2 keys_zone=cfm_micro_60s:10m max_size=1g   inactive=180s use_temp_path=off;
```

Each cache location also carries the **anti-stampede** trio (§5.6):
`proxy_cache_lock on;`, `proxy_cache_use_stale updating error timeout;`,
`proxy_cache_background_update on;` — plus `proxy_cache_bypass`/`proxy_no_cache
$cfm_cache_skip;` (§0) and `proxy_cache_key "g$cfm_cache_gen|$server_addr|$scheme|$cf_xfp://$host$request_uri";` (§4, §10).

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

Resolution: a **menu of TTL buckets**, one cheap zone each (§5.1). A cache HIT
costs the same regardless of which zone, so more buckets = no per-request cost,
only a little startup memory.

> **As-built correction (verified against nginx, Phase B1).** The original wording
> here — "`proxy_cache` accepts a variable zone name … each zone carries its own
> `proxy_cache_valid`" — is **wrong** and would have neutered the buckets. A
> variable `proxy_cache $cfm_cache_zone` selects only the **storage** zone;
> `proxy_cache_valid` is a **per-location** directive and is **not** variablizable,
> so a single catch-all location applies **one** validity to every zone it caches
> into. Confirmed empirically: two locations with `proxy_cache_valid 200 1s` vs
> `5s` expired independently, while a variable-zone location shared its single
> validity. So each TTL bucket is a **separate internal location**
> `@cfm_micro_<n>s` pinning `proxy_cache cfm_micro_<n>s;` +
> `proxy_cache_valid 200 <n>s;`, and the allow-path (Step 2b/4) `ngx.exec`s to the
> bucket its policy snaps to. B1 declares the six zones (inert) + the
> `cfm_cache._micro_bucket` snapper; B2 adds the internal locations + routing.

**Micro — recommended presets AND custom, both work.** The recommended micro
bucket set is **`{1, 2, 5, 10, 30, 60}s`** (6 tiny zones). The UI offers:
- **Recommended presets:** `micro_safe → 1s`, `micro_aggressive → 15–30s`.
- **Custom TTL field:** the operator types a value; it **snaps to the nearest
  bucket**. For micro-cache (herd protection), the difference between 7s and 8s
  is operationally meaningless, so the snapped set behaves as effectively
  continuous — "custom" is honoured without fighting nginx. Per-vhost choice
  (preset or custom) is **reload-free** (just a policy value the edge pulls). An
  admin who wants a bucket outside the menu adds one = a rare zone-list regen +
  reload (never a per-vhost event).

**Static** buckets: `{1h, 7d, 30d}` (you said static is fine as-is). Aggressive
static also adds `Cache-Control: public, immutable` via `add_header` on HIT for
the asset location.

If truly arbitrary (non-snapped) per-request TTL is ever required, the escape
hatch is OpenResty `srcache` with a Lua-computed store TTL — but it needs a
storage backend and is heavier, so it is **explicitly deferred**; the bucket
model is the v1 answer.

### 5.5 Open edge items to validate during implementation

1. **Clearance-cookie ordering.** Confirm the edge-set `cfm_clearance`
   `Set-Cookie` (Step 2b refresh) does **not** mark the *upstream* response
   uncacheable — it must not: it is an edge-added cookie, not an origin one, and
   nginx's "don't cache `Set-Cookie`" check looks at the upstream response
   headers, which is processed before the edge adds the clearance cookie.
   Verify the exact phase where the clearance cookie is set. Output header
   filters (and `add_header` for 2xx/3xx) **do** run on cache HITs, so a cleared
   visitor served from micro-cache still gets a fresh clearance cookie — that is
   precisely why Step 2b is a valid cache-serving path. If any interaction is
   found, Phase 4 ships micro-cache on the Step 4 (uncleared-but-allowed) path
   only and Step 2b is added once verified.
2. **Origin keepalive.** Caching sits in front of the origin regardless of the
   `ORIGIN_KEEPALIVE` pools; 443 `proxy_ssl_session_reuse off` is unaffected.
   Verify HIT/MISS accounting with KA armed.
3. **`Vary`.** Respect only a safe subset (e.g. `Accept-Encoding`); a
   `Vary: Cookie` from origin must force bypass, not key-fragment.

### 5.6 Performance — this must LOWER CPU, not raise it

The whole point is fewer origin round-trips, so the machinery itself must never
become the cost. Three invariants make that a guarantee, not a hope:

- **Invariant 1 — zero per-request daemon RPC.** A cache decision costs **one
  shared-dict lookup** (`cfm_cache.policy_for`), never a bridge call. The policy
  table is pulled by a background timer (`SITE_CACHE_CFG_REFRESH_SEC`, default
  10s) into a shdict + per-worker module — the exact WAF-excludes refresh
  pattern already in production (`cfm.lua:876`). This is *why* we chose edge-pull
  over the fppolicy per-key RPC (§5.2): per-vhost is low-cardinality, the whole
  table fits in a shdict, and **no request ever waits on the daemon.**
- **Invariant 2 — near-zero cost when unused.** A `has_any` meta flag (like WAF
  `handleWAFExcludedMeta`) gates both tiers: if `SITE_CACHE=0` or no vhost has
  caching enabled, the static-location `access_by_lua_block` and the Step 2b/4
  hooks short-circuit on a single boolean — the static path stays effectively as
  cheap as today's bare `return`. A fleet that doesn't use caching pays nothing.
- **Invariant 3 — the request path never blocks on the daemon.** Fail-open
  everywhere: a failed/slow/absent config pull keeps the last snapshot, or (if
  never pulled) leaves caching off (bypass-by-default). A daemon hiccup can only
  ever mean "no caching," never a stalled or slowed request. The pull rides the
  existing keepalive'd unix socket + circuit breaker.

**Anti-stampede is the actual CPU win.** Every cache location sets
`proxy_cache_lock on;` + `proxy_cache_use_stale updating error timeout;` +
`proxy_cache_background_update on;`. Under a burst on a heavy page the origin
sees ~**one** request per TTL window (one filler; everyone else served stale or
briefly queued) instead of N/s of PHP execution. For micro-cache this is the
mechanism that flattens a spike from an origin meltdown into a flat line — the
explicit goal. It holds only while `proxy_cache_lock_timeout` outlasts the
fill: when the wait expires every waiter goes to the origin and nothing it
fetches is stored. Tier B therefore uses 5 s (a 2.5 s render under a cold
20-client burst: 1 origin hit with 5 s, 20 with 1 s — measured) and Tier A 1 s
(§4 lock row). The cost of 5 s is the uncacheable-key queue, and it is a
**sustained** cost, not a burst one: a page that sets a cookie on every
anonymous response (Laravel, PHP `session_start`) is uncacheable on EVERY
request, so under steady concurrency its clients are served one per 500 ms
(measured: 10 clients on a 0.3 s Set-Cookie page — 270 requests in ~8 s
uncached, 45 through a 5 s-lock micro location, max 5.3 s). So Tier B must
learn to remember an uncacheable key and skip the cache for it **before**
`MICRO_CACHE_ENFORCE` is turned on anywhere (a prerequisite, tracked with the
Tier B hardening).

**Per-request cost ledger (caching ON for a vhost):**

| Cost | Magnitude | Notes |
|---|---|---|
| policy shdict lookup | µs | one lock-light read |
| cache key md5 + lookup | µs | nginx-native, only in cache locations |
| stats `incr` (log phase) | µs, off the serving path | gated by `SITE_CACHE_STATS`, cache-enabled hosts only |
| background config pull | once / 10s / node | **not** per-request |
| **on HIT** | **− origin round-trip, − PHP exec** | **large net CPU/latency saving** |
| on MISS | + key hash + store | trivial vs the origin fetch it wraps |

**Disk vs RAM.** `use_temp_path=off` avoids a cross-filesystem rename. Micro
entries are tiny and short-lived, so the micro zones may optionally sit on
**tmpfs** (RAM-backed, zero disk I/O) with a bounded `max_size` — a good default
for herd protection. Static stays on disk (larger, longer-lived).

**Validation before any real caching (Phase 2 is observe-only).** Phase 2 sets
`$cfm_cache_*` + the `X-CFM-Cache` header but does **not** activate
`proxy_cache`, so the added Lua cost (the shdict lookups) is measured in
isolation on a live box — watch `$cfm_lua_ms` (already logged) before/after — and
confirmed to be in the noise before Phase 3 turns on real caching. A `map`-based
static gate (pure C, but reload-bound) is the fallback if the static-path lookup
ever shows measurable overhead; we prefer shdict for no-reload consistency and
expect no measurable delta.

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
  "strict_cookies": false,               // §4.1 advanced: bypass on ANY non-ignored cookie
  "auth_cookies": [],                    // §4.1 per-vhost extra app-session cookie names
  "created_at": "2026-09-21T...", "updated_at": "2026-09-21T..."
}
```

`generation` is folded into the cache key (as built:
`"g<gen>|$server_addr|$scheme|$cf_xfp://$host$request_uri"` via a Lua-set `$cfm_cache_gen`), so a Purge
is a counter bump — old keys become unreachable and age out under `inactive`,
with no filesystem walking.

---

## 7. Management surfaces

### 7.1 HTTP API (`/api/v1`, rows added to `apiRoutes()` in `http_api.go:44-127`)

| Method | Path | Notes |
|---|---|---|
| GET  | `/api/v1/site-cache/list` | scope-filtered; supports `?host=` and sort params |
| GET  | `/api/v1/site-cache/get?host=` | one vhost |
| POST | `/api/v1/site-cache/set` | `requirePOST`; upsert (host in body); scoped→own host only. One entry per vhost, so a single upsert replaces the add/update pair — the host is the immutable key, `set` stamps `scope_hosts` from the token |
| POST | `/api/v1/site-cache/remove` | i.e. OFF for a vhost |
| POST | `/api/v1/site-cache/purge` | `?host=` (per-vhost) or `?all=1` (global, admin) |
| GET  | `/api/v1/site-cache/stats?host=` | per-vhost cache stats (§11), scope-filtered (own vhosts / all) |

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
cfm webtop site-cache set <host> [--static RECIPE] [--micro RECIPE] [--static-ttl D] [--micro-ttl D] [--strict-cookies]
cfm webtop site-cache off <host>          # remove / disable
cfm webtop site-cache purge <host>        # or: purge --all
cfm webtop site-cache stats [host]        # hit-ratio + HIT/MISS/BYPASS breakdown
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
- a **Recipes** panel (§8). Per-URL verification is done with the
  `X-CFM-Cache` debug header (§8, §11.3), not a simulate panel.

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

## 8. Recipes

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

A vhost can combine **one static + one micro** recipe.

**No Simulate.** Unlike traffic rules (where a wrong rule silently blocks
legitimate traffic — hard to spot, high blast radius), a caching mistake is
**bounded and reversible**: the §4 rails mean the worst case is *stale anonymous
content*, never a security break, and the operator simply turns the vhost **OFF**
(or **Purges**). Verification is therefore observational, not predictive:

- **Live check for one URL:** `curl -I` and read the `X-CFM-Cache: HIT|MISS|BYPASS`
  header (§11.3, behind a debug flag) — this is the per-URL "would it cache / why
  bypassed" answer, for near-zero code.
- **Aggregate check:** the §11 stats, especially the **BYPASS counter** — if a
  vhost isn't behaving, its hit/bypass numbers show it immediately.

`fullpage_advanced` still **ships disabled** simply as a safe default (the
operator arms it when ready and watches the stats), not because a simulator gates
it.

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
- List/stats are scope-filtered (`scopeFilterChallengeAccess` shape),
  cross-tenant hosts redacted.
- **Purge-all** (`?all=1`) is **admin-only**; a scoped `purge` is implicitly
  scoped to the caller's own vhosts.

Because the §4 rails are absolute, a tenant's "aggressive" choice can still only
ever cache their own anonymous, cookieless, non-redirect 200s — so full
self-service power carries no cross-tenant or correctness risk.

Update `docs/endpoint_scope_inventory.md` in the same change (hard rule,
CLAUDE.md §5): site-cache list/get/stats = scoped-allowed (own host);
set/remove/purge = scoped-allowed (own host); purge-all = admin-only.

---

## 10. Purge / invalidation

- **Micro-cache is self-healing** (1–30s TTL) — rarely needs an explicit purge.
- **Static (long TTL) needs purge.** Mechanism: **generation bump.** Each
  vhost entry carries `generation`; the cache key includes it
  (`g<gen>|<server IP>|<listener scheme>|<scheme told to origin>://<host><uri>`). Purge = `generation++` in the store →
  new key space → old entries age out under `inactive`. No filesystem walking,
  no `proxy_cache_purge` (commercial) dependency, works on both OpenResty and
  Angie. (A future per-URL purge has to cover every key variant the URL can
  be stored under: each server IP the vhost answers on × listener scheme ×
  scheme told to the origin, since all three are in the key.)
- **Surfaces:** `POST /api/v1/site-cache/purge?host=` (per-vhost; admin or the
  owning scoped user) and `?all=1` (global; admin). CLI `purge <host>` /
  `purge --all`. cfm-admin per-row **Purge** + top **Purge all**.
- **Per-URL purge** (delete a single path) is a later extension building on
  `cfm_purge.lua`; not in Phase 1.

---

## 11. Cache statistics & observability

Yes — we persist per-vhost cache stats and show them in cfm-admin to **both**
the admin (all vhosts) and the scoped user (their own vhosts only). It is cheap
because every counter is incremented in `log_by_lua_block`, which runs **after**
the response is served — zero cost on the serving path. We revive the orphaned
plumbing instead of writing new.

### 11.1 Edge counters (live, in-memory)

- Declare `lua_shared_dict cfm_cache_stats` (both confs).
- Extend `cfm_cache_log.lua` to take a **host** argument and key per-vhost, but
  **only for cache-enabled vhosts** (bounded cardinality → the shdict cannot
  blow up):
  - `cache:host:<h>:status:<HIT|MISS|BYPASS|EXPIRED|STALE|UPDATING|REVALIDATED>`
  - `cache:host:<h>:total`, `cache:host:<h>:last_seen_ts`
  - `cache:host:<h>:tier:<static|micro>:...` (so the two tiers are separable)
  - the existing per-zone + global totals (`cfm_stats.lua:398-399` already reads
    these — the dashboard lights up for free).
- Fed from `$upstream_cache_status` in `log_by_lua_block`. `BYPASS` = the rails
  (§4/§4.1) declined to cache — the most useful diagnostic number (see §4.1).
- Reset on nginx reload/restart (in-memory) — acceptable for a *live* ratio;
  durability is handled by the daemon (§11.2).

### 11.2 Daemon aggregate (durable, scoped, historical)

The daemon pulls a counter snapshot on its existing tick via a new bridge read
`GET /nginx/cache/stats` (token-gated, explicit Content-Length) → `{ hosts: {
"<h>": {hit,miss,bypass,expired,stale,total,last_seen,tier:{...}}, … } }`. The
daemon keeps a rolling per-vhost aggregate in memory (naturally **survives edge
reloads**, since the daemon does not restart when nginx does) with an optional
periodic disk snapshot to survive a daemon restart. This aggregate is the source
the API/UI reads, so scoping is enforced daemon-side.

- **v1 (Phase 3):** totals + HIT/MISS/BYPASS/EXPIRED/STALE breakdown + hit-ratio
  + last-seen, per vhost and per tier. Cheap, immediate.
- **v2 (later):** coarse hourly buckets (e.g. last 24×1h per vhost) for a
  sparkline; optional bytes-saved estimate. Deferred — nice-to-have.

### 11.3 Surfaces

- **API:** `GET /api/v1/site-cache/stats[?host=]` — scope-filtered
  (`vhostAllowed`): admin sees all, scoped user sees only their own vhosts.
- **cfm-admin:** a **hit-ratio** column + a per-vhost detail card
  (HIT/MISS/BYPASS breakdown, last-seen, per tier). A scoped cPanel user sees
  their own site's effectiveness; the admin sees the fleet and a top-N.
- **CLI:** `cfm webtop site-cache stats [host]`.
- **`X-CFM-Cache: HIT|MISS|BYPASS`** response header (behind a debug flag) so an
  operator can `curl -I` and verify a single URL's decision on the spot.

New knob `SITE_CACHE_STATS = 1` (§12) gates the counting + snapshot; `0` drops
even the log-phase increments.

---

## 12. Config knobs (`[webdetector]` in `detectors.conf`)

| Knob | Default | Meaning |
|---|---|---|
| `SITE_CACHE` | `1` (ON) | master **kill switch** (not an opt-in — the per-vhost store arms vhosts); `0` = no caching + no edge cost fleet-wide (mirrored to edge via `manager.go`, like `FP_POLICY`) |
| `SITE_CACHE_STORE_PATH` | `/var/lib/cfm/webdetector_site_cache.json` | per-vhost store |
| `SITE_CACHE_SCOPED` | `1` | allow scoped cPanel self-service (§9) |
| `SITE_CACHE_CFG_REFRESH_SEC` | `10` | edge config-pull cadence |
| `SITE_CACHE_STATS` | `1` | per-vhost cache counters + daemon snapshot (§11); `0` drops the log-phase increments |
| `SITE_CACHE_AUTH_COOKIES` | (built-in allowlist) | extra app-session cookie names that force bypass, fleet-wide (§4.1); per-vhost extension lives in the store |

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
2. **Bridge `/nginx/cache/config` + `cfm_cache.lua`** (edge-pull), stamping an
   `X-CFM-Cache` header **without** activating `proxy_cache` (observe-only). Lets
   us watch decisions in prod before any body is cached.
   *As built:* the module mirrors `cfm_h3_config.lua` — a **per-worker** async
   cache (no shared dict), consumed from the existing server-level
   `header_filter_by_lua_block` (next to the H3 Alt-Svc call), so **`cfm.lua` and
   the access path are untouched** and there is no new nginx var yet. The
   access-phase `$cfm_cache_*` vars land in Phase 3 with `proxy_cache`, where they
   are first needed; the `SITE_CACHE` master knob + edge kill-switch likewise land
   with real caching (in this phase, un-configuring a vhost is the off switch).
3. **Tier A (static)** activation in both confs + `cfm_cache_stats` +
   `cfm_cache_log` (per-vhost) wiring + the daemon stats aggregate
   (`/nginx/cache/stats` pull) + `/api/v1/site-cache/stats` + the cfm-admin
   hit-ratio column + the new CI guard. Lowest-risk caching first, with the
   numbers to judge it.
   *As built (split into 3a + 3b so each stays single-concern):*
   - **3a — master kill-switch + edge gate.** `SITE_CACHE` is a config key in
     `[webdetector]` (`detectors.conf`), published on the bridge config
     (`WebdetectorBridgeConfig.SiteCache` → `cfm_bridge_config.lua`) and read by
     `cfm_cache.site_cache_enabled()`. It is a **kill-switch, default ON** (the
     per-vhost policy store is already the opt-in — a second default-OFF flag
     would be redundant), so an absent field reads TRUE (`~= false`). No env
     vars — CFM is config-file driven.
   - **3b — Tier A static caching.** The static-asset location on both confs
     activates the `cfm_static` `proxy_cache` zone behind the bypass-by-default
     gate: the conf pre-sets `$cfm_cache_skip="1"` / `$cfm_cache_gen="0"` and a
     fail-safe `cfm_cache.static_gate()` (double-`pcall`) flips skip→`0` +
     stamps the generation **only** for a static-armed vhost while the master
     switch is on. **TTL is respect-origin + 1h fallback** (`proxy_cache_valid
     200 1h`, honouring the origin's `Cache-Control`/`Expires`) — the simplest
     correct nginx config; a **per-vhost forced static TTL** needs a
     location-per-bucket layout and is deferred to a follow-up. A single
     `cfm_static` zone (not per-tier) keeps the conf minimal. Anti-stampede
     (`proxy_cache_lock` + `use_stale updating` + `background_update`) and a
     generation-prefixed key (`"g$cfm_cache_gen|$scheme://$host$request_uri"`;
     since widened to `g$cfm_cache_gen|$server_addr|$scheme|$cf_xfp://…` by the §4
     request-identity rails).
     CI guard `check_site_cache_config.sh` pins the bypass-by-default invariant
     + openresty↔angie parity.
     *Correctness constraints found in adversarial review (all folded into the
     shipped 3b), each now pinned by the guard or documented as a limit:*
     - **Response buffering MUST be on in the cache location.** nginx writes to
       `proxy_cache` only on the buffered upstream path; the static-asset
       location historically ran `proxy_buffering off` (a copy of the PHP/media
       streaming pattern — *not* a documented static-asset decision; the
       BUFFERING NOTE lists only PHP/admin + large media), which would make
       Tier A a **silent no-op** (stores nothing, never a HIT — undetectable by
       `nginx -t` or the Lua unit tests). Flipped to `proxy_buffering on`; the
       guard now **fails** any `proxy_cache` location left with buffering off.
       `proxy_request_buffering` stays off (the WAF F07/F08 large-upload
       streaming path is unaffected — that is request-body buffering).
     - **404s are not cached.** `proxy_cache_valid 404 1m` was dropped: on an
       atomic deploy a transiently-404 asset would stick as a cached 404 for up
       to a minute (the generation only bumps on explicit purge). Only `200`
       is cached; a static 404 at the origin is cheap.
     - **Encoding correctness relies on the origin's `Vary: Accept-Encoding`.**
       The cache key omits `Accept-Encoding` (nginx honours a `Vary` response
       header since 1.7.7, and Apache's mod_deflate sets it). A misconfigured
       origin that gzips *without* `Vary` could serve compressed bytes to a
       client that didn't ask for them — a documented residual of respect-origin
       caching, not keyed in (keying would fragment the cache 3× for correct
       origins).
     - **Unarmed vhosts still buffer (unavoidable, bounded).** `proxy_buffering`
       is location-level — nginx cannot toggle it per request/host — so flipping
       it on for the cache to work applies to every vhost hitting the static
       location, armed or not (`proxy_cache_bypass`/`proxy_no_cache` suppress
       *storing*, not *buffering*). Practical effect for an unarmed vhost: small
       assets buffer in memory (transparent), a large image may spill to temp as
       any buffered response does. Consistent with the global `proxy_buffering
       on` default (`location /`); the CHANGELOG states it rather than claiming
       "no change". Large media/archives are untouched (separate streaming
       location).
     - **One shared 10g zone — large images can evict small assets (accepted,
       tunable).** css/js/fonts and multi-MB images share `cfm_static`; a burst
       of large-image traffic on an armed vhost can LRU-evict the small
       high-hit-ratio assets. Open-source nginx has no per-object max-cacheable
       size, so a size cap would need a Content-Length map/Lua gate — deferred
       with the per-tier zone split (a follow-up); single zone is the deliberate
       minimal first cut.
     - **`use_stale updating error timeout` serves stale during origin trouble
       (deliberate).** When the origin errors/times out or an entry is updating,
       an expired copy is served rather than failing — anti-stampede resilience,
       self-healing once the origin recovers. Consequence: a static file changed
       or withdrawn *while the origin is unhealthy* keeps serving stale until the
       origin is back or the operator bumps the purge generation (the only
       forced-invalidation path). Accepted; operators purge to force-invalidate.
     - **Request-cookie allowlist (§4.1) is NOT enforced at Tier A — deferred to
       Tier B (decision, not oversight).** The §4 never-cache table lists the
       *"request carries a named app-session cookie → bypass"* rail as applying
       to every request, but `static_gate` (3b) does not consult it: the policy
       carries `strict_cookies`/`auth_cookies`, yet the built-in allowlist +
       ignore-list + strict-mode machinery lives nowhere at the edge yet. Rather
       than ship a partial allowlist, Tier A relies on the **response-side rails**
       nginx already enforces — a `Set-Cookie` or a `Cache-Control:
       private|no-store|no-cache` response is never stored — which catch the
       per-user cases in practice (WordPress/Woo/Laravel/Roundcube all emit one
       or the other), and static assets are public by nature (the standard CDN
       stance: cache static regardless of cookies). The **full §4.1 request-cookie
       rail lands with Tier B** (HTML micro-cache), where per-user content makes
       it essential. Residual (narrow, accepted): a static-extension URL an origin
       renders per-user with **neither** `Set-Cookie` **nor** a private
       `Cache-Control` would be cached and served cross-user on an armed vhost.
       `static_gate`'s doc-comment states the same scope so code and design agree.
   - **3c — stats/logging (as built).** The undeclared (→ dead) `cfm_cache_stats`
     shared dict is now declared in both confs; `cfm_cache_log.lua` gained a host
     arg (per-vhost keys `cache:vhost:<host>:status:<S>`) and `snapshot_vhosts()`,
     wired in the http-level `log_by_lua` — keyed by the CANONICAL policy key
     (`policy_key_for` → exact host, or the `*.suffix` pattern for a wildcard),
     never the raw request Host, so an armed wildcard vhost cannot let a client
     explode the dict with distinct sub-hosts; cardinality is bounded by the
     number of armed policies. Only **cacheable responses** are counted (a
     served/stored `200`, or a `304` revalidation) — a non-cacheable `404`/`3xx`
     MISS (which `$cfm_cache_non200` never stores) is excluded so a broken-asset
     URL can't peg a vhost's MISS count and depress its hit ratio. The edge
     PUSHES an absolute per-vhost snapshot to a new bridge route
     `POST /nginx/cache/stats` every ~60s (a cross-worker-locked timer in
     `cfm_cache.lua`, mirroring the WAF-stats `maybe_flush`); the daemon
     `handleCacheStats` → `OnCacheStats` hook → `siteCacheStatsStore` (UPSERT,
     absolute counts, in-memory/node-local). The push is triggered from the
     **HTTP-level `log_by_lua`** (`cfm_cache.maybe_flush_stats`), NOT `observe()`
     — `observe()` runs only in the HTTPS `header_filter`, which would leave an
     HTTP-only box's armed vhosts counted but never pushed. **Read paths filter
     to the CURRENTLY-armed policy set** (`armedCacheKeys`): the edge dict keeps a
     vhost's counts until an edge reload, so a vhost unarmed after its last push
     would otherwise linger as a stale "still cached" row — the armed store is
     truth. A by-host query resolves a concrete sub-host to its wildcard policy
     key (`resolveArmedCacheKey`) so a `*.suffix`-armed vhost is drillable.
     Read via `GET /api/v1/site-cache/stats[?host=]` (scope-filtered like the
     other site-cache endpoints), `cfm webtop site-cache stats [host]`, and two
     MCP tools — `site_cache_status` (armed vhosts + tiers) and
     `site_cache_stats` (HIT/MISS/BYPASS + a STRICT hit ratio — STALE/UPDATING/
     REVALIDATED serve from cache but sit in the denominator only, so read the
     full breakdown). `ucache="$upstream_cache_status"` was added to the `cfm`
     access log_format so `edge_access_tail` shows the verdict per request. **v1 scope:** a live totals view (counts since the edge last
     reloaded), not hour-bucketed history, and no cfm-admin column yet — both
     follow-ups. **Deferred to a focused follow-up:** the `whats_wrong`
     "armed but ~0 hits" signal (the automated form of what `site_cache_stats`
     already shows on demand — it would have surfaced the 3b buffering no-op).
4. **Tier B (micro-cache)** + the full §4 rails. Validate §5.5 items
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
`cli.go` (dispatch + help), `nginx_bridge.go` (routes: `handleCachePolicy` +
`ListCachePolicy` hook, and `handleCacheStats` snapshot read), `engine.go`
(construct store + a per-vhost cache-stats aggregate the daemon fills from the
`/nginx/cache/stats` pull + wire hooks),
`webdetector_config.go` + `webdetector_register.go` + `manager.go` (knobs),
`cmd/cfm/main.go` (canonical cache dirs already exist — reconcile bucket dirs).

**Add (Lua):** `configs/lua/cfm_cache.lua`.
**Touch (Lua/conf):** `configs/lua/cfm.lua` (Steps 2b/4 + static-location
mini-gate + `$cfm_cache_*` var decls), `configs/openresty.conf` +
`configs/angie.conf` (zones, `lua_shared_dict cfm_cache_stats`, cache locations,
`log_by_lua_block` wiring, fix stale comment), **extend** `cfm_cache_log.lua`
(per-host arg, §11).

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
- Docs: `docs/traffic-rules-ux-proposal.md` (recipes UX),
  `docs/challenge-access-control.md`, `docs/endpoint_scope_inventory.md`,
  `docs/proxy-performance.md` (origin keepalive / proxy_ssl),
  `docs/challenge-waf-release-checklist.md` (edge release gate).
