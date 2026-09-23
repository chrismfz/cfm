# Site Cache (per-vhost edge caching) — design & plan of record

Status: **Built** (§14 records each phase as built). This is the ONE design doc
for per-vhost edge caching in CFM; the operator view — arming, verifying,
stats, purge, turning Tier B on, incidents — is
[`site-cache-runbook.md`](site-cache-runbook.md).

- **Built:** the per-vhost store + API + CLI with scope checks
  (`internal/webdetector/site_cache*.go`); the edge feed and decision module
  (`configs/lua/cfm_cache.lua`); the `SITE_CACHE` kill switch; **Tier A**
  (static assets) live for armed vhosts; **Tier B** (micro-cache of HTML)
  built with the full §4 rails and in **dry run** until a node sets
  `MICRO_CACHE_ENFORCE = 1` (after §5.7); purge (generation bump); per-vhost
  stats (§11); the read-only MCP tools `site_cache_status` /
  `site_cache_stats`; the audit log; cache-dir provisioning; the CI guard
  (§13).
- **Not built:** the cfm-admin page and its recipe catalog (§7.3, §8 — the
  last item of the sweep), per-URL purge, static TTL buckets (§5.4), durable
  or historical stats, micro-cache on the Step 2b clearance fast path (§5.5),
  the `Vary: Cookie` bypass (§5.5 item 3), the `whats_wrong` "armed but ~0
  hits" signal, the §12 "planned" knobs.

The feature lets an operator (and a scoped cPanel user, for their own domains,
through the API) turn caching **on per vhost** — static-asset cache and/or
short micro-cache of HTML — pick a TTL, **purge** (global or per-vhost), and
see per-vhost state and effectiveness. Managed from the API and the CLI
(`cfm webtop site-cache …`), read through MCP; the cfm-admin page is planned
(§7.3).

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
   panic button: it stops caching on the node (`cfm_cache.lua` gates, stamp and
   stats push off, mirrored to the edge like `FP_POLICY`) within ~10 s — per
   node, from its own `detectors.conf` — **without** disarming any vhost, so
   re-arming is instant.
2. **Arming a vhost is the single opt-in — exact-host.** `myip.gr` and
   `www.myip.gr` are two explicit entries; there is **no** implicit `*.myip.gr`.
   Wildcards are an advanced opt-in, never a default.
3. **Bypass-by-default at the edge.** The conf pre-sets `$cfm_cache_skip "1"`
   (do not cache) and `$cfm_cache_gen "0"` at server level; the Lua
   (`static_gate` / `micro_gate`) flips skip to `0` **only** when every safety
   gate in §4 passes. A regression that drops the gate fails closed (no
   caching), never open.
4. **Caching lives *behind* enforcement.** WAF, Challenge, IP-block, traffic
   rules all run in the `access` phase; the cache is consulted in the upstream
   phase. **A Tier B HIT never bypasses WAF, a challenge, or an IP block** — the
   request runs the full `cfm.lua` (to its Step 4 allow) before any cached
   HTML is served. Tier A lives in the static-asset location, which never ran
   `cfm.lua` (assets skip its WAF / challenge / bridge decisions, cached or
   not — unchanged by caching); an nftables IP block still applies there, below
   the edge.
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
  (CFM's own read-only MCP tools happen to share the prefix:
  `site_cache_status`, `site_cache_stats`.)
- **Not** arbitrary per-request TTL down to the second (nginx constraint, see
  §5.4) — we offer a rich, extensible **menu of TTL buckets** instead.

---

## 2. Leftover inventory (build-on vs delete vs leave-alone)

There is **no** prior cache *design doc* — this is the first. There is only
leftover **code** from the ripped-out global caching. Verdicts:

| Leftover (at design time) | What it was | Verdict | As built |
|---|---|---|---|
| `configs/lua/cfm_cache_log.lua` | Ready HIT/MISS/BYPASS/… counter, `log_by_lua_block`-only, no I/O; orphaned. | Keep & wire (§11). | Wired: the http-level `log_by_lua` counts through it, the stats push reads it. |
| `ngx.shared.cfm_cache_stats` | Read by `cfm_stats.lua`, never declared → silent no-op. | Declare it (§11). | Declared, `8m`, both confs (plus `cfm_cache_uncacheable 4m` for Tier B). |
| Commented "Future caching" recipe in both confs | A note left for this work. | Implement as Tier A. | Implemented (the static-asset locations); the note is gone. |
| Cache dirs `/var/cache/nginx/cfm_static`, `…/cfm_micro` | Created by the daemon and `scripts/cfm-cache-dirs.sh`. | Use the canonical paths. | `cfm_static` + `cfm_micro_{1,2,5,10,30,60}s`; the single `cfm_micro` is **retired** (no conf ever used it; it may linger on older nodes — runbook §10). |
| `configs/lua/cfm_pcw.lua` | **NOT a cache remnant**: the live post-clearance nav-cadence shadow counter. | Do not touch. | Untouched. |
| `configs/lua/cfm_purge.lua` + `nginx_bridge_purge.go` | Purge plumbing (per-IP). | Extend for cache purge (§10). | Not extended: cache purge is the generation bump in the store (§10); these still purge per-IP state only. |

---

## 3. Architecture at a glance

Two tiers, one management model.

```
                     ┌─────────────────────────────── EDGE (OpenResty/Angie) ───────────────────────────────┐
  client ──HTTP(S)─► │ server{}:  set $cfm_cache_skip "1";  set $cfm_cache_gen "0";                         │
                     │           (HTTPS server also: set $cfm_micro_conf "";)                               │
                     │                                                                                      │
                     │ ┌ static-asset location (css/js/img/fonts…), both servers ───────┐  TIER A           │
                     │ │ access_by_lua: cfm_cache.static_gate() only (no cfm.lua)       │  zone cfm_static  │
                     │ │ proxy_cache cfm_static;  valid 200 1h (origin headers win)     │                   │
                     │ └────────────────────────────────────────────────────────────────┘                   │
                     │ ┌ location / (HTTPS): set $cfm_micro_conf "1"; ──────────────────┐  TIER B           │
                     │ │ access_by_lua_file cfm.lua (full enforcement)                  │  (no proxy_cache  │
                     │ │   Step 4 plain allow → micro_gate() → ngx.exec(@cfm_micro_N)   │     here)         │
                     │ └────────────────────────────────────────────────────────────────┘                   │
                     │ ┌ location @cfm_micro_<n>s  ×6  (internal) ──────────────────────┐  TIER B zones     │
                     │ │ proxy_cache cfm_micro_<n>s;  valid 200 <n>s; origin CC off     │                   │
                     │ └────────────────────────────────────────────────────────────────┘                   │
                     │ log phase: cfm_cache_log counters · micro_note · stats push (1 worker/node)          │
                     │   ▲ GET /nginx/cache/config  (each worker, every 60 s)                               │
                     │   │ POST /nginx/cache/stats  (one worker per node, every ~60 s)  ▼                   │
                     └───┼──────────────────────────────────────────────────────────────┼───────────────────┘
                         │   unix socket /var/run/cfm/cfm_nginx.sock, token-gated       │
                     ┌───┴─────────────────────── DAEMON (internal/webdetector) ────────┴───────────────────┐
                     │ siteCacheStore ←→ /var/lib/cfm/webdetector_site_cache.json · stats store (RAM)       │
                     │ API /api/v1/site-cache/*   CLI cfm webtop site-cache                                 │
                     │ MCP site_cache_status / site_cache_stats                                             │
                     └──────────────────────────────────────────────────────────────────────────────────────┘
```

- **Tier A — static asset cache** (low risk). Caches
  `css/js/map/woff/woff2/ttf/eot/png/jpg/jpeg/gif/webp/ico` by extension, in
  the existing static-asset location that already skips the heavy `cfm.lua`,
  on both the HTTP and HTTPS servers. Low risk because assets are rarely
  per-user, and nginx itself never stores a `Set-Cookie` or `private` answer.
  Tier A reads no request cookie and no path, so that is all it relies on
  (§4 residuals).
- **Tier B — micro-cache of anonymous pages** (high risk — this is what broke
  before). Any anonymous GET/HEAD through the HTTPS `location /`, HTML or not.
  Very short TTL, hard gated (§4), and in dry run until
  `MICRO_CACHE_ENFORCE = 1`. Absorbs bursts on heavy pages (the `myip.gr`
  case).

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
| Origin `Cache-Control: private\|no-store\|no-cache` → never store | Tier A: nginx default (not ignored). Tier B (as-built): the micro locations set `proxy_ignore_headers Cache-Control Expires X-Accel-Expires` so the TTL is always the bucket's, and put the shared-cache "do not store" signals back on `proxy_no_cache` through two `volatile` maps: `$cfm_cc_nostore` (`private` / `no-store` / `no-cache` / `s-maxage=0`, anywhere in the header, any case — `no-cache="Set-Cookie"` counts) and `$cfm_xae_nocache` (`X-Accel-Expires` `0` or any absolute `@<time>`). **Deliberately not `max-age=0`**: it is aimed at browsers too, and the common `.htaccess` recipes (H5BP, WP Rocket: `ExpiresByType text/html "access plus 0 seconds"`) send it on every HTML page, so honouring it would switch micro off for exactly the sites it is for; `s-maxage=0` is the shared-cache opt-out and is honoured | origin keeps the final say on *whether* a page is stored; on Tier B not on *how long* (a `max-age=3600` or far-future `Expires` page would otherwise sit in a micro zone for an hour, or for as long as the date says). Residual: a page whose only "do not cache" signal is `max-age=0`, a past or invalid `Expires`, a malformed `Cache-Control` value nginx would refuse (`max-age="60"`, `max-age=-1`) or `Pragma: no-cache` (nginx never read `Pragma`) is micro-cached for the bucket TTL. Stricter the other way: `X-Accel-Expires: 60` + `Cache-Control: no-cache` (natively stored — `X-Accel-Expires` wins) is not stored |
| Panel hosts/ports (`:2083/:2087/:2096`), webmail hosts, `/.well-known/`, `/acctxfer*`, cPanel/webmail bypass paths → never | The panel ports are separate listeners with no cache location; `/.well-known/` is routed at `cfm.lua` Step 0a1. As-built: `panel_host()` in `cfm_cache.lua` skips BOTH tiers for a host with a panel prefix — the `cfm_panel_hosts.lua` list `cfm.lua` and `cfm_panel.lua` share (`cpanel`, `whm`, `webmail`, `webdisk`, `mail`) plus the cache-only service prefixes `autodiscover`, `autoconfig`, `cpcalendars`, `cpcontacts` — whether the policy is a wildcard or the exact host; a missing module caches nothing (one WARN at load). Tier B also skips `/acctxfer*`, `/wp-admin`, `/administrator/`, `/admin/`, `/sysadmin/`, `/___proxy_subdomain_*`, any path to a PHP script (`.php`, `.php<digit>`, `.phtml`, `.pht`, `.phar` at the end of the path or of a segment — `/index.php/cart` too), `?doing_wp_cron` and `?_envelope` (WordPress REST then moves the response headers — a `Cart-Token` — into the body) | **cPanel / webmail / SSO / AutoSSL broken** |
| Cache key excludes cookies; carries purge generation, **destination IP**, the **listener scheme** and the **scheme the origin is told** (as-built) | `proxy_cache_key "g$cfm_cache_gen\|$server_addr\|$scheme\|$cf_xfp://$host$request_uri"` | per-user fragmentation / leakage; **multi-IP poisoning** — the origin is chosen by `$server_addr`, so without it a request to IP B with `Host: victim` stores B's default vhost under victim's key. **Both** schemes, not either: `$scheme` is the listener (:9080 → origin :80, :9043 → origin :443, which Apache may answer from different vhosts — e.g. a domain with no SSL vhost falls back to the IP's default SSL site), `$cf_xfp` is what the origin is told (differs from `$scheme` only behind a trusted peer such as Cloudflare Flexible SSL). Keying on `$cf_xfp` alone let a direct HTTPS client fill an entry that a Cloudflare visitor on :80 then hit (reproduced) |
| Request carries **`Authorization`** → never read, never store (as-built) | `map $http_authorization $cfm_req_auth` (any non-empty value → `"1"`; a raw predicate would read `Authorization: 0` as false) on `proxy_cache_bypass` **and** `proxy_no_cache` in every cache location; Tier B `micro_decision` also reports `bypass:authorization` and does not route | **basic-auth (cPanel Directory Privacy) / bearer response served to anonymous visitors** — nginx does not bypass on `Authorization` by itself |
| **Forwarded headers pinned** in cache locations (as-built) | `proxy_set_header X-Forwarded-Host $host;` and `""` (not sent) for `X-Forwarded-Server/-Port/-Scheme/-Protocol/-Prefix/-Ssl/-Uri/-Path`, `X-Host`, `X-Original-Host`, `X-Original-URL`, `X-Original-Uri`, `X-Rewrite-URL`, `Forwarded`, `Front-End-Https`, `X-Url-Scheme`, `X-Scheme`, `X-HTTP-Method(-Override)`, `X-Method-Override`. Applies to **every** request through a cache location, armed vhost or not (all vhosts' static assets use the Tier A location) | cache poisoning — an app building absolute URLs / routes from these writes attacker input into a page cached for everyone. A denylist of the known URL-building headers, not a proof |
| Lock wait set **per tier** (as-built) | `proxy_cache_lock_timeout 1s` (Tier A) / `5s` (Tier B) | the timeout must outlast the fill, or a cold-key burst all reaches the origin (when it expires every waiter is sent upstream and nothing is stored); yet on an uncacheable key (Set-Cookie / no-store / non-200) waiters queue at 500 ms steps until it expires — nginx has no hit-for-pass. Static files fill in well under 1 s and a popular 404 is the usual uncacheable key → 1 s. HTML can take seconds to render → 5 s, and Tier B remembers its uncacheable keys (next row) |
| Tier B **remembers an uncacheable key** (as-built) | `cfm_cache.micro_note()` in the http-level `log_by_lua`: a micro request that fetched (`MISS`/`EXPIRED`) an answer nginx could not store (non-200, `Set-Cookie`, `$cfm_cc_nostore`, `$cfm_xae_nocache`, a `*` in `Vary` or a `Vary` over 128 bytes) marks `md5($server_addr\|$scheme\|$cf_xfp://$host$request_uri)` in `lua_shared_dict cfm_cache_uncacheable`; `micro_gate` skips micro for a marked key (debug token `bypass:uncacheable`), then the next request after the mark probes again. A `MISS` marks for 60 s; an `EXPIRED` refresh (the page changed: it sets a cookie, went private, redirects, 401/403/404/410) for 240 s — longer than the largest micro zone's `inactive` (180 s; the guard pins the 30 s margin), so the old copy is evicted before the next probe. A 5xx or a request-level 4xx (400, 405, 406, 408, 411-417, 421, 429, 431) is origin trouble or about the request, not the page: on an `EXPIRED` key it **never marks** (the stale copy absorbs it — next row — and any client could provoke one), on a `MISS` it marks for 5 s, the lock timeout (the lock does not spare the origin — every waiter reaches it, as the next filler or when its wait times out — it only delays each visitor up to 5 s; measured on a cold 503 key, 20 req/s: every request reached the origin either way, p50 5.5 s through the lock vs 0.5 s direct). `X-Accel-Buffering: no` (nginx then streams and stores nothing) counts as not storable; an `X-Accel-Redirect` answer is served by an internal redirect and is neither stored nor remembered | the lock queue above: measured on a 1 s page that sets a cookie, 8 concurrent clients finished at 1, 2, 3.5, 4.5, 5.5, 6, 6, 6 s before the mark and all in ~1 s after it. The dict evicts least-recently-used marks when full (a lost mark costs one re-probe); a conf without the dict just does not remember. Residual (like Varnish hit-for-miss): one client's non-storable answer — a UA or language redirect, a cookie, an origin WAF's 403 — skips micro for that URL for everyone until the mark expires, so a client can keep micro off for one URL with a request per mark; the URL is then served as without micro, nothing wrong is stored |
| Tier B: a stale page is not kept alive by refreshes that cannot be stored; a failing origin is (as-built) | `proxy_cache_background_update off` and `proxy_cache_use_stale updating error timeout http_500 http_502 http_503 http_504` in the micro locations (Tier A keeps background updates on) | with background updates on, an expired page is served stale while a background fetch refreshes it — and when that fetch cannot be stored (the page now sets a cookie, turned 404, went private) the stale copy is served on every request for as long as the key stays warm. Off, the request that finds the page expired fetches it itself and only requests arriving during that fetch get the stale copy; a page-changed answer then marks the key long enough for the copy to age out (previous row), so it is served for one fetch window. An origin that fails — connection error, timeout, or a 500/502/503/504 answer — keeps the stale copy served, the fetching request included (measured, 10 clients on a hot page whose origin answers 503 after 1 s: 4 origin hits and all clients 200 with this, 31 hits and 31 clients 503 when a 5xx marked the key). There is **no bound** on that while the origin keeps failing and the key gets a request within its zone's `inactive` (30-180 s): an intentional 503 (a maintenance page) is not shown on a warm key — purge the vhost, or set `MICRO_CACHE_ENFORCE = 0`, to show it. Other 5xx (501, 505, 507, CloudLinux's 508 "resource limit reached") are outside what nginx's `use_stale` can cover: the request that refreshes gets them, everyone arriving meanwhile the stale copy. A worker killed during a refresh can leave its entry locked stale (nginx logs `ignore long locked inactive cache entry`); a purge clears it |
| Tier B **forwards no forgeable client-IP / geo / hint header** (as-built) | micro locations: `X-Forwarded-For $remote_addr` (the real client alone — `mod_remoteip` reads it behind 127.0.0.1, so `REMOTE_ADDR` is unchanged), `CF-IPCountry` / `CF-Visitor` only from the trusted peer (`$cfm_cf_ipcountry` / `$cfm_cf_visitor`, the `$cf_xfp` gate), and `True-Client-IP`, `Client-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `Fastly-Client-IP`, `X-Originating-IP`, `X-ProxyUser-Ip`, `X-Forwarded`, `X-Country-Code`, `HTTPS`, `X-Arr-Ssl`, `X-Proto`, `CloudFront-Forwarded-Proto`, `Surrogate-Capability`, `Proxy` (httpoxy), `Content-Type`, `Content-Encoding` not sent; `X-Real-IP` / `CF-Connecting-IP` are `$remote_addr` (guard-pinned) | WooCommerce geolocation takes `CF-IPCountry` before any IP lookup, PHP helpers read `Client-IP` / the `X-Forwarded-For` prefix, Flexible-SSL snippets read `CF-Visitor`: a direct client choosing any of them would store its forged answer for everyone. The client IP the origin sees is still a residual (above) — the real one |
| Tier B **never forwards a request body** (as-built) | `proxy_pass_request_body off` + `proxy_set_header Content-Length ""` in every micro location (micro serves only GET/HEAD) | fat-GET poisoning: a body on a GET is not in the key, yet an app may read it — the WordPress REST API reads a JSON body on any method, so `GET /wp-json/wp/v2/posts` with `{"search":…}` in the body would store an attacker-shaped listing for everyone (verified with Content-Length, chunked and HTTP/2 bodies). Tier A keeps forwarding bodies (static files, and a POST to a static-extension URL must keep working) |
| Tier B request rails (as-built) | `micro_decision`: a `Range` request, `Accept: text/event-stream` and a partial-page request (`X-Requested-With`, `X-PJAX`, `HX-Request`, `Turbo-Frame`, `X-Inertia` present, empty or not — apps answer those with a fragment, usually without `Vary`), a credential-style request header (`Cart-Token`, `WooCommerce-Session`, `X-WP-Nonce`, `X-Api-Key`, `X-Auth-Token`, `X-Access-Token`) and a `Cookie` header over 8 KB bypass; on the response side a micro location never stores an answer that hands out a session token in a header (`$upstream_http_cart_token` / `$upstream_http_woocommerce_session` on `proxy_no_cache`, mirrored by `micro_storable`, so the key is remembered) — the token-less `GET /wp-json/wc/store/v1/cart` is how a headless WooCommerce client obtains its `Cart-Token`, and a stored one would put every such shopper in one cart. `X-Requested-With` counts with any value: Android WebView (in-app browsers — Facebook, Instagram) sends its app package in it on every request, so that traffic is not micro-cached — an accepted hit-ratio cost, since an app that tests `!empty($_SERVER['HTTP_X_REQUESTED_WITH'])` would otherwise store the fragment it serves them; micro routes only from the HTTPS server's `location /` (the conf sentinel `set $cfm_micro_conf "1"`, `""` by default at server level; `micro_gate` requires `"1"`), never on an internal redirect (`ngx.req.is_internal()`: a named-location redirect keeps the sentinel; a redirect to a URI re-runs the `""` default), and only on an nginx core ≥ 1.23 (older ones expose only the first of several `Cache-Control` headers to the map). `rewrite … last`, `ngx.req.set_uri(…, true)` and every redirect also keep the sentinel, and all of them make the request internal (verified), so the check refuses them; the guard additionally keeps `location /` free of `rewrite` / `try_files` / `error_page` and of `rewrite_by_lua*` (in it, at its server and http level), and of buffering off there or inherited | a micro location buffers, so an SSE stream would be held back until it ends, and the no-buffer PHP/admin and streaming passthroughs would stop streaming; an older live conf (no sentinel) never gets newer Lua's micro routing |
| `cfm_clearance` is edge-set, not origin | see §5.5 open item | edge cookie poisoning the cache |

**Residuals (cannot be seen at the edge).** An origin that varies a `200` on
something outside the key **without sending `Vary`** fills the cache with
whatever the first client got — and on a cold key an attacker can choose to be
that client:
- the **client IP** (`Require ip`, cPanel IP Blocker, a per-IP throttle that
  answers 200) — on Tier B also the country a trusted Cloudflare peer reports
  in `CF-IPCountry`, forwarded but not keyed — or **`Referer`** (hotlink
  protection);
- **`User-Agent` / `Accept` / `Accept-Language` / `Accept-Encoding`** and the
  UA-class hints (`Sec-CH-UA-Mobile`, which `wp_is_mobile()` reads first,
  `X-Wap-Profile`, `X-Operamini-Phone-UA`) — mobile themes, WebP negotiation by
  `.htaccess`, language auto-detect, compression — safe only when the origin
  sends `Vary` (nginx then stores one copy per variant);
- on Tier B, a **non-session preference cookie** the app reads server-side: the
  common WordPress consent / age-gate cookies bypass (Cookie Notice
  `cookie_notice_accepted` / `hu-consent`, CookieYes legacy
  `viewed_cookie_policy`, Moove `moove_gdpr_popup`,
  Complianz `cmplz_*`, Age Gate `age_gate*` — as do the language / currency
  cookies; CookieYes' `cookielawinfo-checkbox-*` do not, they are set for every
  visitor on the first view), so a consenting or age-verified visitor is served
  uncached; any
  other such cookie of the site goes in the vhost's `auth_cookies`. (A cheaper
  follow-up would key on the value of a short fixed list instead, as WP Rocket's
  "dynamic cookies" do.) WooCommerce Order Attribution's `sbjs_session` (set
  client-side on every page, never read server-side) is exempt from the
  `*_session` rule, or every returning shopper would bypass;
- on Tier B, a credential in a **custom header** other than the ones that
  bypass (`Cart-Token` — the WooCommerce Store API's headless session, whose
  cart / checkout GETs send no `Cache-Control` before WooCommerce 10.6 —,
  `WooCommerce-Session`, `X-WP-Nonce`, `X-Api-Key`, `X-Auth-Token`,
  `X-Access-Token`), or a page the app switches to a fragment on a header
  outside the bypass list above (the common partial-page headers do bypass);
  on Tier A, request cookies are not consulted at all (§14 3b — static assets
  rely on the response-side rails);
- on Tier B, what a stored response **replays**: the origin's own headers as
  sent (an `Age`, a `Cache-Control: max-age` — so a browser may keep its copy
  up to one bucket longer), a per-response CSP nonce, and an
  `Access-Control-Allow-Origin` echoed from the request `Origin` without
  `Vary: Origin` (the first caller's origin for everyone); and a per-visitor
  token a page renders from a cookie the lists do not know (a cookie whose
  name contains `csrf` or `xsrf` bypasses).

Non-200 answers are safe (only-200 rail), so the classic cached-throttle
(`429`/`503`) incident cannot recur; a 200 that depends on who asked can. Do not
arm a vhost whose pages are gated or negotiated that way.

Collateral of the header pinning: behind a proxy that rewrites `Host` and
supplies its own `X-Forwarded-Host`, a micro-armed vhost's cached (anonymous)
pages build absolute URLs from `$host`, while uncached requests through
`location /` still see the proxy's value.

`check_site_cache_config.sh` pins the conf-side rails above in every
`proxy_cache` location of both confs: bypass-by-default, only-200, the
`$cfm_req_auth` map + predicates, the full key, the per-tier lock timeout,
`Host $host` and `X-Forwarded-Proto $cf_xfp`, the forwarded-header pins, buffering, `internal` + access
override on micro, and on micro no request body forwarded, the client-IP /
geo / hint header pins, the session-token response predicates
(`$upstream_http_cart_token` / `$upstream_http_woocommerce_session`), the exact
`proxy_ignore_headers Cache-Control Expires X-Accel-Expires`, the
`$cfm_cc_nostore` / `$cfm_xae_nocache` predicates (their maps exact, `volatile`
included, nothing else writing them), `background_update off`, the exact
`use_stale` list and one `proxy_cache_valid 200 <N>s` matching the bucket's
name and zone — and, file-wide, that `proxy_ignore_headers` never lists
`Set-Cookie` or `Vary` and lists `Cache-Control` / `Expires` / `X-Accel-Expires`
only in a micro location (one at server/http level would be inherited by Tier
A), that the `$cfm_micro_conf` sentinel sits once in a redirect-free, buffering
`location /` of the server holding the micro locations (with its server-level
`""` default) and nowhere else, that `lua_shared_dict cfm_cache_uncacheable`
exists and every micro zone's `inactive` sits at least 30 s below `cfm_cache.lua`'s
`MICRO_UNCACHEABLE_STALE_TTL`, that `proxy_cache_convert_head` is never turned
off, that the conf includes exactly its known files, and that
`proxy_cache_methods` never lists a non-GET/HEAD method. A rail variable can be
written by more than a `set`, so the other spellings are refused too: a regex
named capture named `cfm_*` / `cf_*` / `xfp_*` (or after a header family,
escaped quotes read as nginx reads them), any writer (`set`, any `set_*` —
`set_by_lua*`, set-misc —, `auth_request_set`, `js_set` / `js_var`,
`perl_set`, `map`, `geo`, `split_clients`, a block entry that opens with the
variable) of a `$http_*` / `$upstream_http_*` / `$cookie_*` /
`$arg_*` variable — verified on nginx 1.24: each SHADOWS the request/response
value (a `map` for the whole http block), so `map … $http_authorization`
would turn the credentialed-request rail off and `set
$upstream_http_cart_token ""` the session-token one — a string-form
`*_by_lua` directive, and inline Lua that uses `ngx` / `ngx.var` other than
as `ngx.<field>` / `ngx.var.<name>` (brackets, an alias, `require "ngx"`: a
computed name) or assigns an `ngx.var.cfm_*` / `cf_*` / `xfp_*` (a multiple
assignment included); a log message that merely says "ngx" is not code. The micro
buckets are `cfm_cache.lua`'s `MICRO_BUCKETS` — every conf declares exactly
those zones and `@cfm_micro_<n>s` locations — and the openresty↔angie micro
blocks are compared over the span the parser closes each on, not by
indentation. Beyond the conf: `cfm_micro_entry_structure_test.lua` pins that
`cfm.lua` enters micro only at Step 4 (after the WAF, challenge and bridge
decisions), and `cfm_cache_edge_parity_test.lua` feeds the daemon's own feed
(a fixture `site_cache_edge_parity_test.go` generates from the real handler)
to `cfm_cache.lua`, asserting the stats key of every request host matches
`StatsKeyFor`, the real flush path pushes exactly the armed keys, and every
feed field is one the edge knows and keeps in the policy it applies.

`cfm_clearance`-cookie holders (cleared visitors) are still *anonymous* to the
app, and the cookie is on the ignore-list, so they **may** be served
micro-cache; the cache key never varies on the clearance cookie. *As built they
are not:* a cleared visitor returns at cfm.lua's Step 2b fast path, which is
not a micro entry until the clearance-cookie ordering item (§5.5 item 1) is
verified on a live edge — micro is entered only at Step 4 (uncleared but
allowed).

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
- **Ignore-list (treated as anonymous):** **`cfm_clearance` and every `cfm_*`
  CFM-set cookie**, plus common non-session cookies (`_ga`, `_gid`, `_gcl_*`,
  `_fbp`, the IAB `euconsent*` / `__cmp*`, …). A visitor whose **only** cookies
  are these **IS cached.** *As built* the ignore-list is consulted only under
  `strict_cookies` (in the default mode any cookie NOT on the auth allowlist is
  anonymous anyway); and the WordPress consent / age-gate cookies read
  server-side (`cookie_notice_accepted`, `viewed_cookie_policy`, `cmplz_*`, …)
  are on the **auth** list, so they bypass (§4 residuals).

So the answer to "won't our own challenge-solve cookie stop caching?" is **no**:
`cfm_clearance` is on the ignore-list. A visitor who is *anonymous but cleared*
(solved the challenge, no app login) is exactly the burst traffic micro-cache
exists to absorb on a heavy page — and they get cached once Step 2b becomes a
micro entry (as built, only Step 4 is; see above). Only a **named app session**
bypasses.

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

**The debug stamp is how you validate this in production**: on a micro-armed
vhost, `X-CFM-Cache: … microcache=bypass:auth:<cookie>` / `strict:<cookie>`
names the cookie that declined a request (§11.3; `docs/site-cache-runbook.md`
§4) — tune the allowlist there, don't guess. The §11 counters do **not** show
it: a request the cookie rails decline never reaches a cache location, so it
is not counted at all (BYPASS counts something else, §11.1).

> **As-built (Tier A / 3b):** this request-cookie allowlist is **not** wired on
> the Tier A static path — `static_gate` does not read
> `strict_cookies`/`auth_cookies`. Tier A relies on the response-side rails
> (`Set-Cookie` / `Cache-Control: private` → never stored) plus the public nature
> of static assets. Decision + residual: §14 item 3b.
>
> **As-built (Tier B):** the built-in allowlist/ignore-list machinery ships in
> `cfm_cache.lua` (`micro_cookie_verdict` + `micro_decision`). It is the full
> request-side model — auth allowlist (built-in names + per-vhost
> `auth_cookies`; a name is compared as the app reads it — PHP's `.` / space /
> lone `[` → `_` and `a[b]` read as `a`, URL-decoded as older PHP and Rack do,
> `__Host-`/`__Secure-` prefixes stripped; parsed in linear time, and a
> `Cookie` header over 8 KB is not micro-cached), the
> `cfm_*`/analytics ignore-list, `strict_cookies`, the GET/HEAD, credential,
> Range / event-stream, path and panel-host rails — and `micro_gate` routes on
> it under `MICRO_CACHE_ENFORCE = 1`; in dry-run the verdict is surfaced only on
> the debug-gated `X-CFM-Cache` header (`microcache=would/<n>s` |
> `microcache=bypass:<reason>`). The **response**-side rails are enforced at
> store time by the micro locations: `Set-Cookie` / `Vary` natively, and — since
> they ignore the origin's `Cache-Control` / `Expires` / `X-Accel-Expires` for
> the TTL — the `$cfm_cc_nostore` / `$cfm_xae_nocache` maps (§4).

---

## 5. Edge mechanics

### 5.1 Cache zones — declared once, inert until used

`proxy_cache_path` must live in `http{}`. Declaring a zone caches nothing; a
zone only bites when a location activates `proxy_cache` **and** the bypass gate
allows it. Declared identically in **both** confs, under
`/var/cache/nginx/cfm_*` (the paths the daemon already creates):

*As built* (the planned per-TTL static zones `cfm_static_{1h,7d,30d}` were not
built — Tier A has one zone and follows the origin's headers, §5.4):

```nginx
# Static (disk): one zone
proxy_cache_path /var/cache/nginx/cfm_static      levels=1:2 keys_zone=cfm_static:20m    max_size=10g  inactive=7d   use_temp_path=off;
# Micro (tiny, short-lived; on disk): 1/2/5/10/30/60s — cfm_cache.lua MICRO_BUCKETS
proxy_cache_path /var/cache/nginx/cfm_micro_1s   levels=1:2 keys_zone=cfm_micro_1s:10m  max_size=512m inactive=30s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_2s   levels=1:2 keys_zone=cfm_micro_2s:10m  max_size=512m inactive=30s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_5s   levels=1:2 keys_zone=cfm_micro_5s:10m  max_size=512m inactive=60s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_10s  levels=1:2 keys_zone=cfm_micro_10s:10m max_size=512m inactive=60s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_30s  levels=1:2 keys_zone=cfm_micro_30s:10m max_size=1g   inactive=120s use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_60s  levels=1:2 keys_zone=cfm_micro_60s:10m max_size=1g   inactive=180s use_temp_path=off;
```

Each cache location also carries the **anti-stampede** trio (§5.6):
`proxy_cache_lock on;`, `proxy_cache_use_stale updating error timeout;`
(Tier B adds `http_500 http_502 http_503 http_504`),
`proxy_cache_background_update on;` (Tier B: `off`, §4) — plus
`proxy_cache_bypass $cfm_cache_skip $cfm_req_auth;` / `proxy_no_cache
$cfm_cache_skip $cfm_cache_non200 $cfm_req_auth …;` (§0, §4) and
`proxy_cache_key "g$cfm_cache_gen|$server_addr|$scheme|$cf_xfp://$host$request_uri";`
(§4, §10). `check_site_cache_config.sh` pins every one of these (§13).

### 5.2 Per-request decision transport: edge-pull → per-worker table → local lookup

This is the **WAF/Clam/H3-exclude** model, **not** the fppolicy per-key RPC
model — chosen deliberately:

- fppolicy does an **RPC per key** because fingerprints are **high-cardinality**
  (thousands) → it needs an RPC budget.
- Cache policy is **per vhost → low cardinality** (the number of domains). So
  the edge **polls the whole table** via `GET /nginx/cache/config` and **each
  request does a local map lookup** — zero RPC on the hot path, no budget to
  tune.

*As built*, `configs/lua/cfm_cache.lua` mirrors `cfm_h3_config.lua`: each
worker keeps its own table (no shared dict), refreshed every 60 s (fixed) by
an async `ngx.timer.at(0)` that the first request finding it stale schedules;
a failed pull keeps the last table. `rebuild_cache` turns the feed into exact
hosts + `*.suffix` wildcards (most specific first); `policy_for(host)` returns
the raw policy `{gen, static, micro, strict_cookies, auth_cookies}` (or nil).
The public entry points are `static_gate`, `micro_gate`, `observe`,
`policy_key_for`, `maybe_flush_stats` and `micro_note`. It is a `require`d
module, not a file-local — an `access_by_lua_file` resets file-locals per
request (the WAF-excl PITFALL).

### 5.3 Insertion points in `cfm.lua`

Micro-cache (Tier B) is decided at the **allow-return**, after all enforcement.
The plan named two points — **Step 2b** (the clearance fast path) and **Step 4**
(the plain allow); *as built* it is **Step 4 only** (Step 2b waits on §5.5
item 1), and `cfm_micro_entry_structure_test.lua` pins that. Step 4 is after
Step 0a1 (the `/.well-known/` carve-out), so ACME/DCV is never cached.
`micro_cache_target()` calls `cfm_cache.micro_gate()` under a pcall;
`micro_gate` applies the §4 rails and, on a cache decision, sets

```lua
ngx.var.cfm_cache_skip = "0"
ngx.var.cfm_cache_gen  = tostring(p.gen or 0)
return "@cfm_micro_" .. bucket .. "s"   -- cfm.lua then: return ngx.exec(target)
```

HTTPS only (the micro locations live in the HTTPS server), only from the
`location /` carrying the `$cfm_micro_conf "1"` sentinel, never on an internal
redirect, and only while `MICRO_CACHE_ENFORCE = 1`.

Static (Tier A) is decided in the static-asset location, which skips *all* of
`cfm.lua` (correct for assets). Its `access_by_lua_block` calls only
`cfm_cache.static_gate()` — no WAF, no decision RPC: one per-worker table
lookup; when `SITE_CACHE = 0` it returns at once. For an armed static tier (and
not a panel host) it sets `$cfm_cache_skip = "0"` and `$cfm_cache_gen`.

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
> `proxy_cache_valid 200 <n>s;`, and the allow-path (Step 4) `ngx.exec`s to the
> bucket its policy snaps to. B1 declared the six zones + the
> `cfm_cache._micro_bucket` snapper; B3a added the internal locations and B3b
> the routing.

The stored TTL is parsed with the units the daemon accepts (`s`/`m`/`h`/`d`,
an optional leading `+`): `1m` is 60 s (as-built fix — the edge used to read only the digits, so `1m` was
1 s), and anything above 60 s clamps to the 60 s bucket; an empty or
unparseable TTL gets the 1 s bucket.

**Micro — recommended presets AND custom, both work.** The micro bucket set is
**`{1, 2, 5, 10, 30, 60}s`** (6 tiny zones). *As built* the TTL comes only from
the tier's `ttl` (`--micro-ttl`); a recipe name does not set it, so a micro
tier without a TTL gets the 1 s bucket. The planned UI (§7.3) offers:
- **Recommended presets:** `micro_safe → 1s`, `micro_aggressive → 10–30s`.
- **Custom TTL field:** the operator types a value; it **snaps to the nearest
  bucket**. For micro-cache (herd protection), the difference between 7s and 8s
  is operationally meaningless, so the snapped set behaves as effectively
  continuous — "custom" is honoured without fighting nginx. Per-vhost choice
  (preset or custom) is **reload-free** (just a policy value the edge pulls). An
  admin who wants a bucket outside the menu adds one = a rare zone-list regen +
  reload (never a per-vhost event).

**Static** buckets `{1h, 7d, 30d}` and an aggressive `Cache-Control: public,
immutable` were planned and **not built**: *as built* Tier A has one zone
(`cfm_static`) whose location keeps the origin's `Cache-Control` / `Expires`
with a `proxy_cache_valid 200 1h` fallback, and `static_gate` reads only the
static tier's `on` — the stored static recipe and TTL are labels (the CLI and
MCP descriptions say so).

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
   only and Step 2b is added once verified. (Step 4 only, as shipped. Harness
   observation, PR-3: on stock nginx 1.24 + lua-nginx-module 0.10.26, a header
   set with `ngx.header` in the access phase before `ngx.exec` to the micro
   location — `X-CFM-Action` — is present on the micro response, HIT included.
   Evidence for the ordering, not the verification: that belongs on a live
   OpenResty/Angie edge with the real clearance refresh.)
2. **Origin keepalive.** Caching sits in front of the origin regardless of the
   `ORIGIN_KEEPALIVE` pools; 443 `proxy_ssl_session_reuse off` is unaffected.
   Verify HIT/MISS accounting with KA armed. (*Open* — not yet checked on a
   live edge with KA armed.)
3. **`Vary`.** Respect only a safe subset (e.g. `Accept-Encoding`); a
   `Vary: Cookie` from origin must force bypass, not key-fragment. (*Not
   built:* only `Vary: *` or a `Vary` over 128 bytes is treated as
   unstorable — `micro_storable`; any other `Vary`, `Cookie` included, gets
   nginx's native per-variant keying. A cookie that decides a variant is
   already a bypass when it is a session cookie, §4.1.)

### 5.6 Performance — this must LOWER CPU, not raise it

The whole point is fewer origin round-trips, so the machinery itself must never
become the cost. Three invariants make that a guarantee, not a hope:

- **Invariant 1 — zero per-request daemon RPC.** A cache decision costs **one
  per-worker table lookup** (`cfm_cache.policy_for`), never a bridge call. *As
  built:* each worker pulls the policy table on its own every 60 s (fixed, no
  knob), from an async `ngx.timer.at(0)` that the first request finding the
  cache stale schedules — the `cfm_h3_config.lua` model, no shared dict. This is
  *why* we chose edge-pull over the fppolicy per-key RPC (§5.2): per-vhost is
  low-cardinality, the whole table fits in a worker, and **no request ever
  waits on the daemon.**
- **Invariant 2 — near-zero cost when unused.** A `has_any` meta flag (like WAF
  `handleWAFExcludedMeta`) gates both tiers: if `SITE_CACHE=0` or no vhost has
  caching enabled, the static-location `access_by_lua_block` and the Step 4
  hook short-circuit on a single boolean (`has_micro` likewise for Tier B) — the
  static path stays effectively as cheap as a bare `return`. A node that doesn't
  use caching pays nothing.
- **Invariant 3 — the request path never blocks on the daemon.** Fail-open
  everywhere: a failed/slow/absent config pull keeps the last snapshot, or (if
  never pulled) leaves caching off (bypass-by-default). A daemon hiccup can only
  ever mean "no caching," never a stalled or slowed request. *As built* each
  pull is one fresh unix-socket request (`Connection: close`, 200 ms timeouts)
  in a timer, never on the request path; there is no circuit breaker (a failed
  pull just keeps the last table until the next one).

**Anti-stampede is the actual CPU win.** Every cache location sets
`proxy_cache_lock on;` + `proxy_cache_use_stale updating error timeout;` +
`proxy_cache_background_update on;` (Tier B: `off`, see §4 — the request that
finds a page expired refreshes it, everyone arriving meanwhile gets the stale
copy). Under a burst on a heavy page the origin
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
uncached, 45 through a 5 s-lock micro location, max 5.3 s). So Tier B
remembers an uncacheable key and skips the cache for it (as-built, §4
"remembers an uncacheable key" row; measured there) — only the requests that
arrive while a probe of such a key is in flight (one probe per mark) queue.

**Per-request cost ledger (caching ON for a vhost):**

| Cost | Magnitude | Notes |
|---|---|---|
| policy lookup (per-worker table) | µs | normalize_host + one table lookup + a scan of the wildcard list |
| cache key md5 + lookup | µs | nginx-native, only in cache locations |
| stats `incr` (log phase) | ~0.5 µs, off the serving path | counted responses of armed vhosts only (no knob) |
| background config pull | once / 60 s / worker | **not** per-request |
| stats push | once / 60 s / node | ~40 ms in a timer at 5000 vhosts (§14 3c) |
| **on HIT** | **− origin round-trip, − PHP exec** | **large net CPU/latency saving** |
| on MISS | + key hash + store | trivial vs the origin fetch it wraps |

**Disk vs RAM.** `use_temp_path=off` avoids a cross-filesystem rename. Micro
entries are tiny and short-lived, so the micro zones may optionally sit on
**tmpfs** (RAM-backed, zero disk I/O) with a bounded `max_size` — a good default
for herd protection. Static stays on disk (larger, longer-lived). *As built*
every zone is on disk under `/var/cache/nginx` (nothing provisions a tmpfs).

(The observe-only Phase 2 that measured this Lua cost before any body was
cached is history: §14 item 2.)

---

### 5.7 Tier B enforce readiness — on-box checklist (before `MICRO_CACHE_ENFORCE = 1`)

`MICRO_CACHE_ENFORCE` stays `0` (the default) on a node until this has passed
there, one test vhost first (a WordPress site you control). Who never takes
the micro path: requests from loopback, the box's own IPs, `IGNORE_IPS` /
`IGNORE_NETS` and RFC 1918 peers (they bypass `cfm.lua` at Step 0a), the
verified-crawler prefixes of `challenge_waf_bypass.conf` (`$cfm_bypass_ip`,
Step 0), any other request an earlier step allows outright (`/.well-known/` at
Step 0a1, …), and a client holding a valid `cfm_clearance` cookie (it returns
at the Step 2b fast-path, which does not micro-cache yet) — micro serves the
Step 4 plain allows only. So: the debug stamp, from the box,
shows the would-cache verdict; the served verdict comes from a **public-IP
client with no `cfm_clearance`** (e.g. `curl` without a cookie jar), read in
the edge access log (`ucache=` and `up=cfm_apache_micro` vs `up=cfm_apache`).

1. **The live conf carries the Tier B rails** (the reference conf ships them;
   a live conf edited by hand may not). In the live conf
   (`/usr/local/openresty/nginx/conf/nginx.conf`, `/etc/angie/angie.conf`):
   `set $cfm_micro_conf "1";` once (in the HTTPS `location /`) and
   `set $cfm_micro_conf "";` once (its server level),
   `proxy_cache_background_update off;` six times, `lua_shared_dict
   cfm_cache_uncacheable`, the `$cfm_cc_nostore` and `$cfm_xae_nocache` maps;
   the nginx core is ≥ 1.23 (`openresty -V` / `angie -V`); then `-t` and a
   reload. Without the sentinel micro never routes (fail-safe), whatever the
   knob says.
2. **Arm micro on the test vhost, still dry-run:**
   `cfm webtop site-cache set <host> --micro micro_safe --micro-ttl 5s`.
3. **Dry-run verdicts from the box**, against the edge's HTTPS listener :9043
   on the vhost's own IP (so the origin answers from that vhost):
   `curl -sk -o /dev/null -D - -H 'X-CFM-Cache-Debug: 1' --resolve <host>:9043:<vhost-ip> https://<host>:9043/`
   shows `microcache=would/5s`; add `-H 'Cookie: wordpress_logged_in_x=1'` →
   `bypass:auth:…`; `/wp-login.php` or `/?doing_wp_cron=1` → `bypass:path`;
   `-H 'Range: bytes=0-10'` → `bypass:range`; `webmail.<domain>` (if armed by a
   wildcard) → `bypass:panel`.
4. **Enforce on the node:** `MICRO_CACHE_ENFORCE = 1` in `[webdetector]`; the
   daemon applies an edited `detectors.conf` on its own within a few seconds
   (it polls the file) and the edge picks it up ~10 s later (no proxy reload).
5. **From the outside client**, request a plain page three times: the access
   log shows `ucache="MISS"` then `"HIT"`, `up=cfm_apache_micro`. After the
   next stats push (~60 s) `cfm webtop site-cache stats <host>` counts the
   HITs (per vhost; the tier split is in the edge's `/cfm-admin/lua-stats`).
6. **Remembered-uncacheable:** a page that cannot be stored (one that sets
   a cookie, or WooCommerce `/cart/`, which sends no-cache headers) twice
   from outside: first
   `ucache="MISS"`, then `ucache="-"` with `up=cfm_apache` (served direct) for
   ~60 s. No request on it should take seconds longer than the page renders.
   (Marks are per destination IP: a debug request to another IP does not see
   them.)
7. **Logged-in visitor:** log in to `/wp-admin/` from an outside browser and
   browse the front pages: `up=cfm_apache` / `ucache="-"` on every one
   (bypass), the admin bar shows, no anonymous copy is served; log out →
   anonymous pages are HITs again. (A browser that passed a challenge holds
   `cfm_clearance` and never takes the micro path: use a fresh profile.)
8. **Origin TTL is not honoured:** a page with a long `Cache-Control: max-age`
   still shows `ucache="EXPIRED"` after the bucket TTL.
9. **Error log clean:** no `cfm_cache` / Lua errors and no `using
   uninitialized variable` warnings in the edge error log (a debug request of
   yours that the edge itself rejects with a 400 logs one; that is not it).
10. **Roll back** at any point: `MICRO_CACHE_ENFORCE = 0` (~10 s), and
    `cfm webtop site-cache purge <host>` if something wrong got cached — also
    to show a maintenance / 5xx page instead of the last good copy (a failing
    origin keeps the stale copy served), and for an entry stuck stale after a
    worker crash (§4).

## 6. Data model (the per-vhost store)

`siteCacheStore` in `internal/webdetector/site_cache.go`, JSON at
`/var/lib/cfm/webdetector_site_cache.json` (knob `SITE_CACHE_STORE_PATH`; file
mode 0600; at most 5000 entries), write-through source of truth with atomic
save (the store mechanics of
`http3_overrides_store.go`), plus the forward-compatible freezing of rows it
cannot load that `challenge_access.go` uses (below). One entry per
vhost, holding **independent per-tier sub-policies** so a vhost can run static
and micro together:

```jsonc
{
  "host": "myip.gr",
  "scope_hosts": ["myip.gr"],          // audit only: [host] if a scoped token created it, absent if an admin did
  "generation": 1758585600123,           // wall-clock ms, replaced by Purge (§10); part of the cache key
  "static": { "enabled": true,  "recipe": "static_aggressive", "ttl": "7d" },  // recipe/ttl: labels at the edge (§5.4)
  "micro":  { "enabled": false, "recipe": "micro_safe",        "ttl": "1s" },  // ttl snaps to a bucket (§5.4)
  "strict_cookies": false,               // §4.1 advanced: bypass on ANY non-ignored cookie
  "auth_cookies": [],                    // §4.1 per-vhost extra app-session cookie names
  "created_at": "2026-09-21T...", "updated_at": "2026-09-21T..."
}
```

`generation` is folded into the cache key (as built:
`"g<gen>|$server_addr|$scheme|$cf_xfp://$host$request_uri"` via a Lua-set `$cfm_cache_gen`), so a Purge
is a generation change — old keys become unreachable and age out under
`inactive`, with no filesystem walking. A value must **never be issued twice**:
a remove + re-add that reused an old value (it used to restart at 0) turned
that value's still-on-disk objects back into HITs, undoing an earlier purge. So
a new or purged generation is the **wall clock in milliseconds**, bumped past
every generation the store has issued or loaded (`nextGenerationLocked`) —
unique store-wide, so an exact host's fresh policy never shares a key space
with its covering wildcard either. Milliseconds because the edge renders it
with Lua `tostring` (`%.14g`), exact only below 1e14. Neither it nor
`created_at` is client-settable. The high-water mark is rebuilt from the stored
entries on restart, so a removed host's last value is forgotten; a repeat then
needs the clock to have stepped back past it (a VM restore, a boot before NTP
sync) and a new generation to land on exactly that millisecond.

`scope_hosts` records only WHO first enabled caching: exactly `[host]` when a
scoped token created the policy, absent when an admin did, preserved across
later edits. It used to hold the creating token's whole vhost allowlist, which
showed a tenant's full domain list to any other tenant whose scope held that
host; legacy entries are trimmed to `[host]` on load, and the file is
rewritten at once (a stored `:port` or a duplicate host triggers the same
rewrite). Access is gated by the live token scope at the API, never by this
field.

**Feed (`/nginx/cache/config`) and wildcards.** The edge feed carries every
vhost with an armed tier, ordered exact hosts first, then `*.suffix` wildcards
MOST SPECIFIC (longest) first — `cfm_cache.lua` sorts the same way and takes the
first matching wildcard, so with `*.example.com` and `*.shop.example.com` both
armed, `x.shop.example.com` gets the narrower policy. An all-off EXACT host
that an armed wildcard covers is sent as an **opt-out row** (no tier): the
edge's exact match wins, so that host caches nothing — a tenant can opt its own
vhost out of an admin wildcard. An all-off NARROWER wildcard under a broader
armed one is an opt-out row too (the edge takes the most specific wildcard);
an all-off entry nothing armed covers is left out of the feed.

**Off vs remove.** An exact entry with both tiers off IS the opt-out, so the
two ways to stop caching differ under an armed wildcard:

- **off** (CLI `off`/`disable`; API `set` with both tiers `enabled:false`) keeps
  an all-off entry: the host is never cached, wildcard or not. The same works
  for a narrower wildcard under a broader armed one (`off '*.shop.example.com'`
  under `*.example.com`): the feed carries it as an opt-out row too, so none of
  its sub-hosts are cached.
- **remove** (CLI `remove`/`rm`; API `remove`) deletes the entry: the host is
  uncached unless an armed wildcard covers it, which then applies.

Re-arming a tier — static off → on, or micro off → on with the recipe it kept
while off — issues a fresh generation: a tier is often turned off BECAUSE
something wrong got cached (a per-user asset or page, §14), and its zone may
still hold — and, through `use_stale`, serve — those objects, so turning it
back on must not reach them. Both tiers share the generation, so re-arming one
also starts the other from an empty cache (a refill, never a wrong answer). A
FIRST micro enable (no stored recipe) has no old micro objects to hide and
keeps the static cache. Turning a tier off, or any other config change, keeps
it. The same reasoning applies to the `SITE_CACHE = 0` panic button, which
keeps every generation: purge before setting it back to 1 if you pulled it
because something wrong got cached.

Stores written before generations were wall-clock ms counted every policy from
0, so an exact host and its covering wildcard could share one (one key space
for that host, whose objects may belong to either policy) and a value could be
one a purge had retired. On load, EVERY generation below 1e12 (a legacy
counter) or at/above 1e14 (not exactly renderable at the edge) is reissued —
one cache refill per such policy, once — and the file is rewritten.

**Rows this build cannot load** — a recipe or a field from a newer build
(after a downgrade: any unknown field freezes the row, since a newer build's
safety setting must not be ignored), or a malformed hand edit — are kept in the
file as stored (re-indented) through that rewrite and every later save, and
never served. They FAIL CLOSED: the host of such a row (when the edge can match
it — see "Host and cookie validation") is treated as an opt-out
(a frozen wildcard: every sub-host under it that has no more specific
policy), so a covering armed
wildcard does not start caching it. `list` names them under `unloadable`
(scope-filtered), and `get`/`purge` say why there is no row. A `set` that would
arm such a host is refused (merging onto an empty policy would drop the stored
one's cookie settings); `remove` deletes it, and an explicit off REPLACES it —
any `set` (incl. `off`) for a host replaces its unloadable rows in the same
save, so the host then has only the new row, and a later upgrade finds the
replacement, not the old policy. A purge does not reach an unloadable row
(after a re-upgrade it returns with the generation it had). (A loadable and an
unloadable row for one host — a hand edit — serve the loadable one until its
next `set`.) Because any unknown field
freezes a row, a NEW field must be `omitempty` with its zero value meaning the
old behaviour — or a downgrade to a build that lacks it uncaches every vhost.

A tier's recipe cannot be cleared through `set` (disable the tier instead): a
disabled tier keeps its recipe, which is how a re-enable knows the tier may
have cached something and must start from a fresh generation.

Because an all-off entry changes what a covering wildcard does, `set` creates
a NEW entry all-off only when it turns both tiers off explicitly; a `set` that
would merely stage a TTL or a cookie setting for an unconfigured host is
rejected. Hosts carry no `:port` — the edge strips it from the request Host and
from the feed, so a new policy with a port is rejected and a stored one is
normalized.

**Host and cookie validation.** A host is an exact DNS-style name or one
leading `*.` over one: labels of 1-63 characters from `[a-z0-9_-]`, not
starting or ending with `-`, at most 253 characters in all; an
internationalized name in its punycode (`xn--`) form, as the Host header
carries it. A wildcard needs at least two labels after `*.` — `*.com` would arm
every `.com` vhost on the node. A stored row whose host fails these rules (an
older build accepted it) is frozen like any row this build cannot load — never
served as a policy, and still an opt-out when the edge can match its host (a
label ending in `-` still reaches nginx; one with an ASCII space or control
byte cannot) — and
`remove <that host>` deletes it (`off` cannot: the host is invalid for a new
policy). `auth_cookies` are at most 32 names of at most 256 bytes; the edge
takes a request cookie's name up to `=` or whitespace in a `;`-split pair, so a
name with whitespace, `=` or `;` could never match — it is rejected, not
stored (a control character too), as is a 33rd name (which used to be dropped
silently). Names are deduplicated case-insensitively the way the edge compares
them (ASCII only). Anything else is accepted, RFC 6265 token or not (PHP array cookies
such as `cart[id]`, commas, quotes). A stored row with a name the edge cannot
match freezes on upgrade — fail closed: the vhost is opted out until the name
is fixed.

---

## 7. Management surfaces

### 7.1 HTTP API (`/api/v1`, rows in `apiRoutes()` in `http_api.go`)

| Method | Path | Notes |
|---|---|---|
| GET  | `/api/v1/site-cache/list` | scope-filtered; every stored entry (armed, and all-off opt-outs), sorted by host; `unloadable` names hosts whose stored row this build cannot load (treated as opted out, §6) |
| GET  | `/api/v1/site-cache/get?host=` | one vhost |
| POST | `/api/v1/site-cache/set` | `requirePOST`; **merge**-upsert (host in body); scoped→own host only. One entry per vhost, so a single upsert replaces the add/update pair — the host is the immutable key. Only the fields present change (`{"host":"x","micro":{"ttl":"30s"}}` retunes one TTL and keeps the static tier and cookie settings; `enabled:false`, `strict_cookies:false` and an empty `auth_cookies` list are applied, JSON `null` keeps); a new host must enable a tier or turn BOTH tiers off (an opt-out, §6). `scope_hosts` comes from the token (§6) |
| POST | `/api/v1/site-cache/remove?host=` | deletes the vhost's policy (host in the query, not the body); the host then follows a covering armed wildcard (§6 "Off vs remove") |
| POST | `/api/v1/site-cache/purge?host=` \| `?all=1` | per-vhost → `{"status":"ok","generation":N}`; `?all=1` (admin only) → `{"status":"ok","purged":N}` (N counts opt-out entries too) |
| GET  | `/api/v1/site-cache/stats[?host=]` | per-vhost cache stats (§11) → `{rows:[…]}`, scope-filtered (own vhosts / all); `?host=` resolves like the edge (§11.3) |

Prefix `site-cache` added to `SharedAPIPrefixes()` so the shared apiserver
proxies it to the engine mux. Never a bare `mux.HandleFunc` (a prefix-coverage
test walks the table). **Lifecycle audit:** every authenticated set / remove /
purge / purge-all that names a host (or all) — including those refused for
scope, admin-only or validation; not unauthenticated calls, nor a body that
fails before naming a host — writes
one `[site_cache] action=… host=… result=ok|notfound|rejected|denied
actor=admin|scoped:<hosts> remote=… detail=…` line to `cfm.log`
(`logSiteCacheAudit`; the handlers are the single choke point: the CLI goes
through this API and the MCP tools only read).

### 7.2 CLI (`cfm webtop site-cache …`)

`case "site-cache", "cache":` in the `webtop` dispatch (`cli.go`), implemented in
`internal/webdetector/cli_site_cache.go`, mirroring `cli_challenge_access.go`
over the JSON API (through `internal/clihttp`, per the transport guardrail):

```
cfm webtop site-cache list
cfm webtop site-cache get <host>
cfm webtop site-cache set <host> [--static RECIPE|off] [--micro RECIPE|off] [--static-ttl D] [--micro-ttl D]
                                  [--strict-cookies|--no-strict-cookies] [--auth-cookies a,b|--no-auth-cookies]
                                  # sends ONLY the flags given (merge)
cfm webtop site-cache off <host>          # both tiers off, kept: an opt-out (alias: disable)
cfm webtop site-cache remove <host>       # delete the policy; follows a covering wildcard (alias: rm)
cfm webtop site-cache purge <host>        # or: purge --all
cfm webtop site-cache stats [host]        # hit-ratio + HIT/MISS/BYPASS breakdown
```

### 7.3 cfm-admin page "Site Cache"

> **Not built yet** (the last item of the sweep). Until it lands, the API,
> the CLI and the read-only MCP tools (`site_cache_status`,
> `site_cache_stats`) are the surfaces; a scoped cPanel user reaches it only
> through the API. The plan below stands.

Multi-page app, directory-routed (`internal/webui/embed.go`). Template =
**Challenge-Access** (per-vhost + scoped + recipes). Files to add:
`static/webdetector/site-cache/index.html`, `assets/webdet/pages/site-cache.js`,
`assets/webdet/feature-site-cache.js`, `assets/webdet/site-cache-model.js`
(+`.test.js`), `assets/webdet/site-cache-recipes.js` (+`.test.js`). One
`MENU_GROUPS` item in `nav.js` under "Rules & engine". The page has:

- a vhost table with **filter + sort** (host, tier(s) on, recipe, TTL, gen,
  updated, HIT-ratio), a per-row **OFF** and **Purge**, and a top-level
  **Purge all** (admin). OFF is the opt-out (`set` with both tiers off, §6),
  not a delete — a delete (`remove`) lets a covering wildcard cache the vhost
  again, so if the page offers it at all, it is a separate, labelled action;
- a **Recipes** panel (§8). Per-URL verification is done with the
  `X-CFM-Cache` debug header (§8, §11.3), not a simulate panel.

Scoped filtering: leave `site-cache` **out** of `ADMIN_ONLY_NAV_PATHS`
(`controller-bootstrap.js`) so scoped cPanel users keep the link, and add
`v1/site-cache/` to `isScopedSelfServiceWrite` (`core.js`). Backends still
fail-closed regardless of the UI.

### 7.4 Bridge (daemon↔edge, `nginx_bridge.go`)

- `GET /nginx/cache/config` (`handleCacheConfig`) →
  `{"entries":[{host, gen, static?:{on,recipe,ttl}, micro?:{…}, strict_cookies?, auth_cookies?}, …]}`
  — a disabled tier is omitted, an opt-out row has no tier; token-gated,
  **explicit Content-Length** (the minimal Lua reader needs it — the Clam
  handler gotcha); `{"entries":[]}`, never null, when empty. Backed by the
  `ListCachePolicy` engine hook (`PolicyFeed`). Pinned against the edge by
  `site_cache_edge_parity_test.go` + `cfm_cache_edge_parity_test.lua`.
- `POST /nginx/cache/stats` (`handleCacheStats`) ← the edge's stats push,
  `{"rows":[{host, counts:{STATUS:n}}]}`, token-gated, 4 MiB body cap, one
  hook event per push (§11).
- **Purge is not a push.** It is the `generation` bump in the pulled config:
  each worker applies it on its next poll (≤ ~60 s). A per-URL purge (an
  extension of `cfm_purge.lua`, which today purges per-IP state only) is not
  built.

---

## 8. Recipes

> **As built, a recipe is a label.** The daemon accepts the names below
> (`staticCacheRecipes` / `microCacheRecipes` in `site_cache.go`) and the edge
> uses one only in the debug stamp. What decides caching is the tier's `on` and,
> for micro, its `ttl`, snapped to a bucket (empty = 1 s; §5.4) — so
> `micro_aggressive` without `--micro-ttl` behaves as 1 s, every static recipe
> behaves the same (origin headers, 1 h fallback), and `fullpage_advanced` is an
> ordinary micro label, accepted and clamped to 60 s. The front-end catalog
> planned below (TTL presets per recipe) comes with the cfm-admin page (§7.3).

Recipes are planned as a **front-end catalog** (each `build(vars)` emits ordinary CRUD
payloads), exactly like `CA_RECIPES` (`challenge-access-recipes.js`). Catalog:

| Key | Tier | TTL | Ships | For |
|---|---|---|---|---|
| `static_lean` | static | 1h | enabled | the safe default for most sites |
| `static_aggressive` | static | 7–30d + `immutable` | enabled | asset-heavy sites |
| `micro_safe` | micro | 1s, `use_stale updating` | enabled | heavy pages / bursts (`myip.gr`) |
| `micro_aggressive` | micro | 10–30s (stale served while one request refreshes, and while the origin fails — §4) | enabled | near-static pages |
| `micro_custom` | micro | operator TTL (bucket) | enabled | full control |
| `fullpage_advanced` | micro-zone, long TTL | hours | **DISABLED** | advanced, purge-aware only |

A vhost can combine **one static + one micro** recipe.

**No Simulate.** Unlike traffic rules (where a wrong rule silently blocks
legitimate traffic — hard to spot, high blast radius), a caching mistake is
**bounded and reversible**: the §4 rails mean the worst case is *stale anonymous
content*, never a security break, and the operator simply turns the vhost **OFF**
(or **Purges**). Verification is therefore observational, not predictive:

- **Live check for one URL:** `curl -I` and read the `X-CFM-Cache` debug stamp
  (`observe … status=<HIT|MISS|BYPASS|…> microcache=would/<n>s|bypass:<reason>`;
  §11.3, `docs/site-cache-runbook.md` §4 — behind a debug flag, from a trusted source: loopback /
  link-local, the box's own IPs or `IGNORE_IPS` / `IGNORE_NETS`; from the box,
  against the edge's :9043 listener — §5.7 step 3 — since loopback :443 reaches
  the origin) — this is the per-URL "would it cache / why bypassed" answer, for
  near-zero code.
- **Aggregate check:** the §11 stats — if a vhost isn't behaving, its HIT /
  MISS numbers show it. (BYPASS is not the micro rails: those declines are not
  counted at all; §11.1.)

---

## 9. Scope model (scoped cPanel self-service — full power, fenced)

Per decision, scoped users get the **same power** as admins **over their own
vhosts**: enable any recipe (incl. aggressive), set custom TTL, turn OFF, and
Purge — but only for hosts in their token scope, fail-closed otherwise. This
reuses the tested precedent verbatim:

- `RequireScopedOrAdmin` + `scopeAllowsVhosts(r, vhosts)` on every write
  (`challenge_access_api_handlers.go` shape): nil scope = admin (unrestricted);
  empty scope = deny; else every target host must be in the token allowlist.
- The host is the entry's immutable key, so checking the ONE requested host
  (literally, lowercased — the store then only trims a trailing dot or a
  port, so it can never land on a different host) covers set, get, remove and
  purge alike; there is no re-scoping to guard against.
- List/stats are scope-filtered with `vhostAllowed` on each row's key (an
  out-of-scope row is left out, not redacted).
- **Purge-all** (`?all=1`) is **admin-only** (403 for a scoped caller); a
  scoped caller purges one named in-scope host at a time (`?host=` is
  required).
- There is no switch for scoped self-service (the planned
  `SITE_CACHE_SCOPED` was not built): it is always on, through the API only
  until the cfm-admin page lands (§7.3).

Because the §4 rails are absolute, a tenant's "aggressive" choice can still only
ever cache their own anonymous, cookieless, non-redirect 200s — so full
self-service power carries no cross-tenant or correctness risk.

Scope matching is literal, as on the HTTP/3 and challenge-access endpoints: a
token whose scope holds a `*.example.com` entry (cPanel lists an account's
wildcard subdomain that way) manages the `*.example.com` policy — and its
aggregate stats row — even if an admin created it. That reaches another tenant
only if another account hosts a sub-host of that domain, which cPanel allows
only with its cross-account subdomain options (off by default).

Documented in `docs/endpoint_scope_inventory.md` (hard rule, CLAUDE.md §5):
site-cache list/get/stats = scoped-allowed (own host); set/remove/purge =
scoped-allowed (own host); purge-all = admin-only.

---

## 10. Purge / invalidation

- **Micro-cache is self-healing** (1–60 s buckets) — rarely needs an explicit purge.
- **Static (long TTL) needs purge.** Mechanism: **generation bump.** Each
  vhost entry carries `generation`; the cache key includes it
  (`g<gen>|<server IP>|<listener scheme>|<scheme told to origin>://<host><uri>`). Purge = a new, never-used
  generation in the store (wall-clock ms, §6) →
  new key space → old entries age out under `inactive`. No filesystem walking,
  no `proxy_cache_purge` (commercial) dependency, works on both OpenResty and
  Angie. (A future per-URL purge has to cover every key variant the URL can
  be stored under: each server IP the vhost answers on × listener scheme ×
  scheme told to the origin, since all three are in the key.)
- **Surfaces:** `POST /api/v1/site-cache/purge?host=` (per-vhost; admin or the
  owning scoped user) and `?all=1` (global; admin). CLI `purge <host>` /
  `purge --all`. (cfm-admin per-row **Purge** + top **Purge all** come with
  the page, §7.3.)
- **Latency:** a purge is only the new generation in the store; each edge
  worker applies it on its next feed poll, within about 60 s (the poll is
  triggered by traffic). Until then that worker still serves the old objects.
- **Disk:** the old objects stay on disk until `inactive` (static: 7 d) or the
  zone's LRU (`max_size`, static 10 GB) removes them — unreachable, not
  served.
- **Per-URL purge** (delete a single path) is a later extension building on
  `cfm_purge.lua`; not built.
- **A purge covers ONE policy key.** The edge keys a request on the
  generation of the policy that matched it. A host that moves back under a
  covering wildcard — its exact policy removed, or a narrower wildcard removed —
  finds that wildcard's own cached objects for it again (served within the
  wildcard's TTL, like any object of that policy). A purge of the host's former
  exact policy never reached them; only a purge of the wildcard does, and a
  scoped tenant cannot purge an admin's wildcard (unless its scope literally
  holds the `*.suffix` entry, §9). To keep a tenant's purge
  meaningful, keep an exact policy (or an opt-out) rather than removing it.
  Follow-up: a per-host "inherit" row (the host follows the wildcard's tiers
  under its own generation) would give a tenant a per-host purge under an
  admin wildcard.

---

## 11. Cache statistics & observability

Per-vhost cache effectiveness, for the admin (all vhosts) and a scoped user
(their own). Cheap: every counter is incremented in the http-level
`log_by_lua`, which runs **after** the response is served. *As built* it is a
**live totals view** — nothing is persisted, and there is no cfm-admin view yet.

### 11.1 Edge counters (live, in-memory)

- `lua_shared_dict cfm_cache_stats 8m` (both confs), written by
  `cfm_cache_log.lua` from the http-level `log_by_lua`.
- **What is counted:** a response with status 200 or 304 that went through a
  cache location — the static-asset locations, and the `@cfm_micro_<n>s`
  locations (reached only while `MICRO_CACHE_ENFORCE = 1`) — for a host that
  `policy_key_for` maps to an ARMED policy key (the exact host or the matching
  `*.suffix`, never the raw request host, so cardinality is bounded).
- **Keys:** per armed key, `cvh:<md5(policy key)>:<STATUS>` for the seven
  `$upstream_cache_status` values — both tiers in one set of counters; plus
  per-zone totals over those same armed keys, `cache:zone:{cfm_static|cfm_micro}:status:<S>` / `…:total`,
  `cache:total` and `cache:last_seen_ts`, which `cfm_stats.lua` exposes in
  the `/cfm-admin/lua-stats` JSON under `cache.zones` (the dashboard does not
  render them yet). Bounds, the key digest and the `incr` finding: §14 3c.
- **BYPASS** is a counted request that could not use the cache: a static
  asset of an armed policy whose static tier is off (a micro-only vhost shows
  its assets as BYPASS — expected), any cache-location request with an
  `Authorization` header (`$cfm_req_auth`), a panel / service host under an
  armed wildcard, or anything while `SITE_CACHE = 0` (counted, not pushed). It
  is **not** the §4.1 cookie rails nor any Tier B request-side decline: those
  requests stay in `location /`, which has no `proxy_cache`, so they are not
  counted at all — the debug stamp (§11.3) is the view of those.
- A reload keeps the counters (a `lua_shared_dict` survives it unless its
  size changes); a restart resets them.

### 11.2 Daemon live-totals store (in-memory, scoped)

The edge **pushes** its snapshot: one worker per node (a cross-worker lock),
every ~60 s, `POST /nginx/cache/stats` with `{"rows":[{host, counts:{STATUS:n}}]}`
for the armed keys it knows (§7.4). The daemon (`site_cache_stats.go`) keeps
the latest row per key — only for a key armed at that moment, only the known
statuses, at most one row per stored policy — and prunes the rows of keys
disarmed since, every 5 minutes. The counts are absolute since the edge last
restarted, so a daemon restart only empties the view until the next push.
So does any saved change to `detectors.conf`: each config reload builds a new
webdetector `Engine`, and with it a new, empty store.
This store is what the API and MCP read, so scoping is enforced daemon-side.

- **As built (v1):** the seven statuses + a derived STRICT hit ratio
  (hit ÷ (hit+miss+expired+stale+updating+revalidated); BYPASS excluded), per
  policy key, both tiers together. No last-seen, no per-tier split (only the
  per-zone totals, §11.1, which sum the armed vhosts only), no disk snapshot.
- **Later:** hourly buckets for a sparkline, a per-tier split, a bytes-saved
  estimate; the `whats_wrong` "armed but ~0 hits" signal.

### 11.3 Surfaces

- **API:** `GET /api/v1/site-cache/stats[?host=]` — scope-filtered
  (`vhostAllowed`). `?host=` resolves a request host like the edge does
  (`StatsKeyFor`: its exact policy, else the most specific wildcard; nothing
  for an opt-out); a scoped caller resolves only to keys its scope holds (an
  in-scope host that resolves to nothing returns `rows: null`).
- **CLI:** `cfm webtop site-cache stats [host]`. **MCP:** `site_cache_stats`
  (and `site_cache_status` for the policies).
- **cfm-admin:** a hit-ratio column + per-vhost detail card — planned with the
  page (§7.3).
- **Debug stamp** `X-CFM-Cache: observe [opt-out ]static=<r>/<ttl>
  micro=<r>/<ttl> gen=<n> [status=<cache status>] [microcache=would/<n>s |
  microcache=bypass:<reason>]`, only on a request that sends
  `X-CFM-Cache-Debug` from a trusted source (loopback / link-local, the box's
  own IPs, `IGNORE_IPS` / `IGNORE_NETS`), and only on the HTTPS listener
  (:9043; `observe` runs in that server's header filter). The reason
  vocabulary and how to run it: `docs/site-cache-runbook.md` §4.
- **Access log:** `ucache="$upstream_cache_status"` and
  `up=cfm_apache_static|cfm_apache_micro|cfm_apache` on every request
  (`edge_access_tail`).

There is no knob for the counting (the planned `SITE_CACHE_STATS` was not
built); `SITE_CACHE = 0` stops the push.

---

## 12. Config knobs (`[webdetector]` in `detectors.conf`)

*As built:*

| Knob | Default | Meaning |
|---|---|---|
| `SITE_CACHE` | `1` (ON) | node-wide **kill switch** (not an opt-in — the per-vhost store arms vhosts); `0` = no caching, no stamp, no stats push on this node within ~10 s, policies kept. Published via `webdetector_bridge_config.go` → `cfm_bridge_config.lua` (read by `cfm_bridge_cfg.lua`, absent = on) |
| `MICRO_CACHE_ENFORCE` | `0` (OFF) | Tier B **opt-in**: `0` = dry run (the debug stamp shows the verdict, nothing HTML is cached), `1` = armed anonymous HTML is served from its micro bucket. Set per node only after §5.7. Same publication path (absent = off) |
| `SITE_CACHE_STORE_PATH` | `/var/lib/cfm/webdetector_site_cache.json` | the per-vhost store (§6) |

The defaults are pinned by `webdetector_bridge_config_test.go` (code, the
reference `detectors.conf`, the rendered file) and `cfm_bridge_cfg_test.lua`
(the reader). There is no daemon-side gate: with `SITE_CACHE = 0` the API and
the feed keep working and only the edge ignores the feed. The daemon logs
`cfm_bridge_config.lua written … site_cache=… micro_cache_enforce=…` on every
publish (what the edge was actually given). The configured values are also
readable remotely: the MCP tool `detectors_config` (`merged=true` for the
effective value; `node_call node="all"` for the fleet) and the admin
`GET /api/v1/detectors/config`. The `site_cache_*` tools do not include them.

*Planned, not built:* `SITE_CACHE_SCOPED` (scoped self-service is always on,
§9), `SITE_CACHE_CFG_REFRESH_SEC` (the feed poll is a fixed 60 s,
`cfm_cache.lua` `_refresh_sec`), `SITE_CACHE_STATS` (counting has no switch,
§11), `SITE_CACHE_AUTH_COOKIES` (the built-in session-cookie list is
`MICRO_AUTH_*` in `cfm_cache.lua`; the per-vhost `auth_cookies` extends it).

---

## 13. CI guardrails (turn the lesson into an enforced rule)

New `scripts/tests/check_site_cache_config.sh` (in the spirit of
`check_origin_ka_config.sh`), wired into `security.yml` and §3 of CLAUDE.md:

1. **Bypass-by-default:** every location that names `proxy_cache` must also
   carry `proxy_cache_bypass $cfm_cache_skip;` **and** `proxy_no_cache
   $cfm_cache_skip;`. Fails the build otherwise — **unconditional caching can
   never be reintroduced.** *As built:* the exact statements are
   `proxy_cache_bypass $cfm_cache_skip $cfm_req_auth;` and
   `proxy_no_cache $cfm_cache_skip $cfm_cache_non200 $cfm_req_auth;` (plus the
   Tier B no-store rails on micro). `$cfm_cache_skip` defaults to `"1"` in
   every server with a cache location, and only `cfm_cache.lua` may write it.
   The guard also pins, per cache location:
   - buffering on;
   - the whole cache key;
   - the lock and its per-tier timeout;
   - the forwarded-header pins.

   Nothing else may write a rail variable (header-family writers, named
   captures, inline Lua).
2. **Set-Cookie safety:** assert `Set-Cookie` is never added to
   `proxy_ignore_headers` in a cache location. *As built:* the guard also
   forbids ignoring `Vary`, and allows ignoring `Cache-Control` / `Expires` /
   `X-Accel-Expires` only in a `@cfm_micro_<n>s` location that carries the
   replacement no-store rails.
3. **OpenResty↔Angie parity:** the two confs declare the same zones and the same
   cache locations. *As built:*
   - both confs cache the same locations;
   - the `@cfm_micro_<n>s` blocks are byte-identical;
   - the zones and locations are exactly `cfm_cache.lua`'s `MICRO_BUCKETS`,
     checked against the daemon's and the installer's dir lists too.

   The header of `scripts/tests/check_site_cache_config.sh` is the complete,
   current list of what it checks.
4. **Lua↔Go parity** for any cache-policy identifiers (recipe keys), mirroring
   `TestWAFRuleIDs_LuaParity`. *As built:* the feed and the stats key, through
   a Go-generated fixture (`site_cache_edge_parity_test.go` →
   `scripts/tests/fixtures/site_cache_edge_parity.lua` →
   `cfm_cache_edge_parity_test.lua`), and the feed's wire fields
   (`TestCachePolicyRowWireFields`); the edge uses a recipe name only as a
   label in the debug header (the TTL decides), so there is nothing to mirror
   for the recipe vocabulary yet.
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
       ignore-list + strict-mode machinery did not exist at the edge yet (it
       landed with Tier B, which is where it applies). Rather
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
     arg (per-vhost keys `cvh:<md5(policy key)>:<S>` — they were
     `cache:vhost:<host>:status:<S>` until the bound below) and `snapshot_vhosts()`,
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
     vhost's counts until the edge RESTARTS (a reload keeps a
     `lua_shared_dict` whose size it does not change), so a vhost unarmed after its last push
     would otherwise linger as a stale "still cached" row — the armed store is
     truth (a stored but all-off policy is not armed). A by-host query resolves
     a concrete sub-host to the key the edge counts it under
     (`siteCacheStore.StatsKeyFor`, the Go mirror of `policy_key_for`: its exact
     policy, else the most specific wildcard in the feed — nothing when that
     one is an opt-out) so a `*.suffix`-armed vhost is drillable; a scoped
     caller resolves only to keys inside its own scope, so not to a wildcard its
     scope does not literally hold (that row aggregates every tenant under the
     pattern; see §9 for a scope that holds `*.x`).
     Read via `GET /api/v1/site-cache/stats[?host=]` (scope-filtered like the
     other site-cache endpoints), `cfm webtop site-cache stats [host]`, and two
     MCP tools — `site_cache_status` (stored policies + tiers) and
     `site_cache_stats` (HIT/MISS/BYPASS + a STRICT hit ratio — STALE/UPDATING/
     REVALIDATED serve from cache but sit in the denominator only, so read the
     full breakdown). `ucache="$upstream_cache_status"` was added to the `cfm`
     access log_format so `edge_access_tail` shows the verdict per request.
     **Bounds:** the daemon keeps a pushed row only for a policy key armed at
     that moment, only the seven cache statuses (the edge sends no `total`), at most
     one row per stored policy (`maxSiteCacheEntries`), and prunes the rows
     of keys disarmed since every 5 minutes; a push is ONE hook event (it was
     one per row, which could overflow the hook queue and drop rows). The
     edge reads each ARMED policy key's seven status counters by name
     (`cfm_cache_log.lua` snapshot_vhosts, given `cfm_cache.lua`'s
     `stats_keys` — exactly the values `policy_key_for` can return, built
     with the feed), so every armed vhost is pushed with all its statuses
     whatever else the dict holds. Each counter is keyed on a digest of its
     policy key, `cvh:<md5>:<status>` (≤ 48 bytes), so every one takes the
     same small shared-dict slot whatever the host's length: `cfm_cache_stats`
     is 8m, ~65 000 counters — the 5000-policy limit × 7 statuses with room
     to spare. Measured on nginx 1.24 with 5000 armed vhosts (every status) +
     3000 disarmed ones (a counter each): 5000 rows, all complete, with 25-,
     60- and 253-character hosts, ~40 ms per push in the timer, 3.3 MB of the
     dict free. A counter is counted with `incr` without init, then `add`:
     `incr(key, n, init)` in lua-nginx-module 0.10.26 (as shipped with nginx
     1.24 here; the fleet's OpenResty/Angie builds are unchecked) loses
     counters when a new key's crc32 — the dict's tree hash — equals an
     existing key's (the other reads nil, or both count wrong, for the dict's
     life): about K²/2³³ odds per node for K counters, ~13% at 5000 vhosts ×
     7 statuses. Both reviewers' benchmarks hit it (one counter of 35 000
     lost); a colliding pair counted 998 and 999 of 1000 that way, exactly
     1000 each after the fix. It used to scan `get_keys(8000)` — a KEY bound — over keys that
     grew with the host (the slot doubles past a 52-byte key: the 4m dict
     held ~32 000 short counters, ~16 000 of 53-180 bytes, ~8 000 for a
     253-byte host), which pushed
     1143 of those 5000, one with partial counts. Past the dict's capacity,
     LRU evicts the least recently touched counters, a disarmed vhost's first
     (they are no longer read). The push body is ≤ ~2.2 MB at the limit
     (253-byte hosts, 14-digit counts — the longest plain number cjson
     writes); the daemon caps it at 4 MiB and reads a count cjson writes in
     exponent form (1e14 or more) as a number, clamped to 2^53, instead of
     failing the whole push. **v1 scope:** a live totals view (counts since the edge last
     restarted — a reload keeps them, unless it changes the dict's size), not hour-bucketed history, and no cfm-admin column yet — both
     follow-ups. **Deferred to a focused follow-up:** the `whats_wrong`
     "armed but ~0 hits" signal (the automated form of what `site_cache_stats`
     already shows on demand — it would have surfaced the 3b buffering no-op).
4. **Tier B (micro-cache)** + the full §4 rails. Validate §5.5 items
   on a live box (the `myip.gr` case) per the challenge/WAF release checklist.
   Hardening before enforce (as-built, the §4 Tier B rows): bucket-only TTL with
   the `$cfm_cc_nostore` / `$cfm_xae_nocache` store rails, `background_update
   off` + stale-on-5xx, remembered-uncacheable keys (never on 5xx / request
   4xx; long enough after a page changed for its copy to age out), the Range /
   event-stream / admin & script path / panel-host rails, more session
   cookies, the `location /` sentinel (+ no internal redirects, nginx ≥ 1.23),
   the TTL-unit fix, and the trusted-source debug stamp. Enforce per node only
   after §5.7.
5. **cfm-admin page + Recipes** (+ `make test-js`), filter/sort, per-row + global
   Purge UI. *Not built yet* — the last item of the sweep.
6. **Purge generation-bump** end-to-end. *As built*, folded into Phase 1 and 3b
   (§10); the generation became wall-clock ms, never reissued (§6).
7. *As built, the hardening sweep that followed:* PR-1 request-identity rails
   (Authorization, server IP + schemes in the key, forwarded headers, lock
   timeouts); PR-2 cache-dir provisioning (daemon + helper + packaging); PR-4
   the daemon control plane (monotonic generations, `set` merge, scope
   attribution, validation, audit); PR-3 Tier B hardening before enforce (§4
   rows, §5.7); PR-5 the stats bound (§11, 3c), the guard's closed gaps and the
   Go↔Lua parity / default / structural tests (§13); PR-6 this as-built pass +
   `docs/site-cache-runbook.md`.

Each edge-affecting PR runs `docs/challenge-waf-release-checklist.md`. Each
runtime PR adds a `CHANGELOG.md [Unreleased]` entry.

---

## 15. Files (as built)

**Go (daemon):** `internal/webdetector/site_cache.go` (store, model, validation,
feed `PolicyFeed`, `StatsKeyFor`), `site_cache_api_handlers.go` (API + audit),
`site_cache_stats.go` (live stats store, prune, stats API), `cli_site_cache.go`
(+ the `cli.go` dispatch/help); `nginx_bridge.go` (`handleCacheConfig`,
`handleCacheStats`), `engine.go` (store + hooks), `http_api.go` (routes +
`SharedAPIPrefixes`), `webdetector_config.go` (`SiteCacheStorePath` and its
default); `internal/detectors/webdetector_bridge_config.go` (the
`SITE_CACHE` / `MICRO_CACHE_ENFORCE` defaults, called from `manager.go`),
`webdetector_register.go` (reads `SITE_CACHE_STORE_PATH`),
`internal/sslcollector/token.go` (the bridge-config fields);
`internal/mcpserver/status_reads.go` (MCP `site_cache_status` /
`site_cache_stats`, registered in `tools.go`); `cmd/cfm/site_cache_dirs.go`
(cache dirs, every start, called from `main.go`).
Tests: `site_cache_test.go`, `site_cache_stats_test.go`,
`site_cache_edge_parity_test.go`, `cli_site_cache_test.go`,
`webdetector_bridge_config_test.go`, `token_test.go`, `site_cache_dirs_test.go`.

**Lua / conf (edge):** `configs/lua/cfm_cache.lua` (feed, gates, rails, stamp,
stats push, remember-uncacheable), `cfm_cache_log.lua` (counters),
`cfm_hostmatch.lua` (host matcher shared with `cfm_h3_config.lua`),
`cfm_panel_hosts.lua` / `cfm_selfip.lua` (panel rail, trusted debug sources),
`cfm_bridge_cfg.lua` (knob reader), `cfm_stats.lua` (zone totals in
lua-stats), `cfm.lua` (the Step 4 micro entry only). Both confs: the zones,
`lua_shared_dict cfm_cache_stats` / `cfm_cache_uncacheable`, the rail maps,
the static-asset and `@cfm_micro_<n>s` locations, the `location /` sentinel,
the log-phase hook. Tests: `cfm_cache_test.lua`, `cfm_cache_log_test.lua`,
`cfm_cache_edge_parity_test.lua` (+ `fixtures/site_cache_edge_parity.lua`),
`cfm_micro_entry_structure_test.lua`, `cfm_bridge_cfg_test.lua`,
`cfm_hostmatch_test.lua`, `cfm_cache_load_test.lua` (loads without `ngx`).

**Packaging / install:** `scripts/cfm-cache-dirs.sh` (called by the deb
postinst, the rpm `%post` and both installers), `configs/detectors.conf`
(the `[webdetector]` knob blocks).

**CI:** `scripts/tests/check_site_cache_config.sh` (§13), wired in
`security.yml` and CLAUDE.md §3.

**UI (planned, §7.3):** the six files there + `nav.js` / `core.js`.

**Docs:** this file, `docs/site-cache-runbook.md`,
`docs/endpoint_scope_inventory.md`, CLAUDE.md §6/§7, `CHANGELOG.md`.

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
