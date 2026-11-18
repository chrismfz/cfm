# Site Cache (per-vhost edge caching) — design & as-built reference

Status: **built.** This is the one design doc for per-vhost edge caching in
CFM: what it does, why, and the decisions behind it. Operating it — arming,
verifying, stats, purge, turning Tier B on, incidents — is
[`site-cache-runbook.md`](site-cache-runbook.md).

- **Built:** the per-vhost store + API + CLI with scope checks
  (`internal/webdetector/site_cache*.go`); the edge feed and decision module
  (`configs/lua/cfm_cache.lua`); the `SITE_CACHE` kill switch; **Tier A**
  (static assets) for armed vhosts; **Tier B** (micro-cache of anonymous
  pages, HTML or not) with the full §4 rails, enforced for an armed vhost
  (`MICRO_CACHE_ENFORCE = 1`, the default); purge (generation bump);
  per-vhost live stats (§11); the read-only MCP tools `site_cache_status` /
  `site_cache_stats`; the audit log; cache-dir provisioning; the CI guard
  (§13); the cfm-admin **Site cache** page with its recipe catalog (§7.3, §8).
- **Not built (open):** see §14.

An operator (and a scoped cPanel user, for their own domains) turns caching
**on per vhost** — static-asset cache and/or a short micro-cache of anonymous
pages — picks a TTL, **purges** (global or per vhost), and sees per-vhost
state and effectiveness. Managed from the cfm-admin page (§7.3), the API and
the CLI (`cfm webtop site-cache …`); read through MCP.

---

## 0. The governing principle (why this exists and how it stays safe)

CFM once shipped **global, unconditional** caching (hardwired in the edge
conf). It broke customer pages, **redirects**, webmail, cPanel and **SSO**, and
was ripped out (remnants: §2). Everything here is a reaction to that failure.
The invariants, in priority order:

1. **Safe by default via per-vhost opt-in.** The per-vhost store is empty by
   default, so an install caches *nothing* until an operator arms a vhost.
   `[webdetector] SITE_CACHE` is therefore a **kill switch, default ON** (a
   default-off master would be a redundant second opt-in). `SITE_CACHE = 0` is
   the panic button: this node's edge stops caching, stamping and pushing
   stats within ~15 s of saving `detectors.conf`, **without** disarming any
   vhost, so re-arming is instant.
2. **Arming is exact-host.** `myip.gr` and `www.myip.gr` are two entries;
   there is no implicit `*.myip.gr`. Wildcards are an explicit, advanced
   opt-in.
3. **Bypass-by-default at the edge.** The conf pre-sets `$cfm_cache_skip "1"`
   and `$cfm_cache_gen "0"` at server level; only the Lua (`static_gate` /
   `micro_gate`) flips skip to `0`, and only when every §4 gate passes. A
   regression that drops the gate fails closed.
4. **Caching lives behind enforcement.** **A Tier B HIT never bypasses the
   WAF, a challenge or an IP block**: the request runs `cfm.lua` to its Step 4
   allow before any cached page is served. Tier A lives in the static-asset
   location, which never ran `cfm.lua` (assets skip its WAF / challenge /
   bridge decisions, cached or not); an nftables block still applies below the
   edge, and the edge ban check runs there too.
5. **The rails (§4) are absolute.** They do not depend on recipe, TTL or who
   armed the vhost. "Full power" (§9) is freedom over TTL and recipe, never
   over a rail.

**TTL controls staleness, not who-sees-what.** We never store a response that
sets a cookie (Tier B: except tracking-only cookies, which are stripped from
every micro response — §4), never serve the cache to a request with a session
cookie, and never cache redirects or panel traffic. So the worst outcome of an
aggressive TTL is *stale anonymous content*, which the operator opted into and
can purge (§10) — never user A's session served to user B.

---

## 1. Non-goals

- **Not** a CDN, no cache sharing between nodes. Each node caches its own
  origin locally.
- **Not** DNAT-mode caching. The teeth are in the in-path edge only
  (OpenResty/Angie), like the WAF and traffic rules; DNAT clients reach the
  origin directly.
- **Not** an integration with the `ngm1` MCP `site_cache_*` tools — a separate
  product. CFM's own read-only MCP tools happen to share the prefix
  (`site_cache_status`, `site_cache_stats`).
- **Not** arbitrary per-request TTL to the second (nginx constraint, §5.4): a
  menu of TTL buckets instead.

---

## 2. Leftover inventory

The ripped-out global cache left code behind. What became of it, where it
still guides a decision:

- `cfm_cache_log.lua` (an orphaned counter) and the never-declared
  `ngx.shared.cfm_cache_stats` are now the §11 stats path.
- `/var/cache/nginx/cfm_micro` (one undivided micro dir) is **retired**: the
  zones are `cfm_micro_<n>s` per bucket. It may linger on older nodes
  (runbook §10).
- `cfm_pcw.lua` is **not** a cache remnant: it is the live post-clearance
  nav-cadence shadow counter. Do not touch it.
- `cfm_purge.lua` / `nginx_bridge_purge.go` purge per-IP state only. Cache
  purge is the generation bump (§10), not an extension of them.

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
                     │ ┌ location @cfm_micro_<n>s  ×8  (internal) ──────────────────────┐  TIER B zones     │
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
  the static-asset location that already skips `cfm.lua`, on both the HTTP and
  HTTPS servers. Assets are rarely per-user. Its rails:
  - nginx itself never stores a `Set-Cookie` or `private` answer;
  - only GET/HEAD is cached;
  - only a 200 is stored;
  - a request with `Authorization` is never served or stored;
  - panel and webmail hosts are skipped.

  It reads no request cookie and looks at the path only for its extension, so
  per-user safety rests on the origin's response headers (§4 residuals, §14).
- **Tier B — micro-cache of anonymous pages** (high risk — this is what broke
  before). Any anonymous GET/HEAD through the HTTPS `location /`, HTML or not.
  Very short TTL, hard gated (§4); a dry run on a node that sets
  `MICRO_CACHE_ENFORCE = 0`. Absorbs bursts on heavy pages (the `myip.gr`
  case).

A vhost may enable Tier A, Tier B, or both.

---

## 4. Safety rails — the never-cache table (absolute, layered)

Enforced on **every** request regardless of the vhost's recipe/TTL. Two layers:
request-time (Lua, `access` phase) and response-time (nginx-native + a thin
`header_filter`).

| Rail | Enforced where | Prevents |
|---|---|---|
| `GET`/`HEAD` only | `proxy_cache_methods` (default) | POST / logins cached |
| Status: **only `200` is stored** | `map $upstream_status $cfm_cache_non200` → `proxy_no_cache` (hard block, beats any origin `Cache-Control`), not just `proxy_cache_valid` | **3xx redirect / SSO loop cached** (the incident that removed CFM's global cache) |
| Response has `Set-Cookie` → never store | Tier A: nginx default (`Set-Cookie` is never in its `proxy_ignore_headers`). Tier B: the micro locations ignore `Set-Cookie` for nginx's own decision and put `$cfm_sc_unsafe` on `proxy_no_cache` instead. It defaults to `"1"` at server level and only `cfm_cache.micro_setcookie_filter` (the HTTPS server's `header_filter_by_lua_block`) clears it, for a response with no `Set-Cookie` or whose `Set-Cookie` headers are ALL tracking cookies (`_fbp`, `_fbc`, `_ga`, `_ga_<ID>`, `_gid`, `_gat` (exact — `_gat_<id>` is not on the list), `_gcl_au/aw/dc/gb/gf/ha/gs`), which it then strips — on the fetch and on every HIT, since nginx stores the origin's headers. Any other or unreadable cookie keeps `"1"`: not stored, delivered untouched. The filter removes every tracking line from every micro response, whatever else it carries (a stored copy keeps the first fetch's line, and a cookie set before the micro exec must not turn a HIT into "not tracking-only"). Names are read as the browser stores them (`[A-Za-z0-9_-]`, case-sensitive — `_FBP` is not Meta's; only a `__Secure-` / `__Host-` prefix is matched in any case; `_ga_<ID>` only with Google's upper-case id; `_gcl_` only `au/aw/dc/gb/gf/ha/gs`); a line with a `,` in its name-value pair (several cookies joined) is unreadable → unsafe. The micro key is `g$cfm_cache_gen|sc1|…`, so a downgraded conf without the filter never HITs an entry that holds a tracking line. nginx tests `proxy_no_cache` after the header filters ran (`ngx_http_upstream_send_response` sends the header before testing `no_cache`; Angie shares it; verified on nginx 1.24 + lua-nginx-module 0.10.26: `_fbp`-only and Google-only pages MISS → HIT with no cookie served; a session, a session + `_fbp`, a cookie without `=`, `_fbp` + `no-store` never stored, cookies delivered; HEAD-first, stale-on-502, lock waiters and a 300 KB body checked in review). Cost, by design: a visitor never gets the server-set `_fbp` / `_ga` from a micro response, so Safari (which caps script-set cookies at 7 days) keeps them shorter, and a Facebook pixel `eventID` rendered into a stored page is shared by the visitors of one TTL. Residual: storing is fail-closed (a filter error leaves `"1"`), but the strip on a HIT is not — a filter error on a HIT, or old Lua against this conf, would deliver the stored entry's tracking line (an analytics id, never a session) for up to the bucket TTL (plus stale-on-error) | user A's session served to user B; one visitor's analytics id handed to everyone (hence the strip) |
| Request carries a **named app-session cookie** → `$cfm_cache_skip=1` (see §4.1 — **allowlist by name**, NOT "any cookie") | Lua cookie-name allowlist | **logged-in users get stale/foreign content** |
| Origin `Cache-Control: private\|no-store\|no-cache` → never store | Tier A: nginx default (not ignored). Tier B: the micro locations set `proxy_ignore_headers Cache-Control Expires X-Accel-Expires` so the TTL is always the bucket's, and put the shared-cache "do not store" signals back on `proxy_no_cache` through two `volatile` maps: `$cfm_cc_nostore` (`private` / `no-store` / `no-cache` / `s-maxage=0`, anywhere in the header, any case — `no-cache="Set-Cookie"` counts) and `$cfm_xae_nocache` (`X-Accel-Expires` `0` or any absolute `@<time>`). **Deliberately not `max-age=0`**: it is aimed at browsers too, and the common `.htaccess` recipes (H5BP, WP Rocket: `ExpiresByType text/html "access plus 0 seconds"`) send it on every HTML page, so honouring it would switch micro off for exactly the sites it is for; `s-maxage=0` is the shared-cache opt-out and is honoured | origin keeps the final say on *whether* a page is stored; on Tier B not on *how long* (a `max-age=3600` or far-future `Expires` page would otherwise sit in a micro zone for an hour, or for as long as the date says). Residual: a page whose only "do not cache" signal is `max-age=0`, a past or invalid `Expires`, a malformed `Cache-Control` value nginx would refuse (`max-age="60"`, `max-age=-1`) or `Pragma: no-cache` (nginx never read `Pragma`) is micro-cached for the bucket TTL. Stricter the other way: `X-Accel-Expires: 60` + `Cache-Control: no-cache` (natively stored — `X-Accel-Expires` wins) is not stored |
| Panel hosts/ports (`:2083/:2087/:2096`), webmail hosts, `/.well-known/`, `/acctxfer*`, cPanel/webmail bypass paths → never | The panel ports are separate listeners with no cache location; a plain `/.well-known/` fetch is routed at `cfm.lua` Step 0a1, and Tier B also skips the whole prefix (the rest of it reaches Step 4). `panel_host()` in `cfm_cache.lua` skips BOTH tiers for a host with a panel prefix — the `cfm_panel_hosts.lua` list `cfm.lua` and `cfm_panel.lua` share (`cpanel`, `whm`, `webmail`, `webdisk`, `mail`) plus the cache-only service prefixes `autodiscover`, `autoconfig`, `cpcalendars`, `cpcontacts` — whether the policy is a wildcard or the exact host; a missing module caches nothing (one WARN at load). Tier B also skips `/.well-known/`, `/acctxfer*`, `/wp-admin`, `/administrator/`, `/admin/`, `/sysadmin/`, `/___proxy_subdomain_*`, any path to a PHP script (`.php`, `.php<digit>`, `.phtml`, `.pht`, `.phar` at the end of the path or of a segment — `/index.php/cart` too), `?doing_wp_cron` and `?_envelope` (WordPress REST then moves the response headers — a `Cart-Token` — into the body) | **cPanel / webmail / SSO / AutoSSL broken** |
| Cache key excludes cookies; carries purge generation, **destination IP**, the **listener scheme** and the **scheme the origin is told** | `proxy_cache_key "g$cfm_cache_gen\|$server_addr\|$scheme\|$cf_xfp://$host$request_uri"` (Tier A); the micro locations add a `sc1` marker after the generation, `g$cfm_cache_gen\|sc1\|…` (Set-Cookie row) | per-user fragmentation / leakage; **multi-IP poisoning** — the origin is chosen by `$server_addr`, so without it a request to IP B with `Host: victim` stores B's default vhost under victim's key. **Both** schemes, not either: `$scheme` is the listener (:9080 → origin :80, :9043 → origin :443, which Apache may answer from different vhosts — e.g. a domain with no SSL vhost falls back to the IP's default SSL site), `$cf_xfp` is what the origin is told (differs from `$scheme` only behind a trusted peer such as Cloudflare Flexible SSL). Keying on `$cf_xfp` alone let a direct HTTPS client fill an entry that a Cloudflare visitor on :80 then hit (reproduced) |
| Request the **WAF flagged or could not inspect** → never micro-cached | `cfm.lua` sets `ngx.ctx.cfm_no_micro` on a logonly WAF hit and on a `waf_error` (fail_open); `micro_cache_target()` then returns no target, before `cfm_cache.micro_gate` runs (so the debug stamp may still read `would`). Tier B only | the response to a payload a rule flagged, or one the WAF never saw, served to other visitors. Includes logonly tells with no payload (rule 612, no `Sec-Fetch-*`) |
| Request carries **`Authorization`** → never read, never store | `map $http_authorization $cfm_req_auth` (any non-empty value → `"1"`; a raw predicate would read `Authorization: 0` as false) on `proxy_cache_bypass` **and** `proxy_no_cache` in every cache location; Tier B `micro_decision` also reports `bypass:authorization` and does not route | **basic-auth (cPanel Directory Privacy) / bearer response served to anonymous visitors** — nginx does not bypass on `Authorization` by itself |
| **Forwarded headers pinned** in cache locations | `proxy_set_header X-Forwarded-Host $host;` and `""` (not sent) for `X-Forwarded-Server/-Port/-Scheme/-Protocol/-Prefix/-Ssl/-Uri/-Path`, `X-Host`, `X-Original-Host`, `X-Original-URL`, `X-Original-Uri`, `X-Rewrite-URL`, `Forwarded`, `Front-End-Https`, `X-Url-Scheme`, `X-Scheme`, `X-HTTP-Method(-Override)`, `X-Method-Override`. Applies to **every** request through a cache location, armed vhost or not (all vhosts' static assets use the Tier A location) | cache poisoning — an app building absolute URLs / routes from these writes attacker input into a page cached for everyone. A denylist of the known URL-building headers, not a proof |
| Lock wait set **per tier** | `proxy_cache_lock_timeout 1s` (Tier A) / `5s` (Tier B) | the timeout must outlast the fill, or a cold-key burst all reaches the origin (when it expires every waiter is sent upstream and nothing is stored); yet on an uncacheable key (Set-Cookie / no-store / non-200) waiters queue at 500 ms steps until it expires — nginx has no hit-for-pass. Static files fill in well under 1 s and a popular 404 is the usual uncacheable key → 1 s. HTML can take seconds to render → 5 s, and Tier B remembers its uncacheable keys (next row) |
| Tier B **remembers an uncacheable key** | `cfm_cache.micro_note()` in the http-level `log_by_lua`: a micro request that fetched (`MISS`/`EXPIRED`) an answer nginx could not store (non-200, `$cfm_sc_unsafe` — any non-tracking `Set-Cookie` — `$cfm_cc_nostore`, `$cfm_xae_nocache`, a `*` in `Vary` or a `Vary` over 128 bytes) marks `md5($server_addr\|$scheme\|$cf_xfp://$host$request_uri)` in `lua_shared_dict cfm_cache_uncacheable`; `micro_gate` skips micro for a marked key (debug token `bypass:uncacheable`), then the next request after the mark probes again. A `MISS` marks for 60 s; an `EXPIRED` refresh (the page changed: it sets a cookie, went private, redirects, 401/403/404/410) for 240 s — longer than the largest micro zone's `inactive` (210 s; the guard pins the 30 s margin), so the old copy is evicted before the next probe. A 5xx or a request-level 4xx (400, 405, 406, 408, 411-417, 421, 429, 431) is origin trouble or about the request, not the page: on an `EXPIRED` key it **never marks** (the stale copy absorbs it — next row — and any client could provoke one), on a `MISS` it marks for 5 s, the lock timeout (the lock does not spare the origin — every waiter reaches it, as the next filler or when its wait times out — it only delays each visitor up to 5 s; measured on a cold 503 key, 20 req/s: every request reached the origin either way, p50 5.5 s through the lock vs 0.5 s direct). `X-Accel-Buffering: no` (nginx then streams and stores nothing) counts as not storable; an `X-Accel-Redirect` answer is served by an internal redirect and is neither stored nor remembered | the lock queue above: measured on a 1 s page that sets a cookie, 8 concurrent clients finished at 1, 2, 3.5, 4.5, 5.5, 6, 6, 6 s before the mark and all in ~1 s after it. The dict evicts least-recently-used marks when full (a lost mark costs one re-probe); a conf without the dict just does not remember. Residual (like Varnish hit-for-miss): one client's non-storable answer — a UA or language redirect, a cookie, an origin WAF's 403 — skips micro for that URL for everyone until the mark expires, so a client can keep micro off for one URL with a request per mark; the URL is then served as without micro, nothing wrong is stored |
| Tier B: a stale page is not kept alive by refreshes that cannot be stored; a failing origin is | `proxy_cache_background_update off` and `proxy_cache_use_stale updating error timeout http_500 http_502 http_503 http_504` in the micro locations (Tier A keeps background updates on) | with background updates on, an expired page is served stale while a background fetch refreshes it — and when that fetch cannot be stored (the page now sets a cookie, turned 404, went private) the stale copy is served on every request for as long as the key stays warm. Off, the request that finds the page expired fetches it itself and only requests arriving during that fetch get the stale copy; a page-changed answer then marks the key long enough for the copy to age out (previous row), so it is served for one fetch window. An origin that fails — connection error, timeout, or a 500/502/503/504 answer — keeps the stale copy served, the fetching request included (measured, 10 clients on a hot page whose origin answers 503 after 1 s: 4 origin hits and all clients 200 with this, 31 hits and 31 clients 503 when a 5xx marked the key). There is **no bound** on that while the origin keeps failing and the key gets a request within its zone's `inactive` (30-210 s): an intentional 503 (a maintenance page) is not shown on a warm key — purge the vhost, or set `MICRO_CACHE_ENFORCE = 0`, to show it. Other 5xx (501, 505, 507, CloudLinux's 508 "resource limit reached") are outside what nginx's `use_stale` can cover: the request that refreshes gets them, everyone arriving meanwhile the stale copy. A worker killed during a refresh can leave its entry locked stale (nginx logs `ignore long locked inactive cache entry`); a purge clears it |
| Tier B **forwards no forgeable client-IP / geo / hint header** | micro locations: `X-Forwarded-For $remote_addr` (the real client alone — `mod_remoteip` reads it behind 127.0.0.1, so `REMOTE_ADDR` is unchanged), `CF-IPCountry` / `CF-Visitor` only from the trusted peer (`$cfm_cf_ipcountry` / `$cfm_cf_visitor`, the `$cf_xfp` gate), and `True-Client-IP`, `Client-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `Fastly-Client-IP`, `X-Originating-IP`, `X-ProxyUser-Ip`, `X-Forwarded`, `X-Country-Code`, `HTTPS`, `X-Arr-Ssl`, `X-Proto`, `CloudFront-Forwarded-Proto`, `Surrogate-Capability`, `Proxy` (httpoxy), `Content-Type`, `Content-Encoding` not sent; `X-Real-IP` / `CF-Connecting-IP` are `$remote_addr` (guard-pinned) | WooCommerce geolocation takes `CF-IPCountry` before any IP lookup, PHP helpers read `Client-IP` / the `X-Forwarded-For` prefix, Flexible-SSL snippets read `CF-Visitor`: a direct client choosing any of them would store its forged answer for everyone. The client IP the origin sees is still a residual (above) — the real one |
| Tier B **never forwards a request body** | `proxy_pass_request_body off` + `proxy_set_header Content-Length ""` in every micro location (micro serves only GET/HEAD) | fat-GET poisoning: a body on a GET is not in the key, yet an app may read it — the WordPress REST API reads a JSON body on any method, so `GET /wp-json/wp/v2/posts` with `{"search":…}` in the body would store an attacker-shaped listing for everyone (verified with Content-Length, chunked and HTTP/2 bodies). Tier A keeps forwarding bodies (static files, and a POST to a static-extension URL must keep working) |
| Tier B request rails | `micro_decision`: a `Range` request, `Accept: text/event-stream` and a partial-page request (`X-Requested-With`, `X-PJAX`, `HX-Request`, `Turbo-Frame`, `X-Inertia` present, empty or not — apps answer those with a fragment, usually without `Vary`), a credential-style request header (`Cart-Token`, `WooCommerce-Session`, `X-WP-Nonce`, `X-Api-Key`, `X-Auth-Token`, `X-Access-Token`) and a `Cookie` header over 8 KB bypass; on the response side a micro location never stores an answer that hands out a session token in a header (`$upstream_http_cart_token` / `$upstream_http_woocommerce_session` on `proxy_no_cache`, mirrored by `micro_storable`, so the key is remembered) — the token-less `GET /wp-json/wc/store/v1/cart` is how a headless WooCommerce client obtains its `Cart-Token`, and a stored one would put every such shopper in one cart. `X-Requested-With` counts with any value: Android WebView (in-app browsers — Facebook, Instagram) sends its app package in it on every request, so that traffic is not micro-cached — an accepted hit-ratio cost, since an app that tests `!empty($_SERVER['HTTP_X_REQUESTED_WITH'])` would otherwise store the fragment it serves them; micro routes only from the HTTPS server's `location /` (the conf sentinel `set $cfm_micro_conf "1"`, `""` by default at server level; `micro_gate` requires `"1"`), never on an internal redirect (`ngx.req.is_internal()`: a named-location redirect keeps the sentinel; a redirect to a URI re-runs the `""` default), and only on an nginx core ≥ 1.23 (older ones expose only the first of several `Cache-Control` headers to the map). `rewrite … last`, `ngx.req.set_uri(…, true)` and every redirect also keep the sentinel, and all of them make the request internal (verified), so the check refuses them; the guard additionally keeps `location /` free of `rewrite` / `try_files` / `error_page` and of `rewrite_by_lua*` (in it, at its server and http level), and of buffering off there or inherited | a micro location buffers, so an SSE stream would be held back until it ends, and the no-buffer PHP/admin and streaming passthroughs would stop streaming; an older live conf (no sentinel) never gets newer Lua's micro routing |
| `cfm_clearance` is edge-set, not origin | see §5.5.1 (open) | edge cookie poisoning the cache |

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
  on Tier A, request cookies are not consulted at all (§14 — static assets
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
`proxy_cache` location of both confs, and refuses every other writer of a rail
variable (any `set*` / `map` / `geo` / named capture / inline Lua on a
`$http_*` / `$upstream_http_*` / `$cookie_*` / `$arg_*` variable SHADOWS the
real value, so `map … $http_authorization` would turn the credentialed-request
rail off). What it checks: §13.

`cfm_clearance`-cookie holders (cleared visitors) are still *anonymous* to the
app, and the cookie is on the ignore-list, so they **may** be served
micro-cache; the cache key never varies on the clearance cookie. *As built
they are not:* a cleared visitor returns at `cfm.lua`'s Step 2b fast path,
which is not a micro entry until the clearance-cookie ordering (§5.5.1) is
verified on a live edge. Micro is entered only at Step 4 (uncleared but
allowed).

### 4.1 Cookie handling — why the challenge cookie does **not** block caching

The easiest way to neuter micro-cache by accident, so it is a first-class
rail. The bypass is **not** "the request has a `Cookie` header". It is a
**positive allowlist of app-session cookie names**, plus an **ignore-list**
that strict mode treats as anonymous (`micro_cookie_verdict` in
`cfm_cache.lua`; the lists are `MICRO_AUTH_*` / `MICRO_IGNORE_*` there):

- **Auth allowlist (bypass):** the PHP / cPanel ecosystem (`PHPSESSID`,
  `wordpress_logged_in_*`, `wordpress_sec_*`, `wp-postpass_*`,
  `comment_author_*`, `woocommerce_*`, `cpsession`, `whmsession`,
  `roundcube_sessid` / `roundcube_sessauth`, `horde*`, `PrestaShop-*`,
  `laravel_session`, `ci_session`, `XSRF-TOKEN`, …), other stacks' sessions,
  the `*_session` / `*_sid` families, any name containing `csrf` / `xsrf`, the
  language / currency cookies and the server-read consent / age-gate cookies
  (§4 residuals) — plus the vhost's own `auth_cookies`.
- **Ignore-list (anonymous; consulted only under `strict_cookies`):**
  `cfm_clearance` and every `cfm_*` cookie, plus common analytics / consent
  cookies (`_ga`, `_gid`, `_gcl_*`, `_fbp`, the IAB `euconsent*` / `__cmp*`,
  …). In the default mode any cookie NOT on the auth allowlist is anonymous
  anyway.

A name is compared as the app reads it: PHP's `.` / space / lone `[` → `_`
and `a[b]` read as `a`, URL-decoded as older PHP and Rack do, `__Host-` /
`__Secure-` prefixes stripped; parsed in linear time; a `Cookie` header over
8 KB is not micro-cached.

So "won't our own challenge-solve cookie stop caching?" — **no**:
`cfm_clearance` is on the ignore-list. An anonymous-but-cleared visitor is
exactly the burst traffic micro-cache exists for; they get cached once Step 2b
becomes a micro entry (§5.5.1). Only a **named app session** bypasses.

**The allowlist's blind spot** is an app with an unknown session-cookie name.
Two layers cover it: (1) the **response-side rails** — a page rendered
per-user almost always sends `Set-Cookie` and/or `Cache-Control:
private|no-cache` (WordPress, Woo, Laravel, Roundcube all do), and both force
"do not store"; (2) the per-vhost **`strict_cookies`** flag, which bypasses on
any cookie not on the ignore-list — max safety, at the cost of not caching
visitors with a stray analytics cookie. Default is the allowlist; strict is
opt-in. This is the trade-off of the classic nginx WordPress micro-cache
recipe, tuned for the cPanel fleet.

**Validate it with the debug stamp**, not guesses: on a micro-armed vhost
`X-CFM-Cache: … microcache=bypass:auth:<cookie>` / `bypass:strict:<cookie>`
names the cookie that declined a request (§11.3; runbook §4). The §11
counters do **not** show it: a request the cookie rails decline never reaches
a cache location, so it is not counted (BYPASS counts something else, §11.1).

Tier A does not consult this allowlist at all (`static_gate` does not read
`strict_cookies` / `auth_cookies`); decision and residual in §14. In dry run
(`MICRO_CACHE_ENFORCE = 0`) the Tier B verdict only shows on the debug stamp
(`microcache=would/<n>s` | `microcache=bypass:<reason>`).

---

## 5. Edge mechanics

### 5.1 Cache zones — declared once, inert until used

`proxy_cache_path` must live in `http{}`. Declaring a zone caches nothing; a
zone only bites when a location activates `proxy_cache` **and** the bypass
gate allows it. Declared identically in both confs, under
`/var/cache/nginx/cfm_*` (the dirs the daemon and `scripts/cfm-cache-dirs.sh`
create):

```nginx
# Static (disk): one zone
proxy_cache_path /var/cache/nginx/cfm_static      levels=1:2 keys_zone=cfm_static:20m    max_size=10g  min_free=2g inactive=7d   use_temp_path=off;
# Micro (tiny, short-lived; on disk): 1/2/5/10/30/60/90/120s — cfm_cache.lua MICRO_BUCKETS
proxy_cache_path /var/cache/nginx/cfm_micro_1s   levels=1:2 keys_zone=cfm_micro_1s:10m  max_size=512m min_free=2g inactive=30s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_2s   levels=1:2 keys_zone=cfm_micro_2s:10m  max_size=512m min_free=2g inactive=30s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_5s   levels=1:2 keys_zone=cfm_micro_5s:10m  max_size=512m min_free=2g inactive=60s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_10s  levels=1:2 keys_zone=cfm_micro_10s:10m max_size=512m min_free=2g inactive=60s  use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_30s  levels=1:2 keys_zone=cfm_micro_30s:10m max_size=1g   min_free=2g inactive=120s use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_60s  levels=1:2 keys_zone=cfm_micro_60s:10m max_size=1g   min_free=2g inactive=180s use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_90s  levels=1:2 keys_zone=cfm_micro_90s:10m max_size=1g   min_free=2g inactive=180s use_temp_path=off;
proxy_cache_path /var/cache/nginx/cfm_micro_120s levels=1:2 keys_zone=cfm_micro_120s:10m max_size=1g  min_free=2g inactive=210s use_temp_path=off;
```

Tier A has one zone and follows the origin's headers (§5.4); per-TTL static
zones were not built.

**Disk rails.** The Tier A key carries the query string (asset versions ride
on `?ver=`), so every distinct query was a new full object on disk, and a HEAD
(nginx fetches it as a GET) or an aborted GET still stored the whole file. So
every zone keeps `min_free=2g` (the cache manager evicts while the filesystem
has less than 2 GB free), and the Tier A locations add
`proxy_cache_min_uses 2` (a key is stored on its second request: a one-off
random query never reaches the disk) and `$cfm_cache_too_big` on
`proxy_no_cache` (a `Content-Length` of 10 MB or more is never stored; big
media already streams uncached through the passthrough location). The guard
pins all three.

These bound the write amplification; they do not close it: `min_free` is
sampled about every 10 s (a fast fill can overshoot by ~1 GB); a response
without `Content-Length` (chunked compression) is not capped; two tiny
requests (two HEADs, two `Range: bytes=0-0`) still store a full object, once
per `Accept-Encoding` variant; Tier B has no size cap or `min_uses` (bounded
by its zones' `max_size`); random-query keys still take `keys_zone` slots. A
per-vhost fill budget would bound the write rate whatever the headers — not
built (§14).

Each cache location also carries the **anti-stampede** set (§5.6):
`proxy_cache_lock on;`, `proxy_cache_use_stale updating error timeout;`
(Tier B adds `http_500 http_502 http_503 http_504`),
`proxy_cache_background_update on;` (Tier B: `off`, §4) — plus
`proxy_cache_bypass $cfm_cache_skip $cfm_req_auth;` / `proxy_no_cache
$cfm_cache_skip $cfm_cache_non200 $cfm_req_auth …;` (§0, §4) and the key of
§4 (Tier A `g$cfm_cache_gen|$server_addr|$scheme|$cf_xfp://$host$request_uri`,
Tier B the same with `sc1|` after the generation). The guard pins every one.

### 5.2 Per-request decision transport: edge-pull → per-worker table → local lookup

The WAF-exclude / H3 model, **not** the fppolicy per-key RPC model:
fingerprints are high-cardinality and need an RPC budget; cache policy is per
vhost — low cardinality — so the edge **polls the whole table**
(`GET /nginx/cache/config`) and each request does a local lookup. Zero RPC on
the hot path, no budget to tune.

`cfm_cache.lua` mirrors `cfm_h3_config.lua`: each worker keeps its own table
(no shared dict), refreshed every 60 s (fixed, `_refresh_sec`) by an async
`ngx.timer.at(0)` that the first request finding it stale schedules; a failed
pull keeps the last table. `rebuild_cache` turns the feed into exact hosts +
`*.suffix` wildcards (most specific first); `policy_for(host)` returns the raw
policy `{gen, static, micro, strict_cookies, auth_cookies}` (or nil). The
public entry points are `static_gate`, `micro_gate`, `observe`,
`policy_key_for`, `maybe_flush_stats`, `micro_note` and
`micro_setcookie_filter`. It is a `require`d module, not a file-local: an
`access_by_lua_file` resets file-locals per request.

### 5.3 Insertion points in `cfm.lua`

Micro-cache (Tier B) is decided at the **allow-return**, after all
enforcement: **Step 4 only** (Step 2b waits on §5.5.1);
`cfm_micro_entry_structure_test.lua` pins it. Step 4 is after Step 0a1 (the
`/.well-known/` carve-out for a plain fetch), so ACME/DCV is never cached; the
rest of the prefix reaches Step 4 and is refused by the `MICRO_PATH_PREFIX`
rail. `micro_cache_target()` calls `cfm_cache.micro_gate()` under a pcall;
`micro_gate` applies the §4 rails and, on a cache decision, sets

```lua
ngx.var.cfm_cache_skip = "0"
ngx.var.cfm_cache_gen  = tostring(p.gen or 0)
return "@cfm_micro_" .. bucket .. "s"   -- cfm.lua then: return ngx.exec(target)
```

HTTPS only (the micro locations live in the HTTPS server), only from the
`location /` carrying the `$cfm_micro_conf "1"` sentinel, never on an internal
redirect, and only while `MICRO_CACHE_ENFORCE = 1`.

Static (Tier A) is decided in the static-asset location, which skips all of
`cfm.lua`. Its `access_by_lua_block` calls only `cfm_cache.static_gate()` — no
WAF, no decision RPC, one table lookup; it returns at once when
`SITE_CACHE = 0`. For an armed static tier (not a panel host) it sets
`$cfm_cache_skip = "0"` and `$cfm_cache_gen`.

### 5.4 TTL model (nginx constraint → TTL buckets)

nginx computes a cached entry's validity from the **upstream** response
headers, before any Lua `header_filter` runs — so `X-Accel-Expires` set from
Lua is too late — and `proxy_cache_valid` is a per-location directive that is
**not** variablizable. A variable `proxy_cache $zone` selects only the storage
zone; one location applies one validity to every zone it caches into
(verified: two locations at `1s` / `5s` expire independently, a variable-zone
location shares one validity).

So each micro bucket is a **separate internal location** `@cfm_micro_<n>s`
pinning `proxy_cache cfm_micro_<n>s;` + `proxy_cache_valid 200 <n>s;`, and
Step 4 `ngx.exec`s to the bucket the policy snaps to. A HIT costs the same in
any zone, so more buckets cost only a little startup memory.

- **Buckets:** `MICRO_BUCKETS = {1, 2, 5, 10, 30, 60, 90, 120}` s in
  `cfm_cache.lua`; the guard pins the confs' zones and locations to it.
- **TTL source:** only the micro tier's `ttl` (`--micro-ttl`); a recipe name
  does not set it. The stored TTL is parsed with the units the daemon accepts
  (`s`/`m`/`h`/`d`, an optional leading `+`), snaps to the nearest bucket
  (ties down), clamps above 120 s to 120 s; an empty or unparseable TTL gets
  the 1 s bucket. For herd protection 7 s vs 8 s does not matter, so the
  snapped menu behaves as continuous. A per-vhost choice is reload-free (a
  policy value the edge pulls); a new bucket is a zone-list change + reload,
  never a per-vhost event.
- **Static:** one zone, the origin's `Cache-Control` / `Expires` with a
  `proxy_cache_valid 200 1h` fallback. `static_gate` reads only the static
  tier's `on`: the stored static recipe and TTL are **labels** (the CLI and
  MCP descriptions say so). Static TTL buckets and a forced
  `Cache-Control: public, immutable` were not built.

Truly arbitrary per-request TTL would need OpenResty `srcache` with a
Lua-computed store TTL and a storage backend — heavier, deliberately deferred;
the bucket model is the answer.

### 5.5 Open edge items

1. **§5.5.1 Clearance-cookie ordering — OPEN.** Before Step 2b (the
   clearance fast path) can be a micro entry, verify on a live
   OpenResty/Angie edge that the edge-set `cfm_clearance` refresh
   (`refresh_clearance_cookie`, `ngx.header` in the access phase) survives the
   `ngx.exec` to `@cfm_micro_<n>s`, HIT included, and does not make the
   response unstorable. nginx's "don't store `Set-Cookie`" check reads the
   upstream headers, but the micro locations decide on `$cfm_sc_unsafe`,
   which `micro_setcookie_filter` computes from `headers_out` — so an
   edge-added cookie also keeps it at `"1"`. Wiring Step 2b must exclude
   edge-set cookies in that filter **and** in `micro_note`, which marks a URL
   uncacheable on the same variable. Harness evidence only (nginx 1.24 +
   lua-nginx-module 0.10.26): a header set with `ngx.header` before the
   `ngx.exec` (`X-CFM-Action`) is present on the micro response, HIT
   included. Until then micro serves Step 4 only.
2. **Origin keepalive — OPEN.** Caching sits in front of the origin whatever
   the `ORIGIN_KEEPALIVE` pools; 443 `proxy_ssl_session_reuse off` is
   unaffected. HIT/MISS accounting with keepalive armed is not yet checked on
   a live edge.
3. **`Vary: Cookie` — not built.** Only `Vary: *` or a `Vary` over 128 bytes
   is treated as unstorable (`micro_storable`); any other `Vary`, `Cookie`
   included, gets nginx's native per-variant keying. A cookie that picks a
   variant is already a bypass when it is a session cookie (§4.1). Forcing a
   bypass on `Vary: Cookie` is the open idea.

### 5.6 Performance — this must LOWER CPU, not raise it

The point is fewer origin round-trips, so the machinery must never become the
cost:

- **Invariant 1 — zero per-request daemon RPC.** A cache decision is one
  per-worker table lookup (`cfm_cache.policy_for`); the table is pulled in a
  timer (§5.2). No request ever waits on the daemon.
- **Invariant 2 — near-zero cost when unused.** A `has_any` flag gates both
  tiers (`has_micro` likewise for Tier B): with `SITE_CACHE = 0` or no armed
  vhost, the static-location gate and the Step 4 hook return on one boolean.
  A node that does not use caching pays nothing.
- **Invariant 3 — the request path never blocks on the daemon.** A failed,
  slow or absent pull keeps the last table, or (never pulled) leaves caching
  off. Each pull is one unix-socket request (`Connection: close`, 200 ms
  timeouts) in a timer; there is no circuit breaker.

**Anti-stampede is the actual CPU win.** Under a burst on a heavy page the
origin sees ~one request per TTL window (one filler; everyone else served
stale or briefly queued) instead of N/s of PHP. That holds only while
`proxy_cache_lock_timeout` outlasts the fill: when the wait expires every
waiter goes to the origin and nothing it fetches is stored. Tier B uses 5 s (a
2.5 s render under a cold 20-client burst: 1 origin hit with 5 s, 20 with
1 s — measured), Tier A 1 s. The cost of 5 s is the uncacheable-key queue,
and it is **sustained**: a page that sets a cookie on every anonymous
response (Laravel, PHP `session_start`) is uncacheable on every request, so
under steady concurrency its clients are served one per 500 ms (measured: 10
clients on a 0.3 s Set-Cookie page — 270 requests in ~8 s uncached, 45
through a 5 s-lock micro location). Hence Tier B remembers an uncacheable key
(§4) and only the requests arriving during one probe queue.

**Per-request cost (caching ON for a vhost):**

| Cost | Magnitude | Notes |
|---|---|---|
| policy lookup (per-worker table) | µs | normalize_host + one table lookup + a scan of the wildcard list |
| cache key md5 + lookup | µs | nginx-native, only in cache locations |
| stats `incr` (log phase) | ~0.5 µs, off the serving path | counted responses of armed vhosts only |
| background config pull | once / 60 s / worker | not per request |
| stats push | once / ~60 s / node | ~40 ms in a timer at 5000 vhosts (§11.1) |
| **on HIT** | **− origin round-trip, − PHP exec** | the saving |
| on MISS | + key hash + store | trivial vs the origin fetch it wraps |

**Disk vs RAM.** `use_temp_path=off` avoids a cross-filesystem rename. The
micro zones could sit on tmpfs; as built every zone is on disk under
`/var/cache/nginx` (nothing provisions a tmpfs).

### 5.7 Tier B readiness — on-box checklist (a node's first micro vhost, or a new kind of app)

`MICRO_CACHE_ENFORCE` shipped `0` until this passed on a live vhost
(infected.gr, a WordPress blog on virgo, 2026-09-23); it has defaulted to `1`
since, so arming a vhost's micro tier is what turns it on. Run this on a
node's first micro vhost (a site you control). For a new kind of app (a shop,
a membership site) follow runbook §7: arm it `--strict-cookies`, find its
session cookies with the debug stamp, add them with `--auth-cookies`, then run
steps 5–7 here. Who never takes the micro path: requests from loopback, the
box's own IPs, `IGNORE_IPS` / `IGNORE_NETS` and RFC 1918 peers (they bypass
`cfm.lua` at Step 0a), the verified-crawler prefixes of
`challenge_waf_bypass.conf` (`$cfm_bypass_ip`, Step 0), any other request an
earlier step allows outright (a plain `/.well-known/` fetch at Step 0a1, …),
and a client holding a valid `cfm_clearance` cookie (Step 2b, §5.5.1) — micro
serves the Step 4 plain allows only. So the debug stamp, from the box, shows
the would-cache verdict; the served verdict comes from a **public-IP client
with no `cfm_clearance`** (e.g. `curl` without a cookie jar), read in the edge
access log (`ucache=` and `up=cfm_apache_micro` vs `up=cfm_apache`).

1. **The live conf carries the Tier B rails** (the reference conf ships them;
   a live conf edited by hand may not). In the live conf
   (`/usr/local/openresty/nginx/conf/nginx.conf`, `/etc/angie/angie.conf`):
   `set $cfm_micro_conf "1";` once (in the HTTPS `location /`) and
   `set $cfm_micro_conf "";` once (its server level),
   `proxy_cache_background_update off;` eight times (one per bucket), `lua_shared_dict
   cfm_cache_uncacheable`, the `$cfm_cc_nostore` and `$cfm_xae_nocache` maps;
   the nginx core is ≥ 1.23 (`openresty -V` / `angie -V`); then `-t` and a
   reload. Without the sentinel micro never routes (fail-safe), whatever the
   knob says.
2. **Arm micro on the test vhost, strict:**
   `cfm webtop site-cache set <host> --micro micro_safe --micro-ttl 5s --strict-cookies`.
   Enforce is on by default, so strict mode (any cookie not on the ignore list
   bypasses) keeps visitors with a session out of the cache while you check.
3. **Verdicts from the box** (they read the same with or without enforce), against the edge's HTTPS listener :9043
   on the vhost's own IP (so the origin answers from that vhost):
   `curl -sk -o /dev/null -D - -H 'X-CFM-Cache-Debug: 1' --resolve <host>:9043:<vhost-ip> https://<host>:9043/`
   shows `microcache=would/5s`; add `-H 'Cookie: wordpress_logged_in_x=1'` →
   `bypass:auth:…`; `/wp-login.php` or `/?doing_wp_cron=1` → `bypass:path`;
   `-H 'Range: bytes=0-10'` → `bypass:range`; `webmail.<domain>` (if armed by a
   wildcard) → `bypass:panel`.
4. **Cookies, then enforce:** each session cookie of the app, sent on its own,
   must say `bypass:auth:<name>`; one that says `bypass:strict:<name>` goes into
   `--auth-cookies` (runbook §7). Then drop strict (`--no-strict-cookies`) or
   keep it. `MICRO_CACHE_ENFORCE` must be `1` (the default) for steps 5–7; the
   daemon applies an edited `detectors.conf` on its own within a few seconds (it
   polls the file) and the edge picks it up ~10 s later (no proxy reload).
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
10. **Roll back** at any point: `MICRO_CACHE_ENFORCE = 0` (~15 s after the save), and
    `cfm webtop site-cache purge <host>` if something wrong got cached — also
    to show a maintenance / 5xx page instead of the last good copy (a failing
    origin keeps the stale copy served), and for an entry stuck stale after a
    worker crash (§4).

## 6. Data model (the per-vhost store)

`siteCacheStore` in `internal/webdetector/site_cache.go`, JSON at
`/var/lib/cfm/webdetector_site_cache.json` (knob `SITE_CACHE_STORE_PATH`; mode
0600; at most 5000 entries), write-through with atomic save (the mechanics of
`http3_overrides_store.go`), plus the freezing of rows it cannot load
(below). One entry per vhost, with **independent per-tier sub-policies**:

```jsonc
{
  "host": "myip.gr",
  "scope_hosts": ["myip.gr"],          // audit only: [host] if a scoped token created it, absent if an admin did
  "generation": 1758585600123,           // wall-clock ms, replaced by Purge (§10); part of the cache key
  "static": { "enabled": true,  "recipe": "static_aggressive", "ttl": "7d" },  // recipe/ttl: labels at the edge (§5.4)
  "micro":  { "enabled": false, "recipe": "micro_safe",        "ttl": "1s" },  // ttl snaps to a bucket (§5.4)
  "strict_cookies": false,               // §4.1: bypass on ANY non-ignored cookie
  "auth_cookies": [],                    // §4.1: per-vhost extra app-session cookie names
  "created_at": "2026-09-21T...", "updated_at": "2026-09-21T..."
}
```

**Generation.** It is in the cache key (§4, via the Lua-set `$cfm_cache_gen`),
so a purge is a generation change: old keys become unreachable and age out
under `inactive`, no filesystem walk. A value must **never be issued twice**
(a remove + re-add that reused one turned still-on-disk objects back into
HITs, undoing a purge). So a new or purged generation is the **wall clock in
ms**, bumped past every generation the store has issued or loaded
(`nextGenerationLocked`) — unique store-wide, so an exact host never shares a
key space with its covering wildcard. Milliseconds because the edge renders
it with Lua `tostring` (`%.14g`), exact only below 1e14. It is not
client-settable. The high-water mark is rebuilt from stored entries on
restart, so a repeat needs the clock to step back (VM restore, boot before
NTP) onto a removed host's exact last value. On load a generation below 1e12
(a legacy counter) or at/above 1e14 is reissued once and the file rewritten.

**`scope_hosts`** records only WHO first enabled caching: exactly `[host]`
when a scoped token created the policy, absent when an admin did, kept across
edits. (It used to hold the token's whole vhost allowlist, which showed a
tenant's domain list to other tenants; legacy entries are trimmed on load and
the file rewritten, as for a stored `:port` or a duplicate host.) Access is
gated by the live token scope at the API, never by this field.

**Feed (`/nginx/cache/config`) and wildcards.** The feed carries every vhost
with an armed tier: exact hosts first, then `*.suffix` wildcards most
specific (longest) first — `cfm_cache.lua` sorts the same way and takes the
first matching wildcard, so `x.shop.example.com` gets `*.shop.example.com`
over `*.example.com`. An all-off EXACT host that an armed wildcard covers is
sent as an **opt-out row** (no tier): the exact match wins, so that host
caches nothing — a tenant can opt its vhost out of an admin wildcard. An
all-off narrower wildcard under a broader armed one is an opt-out row too; an
all-off entry nothing armed covers is left out.

**Off vs remove.** Under an armed wildcard the two ways to stop caching
differ:

- **off** (CLI `off`/`disable`; API `set` with both tiers `enabled:false`)
  keeps an all-off entry: the host (or every host under a narrower wildcard)
  is never cached.
- **remove** (CLI `remove`/`rm`; API `remove`) deletes the entry: the host is
  uncached unless an armed wildcard covers it, which then applies.

**Re-arming issues a fresh generation** — static off → on, or micro off → on
with the recipe it kept while off. A tier is often turned off BECAUSE
something wrong got cached (a per-user asset or page, §14), and its zone may
still hold — and, through `use_stale`, serve — those objects. Both tiers share
the generation, so re-arming one also starts the other from an empty cache (a
refill, never a wrong answer). A FIRST micro enable (no stored recipe) keeps
the static cache. Turning a tier off, or any other change, keeps the
generation; so does the `SITE_CACHE = 0` panic button (incident order:
runbook §8, and §10 here).

**Rows this build cannot load** — a recipe or field from a newer build (any
unknown field freezes a row, so a newer build's safety setting is never
ignored after a downgrade), or a malformed hand edit — are kept in the file
as stored and never served. They FAIL CLOSED: the host (when the edge can
match it) is an opt-out (a frozen wildcard: every sub-host with no more
specific policy), so a covering armed wildcard does not start caching it.
`list` names them under `unloadable` (scope-filtered); `get`/`purge` say why
there is no row; a purge does not reach them. A `set` that would arm such a
host is refused (a merge would drop the stored cookie settings); `remove`
deletes it, and any `set` (incl. `off`) replaces it in the same save. Because
any unknown field freezes a row, **a new field must be `omitempty` with its
zero value meaning the old behaviour** — or a downgrade uncaches every vhost.

**`set` rules.** A tier's recipe cannot be cleared through `set` (disable the
tier instead): a disabled tier keeps its recipe, which is how a re-enable
knows to start a fresh generation. Because an all-off entry changes what a
covering wildcard does, `set` creates a NEW all-off entry only when it turns
both tiers off explicitly; a `set` that would merely stage a TTL or a cookie
setting for an unconfigured host is rejected. Hosts carry no `:port` (the
edge strips it from the request Host and the feed): a new policy with a port
is rejected, a stored one normalized.

**Host and cookie validation.** A host is an exact DNS-style name or one
leading `*.` over one: labels of 1-63 characters from `[a-z0-9_-]`, not
starting or ending with `-`, at most 253 characters; an internationalized
name in its punycode (`xn--`) form. A wildcard needs at least two labels
after `*.` (`*.com` would arm every `.com` vhost). A stored row whose host
fails these rules is frozen like any unloadable row (still an opt-out when
the edge can match its host), and `remove <that host>` deletes it (`off`
cannot: the host is invalid for a new policy). `auth_cookies`: at most 32
names of at most 256 bytes; the edge takes a cookie's name up to `=` or
whitespace in a `;`-split pair, so a name with whitespace, `=`, `;` or a
control character could never match and is rejected, as is a 33rd name.
Names are deduplicated case-insensitively as the edge compares them (ASCII
only). Anything else is accepted, RFC 6265 token or not (PHP array cookies
such as `cart[id]`, commas, quotes). A stored row with a name the edge cannot
match freezes on upgrade — fail closed until the name is fixed.

---

## 7. Management surfaces

### 7.1 HTTP API (`/api/v1`, rows in `apiRoutes()` in `http_api.go`)

| Method | Path | Notes |
|---|---|---|
| GET  | `/api/v1/site-cache/list` | scope-filtered; every stored entry (armed, and all-off opt-outs), sorted by host; `unloadable` names hosts whose stored row this build cannot load (treated as opted out, §6); `switches` is the node's `{site_cache, micro_cache_enforce}` as last handed to the edge (§12), returned to every caller (node-wide, not tenant data) |
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

`case "site-cache", "cache":` in the `webtop` dispatch (`cli.go`), implemented
in `internal/webdetector/cli_site_cache.go` over the JSON API (through
`internal/clihttp`):

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

### 7.3 cfm-admin page "Site cache"

`/cfm-admin/webdetector/site-cache/`, under "Rules & engine" ("Site cache for
<host>" in the Ctrl-K palette; `?vhost=` filters the list). A
directory-routed page modelled on Challenge-Access; files in §15. It has:

- **callouts** on what each tier does and never does, and the node's
  `SITE_CACHE` / `MICRO_CACHE_ENFORCE` from the list response's `switches`:
  the micro tier reads "enforced" or "dry run". When the page cannot tell it
  says to treat an armed micro tier as live; a `SITE_CACHE = 0` node gets a
  danger banner;
- an **editor** (host, static tier + recipe label, micro tier + TTL bucket
  menu + recipe label + auth cookies + strict) with a plain-language review
  sentence. The model validates what the daemon validates (host, TTL, recipe,
  cookie names, the 32-name cap) and warns about an opt-out, a TTL that snaps,
  a re-enable that starts the cache over, a host a wildcard covers;
- **Check one URL**: the §11.3 debug-stamp `curl` for a vhost and path;
- the **policy table** (filters, search, sort incl. HIT %; per row Edit,
  Check, Purge, Turn off = the opt-out, and a separate, labelled Delete =
  `remove`, whose confirm names the wildcard the host will then follow);
  **Purge all** for an admin; the unloadable hosts with Delete (and Turn off
  where the host is still valid);
- a **Recipes** panel (§8) with a per-vhost preview, and a **Hit counts**
  table (§11).

**Saves are merge patches carrying only what the operator decided** (§6): a
new policy sends only the tiers turned on (both off explicitly for an
opt-out) and the cookie settings when set; an edit sends only the fields that
differ from the policy it loaded; a tier's recipe / TTL go only while it is
on, never the static TTL label. A new-policy form over an existing or
unloadable host, or before the list loaded, is refused; an edit whose policy
changed meanwhile is reloaded if untouched, flagged if not. **Never make a
save resend the whole form:** that silently reverted a concurrent cookie-rail
change, and a new-policy form over an existing host switched its caching off.
Turning the micro tier on asks for confirmation unless the node is known to
be in a dry run.

**Scoped users:** `site-cache` stays **out** of `ADMIN_ONLY_NAV_PATHS`
(`controller-bootstrap.js`), and `v1/site-cache/` is in both the viewer write
guard and the scoped self-service write list (`core.js`), like `v1/http3/`. A
host outside the token's vhosts is refused before the request (a literal
match, as the API checks; an empty scope allows nothing). Purge all is not
shown; the switch callouts say the operator set them; a scoped Delete
confirm says an operator wildcard may cover the host. The backend fails closed regardless.

**Parity:** the model is a second copy of daemon and edge rules, so it is
pinned. `site-cache-model.test.js` reads the recipe vocabularies and limits
from `site_cache.go` and `MICRO_BUCKETS` from `cfm_cache.lua`;
`scripts/tests/fixtures/site_cache_ui_parity.txt` holds TTL, bucket, host and
cookie cases, run by the JS model (all), the daemon
(`site_cache_ui_parity_test.go`: host and cookie through the real set path,
TTL through `parseCacheTTL`) and the edge (`cfm_cache_ui_parity_test.lua`:
buckets).

### 7.4 Bridge (daemon↔edge, `nginx_bridge.go`)

- `GET /nginx/cache/config` (`handleCacheConfig`) →
  `{"entries":[{host, gen, static?:{on,recipe,ttl}, micro?:{…}, strict_cookies?, auth_cookies?}, …]}`
  — a disabled tier is omitted, an opt-out row has no tier; token-gated,
  **explicit Content-Length** (the minimal Lua reader needs it);
  `{"entries":[]}`, never null, when empty. Backed by the `ListCachePolicy`
  bridge hook (`siteCacheStore.PolicyFeed`). Pinned against the edge by
  `site_cache_edge_parity_test.go` + `cfm_cache_edge_parity_test.lua`.
- `POST /nginx/cache/stats` (`handleCacheStats`) ← the edge's stats push,
  `{"rows":[{host, counts:{STATUS:n}}]}`, token-gated, 4 MiB body cap, one
  hook event per push (§11).
- **Purge is not a push.** It is the `generation` in the pulled config: each
  worker applies it on its next poll (≤ ~60 s).

---

## 8. Recipes

**A recipe is a label.** The daemon accepts the names below
(`staticCacheRecipes` / `microCacheRecipes` in `site_cache.go`) and the edge
uses one only in the debug stamp. What decides caching is the tier's `on`
and, for micro, its `ttl` snapped to a bucket (empty = 1 s; §5.4) — so
`micro_aggressive` without `--micro-ttl` behaves as 1 s, every static recipe
behaves the same (origin headers, 1 h fallback), and `fullpage_advanced` is
an ordinary micro label, clamped to 120 s. The page's recipes therefore
always send the micro TTL.

Stored vocabulary: `static_lean`, `static_aggressive` (static);
`micro_safe`, `micro_aggressive`, `micro_custom`, `fullpage_advanced`
(micro). `fullpage_advanced` (a planned hours-long full-page tier) was not
built; the page offers it only on an entry that already has it.

The recipes are a **front-end catalog** in `site-cache-recipes.js` (like
`CA_RECIPES` in `challenge-access-recipes.js`): each `build(vars)` emits one
ordinary `set` patch per vhost, and since `set` merges, a recipe changes only
the tier it names:

| Recipe (page) | Sets | For |
|---|---|---|
| Cache static assets | static on, `static_lean` | the usual first step |
| Burst shield (micro-cache 1 s) | micro on, `micro_safe`, `1s` | heavy pages / bursts (`myip.gr`) |
| Near-static pages (micro-cache 10–120 s) | micro on, `micro_aggressive`, `10s`, `30s`, `60s`, `90s` or `120s` | pages that rarely change |
| Static assets + burst shield | both of the above | |
| Never cache this host (opt-out) | both tiers off | a sub-host under an armed wildcard |

A vhost combines at most one static and one micro tier.

**No Simulate (decision).** Unlike traffic rules, where a wrong rule silently
blocks legitimate traffic, a caching mistake is **bounded and reversible**:
the §4 rails mean the worst case is *stale anonymous content*, and the
operator turns the vhost off or purges. Verification is observational:

- **One URL:** read the `X-CFM-Cache` debug stamp
  (`observe … status=<HIT|MISS|BYPASS|…> microcache=would/<n>s|bypass:<reason>`;
  §11.3, runbook §4) — from a trusted source, against the edge's :9043
  listener (loopback :443 reaches the origin; §5.7 step 3).
- **Aggregate:** the §11 stats. (BYPASS is not the micro rails: those
  declines are not counted at all; §11.1.)

---

## 9. Scope model (scoped cPanel self-service — full power, fenced)

Scoped users get the **same power** as admins **over their own vhosts**: any
recipe, custom TTL, off, purge — only for hosts in their token scope,
fail-closed otherwise. It reuses the challenge-access precedent:

- `RequireScopedOrAdmin` + `scopeAllowsVhosts(r, vhosts)` on every write: nil
  scope = admin (unrestricted); empty scope = deny; else every target host
  must be in the token allowlist.
- The host is the entry's immutable key, so checking the ONE requested host
  (literally, lowercased — the store then only trims a trailing dot or a
  port, so it can never land on a different host) covers set, get, remove and
  purge alike.
- List/stats are scope-filtered with `vhostAllowed` on each row's key (an
  out-of-scope row is left out, not redacted).
- **Purge-all** (`?all=1`) is **admin-only** (403 for a scoped caller); a
  scoped caller purges one named in-scope host (`?host=` required).
- Scoped self-service has no switch: it is always on, through the API and the
  page.

Because the §4 rails are absolute, a tenant's "aggressive" choice can still
only cache their own anonymous, cookieless, non-redirect 200s — no
cross-tenant or correctness risk.

Scope matching is literal, as on the HTTP/3 and challenge-access endpoints: a
token whose scope holds `*.example.com` (cPanel lists an account's wildcard
subdomain that way) manages the `*.example.com` policy — and its aggregate
stats row — even if an admin created it. That reaches another tenant only if
another account hosts a sub-host of that domain, which cPanel allows only with
its cross-account subdomain options (off by default).

Recorded in `docs/endpoint_scope_inventory.md` (CLAUDE.md §5): list / get /
stats / set / remove / purge = scoped-allowed (own host); purge-all =
admin-only.

---

## 10. Purge / invalidation

- **Micro-cache is self-healing** (1–120 s buckets); it rarely needs a purge.
- **Static needs purge.** Mechanism: the **generation bump** (§6). The key
  includes the generation; a purge stores a new, never-used one → new key
  space → old entries age out under `inactive`. No filesystem walk, no
  `proxy_cache_purge` (commercial) dependency, works on OpenResty and Angie.
- **Surfaces:** `POST /api/v1/site-cache/purge?host=` (admin or the owning
  scoped user) and `?all=1` (admin); CLI `purge <host>` / `purge --all`;
  cfm-admin per-row **Purge** and, for an admin, **Purge all**.
- **Latency:** each edge worker applies the new generation on its next feed
  poll, within ~60 s (the poll is triggered by traffic); until then that
  worker serves the old objects. An edge reload applies it at once. While
  `SITE_CACHE = 0` no worker polls, so after a purge reload the edge while the
  switch is still `0`, then restore it (runbook §8); reloading after the
  restore leaves an old worker serving the old generation until its next poll.
- **Disk:** old objects stay until `inactive` (static: 7 d) or the zone's LRU
  (`max_size`, static 10 GB) removes them — unreachable, not served.
- **A purge covers ONE policy key.** The edge keys a request on the
  generation of the policy that matched it. A host that moves back under a
  covering wildcard (its exact policy, or a narrower wildcard, removed) finds
  that wildcard's own cached objects for it again. A purge of the host's
  former exact policy never reached them; only a purge of the wildcard does,
  and a scoped tenant cannot purge an admin's wildcard (unless its scope
  literally holds `*.suffix`, §9). To keep a tenant's purge meaningful, keep
  an exact policy (or an opt-out) rather than removing it.
- **Per-URL purge** is not built (§14). It would have to cover every key
  variant the URL can be stored under: each server IP the vhost answers on ×
  listener scheme × scheme told to the origin (and the micro `sc1` key).

---

## 11. Cache statistics & observability

Per-vhost cache effectiveness for the admin (all vhosts) and a scoped user
(their own). Every counter is incremented in the http-level `log_by_lua`,
after the response is served. It is a **live totals view**; nothing is
persisted.

### 11.1 Edge counters (live, in-memory)

- `lua_shared_dict cfm_cache_stats 8m` (both confs), written by
  `cfm_cache_log.lua`.
- **Counted:** a response with status 200 or 304 that went through a cache
  location — the static-asset locations, and `@cfm_micro_<n>s` (reached only
  while `MICRO_CACHE_ENFORCE = 1`) — for a host that `policy_key_for` maps to
  an ARMED policy key (the exact host or the matching `*.suffix`, never the
  raw request Host, so a client cannot explode the dict with sub-hosts).
  A non-cacheable 404/3xx MISS is not counted, so a broken asset URL cannot
  depress a vhost's hit ratio.
- **Keys:** per armed key, `cvh:<md5(policy key)>:<STATUS>` for the seven
  `$upstream_cache_status` values — both tiers in one set. A digest key
  (≤ 48 bytes) takes the same small slot whatever the host's length, so the
  8m dict holds ~65 000 counters: the 5000-policy limit × 7 statuses with
  room to spare (measured on nginx 1.24 with 5000 armed vhosts + 3000
  disarmed: every row complete with 25- to 253-character hosts). Past
  capacity, LRU evicts the least recently touched counters, a disarmed
  vhost's first. Plus per-zone totals over the same armed keys,
  `cache:zone:{cfm_static|cfm_micro}:status:<S>` / `…:total`, `cache:total`
  and `cache:last_seen_ts`, which `cfm_stats.lua` exposes in the
  `/cfm-admin/lua-stats` JSON under `cache.zones`.
- **Counting** goes through `cfm_shdict.incr` (`incr` without init, then
  `add`): `incr(key, n, init)` in lua-nginx-module 0.10.26 loses counters when
  two keys' crc32 collide (~13% odds per node at 35 000 counters).
- **BYPASS** is a counted request that could not use the cache: a static
  asset of an armed policy whose static tier is off (a micro-only vhost shows
  its assets as BYPASS — expected), a cache-location request with an
  `Authorization` header, a panel / service host under an armed wildcard, or
  anything while `SITE_CACHE = 0` (counted, not pushed). It is **not** the
  §4.1 cookie rails nor any Tier B request-side decline: those requests stay
  in `location /`, which has no `proxy_cache`, so they are not counted at all
  — the debug stamp (§11.3) is the view of those.
- A reload keeps the counters (a `lua_shared_dict` survives it unless its
  size changes); a restart resets them.

### 11.2 Daemon live-totals store (in-memory, scoped)

The edge **pushes** its snapshot: one worker per node (a cross-worker lock),
about every 60 s, from the HTTP-level `log_by_lua` (`maybe_flush_stats`, so
an HTTP-only box pushes too): `POST /nginx/cache/stats` with
`{"rows":[{host, counts:{STATUS:n}}]}` for every armed key the feed names
(`stats_keys`), read by name, so every armed vhost is pushed complete. The
body is ≤ ~2.2 MB at the 5000-policy limit (cap 4 MiB; a count cjson writes
in exponent form is read as a number, clamped to 2^53). The daemon
(`site_cache_stats.go`) keeps the latest row per key — only for a key armed
at that moment (`armedCacheKeys`), only the seven statuses, at most one row
per stored policy — and prunes the rows of keys disarmed since, every 5
minutes. A push is one hook event.

The counts are absolute since the edge last restarted, so a daemon restart
empties the view only until the next push. So does any save of
`detectors.conf` or a `detectors.d/*.conf` overlay, and the rotation of a log
a detector tails: each config reload builds a new webdetector `Engine`, and
with it a new, empty store. This store is what the API and MCP read, so
scoping is enforced daemon-side.

As built: the seven statuses + a derived STRICT hit ratio (hit ÷
(hit+miss+expired+stale+updating+revalidated); BYPASS excluded), per policy
key, both tiers together. STALE / UPDATING / REVALIDATED are served from cache
but sit in the denominator, so read the full breakdown. No last-seen, no
per-tier split (only the per-zone totals, §11.1), no history (§14).

### 11.3 Surfaces

- **API:** `GET /api/v1/site-cache/stats[?host=]` — scope-filtered
  (`vhostAllowed`). `?host=` resolves a request host as the edge does
  (`StatsKeyFor`: its exact policy, else the most specific wildcard; nothing
  for an opt-out); a scoped caller resolves only to keys its scope holds (an
  in-scope host that resolves to nothing returns `rows: null`).
- **CLI:** `cfm webtop site-cache stats [host]`. **MCP:** `site_cache_stats`
  (and `site_cache_status` for the policies).
- **cfm-admin:** a HIT % column in the policy table and the Hit counts table
  (§7.3).
- **Debug stamp** `X-CFM-Cache: observe [opt-out ]static=<r>/<ttl>
  micro=<r>/<ttl> gen=<n> [status=<cache status>] [microcache=would/<n>s |
  microcache=bypass:<reason>]`, only on a request that sends
  `X-CFM-Cache-Debug` from a trusted source (loopback / link-local, the box's
  own IPs, `IGNORE_IPS` / `IGNORE_NETS`), and only on the HTTPS listener
  (:9043; `observe` runs in that server's header filter). The reason
  vocabulary and how to run it: runbook §4.
- **Access log:** `ucache="$upstream_cache_status"` and
  `up=cfm_apache_static|cfm_apache_micro|cfm_apache` on every request
  (`edge_access_tail`).

Counting has no knob; `SITE_CACHE = 0` stops the push.

---

## 12. Config knobs (`[webdetector]` in `detectors.conf`)

| Knob | Default | Meaning |
|---|---|---|
| `SITE_CACHE` | `1` (ON) | node-wide **kill switch** (not an opt-in — the per-vhost store arms vhosts); `0` = no caching, no stamp, no stats push on this node within ~15 s of saving `detectors.conf`, policies kept. Published via `webdetector_bridge_config.go` → `cfm_bridge_config.lua` (read by `cfm_bridge_cfg.lua`, absent = on) |
| `MICRO_CACHE_ENFORCE` | `1` (ON; `0` until 2026-09-23) | Tier B **kill switch**: `1` = an armed, anonymous, cacheable GET/HEAD through the HTTPS `location /` (HTML or not) is served from its micro bucket, `0` = a dry run on this node (the debug stamp shows the verdict, nothing is micro-cached, no vhost disarmed). Arming a vhost's micro tier is the opt-in (§5.7 before a new kind of app). Same publication path; the edge reads an absent field as off (fail-safe: the daemon always writes it) |
| `SITE_CACHE_STORE_PATH` | `/var/lib/cfm/webdetector_site_cache.json` | the per-vhost store (§6) |

The defaults are pinned by `webdetector_bridge_config_test.go` (code, the
reference `detectors.conf`, the rendered file) and `cfm_bridge_cfg_test.lua`
(the reader). There is no daemon-side gate: with `SITE_CACHE = 0` the API and
the feed keep working and only the edge ignores the feed. The daemon logs
`cfm_bridge_config.lua written … site_cache=… micro_cache_enforce=…` on every
publish. `GET /api/v1/site-cache/list` (and so `site_cache_status`, the CLI
`list` and the page) returns the published pair as `switches`: recorded after
each successful write of `cfm_bridge_config.lua`
(`webdetector.PublishSiteCacheSwitches`), so it is what the edge was handed,
and absent until the first write. It is package state, not per Engine: a
reload whose webdetector fails to build leaves the old engine serving the
API, and a per-engine copy would then lag the edge. The configured values are
also readable through MCP `detectors_config` and `GET /api/v1/detectors/config`.

Not built (the behaviour is fixed in code instead):
`SITE_CACHE_SCOPED` (self-service is always on, §9),
`SITE_CACHE_CFG_REFRESH_SEC` (the feed poll is a fixed 60 s),
`SITE_CACHE_STATS` (counting has no switch), `SITE_CACHE_AUTH_COOKIES` (the
built-in list is `MICRO_AUTH_*` in `cfm_cache.lua`; per-vhost `auth_cookies`
extends it).

---

## 13. CI guardrails (turn the lesson into an enforced rule)

`scripts/tests/check_site_cache_config.sh`, wired into `security.yml` and
CLAUDE.md §3. **Its header is the complete, current list of what it checks**;
keep it strict and mutation-test any change. In short:

1. **Bypass-by-default:** every location that names `proxy_cache` carries
   `proxy_cache_bypass $cfm_cache_skip $cfm_req_auth;` and
   `proxy_no_cache $cfm_cache_skip $cfm_cache_non200 $cfm_req_auth …;` —
   unconditional caching can never come back. `$cfm_cache_skip` defaults to
   `"1"` in every server with a cache location, and nothing in the confs may
   write it (only `cfm_cache.lua` does; the guard does not scan other Lua
   modules). Per cache location it also pins buffering on, the whole key, the
   lock and its per-tier timeout, the forwarded-header pins, the only-200 and
   `Authorization` maps, and the Tier A disk rails. Nothing else may write a
   rail variable (header-family writers, named captures, inline Lua).
2. **Set-Cookie / origin-header safety:** `proxy_ignore_headers` never lists
   `Vary`, and lists `Cache-Control` / `Expires` / `X-Accel-Expires` /
   `Set-Cookie` only in a `@cfm_micro_<n>s` location, in the exact form, with
   the replacement rails (`$cfm_cc_nostore`, `$cfm_xae_nocache`,
   `$cfm_sc_unsafe`), the server's one `set $cfm_sc_unsafe "1";` and one
   `header_filter_by_lua_block` calling `micro_setcookie_filter`.
3. **Tier B structure:** the `$cfm_micro_conf` sentinel once in a
   redirect-free, buffering `location /` (with its server-level `""`
   default); `background_update off`, the exact `use_stale` list, one
   `proxy_cache_valid 200 <N>s` per bucket, no request body, the client-IP /
   geo / hint header pins, the session-token response predicates;
   `lua_shared_dict cfm_cache_uncacheable` exists and every micro `inactive`
   sits at least 30 s below `MICRO_UNCACHEABLE_STALE_TTL`.
4. **OpenResty↔Angie parity:** both confs cache the same locations, the micro
   blocks match, and zones and locations are exactly `MICRO_BUCKETS`, checked
   against the daemon's and installer's dir lists too.
5. **Beyond the conf:** `cfm_micro_entry_structure_test.lua` (micro only at
   Step 4); the Go↔Lua feed / stats-key parity through a generated fixture
   (`site_cache_edge_parity_test.go` → `fixtures/site_cache_edge_parity.lua`
   → `cfm_cache_edge_parity_test.lua`; regenerate with `-update-edge-parity`
   and review the diff) and `TestCachePolicyRowWireFields`; the UI parity of
   §7.3. The edge uses a recipe name only as a label, so the recipe
   vocabulary needs no Lua mirror.
6. **Logrotate:** stats live in a shdict; a new `/var/log/cfm/…` cache log
   would need a rotation entry (`check_logrotate_coverage.sh`).

---

## 14. As shipped, decisions, open items

**As shipped (Sep–Oct 2026, small PRs):** (1) store + API + CLI + scope;
(2) bridge feed + `cfm_cache.lua`, observe-only stamp; (3) Tier A — 3a the
`SITE_CACHE` kill switch, 3b static caching (decisions below), 3c stats (§11);
(4) Tier B with the §4 rails as a dry run, enforce on by default from
2026-09-23 after §5.7 passed; (5) the cfm-admin page + recipes; (6) purge as a
generation bump (wall-clock ms later, §6); then a hardening sweep
(request-identity rails, cache dirs, the control plane, the stats bound,
guard gaps, parity tests), the disk rails and remembered-uncacheable / WAF
rows, and tracking-cookie storage + the 90 s / 120 s buckets.

**Tier A decisions (3b) — do not reopen without a reason:**

- **Response buffering must be on in a cache location.** nginx writes to
  `proxy_cache` only on the buffered path; the static location used to run
  `proxy_buffering off`, which made Tier A a **silent no-op** (never a HIT,
  invisible to `nginx -t` and the Lua tests). The guard fails a `proxy_cache`
  location with buffering off. `proxy_request_buffering` stays off (large
  uploads still stream). Because buffering is location-level, unarmed vhosts'
  static assets buffer too (transparent for small assets; a large image may
  spill to temp like any buffered response). Large media / archives use a
  separate streaming location.
- **Only 200 is stored.** `proxy_cache_valid 404 1m` was dropped: on an atomic
  deploy a transiently missing asset would stick as a cached 404.
- **Encoding relies on the origin's `Vary: Accept-Encoding`.** The key omits
  `Accept-Encoding` (nginx honours `Vary`; mod_deflate sets it). An origin
  that compresses without `Vary` could serve compressed bytes to a client that
  did not ask — accepted; keying it would fragment the cache 3× for correct
  origins.
- **One shared 10g zone.** css/js/fonts and large images share `cfm_static`,
  so large-image traffic can LRU-evict small assets. Accepted; the 10 MB
  `$cfm_cache_too_big` cap (§5.1) limits it.
- **`use_stale updating error timeout` serves stale during origin trouble**
  (deliberate): a file changed while the origin is unhealthy is served stale
  until it recovers or the operator purges.
- **The §4.1 request-cookie allowlist is NOT enforced at Tier A** (decision,
  not oversight). Static assets are public by nature (the standard CDN
  stance), and the response-side rails catch the per-user cases in practice
  (a `Set-Cookie` or `Cache-Control: private|no-store|no-cache` response is
  never stored). **Residual (narrow, accepted):** a static-extension URL an
  origin renders per-user with **neither** `Set-Cookie` **nor** a private
  `Cache-Control` would be cached and served cross-user on an armed vhost.
  `static_gate`'s doc-comment says the same. If something like that got
  cached, turning the tier off and on again starts a fresh generation (§6).

**Open (not built):**

- Micro-cache on the Step 2b clearance fast path (§5.5.1).
- Origin-keepalive HIT/MISS check on a live edge (§5.5 item 2).
- Bypass on `Vary: Cookie` (§5.5 item 3).
- Per-URL purge (§10).
- A per-host "inherit" row (a host follows a wildcard's tiers under its own
  generation), so a tenant can purge per host under an admin wildcard (§10).
- A per-vhost fill budget to bound disk write rate (§5.1).
- Static TTL buckets / a forced static TTL (§5.4).
- Keying on the value of a short list of preference cookies instead of
  bypassing them (§4 residuals).
- Durable / historical stats (hourly buckets, per-tier split, bytes saved)
  and the `whats_wrong` "armed but ~0 hits" signal (§11.2).
- Rendering the `cache.zones` totals on the lua-stats dashboard (§11.1).

Each edge-affecting PR runs `docs/challenge-waf-release-checklist.md`; each
runtime PR adds a `CHANGELOG.md [Unreleased]` entry.

---

## 15. Files (as built)

- **Daemon** (`internal/webdetector/`): `site_cache.go` (store, model,
  validation, `PolicyFeed`, `StatsKeyFor`), `site_cache_api_handlers.go` (API,
  audit, `switches`), `site_cache_stats.go` (live stats, prune),
  `cli_site_cache.go` (+ the `cli.go` dispatch), `nginx_bridge.go`
  (`handleCacheConfig`, `handleCacheStats`), `engine.go`, `http_api.go`
  (routes, `SharedAPIPrefixes`), `webdetector_config.go`. Elsewhere:
  `internal/detectors/webdetector_bridge_config.go` (the two switches) and
  `webdetector_register.go` (`SITE_CACHE_STORE_PATH`),
  `internal/sslcollector/token.go` (bridge-config fields),
  `internal/mcpserver/status_reads.go` (MCP tools, registered in `tools.go`),
  `cmd/cfm/site_cache_dirs.go` (cache dirs on every start).
- **Edge:** `configs/lua/cfm_cache.lua` (feed, gates, rails, stamp, stats
  push, remembered-uncacheable, Set-Cookie filter), `cfm_cache_log.lua`
  (counters), `cfm_shdict.lua`, `cfm_hostmatch.lua`, `cfm_panel_hosts.lua`,
  `cfm_selfip.lua` (trusted debug sources), `cfm_bridge_cfg.lua`,
  `cfm_stats.lua` (zone totals), `cfm.lua` (the Step 4 entry only). Both
  confs: zones, the two shared dicts, the rail maps, the static-asset and
  `@cfm_micro_<n>s` locations, the `location /` sentinel, the HTTPS header
  filter, the log-phase hook.
- **UI:** `internal/webui/static/webdetector/site-cache/index.html`,
  `assets/webdet/pages/site-cache.js`, `feature-site-cache.js`,
  `site-cache-model.js`, `site-cache-recipes.js`, plus `nav.js` / `core.js`
  hooks.
- **Install:** `scripts/cfm-cache-dirs.sh` (deb postinst, rpm `%post`, both
  installers); `configs/detectors.conf` (`[webdetector]` knobs).
- **Tests:** Go `site_cache_test.go`, `site_cache_stats_test.go`,
  `site_cache_edge_parity_test.go`, `site_cache_ui_parity_test.go`,
  `cli_site_cache_test.go`, `webdetector_bridge_config_test.go`,
  `token_test.go`, `site_cache_dirs_test.go`; Lua `cfm_cache_test.lua`,
  `cfm_cache_log_test.lua`, `cfm_cache_edge_parity_test.lua`,
  `cfm_cache_ui_parity_test.lua`, `cfm_micro_entry_structure_test.lua`,
  `cfm_bridge_cfg_test.lua`, `cfm_hostmatch_test.lua`,
  `cfm_cache_load_test.lua`; JS `site-cache-model.test.js`,
  `site-cache-recipes.test.js`; fixtures `site_cache_edge_parity.lua`,
  `site_cache_ui_parity.txt`; CI `check_site_cache_config.sh` (§13).

---

## 16. References

- Templates this design reuses: `cfm_h3_config.lua` (per-worker edge pull),
  `http3_overrides_store.go` (store mechanics),
  `challenge_access_api_handlers.go` + `vhost_filter.go` / `authz.go` (scoped
  writes), `webdetector/challenge-access/` + `challenge-access-recipes.js`
  (page and recipe catalog).
- `cfm.lua` decision flow (Steps 0a1 / 2b / 4); `cfm_purge.lua` (per-IP purge
  only).
- Docs: `site-cache-runbook.md`, `endpoint_scope_inventory.md`,
  `proxy-performance.md` (origin keepalive), `challenge-waf-release-checklist.md`.
