# Site Cache — operator runbook

How to run per-vhost edge caching on a node: arm a vhost, check that it is
served from cache, read the stats, purge, turn the micro-cache on, and pull
the switch when something goes wrong. The design and the safety argument live
in [`site-cache-design.md`](site-cache-design.md). This page is the as-built
operating view.

## 1. What it is

Two tiers, both off for every vhost until one is armed:

| Tier | What is cached | Where | TTL |
|---|---|---|---|
| **A: static** | Files ending in `.css .js .map .woff .woff2 .ttf .eot .png .jpg .jpeg .gif .webp .ico`, on :9080 and :9043 | the static-asset locations, zone `cfm_static` (10 GB, `inactive=7d`) | the origin's `Cache-Control` / `Expires`, **1 h fallback**. The stored static recipe and TTL are labels only. |
| **B: micro** | Anonymous GET/HEAD responses through the HTTPS `location /`: HTML pages, but also anything else served there (REST JSON, feeds, svg…). It runs on the plain-allow path, after the WAF, challenge and bridge decisions. | internal `@cfm_micro_<n>s` locations, one zone per bucket | the vhost's micro TTL snapped to 1 / 2 / 5 / 10 / 30 / 60 s (empty = 1 s, above 60 s = 60 s). The origin's cache headers are ignored except for their "do not store" signals. |

Tier B serves an armed vhost's anonymous pages from cache while
`MICRO_CACHE_ENFORCE = 1`, the default since 2026-09-23. At `0` it is a dry
run on the whole node: it only reports what it would cache.

Caching is bypass-by-default. What is never cached, whatever a policy says
(`site-cache-design.md` §4 has the full list), differs by tier:

- **Both tiers:**
  - a request with an `Authorization` header;
  - a response with `Set-Cookie`, or with `Cache-Control: private` / `no-store`;
  - a non-200 response;
  - panel and webmail hosts;
  - methods other than GET/HEAD;
  - script paths (`.php` and the like, so `wp-login.php` too; Tier A's
    extension list never matches one).
- **Tier B only:** anything else that marks the request as belonging to one
  visitor:
  - session cookies;
  - credential headers;
  - partial-page requests;
  - the admin and transfer paths (`/wp-admin`, `/administrator/`, `/admin/`,
    `/sysadmin/`, `/acctxfer`, cPanel's proxy-subdomain paths).

  A login page at a path that is neither (`/login`, `/user/login`) is
  eligible for the micro-cache when the request is anonymous, and is stored
  unless its response sets a cookie or says private / no-store. The pages behind the login are
  not, as long as their session cookie is on the auth list (built in, or added
  with `--auth-cookies`).

  **Tier A does not read request cookies, and looks at the path only for its
  extension.** A `.css` under `/wp-admin/` requested with a login cookie is
  cached like any other asset. Tier A relies on the origin's response headers
  for anything per-user.

## 2. Knobs (`[webdetector]` in `/etc/cfm/detectors.conf`)

| Knob | Default | Effect |
|---|---|---|
| `SITE_CACHE` | `1` | The node-wide kill switch. It is not an opt-in: the per-vhost store arms vhosts. `0` stops caching, stamping and the stats push on this node within about 15 s, and leaves every policy as it is. While it is `0` the edge also stops reading the policy feed (see §8 before turning it back on). |
| `MICRO_CACHE_ENFORCE` | `1` | The Tier B kill switch (the default was `0` until 2026-09-23). `1` serves armed, anonymous, cacheable responses from the micro buckets; `0` is a dry run on this node, and leaves every policy as it is. Arming a vhost's micro tier is the opt-in (§7). |
| `SITE_CACHE_STORE_PATH` | `/var/lib/cfm/webdetector_site_cache.json` | The per-vhost policy store (file mode 0600). |

To change a switch, edit and save `detectors.conf`; nothing needs reloading.
- The daemon notices the change by itself within about 5 s and rewrites
  `/var/lib/cfm/lua/cfm_bridge_config.lua`. The edge re-reads that file within
  about 10 s more, with no proxy reload.
- `systemctl reload cfm` is not needed for this: it restarts the daemon.

To see the current values, use:
- `cfm webtop site-cache list`, the cfm-admin Site cache page, or the MCP tool
  `site_cache_status`: each shows the switches as the edge was last handed
  them (the list API's `switches`, which a scoped cPanel user sees too). The
  daemon records them each time it writes `cfm_bridge_config.lua`, so a save
  it could not apply (the file write failed) still shows the old pair.
- the MCP tool `detectors_config` with `merged=true`, or
  `GET /api/v1/detectors/config?view=merged`, for the effective values
  (`detectors.conf` plus any `detectors.d/*.conf` overlay). A key that is not
  set anywhere has its default: `SITE_CACHE` 1, `MICRO_CACHE_ENFORCE` 1.
- `cfm_bridge_config.lua` itself, or the daemon's
  `cfm_bridge_config.lua written … site_cache=… micro_cache_enforce=…` log line,
  for what the edge was handed.

`site_cache_stats` does not report the switches.

## 3. Arming a vhost

Three ways to manage policies:
- the cfm-admin **Site cache** page (Rules & engine), which also has recipes,
  the debug-stamp command for one URL, and the hit counts;
- the admin CLI `cfm webtop site-cache …` (alias `cache`), which can also set
  a custom micro TTL (it snaps to a bucket) and the static TTL label;
- the API at `/api/v1/site-cache/*`.

A scoped cPanel token manages its own vhosts through the page or the API.
Purge all is admin only.

```bash
cfm webtop site-cache set shop.example --static static_lean            # Tier A
cfm webtop site-cache set shop.example --micro micro_safe --micro-ttl 5s   # Tier B (5 s bucket)
cfm webtop site-cache set '*.example.com' --static static_lean          # every sub-host (not example.com itself)
cfm webtop site-cache off tenant.example.com    # opt-out: never cached, even under the armed wildcard
cfm webtop site-cache remove tenant.example.com # delete the policy (the host follows the wildcard again)
cfm webtop site-cache list
cfm webtop site-cache get <host>
```

- `set` changes only the flags you pass.
- Turning the static tier on, or re-enabling micro, starts the vhost from an
  empty cache (a new generation).
- The micro TTL comes only from `--micro-ttl`. A recipe name does not set it.
- `--strict-cookies` (micro only) bypasses on any cookie that is not on the
  ignore list (analytics, TCF consent, `cfm_*`).
- `--auth-cookies a,b` adds app-specific session cookie names to the built-in
  list.
- A change reaches each edge worker within about 60 s, on its next feed poll.
  While `SITE_CACHE = 0` the workers do not poll, so the change waits until the
  switch is back on (see §8).

Every set, remove and purge, including refused ones, writes a
`[site_cache] action=… host=… result=… actor=admin|scoped:<vhosts> remote=…`
line to `cfm.log`.

## 4. Is it working? Checking one URL

**The debug stamp.** Run this on the box itself, against the edge's HTTPS
listener and the vhost's IP (port 443 on loopback reaches the origin, not the
edge):

```bash
curl -sk -o /dev/null -D - -H 'X-CFM-Cache-Debug: 1' \
  --resolve shop.example:9043:<vhost-ip> 'https://shop.example:9043/some/path'
```

The edge answers only for trusted sources: the box, its own IPs,
`IGNORE_IPS` / `IGNORE_NETS`. It stamps:

```
X-CFM-Cache: observe [static=<recipe>[/<ttl>]] [micro=<recipe>[/<ttl>]] gen=<n> [status=<HIT|MISS|BYPASS|…>] [microcache=would/<n>s | microcache=bypass:<reason>]
X-CFM-Cache: observe opt-out gen=<n>
```

- `static=` and `micro=` appear only for a tier that is on.
- An opt-out row (`off <host>`) under a broader armed wildcard shows
  `observe opt-out gen=<n>` (plus `status=BYPASS` on a static asset).
- **No header at all** means one of these:
  - `SITE_CACHE = 0`;
  - the request did not come from a trusted source;
  - the worker has no policy for the host yet (none of its own and no
    covering wildcard, or the next feed poll has not happened);
  - the host is opted out and no armed wildcard covers it. The feed leaves such
    a row out, since there is nothing to opt out of;
  - it went to the :9080 listener (the stamp is HTTPS only).

- `status=` is the nginx cache verdict for a request that went through a cache
  location.
- `microcache=` is Tier B's request-side verdict for a micro-armed vhost. It
  reports the verdict even in dry run.
- Reasons:

  | Reason | Why the request is not micro-cached |
  |---|---|
  | `method` | not GET/HEAD |
  | `authorization` | the request carries `Authorization` |
  | `range` | a `Range` request |
  | `event-stream` | `Accept: text/event-stream` |
  | `fragment` | a partial-page request (X-Requested-With, HX-Request …) |
  | `credential-header` | Cart-Token, X-WP-Nonce, X-Api-Key … |
  | `path` | an admin, script or transfer path, or a `?doing_wp_cron` / `?_envelope` query |
  | `panel` | a panel or webmail host |
  | `auth:<cookie>` | a session cookie |
  | `strict:<cookie>` | strict mode, and the cookie is not on the ignore list |
  | `cookie-size` | a `Cookie` header over 8 KB |
  | `uncacheable` | the page recently could not be stored |
  | `location` | not the HTTPS `location /` |
  | `nginx-version` | the core is older than 1.23 |

- A request from the box skips cfm.lua (Step 0a). For HTML the stamp therefore
  shows the would-verdict only.

**The access log.** For real traffic, the served verdict is in the edge's main
access log:
- the fields are `ucache="$upstream_cache_status"` (quoted, e.g. `ucache="HIT"`)
  and `up=cfm_apache_static | cfm_apache_micro | cfm_apache`;
- OpenResty writes `/usr/local/openresty/nginx/logs/access.log`; Angie writes
  `/var/log/angie/access.log`. (`access.cfm.log` holds only challenge and
  block lines.)
- the same lines are available through the MCP tool `edge_access_tail`.

`ucache="-"` with `up=cfm_apache` means the request never reached a cache
location. That is normal for HTML while Tier B is in dry run or declines it.

## 5. Reading the stats

```bash
cfm webtop site-cache stats [host]      # also: MCP site_cache_stats, GET /api/v1/site-cache/stats
```

- **Where the numbers come from.** The edge pushes absolute counts about every
  60 s. It sends a row only for vhosts armed at that moment, with both tiers
  in one row.
- **When they reset.** The counts run since the edge last restarted. An edge
  reload keeps them, unless it changes the stats dict's size. This view is
  empty until the next push after:
  - a daemon restart;
  - any save of `detectors.conf` or a `detectors.d/*.conf` overlay (the daemon
    watches the files' modification time), because each reload builds a fresh
    view;
  - the rotation of a log that a detector tails (a new file at the same path
    reloads the config too).

  Right after flipping `MICRO_CACHE_ENFORCE`, for example, expect "No cache
  stats yet" for up to a minute.
- **What is counted.** A 200 or 304 response that went through a cache
  location: the static-asset locations, and the micro locations while
  `MICRO_CACHE_ENFORCE = 1`. HTML that Tier B declines, or that it only
  evaluates in dry run, is **not counted**. Use the debug stamp for those.
- **BYPASS** is a counted request that could not use the cache. That is
  usually one of these:
  - a static asset of an armed vhost whose static tier is off (a micro-only
    vhost shows its assets as BYPASS, which is expected);
  - a request with an `Authorization` header;
  - a panel or webmail host under an armed wildcard;
  - any request counted while `SITE_CACHE = 0`. Those counts are pushed once
    the switch is back on.
- **The hit ratio** is strict: HIT ÷ (everything except BYPASS). STALE,
  UPDATING and REVALIDATED are served from cache but sit in the denominator,
  so read the breakdown too. The CLI table shows HIT, MISS, EXPIRED, STALE and
  BYPASS; UPDATING and REVALIDATED are in the API and MCP JSON.
- **Near-zero HIT with high MISS/EXPIRED** means the origin is not sending
  cacheable responses (e.g. `private`, `no-store`, `Set-Cookie`), or the
  location is misconfigured.
- **Per-tier totals** (`cfm_static`, `cfm_micro`) are in the admin JSON
  `/cfm-admin/lua-stats` under `cache.zones`. They sum the armed vhosts only.

## 6. Purge

```bash
cfm webtop site-cache purge shop.example    # one policy key (a wildcard purges all its sub-hosts)
cfm webtop site-cache purge --all           # every vhost (admin only)
```

- A purge issues a new **generation**, which is part of every cache key, so
  the old objects become unreachable.
- Each edge worker picks the new generation up on its next feed poll, within
  about 60 s. Until then that worker can still serve old objects. While
  `SITE_CACHE = 0` there is no poll at all (see §8).
- Old objects stay on disk until they age out (`inactive`) or LRU evicts them.
- A purge covers one policy key. A host that goes back under a covering
  wildcard serves the wildcard's objects; purge the wildcard to clear those.
- A purge needs the policy to exist: after `remove`, a purge of that host
  returns 404. Purge first. A policy added again later starts on a new
  generation anyway.

## 7. Arming Tier B on a vhost

`MICRO_CACHE_ENFORCE = 1` is the default, so arming a vhost's micro tier
serves its anonymous pages from cache at once. What keeps a logged-in page out
of the cache is the cookie rail, so for a kind of app this node has not
micro-cached before (a shop, a membership site, anything with its own session
cookie), find its session cookies first:

1. Arm it strict: `cfm webtop site-cache set <host> --micro micro_safe
   --micro-ttl 5s --strict-cookies`. Any cookie not on the ignore list
   (analytics, consent, `cfm_*`) now bypasses, so no visitor holding a session
   is served from cache while you check.
2. Log in to the app in a browser and read its cookies. From the box, send each
   one on its own with the debug stamp (§4) on a logged-in page and a cart
   page (`-H 'Cookie: <name>=<value>'`):
   - `bypass:auth:<name>`: the rail knows it as a session cookie;
   - `bypass:strict:<name>`: it bypasses only because of strict mode. If it is
     a session cookie, add it with `--auth-cookies`, then check it again;
   - no bypass reason: an analytics or consent cookie on the ignore list.
3. When every session cookie shows `auth:`, drop strict
   (`--no-strict-cookies`), or keep it for this vhost (less cache, nothing to
   maintain).
4. From an outside client, run steps 5–7 of the on-box checklist in
   `site-cache-design.md` §5.7: anonymous MISS then HIT, a logged-in visitor
   never served a cached page, anonymous HITs again after logout. Check that
   access-log lines with `ucache="HIT"` and `up=cfm_apache_micro` show up.

The debug stamp works whatever `MICRO_CACHE_ENFORCE` says; steps 4's MISS/HIT
checks need it at `1`. `MICRO_CACHE_ENFORCE = 0` is the node-wide dry run: it
stops the micro tier on every vhost of this node, not only the one you check.

To roll back one vhost, `cfm webtop site-cache set <host> --micro off`; the
whole node, `MICRO_CACHE_ENFORCE = 0` (dry run again within about 15 s). If
anything wrong was cached, also purge the affected vhost, or `purge --all`.

## 8. Incident: something wrong is being served

Keep this order.

1. Set `SITE_CACHE = 0` in `detectors.conf` and save. Caching stops on the
   node within about 15 s, and no policy is lost.
2. Run `cfm webtop site-cache purge --all`.
3. **Reload the edge proxy while the switch is still `0`**:
   `openresty -t && systemctl reload openresty`, or
   `angie -t && systemctl reload angie`.
4. Set `SITE_CACHE = 1` and save.

Why the reload, and why before step 4:
- While the switch is off, the workers do not poll the policy feed. Each one
  keeps the generations it had before the purge.
- If the switch came back on first, each old worker would pick up the new
  switch value within about 10 s. It would then serve the pre-purge objects
  again until its next poll, up to about 60 s after its last one.
- A worker started by the reload has an empty table. It caches nothing until
  its first poll. It makes that poll on its first request after it sees the
  switch at `1` (about 15 s after the save), and the poll brings the new
  generations.

For one bad vhost, you don't need the switch:
1. `purge <host>` first. After a `remove`, a purge returns 404.
2. Then `off <host>` if it should stay uncached.
3. Both reach each worker on its next poll, up to about 60 s later. To apply
   them at once, reload the edge proxy.

If the bad objects were stored under a covering wildcard's key, purge the
wildcard too (§6).

## 9. Timing at a glance

| Change | Reaches the edge |
|---|---|
| `SITE_CACHE` / `MICRO_CACHE_ENFORCE` (save `detectors.conf`) | ~15 s (~5 s for the daemon, then ~10 s for the edge), no reload |
| Policy set / off / remove / purge | ≤ ~60 s per worker (next feed poll), or at once with an edge reload. There is no poll while `SITE_CACHE = 0`. |
| Stats | pushed ~every 60 s |

## 10. Disk and housekeeping

- **Where the caches live.** Under `/var/cache/nginx`: `cfm_static` (10 GB,
  `inactive=7d`) and `cfm_micro_{1,2,5,10,30,60}s` (512 MB to 1 GB each).
  The daemon creates them on start and the installers and packages create them
  before any `-t`, owned `root:cfm`.
- **Retired cache dirs.** Nothing creates these any more, and the current
  confs name none of them, so they are safe to delete:
  - `/var/cache/nginx/cfm_micro`, from before the per-bucket zones;
  - `/var/cache/angie/cfm_static` and `/var/cache/angie/cfm_micro`, from older
    Angie installs.

  Check first that no live conf still names one:
  ```bash
  grep -rnE 'cache/nginx/cfm_micro([^_]|$)|cache/angie/cfm_' /etc/angie /usr/local/openresty/nginx/conf 2>/dev/null  # expect nothing
  rm -rf /var/cache/nginx/cfm_micro /var/cache/angie/cfm_static /var/cache/angie/cfm_micro
  ```
- **The stats dict** is `lua_shared_dict cfm_cache_stats 8m`, about 65 000
  counters: room for the 5000-policy limit × 7 statuses.

## 11. Known limits (as built)

- Static TTL and recipe are labels. Tier A follows the origin's headers with a
  1 h fallback.
- Stats are a live view: nothing is persisted, there is no history, and each
  row mixes both tiers.
- `site_cache_stats` doesn't show the switch state (`SITE_CACHE`,
  `MICRO_CACHE_ENFORCE`). `site_cache_status`, the CLI `list` and the cfm-admin
  page (admin and scoped) do (§2).
- While `SITE_CACHE = 0` the edge does not read the policy feed. Policy
  changes and purges wait for the switch, and applying a purge before
  restoring it needs an edge reload while it is still off (§8).
- A cleared visitor (holding a `cfm_clearance` cookie) is not micro-cached.
  The Step 2b fast path is not a micro entry yet (`site-cache-design.md` §5.5).
