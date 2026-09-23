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
| **A: static** | Static assets (css/js/images/fonts…), on :9080 and :9043 | the static-asset locations, zone `cfm_static` (10 GB, `inactive=7d`) | the origin's `Cache-Control` / `Expires`, **1 h fallback**. The stored static recipe and TTL are labels only. |
| **B: micro** | Anonymous HTML, HTTPS only, on the plain-allow path (after WAF, challenge and bridge decisions) | internal `@cfm_micro_<n>s` locations, one zone per bucket | the vhost's micro TTL snapped to 1 / 2 / 5 / 10 / 30 / 60 s (empty = 1 s, above 60 s = 60 s). The origin's cache headers are ignored except for their "do not store" signals. |

Tier B is a **dry run** until `MICRO_CACHE_ENFORCE = 1` on the node. Until
then it only reports what it would cache.

Caching is bypass-by-default. Everything in `site-cache-design.md` §4 is never
cached, whatever a policy says. That covers credentialed and session-cookie
requests, `Set-Cookie` and private responses, non-200 responses, panel and
webmail hosts, admin and script paths, and the rest of the list.

## 2. Knobs (`[webdetector]` in `/etc/cfm/detectors.conf`)

| Knob | Default | Effect |
|---|---|---|
| `SITE_CACHE` | `1` | The node-wide kill switch. It is not an opt-in: the per-vhost store arms vhosts. `0` stops caching, stamping and the stats push on this node within about 10 s, and leaves every policy as it is. |
| `MICRO_CACHE_ENFORCE` | `0` | The Tier B opt-in. `0` is the dry run; `1` serves armed, anonymous, cacheable HTML from the micro buckets. Set it only after the on-box checklist in `site-cache-design.md` §5.7 has passed on this node. |
| `SITE_CACHE_STORE_PATH` | `/var/lib/cfm/webdetector_site_cache.json` | The per-vhost policy store (file mode 0600). |

Both switches reach the edge through `/var/lib/cfm/lua/cfm_bridge_config.lua`
about 10 s after a daemon reload, with no proxy reload. No API or MCP tool
reports their state. Check that file, or the daemon's
`cfm_bridge_config.lua written … site_cache=… micro_cache_enforce=…` log line.

## 3. Arming a vhost

The admin CLI is `cfm webtop site-cache …` (alias `cache`). The same operations
are available over the API at `/api/v1/site-cache/*`. A scoped cPanel token
can manage its own vhosts through the API; there is no cfm-admin page yet.

```bash
cfm webtop site-cache set shop.example --static static_lean            # Tier A
cfm webtop site-cache set shop.example --micro micro_safe --micro-ttl 5s   # Tier B (5 s bucket)
cfm webtop site-cache set '*.example.com' --static static_lean          # every sub-host (not example.com itself)
cfm webtop site-cache off tenant.example.com    # opt-out: never cached, even under the armed wildcard
cfm webtop site-cache remove tenant.example.com # delete the policy (the host follows the wildcard again)
cfm webtop site-cache list | get <host>
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
X-CFM-Cache: observe [opt-out ]static=<recipe>/<ttl> micro=<recipe>/<ttl> gen=<n> [status=<HIT|MISS|BYPASS|…>] [microcache=would/<n>s | microcache=bypass:<reason>]
```

- `status=` is the nginx cache verdict for a request that went through a cache
  location.
- `microcache=` is Tier B's request-side verdict for a micro-armed vhost. It
  reports the verdict even in dry run.
- Reasons:

  | Reason | Why the request is not micro-cached |
  |---|---|
  | `unarmed` | the micro tier is not armed for this vhost |
  | `method` | not GET/HEAD |
  | `authorization` | the request carries `Authorization` |
  | `range` | a `Range` request |
  | `event-stream` | `Accept: text/event-stream` |
  | `fragment` | a partial-page request (X-Requested-With, HX-Request …) |
  | `credential-header` | Cart-Token, X-WP-Nonce, X-Api-Key … |
  | `path` | an admin, script or transfer path |
  | `panel` | a panel or webmail host |
  | `auth:<cookie>` | a session cookie |
  | `strict:<cookie>` | strict mode, and the cookie is not on the ignore list |
  | `cookie-size` | a `Cookie` header over 8 KB |
  | `uncacheable` | the page recently could not be stored |
  | `location` | not the HTTPS `location /` |
  | `nginx-version` | the core is older than 1.23 |

- A request from the box skips cfm.lua (Step 0a). For HTML the stamp therefore
  shows the would-verdict only.

**The access log.** For real traffic, the served verdict is in the edge access
log:
- the fields are `ucache="$upstream_cache_status"` and
  `up=cfm_apache_static | cfm_apache_micro | cfm_apache`;
- OpenResty writes `/usr/local/openresty/nginx/logs/access.log` and
  `access.cfm.log`; Angie writes `/var/log/angie/access.log`;
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
- **When they reset.** The counts run since the edge last restarted. A reload
  keeps them, unless it changes the stats dict's size. A daemon restart empties
  this view until the next push.
- **What is counted.** A 200 or 304 response that went through a cache
  location: the static-asset locations, and the micro locations while
  `MICRO_CACHE_ENFORCE = 1`. HTML that Tier B declines, or that it only
  evaluates in dry run, is **not counted**. Use the debug stamp for those.
- **BYPASS** is a counted request that could not use the cache. That is
  usually one of these:
  - a static asset of an armed vhost whose static tier is off (a micro-only
    vhost shows its assets as BYPASS, which is expected);
  - a request with an `Authorization` header;
  - a panel or webmail host under an armed wildcard.
- **The hit ratio** is strict: HIT ÷ (everything except BYPASS). STALE,
  UPDATING and REVALIDATED are served from cache but sit in the denominator,
  so read the breakdown too.
- **Near-zero HIT with high MISS/EXPIRED** means the origin is not sending
  cacheable responses (e.g. `private`, `no-store`, `Set-Cookie`), or the
  location is misconfigured.
- **Node-wide totals per tier** (`cfm_static`, `cfm_micro`) are in the admin
  JSON `/cfm-admin/lua-stats` under `cache.zones`.

## 6. Purge

```bash
cfm webtop site-cache purge shop.example    # one policy key (a wildcard purges all its sub-hosts)
cfm webtop site-cache purge --all           # every vhost (admin only)
```

- A purge issues a new **generation**, which is part of every cache key, so
  the old objects become unreachable.
- Each edge worker picks the new generation up on its next feed poll, within
  about 60 s. Until then that worker can still serve old objects.
- Old objects stay on disk until they age out (`inactive`) or LRU evicts them.
- A purge covers one policy key. A host that goes back under a covering
  wildcard serves the wildcard's objects; purge the wildcard to clear those.

## 7. Turning Tier B on (per node)

1. Arm micro on the vhosts you want (`--micro … --micro-ttl …`). Leave the node
   in dry run.
2. Watch the debug stamp on real pages: logged-in pages, carts, forms, and
   pages that should be personalised must say `microcache=bypass:<reason>`.
   Add app session cookies with `--auth-cookies` where needed.
3. Run the on-box checklist in `site-cache-design.md` §5.7 on this node.
4. Set `MICRO_CACHE_ENFORCE = 1` in `detectors.conf` and reload the daemon. It
   takes effect within about 10 s.
5. Check that `up=cfm_apache_micro ucache=HIT` shows up in the access log and
   that the stats rows move.

To roll back, set `MICRO_CACHE_ENFORCE = 0` (dry run again within about 10 s).
If anything wrong was cached, also purge the affected vhost, or `purge --all`.

## 8. Incident: something wrong is being served

1. Set `SITE_CACHE = 0` and reload the daemon. Caching stops on the node
   within about 10 s, and no policy is lost.
2. Run `cfm webtop site-cache purge --all` **before** setting it back to `1`.
   Restoring the switch resumes each vhost's cache as it was, including
   anything cached before the switch-off.
3. For one bad vhost, `off <host>` (or `remove`) plus `purge <host>` is
   enough.

## 9. Timing at a glance

| Change | Reaches the edge |
|---|---|
| `SITE_CACHE` / `MICRO_CACHE_ENFORCE` (daemon reload) | ~10 s, no proxy reload |
| Policy set / off / remove / purge | ≤ ~60 s per worker (next feed poll) |
| Stats | pushed ~every 60 s |

## 10. Disk and housekeeping

- **Where the caches live.** Under `/var/cache/nginx`: `cfm_static` (10 GB,
  `inactive=7d`) and `cfm_micro_{1,2,5,10,30,60}s` (512 MB to 1 GB each).
  The daemon creates them on start and the installers and packages create them
  before any `-t`, owned `root:cfm`.
- **The retired `/var/cache/nginx/cfm_micro`.** A node installed before the
  per-bucket zones may still have this dir. No conf ever used it as a zone and
  nothing creates it any more, so it is safe to delete. Check first that no
  live conf names it:
  ```bash
  grep -rn 'cache/nginx/cfm_micro[^_]' /etc/angie /usr/local/openresty/nginx/conf 2>/dev/null  # expect nothing
  rm -rf /var/cache/nginx/cfm_micro
  ```
- **The stats dict** is `lua_shared_dict cfm_cache_stats 8m`, about 65 000
  counters: room for the 5000-policy limit × 7 statuses.

## 11. Known limits (as built)

- Static TTL and recipe are labels. Tier A follows the origin's headers with a
  1 h fallback.
- There is no cfm-admin page yet. Use the API, CLI and MCP.
- Stats are a live view: nothing is persisted, there is no history, and each
  row mixes both tiers.
- The switch state (`SITE_CACHE`, `MICRO_CACHE_ENFORCE`) is not visible over
  the API or MCP.
- A cleared visitor (holding a `cfm_clearance` cookie) is not micro-cached.
  The Step 2b fast path is not a micro entry yet (`site-cache-design.md` §5.5).
