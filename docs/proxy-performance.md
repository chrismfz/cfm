# In-path proxy performance: measuring & shaving the CFM hop

Field measurement (2026-07, single dedicated server, same fetcher, fresh
cache-busters, full ~94 KB HTML + TLS): direct-to-Apache ≈ 50 ms,
through CFM DNAT (443→9043) ≈ 76 ms — **the in-path edge costs ~25 ms per
cold request**. That price buys TLS termination + challenge + WAF + rules
+ log-driven scoring, but most of it is avoidable connection overhead,
not filtering work. This doc explains where the milliseconds live, how to
measure the split on any box, and which knobs shave them.

## Where the per-request cost lives

| Segment | What happens today (defaults) | Typical cost |
|---|---|---|
| Client TLS handshake | Full handshake against OpenResty/Angie on a cold connection. A shared `ssl_session_cache` (now on by default) lets *reconnecting* clients resume abbreviated handshakes. | 1 RTT + crypto |
| Access-phase Lua (`cfm.lua`) | Clearance validation, WAF regex battery, shdict lookups. Bridge RPC + GeoIP are cached (90 s / 5 min); the former per-request `loadfile()` churn (self-ips, ignore-nets, bridge token/config, clamav config) is now cached in `cfm_filecache.lua`. | ≲ 1–2 ms warm |
| Backend hop to Apache | `proxy_pass http(s)://$server_addr` opens a **fresh TCP connection per request**, and on 443 pays a **full upstream TLS handshake per request**. This is usually the largest avoidable slice. | several ms on 443 |
| Response relay | Buffered proxying, loopback. | negligible |

## Measuring the split (do this before and after tuning)

The `cfm` access-log format now carries the split directly:

```
rt=0.081 urt="0.041" uct="0.012" uht="0.040" sslr="." luams=1.4
```

* `uct` (`$upstream_connect_time`) — TCP connect **+ upstream TLS
  handshake** to Apache. Origin keepalive eliminates this on the pooled
  **port-80** path (drops to ~0.000–0.001 on a warm connection); the 443
  path keeps a per-request connection by design (see Knob 2), so `uct`
  stays non-zero there.
* `uht` (`$upstream_header_time`) — `uct` + request send + Apache TTFB.
  `uht - uct` ≈ genuine application time (PHP etc.), not CFM's fault.
* `luams` (`$cfm_lua_ms`) — wall-clock ms from request start to the end of
  the cfm.lua routing decision (stamped on origin-allow paths; `-` on
  challenge/block and on bypass locations that skip cfm.lua). This is the
  whole "CFM thinking time" including the bridge decision RPC on cache
  misses.
* `sslr` (`$ssl_session_reused`) — `r` when the *client* handshake was
  resumed from the session cache; `.` on a full handshake. Watch the ratio
  climb after `ssl_session_cache` deploys.
* `rt - uht` ≈ response transfer to the client (network-bound).

So: `rt ≈ luams + uct + (uht - uct) + transfer`. Whatever bucket dominates
tells you what to tune next — don't guess.

## Knob 1 (default ON): client TLS session resumption

`ssl_session_cache shared:cfm_ssl:20m; ssl_session_timeout 4h;` at the
`http {}` level of both `openresty.conf` and `angie.conf` (panel listeners
inherit it). Repeat visitors and mobile clients that drop/re-open
connections skip the full handshake. No knobs, no caveats; session
resumption bypasses `ssl_certificate_by_lua`, so it coexists with
sslcollector's dynamic certs.

## Knob 2 (OPT-IN): origin keepalive — `[webdetector] ORIGIN_KEEPALIVE = 1`

Set in `/etc/cfm/detectors.conf`:

```ini
[webdetector]
ORIGIN_KEEPALIVE = 1
```

and reload the cfm daemon. The daemon publishes the knob to the edge via
`/var/lib/cfm/lua/cfm_bridge_config.lua`; every worker re-reads it within
~10 s (`cfm_bridge_cfg.lua` TTL cache) — **no proxy reload needed**, and
turning it back to `0` rolls back the same way. This is the only switch.

Safety interlock: cfm.lua routes to the pools only when the live proxy
conf also declares them — current `openresty.conf`/`angie.conf` set the
`$cfm_origin_ka_conf` sentinel next to the other `set $cfm_*` vars. On a
box whose live conf predates the upstream blocks, arming the knob is a
no-op (direct proxying continues) instead of a fleet-wide 502 from
`proxy_pass` resolving a nonexistent upstream.

Once on, cfm.lua's `origin_pass_for()` routes allow-traffic through the
`cfm_origin_http` / `cfm_origin_https` upstream blocks, where
`cfm_origin_ka.lua` (balancer_by_lua) sets the peer to `$server_addr`
per request — dedicated-IP routing is preserved:

`origin_pass_for()` picks the upstream by the **client's scheme**: an HTTPS
client is proxied to `cfm_origin_https:443`, an HTTP client to
`cfm_origin_http:80`.

* **Port 80** — pooled. HTTP/1.1 keepalive + Host-header vhost routing is
  standard Apache behaviour: one connection serves many vhosts, so reuse is
  always correct.
* **Port 443** — **never pooled** (per-request TLS connection, SNI from
  `proxy_ssl_name $host`). See the box below for why. Only the upstream TLS
  handshake returns on 443; everything else the edge does is unchanged.

Because the split is by client scheme, on a TLS-everywhere panel **most**
traffic is HTTPS and therefore takes the per-request 443 path; the retained
port-80 pool mainly benefits plain-HTTP origin requests (HTTP→HTTPS
redirects, ACME/`.well-known` HTTP DCV, plain-HTTP sites). Don't assume the
knob still eliminates the handshake for your HTTPS document traffic — it does
not, until safe host-keyed 443 pooling lands (see the box).

> ### Why HTTPS origin connections are not pooled (the 421 incident, 2026-08)
>
> An HTTPS origin keepalive pool would only be safe if a connection
> handshaked with `SNI=hostA` were never reused for a request to `hostB`:
> the SNI is fixed in the TLS handshake and cannot change on an established
> connection, so a cross-vhost reuse makes Apache answer `AH02032 …
> 421 Misdirected Request` on shared-IP vhosts.
>
> lua-resty-core's `balancer.enable_keepalive` keys its pool by the **peer
> address** only — the default pool name is `"<peer_addr>:<port>"` (e.g.
> `"84.54.49.35:443"`), which does **not** include the SNI. The third
> `host` argument to `set_current_peer` sets the SNI for the *handshake*
> but does **not** change the pool name (and lua-resty-core advises against
> combining that arg with `proxy_ssl_name`). An earlier version of
> `cfm_origin_ka.lua` assumed the 3-arg form keyed the pool by host; it does
> not. On `server.speedhost.gr` (OpenResty 1.31.1.1 → Apache) that produced
> ~17.5 k `status=421` responses over a week — warm (`uct=0.000`)
> connections carrying the wrong SNI, across dozens of vhosts, hitting real
> browsers and Googlebot/Bingbot alike.
>
> The fix does not depend on any version-specific pool-naming behaviour: 443
> is simply not pooled. The knob is therefore safe to run fleet-wide as-is;
> the safe HTTP (port 80) origin pool is retained (see the scope note above
> for what that actually covers).
>
> **Future (not yet implemented):** safe 443 pooling is possible by giving
> each pool a host-scoped name (fold the SNI into the `pool` option of
> `set_current_peer`) so `hostA` and `hostB` never share a pool. Because the
> exact API shape is version-specific and a wrong assumption here is what
> caused this incident, it must be gated behind an integration self-test
> that deliberately drives `hostA` → pooled connection → immediate `hostB`
> request against the **deployed** engine and proves the second request does
> **not** reuse `hostA`'s TLS connection (assert `uct > 0` for `hostB`), not
> merely a unit test with a stubbed balancer.

Tuning — all in `[webdetector]`; fields absent (older daemon) fall back to
the built-in defaults below:

| detectors.conf key | Default | Meaning |
|---|---|---|
| `ORIGIN_KEEPALIVE` | `0` | `1` routes allow-traffic through the pooled upstreams |
| `ORIGIN_KEEPALIVE_IDLE_SEC` | `3` | Idle seconds before a pooled **port-80** connection is retired. **Keep below Apache's `KeepAliveTimeout`** (EA4/cPanel default 5 s) so Apache never closes a connection nginx still considers fresh. Clamped to 1–60. |
| `ORIGIN_KEEPALIVE_MAX_REQS` | `1000` | Requests served per pooled port-80 connection before recycling |

(The idle/max-reqs knobs govern the port-80 pool only; 443 is never
pooled.)

Keepalive races are handled: `balancer_by_lua` disables nginx's default
upstream retries, so `cfm_origin_ka.lua` arms exactly one retry
(`set_more_tries(1)`) on each request's first attempt — a pooled
port-80 connection that Apache closed in the idle window is transparently
retried on a fresh connection instead of surfacing a 502.

Engine support (OpenResty vs Angie): the code path is identical — both
load the same lua-nginx-module + lua-resty-core stack, and
`cfm_origin_ka.lua` detects capabilities at runtime rather than assuming
them. Two per-worker tiers:

1. `enable_keepalive` works → port 80 pooled, port 443 per-request
   (SNI-safe). This is the normal case on OpenResty and current Angie.
2. `enable_keepalive` missing or its FFI shim absent from the engine's
   lua module build (possible on some Angie `angie-module-lua` versions) →
   one WARN, the worker permanently degrades to per-request connections on
   port 80 too (no per-request errors). Never worse than the knob being off.

When the knob is on, each worker logs its effective state once per worker,
the first time it routes a request on each port — two separate lines, so a
worker serving only one port logs only one of them:

* `[cfm_origin_ka] HTTP(80) origin pooling active` on the first port-80
  request (the line confirms pooling is on; the live idle/max_reqs follow
  `ORIGIN_KEEPALIVE_*` in detectors.conf) — or, on the degraded tier above, a WARN naming
  the reason: `engine lacks balancer.enable_keepalive` (API absent) or
  `enable_keepalive raised (…) — … degrading to per-request` (FFI shim
  present but throws), and `enable_keepalive failed: …` (a non-raising error
  return, warned once/worker);
* `[cfm_origin_ka] HTTPS(443) origin: per-request TLS by design …` on the
  first port-443 request.

These are intentionally at WARN, not NOTICE: `error_log` runs at `warn`, so
a NOTICE would never be written — that log blind spot is what hid this
incident's root cause for a week. **They are expected, once-per-worker
activation lines, not error conditions** — a healthy box re-emits them on
every proxy reload (one set per worker), so exclude `[cfm_origin_ka]` from
any warn-count alerting rather than paging on them. After enabling,
`grep '\[cfm_origin_ka\]' error.log` to confirm the module is active and see
which tier the box landed on.

Prerequisites & rollout:

1. Apache `KeepAlive On` (cPanel default). If an operator lowered
   `KeepAliveTimeout` below 3 s, lower `ORIGIN_KEEPALIVE_IDLE_SEC` to match.
2. Enable on one box, watch `uct=` in the access log collapse toward 0 on
   warm **HTTP (port 80)** traffic, and grep error.log for the
   `[cfm_origin_ka]` activation lines (above). 443 keeps its per-request
   handshake (`uct > 0`) by design and cannot produce a cross-SNI `421`.
3. The static-asset and streaming bypass locations keep their direct
   `proxy_pass` (they intentionally skip cfm.lua); the pooled path covers
   `location /` and the PHP/admin no-buffer location — i.e. the HTML
   document path that dominates TTFB.

## What is already cached (don't re-solve)

* Bridge decision verdicts: 90 s shdict cache per (ip, host, method,
  scheme, uri-prefix); static assets coalesce to one entry per
  (ip, host, scope). ~95 % of requests never touch the Go socket.
* GeoIP country: 5 min shdict cache per IP.
* WAF excludes: shdict snapshot every 10 s + per-worker decoded cache.
* Small config files (bridge token/config, self-ips, ignore-nets, clamav
  toggle): per-worker TTL cache in `cfm_filecache.lua` (this was the
  per-request `loadfile()` bug fixed in 2026-07).
* The inline WAF itself deliberately has **no** verdict cache — it
  inspects every request's URI/args/headers/body; that's the product.

## Known non-CFM latency

A field TTFB of seconds on mobile while `rt=` stays ~tens of ms is
real-user network (cellular handshake, distance, redirect chains), not
the edge. Prove it with the split fields before touching CFM.
