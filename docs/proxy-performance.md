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
  handshake** to Apache. This is what origin keepalive eliminates; on a
  pooled connection it drops to ~0.000–0.001.
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
turning it back to `0` rolls back the same way. (The
`CFM_ORIGIN_KEEPALIVE=1` proxy-master env var still works, but only as a
fallback when the daemon is older and doesn't write the field; when the
config key is present it is authoritative.)

Once on, cfm.lua's `origin_pass_for()` routes allow-traffic through the
`cfm_origin_http` / `cfm_origin_https` upstream blocks, where
`cfm_origin_ka.lua` (balancer_by_lua) sets the peer to `$server_addr`
per request — dedicated-IP routing is preserved — and pools connections:

* **Port 80** — always pooled. HTTP/1.1 keepalive + Host-header vhost
  routing is standard Apache behaviour.
* **Port 443** — pooled **only** when lua-resty-core's
  `balancer.set_current_peer(addr, port, host)` accepts the third `host`
  argument (OpenResty 1.27.1.1+), which sets the upstream SNI *and* keys
  the pool by it, so a connection handshaked for `hostA` is never reused
  for `hostB`. On older cores the module logs one NOTICE per worker and
  keeps per-request connections for HTTPS (identical to the knob being
  off) — never risking Apache `421 Misdirected Request` on shared-vhost
  boxes.

Tuning — all in `[webdetector]` (env fallbacks in parentheses apply only
when the daemon predates the key):

| detectors.conf key | Default | Meaning |
|---|---|---|
| `ORIGIN_KEEPALIVE` (`CFM_ORIGIN_KEEPALIVE`) | `0` | `1` routes allow-traffic through the pooled upstreams |
| `ORIGIN_KEEPALIVE_IDLE_SEC` (`CFM_ORIGIN_KA_IDLE_SEC`) | `3` | Idle seconds before a pooled connection is retired. **Keep below Apache's `KeepAliveTimeout`** (EA4/cPanel default 5 s) so Apache never closes a connection nginx still considers fresh. Clamped to 1–60. |
| `ORIGIN_KEEPALIVE_MAX_REQS` (`CFM_ORIGIN_KA_MAX_REQS`) | `1000` | Requests served per pooled connection before recycling |

Engine support (OpenResty vs Angie): the code path is identical — both
load the same lua-nginx-module + lua-resty-core stack, and
`cfm_origin_ka.lua` detects capabilities at runtime rather than assuming
them. Three graceful degradation tiers, checked per worker:

1. `set_current_peer` accepts the SNI `host` argument → full pooling
   (80 + 443).
2. No SNI-keyed pools (older lua-resty-core, likely on some Angie
   `angie-module-lua` builds) → one NOTICE in error.log, port 80 pooled,
   443 stays per-request. Never worse than the knob being off.
3. `enable_keepalive` missing or its FFI shim absent from the engine's
   lua module build → one WARN, the worker permanently degrades to
   per-request connections (no per-request errors).

After enabling on an Angie box, grep error.log for `[cfm_origin_ka]` to
see which tier you landed on.

Prerequisites & rollout:

1. Apache `KeepAlive On` (cPanel default). If an operator lowered
   `KeepAliveTimeout` below 3 s, lower `CFM_ORIGIN_KA_IDLE_SEC` to match.
2. Enable on one box, watch `uct=` in the access log collapse toward 0 on
   warm traffic, and check error.log for `[cfm_origin_ka]` warnings and
   for any 421/400 SNI-mismatch responses (`ust=421`) before fleet-wide
   rollout.
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
