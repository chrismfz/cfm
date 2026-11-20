# edge_health — edge → origin hop correctness check

`edge_health` is a **read-only** node MCP tool over
`GET /api/v1/system/edge-health` (admin-only). It answers one question the raw
tails (`edge_access_tail`, `edge_error_tail`) and generic `config_drift` cannot
in one call: **is the in-path edge → origin hop correct right now, on this
engine, with this config?** It reads the edge logs, the published bridge
config, the engine version, the origin's configuration and the nft ruleset
together, and correlates them. On the node, `cfm edge check` prints the same
report: every check with its severity, and the next step for a non-ok one.
`--json` prints the report as it came, `--window N` sets the access lines to
scan. It exits 0 only when the overall verdict and every finding are ok, so a
warn exits 1: a resolved 421 storm still in the log tail stays warn until it
scrolls out, which a cron alert should allow for. `whats_wrong` surfaces its findings (below).

It exists because of the 2026-08 `421 Misdirected Request` incident
(`docs/proxy-performance.md`): the symptom sat in the edge access log for a
week while the root cause was the engine version (nginx ≥ 1.29.7 turned native
upstream keepalive ON by default, SNI-blind), and nothing correlated the two.

Read-only: it reads files and the nft ruleset, and runs the edge binary's `-v`
for the version. It never runs `-t`, reloads, blocks or changes config.

Code: `internal/apiserver/edge_health_endpoint.go` (checks A–G),
`internal/apiserver/edge_health_webshield.go` (check H),
`internal/mcpserver/edge_health.go` (the tool),
`internal/mcpserver/whats_wrong_edge_health.go` (the `whats_wrong` mapping).

## Input

- `window` — trailing edge access-log lines to scan (default 50 000, max
  500 000). It bounds checks B and E; the error log scan (check C) is a fixed
  20 000 lines.

## Severities

Each finding carries a `severity`: `ok | warn | critical | unknown`. `overall`
is the maximum (`critical` > `warn` > `unknown` > `ok`). `unknown` means a log,
the version or the ruleset could not be read, and is never silently turned into
`ok`. Where a check needs a timestamp to age its evidence and a line carries
none it can parse, the line counts as fresh (fail-safe toward flagging).

## Checks

| Letter | `check` id | Reads |
|---|---|---|
| A | `engine-version-trap` | engine + version, the D knob, B's live warm 421s |
| B | `origin-421-fingerprint` | edge access log |
| C | `origin-ka-tier` | edge error log |
| D | — (input to A) | `/var/lib/cfm/lua/cfm_bridge_config.lua` |
| E | `origin-premature-close` | edge access log (same pass as B) |
| F | `cdn-cached-challenge` | the challenge server's in-memory counts |
| G | `origin-real-ip` | the origin's configuration |
| H | `web-dnat-order` | nft ruleset + WebShield access log |

### A. Engine + version trap (`engine-version-trap`)

nginx ≥ 1.29.7 (OpenResty's nginx base, the first three components of its
version) turns native upstream keepalive ON by default and SNI-blind; Angie
does not (and rejects `keepalive 0`), so Angie is never the trap.

- Engine not detected ⇒ `unknown`. OpenResty/nginx with an unreadable version
  ⇒ `unknown` (the trap cannot be ruled out).
- Trap + knob on + live warm-reuse 421s (check B) ⇒ `critical`.
- Trap + knob on, no live warm 421s ⇒ `ok` (informative). This check does NOT
  verify the `keepalive 0` / `proxy_ssl_session_reuse off` invariant (the CI
  gate `check_origin_ka_config.sh` checks the reference config); warning here
  would fire on every healthy node.
- Trap + knob off ⇒ `ok`. Trap + knob unreadable ⇒ `unknown`.
- Not the trap engine/version ⇒ `ok`.

### B. Origin 421 / warm-reuse fingerprint (`origin-421-fingerprint`)

Counts the real `status=421` field (read only outside quoted values, see E),
and the **warm-reuse** shape: the line names `cfm_origin_https` and carries the
single value `uct="0.000"` (a retry list such as `uct="0.000, 0.052"` is a
fresh connect and does not match). Evidence: `status_421_total`,
`warm_reuse_421`, `recent_warm_421`, `fresh_window_sec`,
`newest_warm_421_age_sec`, `top_hosts`, `scanned_lines`, `log_file`.

Recency: an edge reload empties the upstream pool, so only warm 421s inside a
5-minute window (`msec=` epoch on each line) are live.

- Live warm-reuse 421s (or warm 421s none of which carries a parseable
  `msec`) ⇒ `critical`.
- Warm-reuse 421s, all older than 5 min ⇒ `warn` (a stopped storm; it decays
  to `ok` as the lines leave the window).
- `status=421` without the warm shape ⇒ `warn` (likely a misconfigured origin
  vhost, not pooling).
- None ⇒ `ok`. Access log unreadable ⇒ `unknown` (and E is skipped).

### C. `[cfm_origin_ka]` tiers (`origin-ka-tier`)

Classifies the edge error-log lines into the `tiers` map:

- fatal: `ngx.balancer unavailable` (`balancer_unavailable`: every origin
  request through `cfm_origin_*` fails) and `cfm_origin_ka load failed`
  (`module_load_failed`, a `[cfm]` line: balancer_by_lua fell back to inline
  `set_current_peer`);
- degraded: `keepalive-race retry is unavailable` (`degraded_no_retry`) and the
  `enable_keepalive` lines (`degraded_unpooled_80`);
- activation (counted, never a problem): `HTTP(80) origin pooling active`,
  `origin port 443: per-request`.

These lines are written once per worker, so each problem tier is aged by its
own newest line (local-time stamp at the start of the line; `tier_age_sec`),
against a 6-hour window:

- fatal tier, fresh ⇒ `critical`; stale ⇒ `warn`, never `ok` (the fault is
  still live if the edge has not been reloaded since; its acute symptom, a 502
  storm, surfaces in E);
- degraded tier, fresh ⇒ `warn`; stale ⇒ `ok`, still shown in the summary,
  `tiers` and `tier_age_sec`;
- no problem tier ⇒ `ok`, including an empty map (activation lines age out of
  a healthy log); error log unreadable ⇒ `unknown`.

### D. ORIGIN_KEEPALIVE knob

Not a finding of its own: `origin_keepalive` (`true`/`false`) is read from
`/var/lib/cfm/lua/cfm_bridge_config.lua` and reported top-level as
`origin_keepalive_knob` (`unknown` when unreadable). It feeds A.

### E. Origin premature-close / gateway 5xx (`origin-premature-close`)

A gateway status (502/503/504) where **every** upstream attempt logged no
response header (`uht="-"`, or `"-, -"` after the `cfm_origin_ka` retry) and
`uaddr=` names a real peer: the edge chose an origin and never got a header
back (a dropped connection, or a connect/TLS failure). An application 500
always carries a header, and a response the edge produced itself (challenge,
block, admin error page) names no peer, so neither counts.

The status is read only from the line with its quoted values blanked:
client-controlled fields such as `cf=` sit before `status=` and nginx does not
escape spaces in them, but escapes `"` as `\x22`, so nothing can be injected
outside the quotes.

Thresholds (`edge_health_endpoint.go`): at least 10 events AND a rate of
0.02 % of the scanned lines for `warn`, 0.2 % for `critical`; live means a drop
inside the last 15 min.

- ≥ 10 events, ≥ 0.2 %, live ⇒ `critical`;
- ≥ 10 events, ≥ 0.02 %, live ⇒ `warn`;
- ≥ 10 events, ≥ 0.02 %, none in 15 min ⇒ `warn` ("appears to have stopped");
- otherwise ⇒ `ok` (below the floor, or none).

The summary names the vhost spread (many vhosts: the origin; one: that app).
`next`: `edge_error_tail grep="upstream prematurely closed"`, then
`dmesg_tail grep=segfault` and `service_status` for the origin daemon.

### F. A CDN caching CFM's challenge (`cdn-cached-challenge`)

The challenge server serves its page only at `/__cfm_challenge`, marks every
response `no-store` for CDNs too (`CDN-Cache-Control`,
`Cloudflare-CDN-Cache-Control`), and sends a **cleared** visitor bounced back
to it for the same target, once per target per breaker window and for web
scope only, to `next` again with a fresh `cfm_nc` parameter (the edge strips it
before the origin on a plain path). It counts those bounces per host and per
distinct client (an IPv4 address, an IPv6 /64) over 24 h, in memory
(`internal/webdetector/challenge_cdn_cache.go`; empty after a daemon restart).
Each bounce writes a `cdn_cached_challenge … relayed=0|1|-` line to
`cfm.challenges.log`.

The edge's `/__cfm_challenge` location sends `X-CFM-Relayed:
$xfp_trusted_peer` (`1`: the peer is in `trusted_proxies.conf`; `0`: the peer
is the client). A bounce is filed as:

- relayed (`1`, or no header from an older edge conf), page target ⇒ `hosts`;
  3+ distinct clients on a host ⇒ `warn` ("likely a CDN"). The fix is that
  vhost's CDN rule (respect the origin's `Cache-Control`), then a purge;
- direct (`0`), page target ⇒ `evidence.direct_hosts` (a browser re-opening
  the address, or a CDN the edge does not trust as a proxy), never a warning;
- relayed, download target (`.pdf`, `.zip`, office documents, media …, by the
  path's extension) ⇒ `evidence.download_hosts` (a re-tapped download, or a
  CDN rule caching only file extensions), never a warning;
- direct, download target ⇒ not counted.

The lists use the same 3-client floor and are named in the summary. The
evidence key `ips` is the distinct-client count. The floor is on clients, not
bounces, because the host is the client's own `Host` header: one client must
not be able to make a tenant look like a CDN casualty.

With no challenge server serving (`CHALLENGE_HTTP_LISTEN` unset, or its
listener down) and no host over the floor ⇒ `ok` with `measured: false` (no
challenge page to cache). Hosts already counted still `warn`.

Honest limits:

- a CDN that overrides `no-store` ignores the CDN headers too;
- one that drops the query string from its cache key defeats the `cfm_nc`
  retry;
- one that also caches `/__cfm_challenge?next=X` defeats all of it, and no
  bounce reaches the origin, so F stays silent;
- a cached redirect still challenges every visitor of that URL until the
  entry expires;
- it is a heuristic: a cleared bounce with no CDN (several tabs on one target,
  a bridge-token rotation window, which can hit many IPs at once) counts too,
  hence "likely".

### G. The origin sees the visitor, not 127.0.0.1 (`origin-real-ip`)

The edge proxies to the origin from 127.0.0.1; an origin that does not trust
the loopback with a header the edge sets logs 127.0.0.1 for every visitor and
hands PHP `REMOTE_ADDR=127.0.0.1`. Reads the origin's configuration with the
same probe as `cfm health` and `cfm realip` (`internal/originrealip`):

- `ok` when the origin trusts the edge, or when no edge engine runs;
- `unknown` when an edge runs and no origin stack is found;
- `warn` otherwise. `next` is `cfm edge realip fix`, or, where CFM writes nothing
  (LiteSpeed, NGM, some nginx cases), the manual step the finding names.

Per panel and stack: [`origin-real-ip.md`](origin-real-ip.md).

### H. Web traffic reaches the edge, not a DNAT ahead of it (`web-dnat-order`)

A connection is NAT'd once, by the first nat chain that rewrites it. Imunify360
DNATs its sets to WebShield at priority -100, and on a cPanel node its
`remote_proxy_static` set holds Cloudflare's ranges; CFM's web redirect
defaults to -99 (`cfm dnat`), so with that default every Cloudflare visitor
skips the edge (earth, 2026-11-17: ~29 % of its web requests). See
`docs/imunify360-gap-analysis.md` ("WebShield").

The check reads the ruleset (`netfilterdiag.WebDNATAhead`: non-CFM `dnat` /
`redirect` rules in prerouting for tcp/80 or tcp/443 at a priority no later
than `inet cfm_redirect`'s; an equal priority counts) and counts
`/var/log/imunify360-webshield/access.log` over the last 15 min (at most the
last 8 MB; `webshield_count_complete: false` means the count is a floor).
Packet counters are not used: they are cumulative and would keep warning after
the fix.

- ruleset unreadable ⇒ `unknown`;
- no `cfm_redirect` chain (web DNAT off) ⇒ `ok`;
- CFM's redirect runs first ⇒ `ok`;
- a rule ahead owned by anything other than Imunify (Docker publishing :443, a
  hand rule), alone or with Imunify's ⇒ `warn` on the order alone;
- Imunify's rule ahead: WebShield served 100+ requests in the window ⇒ `warn`;
  fewer ⇒ `ok` (Imunify-first is then a working choice); no WebShield log ⇒
  `unknown`.

For another owner's rule, `next` says to move that DNAT after CFM's redirect
or set `NFT_DNAT_PRIORITY` below its priority. For Imunify's:
`NFT_DNAT_PRIORITY = <ahead priority − 1>` in
`/etc/cfm/cfm.conf` (-101 for Imunify's -100) and
`cfm edge on --priority <same>` (one transaction). nft refuses a nat chain at
-200 or below, so a chain ahead at -199 or lower has to move instead. With CFM
first, a client on Imunify's graylist is dropped by Imunify's own filter on the
edge's ports, not given a WebShield captcha.

## Output

```jsonc
{
  "ok": true,
  "schema": "system.edge_health.v1",
  "engine": "openresty", "version": "1.31.1.1", "nginx_base": "1.31.1",
  "native_keepalive_trap": true,
  "origin_keepalive_knob": "true",
  "origin_keepalive_source": "/var/lib/cfm/lua/cfm_bridge_config.lua",
  "overall": "critical",
  "findings": [
    {
      "check": "origin-421-fingerprint",
      "severity": "critical",
      "summary": "…",
      "evidence": { "status_421_total": 1204, "warm_reuse_421": 1180, "recent_warm_421": 312, "…": "…" },
      "next": "…"
    }
    // one finding per check A–C, E–H, most severe first
  ]
}
```

Each finding has `check`, `severity`, a one-line `summary`, `evidence`, and a
`next` drill-down when there is one.

## In `whats_wrong`

`whats_wrong` pulls `/api/v1/system/edge-health` as a section
(`evalEdgeHealth`): `critical` ⇒ a critical `edge` finding, `warn` ⇒ a
warning, pointing back at `edge_health`; `ok` and `unknown` emit nothing
(`unknown` would fire on every node that hides its version string). The section
is evaluated only when the health snapshot resolves a known edge engine
(`edgeEngineUnits`: angie, openresty, nginx); otherwise `sources` says it was
not evaluated.

## Not checked

- The live-config origin-hop invariant: parse the live `openresty.conf` /
  `angie.conf` and assert what `check_origin_ka_config.sh` asserts on the
  reference config (OpenResty `keepalive 0` on the 443 origin upstream,
  `proxy_ssl_session_reuse off`, Angie without `keepalive 0`). A's "the class
  applies" stays informative until then.
- The Apache-side AH02032 421 fingerprint (origin error log), aborted Lua
  threads, `-t` + reload freshness (conf edited but not reloaded), WAF /
  challenge Lua errors.
- Latency split (`uct`/`uht`/`luams`/`sslr`), 499 rates, worker respawns,
  cert/SSL edge errors.
- A notifier alert on a 421 rate.
- The two-vhost same-IP integration test (backend-observed SNI == Host, zero
  421) belongs in a test harness, not this read tool.
