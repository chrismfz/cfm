# Imunify360 WebShield vs the CFM edge: what moves when CFM goes first

Status: **analysis + proposal** (2026-11-17). Nothing below P0 is built.

## P0. What happened (done)

A connection is NAT'd once, by the first nat chain that rewrites it.
Imunify360 DNATs its IP sets to WebShield (`:52223` https, `:52224` http, and
the panel ports) from `ip nat PREROUTING` at priority -100 (dstnat). CFM's web
redirect (`inet cfm_redirect`) defaults to -99 ("Imunify first"). On a cPanel
node `i360.ipv4.remote_proxy_static` holds Cloudflare's ranges (1 580 ranges
of 20 CDNs), so **every Cloudflare visitor went to WebShield and never reached
the CFM edge** (WAF, challenge, edge bans, logging).

earth, 10:00-10:59 on 2026-11-17: the edge served 74 407 requests, 235 of them
through Cloudflare; WebShield served 30 650, ~93% from Cloudflare addresses.
WebShield's archived logs go back to September at ~30 MB/day: months, not
hours. earth and speedhost had no `NFT_DNAT_PRIORITY` in `cfm.conf`; titan,
rigel, orion, qualityweb run -101, virgo and mars run CFM first.

Fixed the same day: `NFT_DNAT_PRIORITY = -101` on earth and speedhost and
`cfm dnat on --priority -101` (one transaction). On earth WebShield fell from
~1 100 requests/min to 1-2 and the edge's Cloudflare requests rose from 1-2/min
to ~505. `edge_health` check H (`web-dnat-order`, `docs/edge-health.md`) now
warns when a DNAT runs ahead of CFM's redirect while WebShield serves real
traffic.

## What WebShield does, per request

From the package on earth (`imunify360-webshield-bundle` 1.50.1:
`/etc/imunify360-webshield/webshield.conf`, `virtserver.conf`, `wscheck.conf`,
`/opt/imunify360-webshield/nginx/lua/{accesscheck,reqrouter}.lua`):

1. **Real client IP** (`$wsuserip`, `wscheck_ipsearch`): behind Cloudflare from
   `CF-Connecting-IP` / `True-Client-IP`; behind any other proxy in its geo map
   (bunnycdn, gcore, cloudfront, quic-cloud, fastly, ezoic, sucuri, ...) from
   `X-Forwarded-For`.
2. **Verdict** (`accesscheck.lua`): one protobuf query per request to
   `/var/run/imunify360/libiplists-daemon.sock` with the real IP. Answers:
   `WHITE`, `WHITE_STATIC`, `REMOTE_PROXY`, `BLACK`, `BLACK_LOCAL`,
   `COUNTRY_BLACK`, `GRAY`, `SPLASH`, `NOT_FOUND`.
3. **Route** (`reqrouter.lua`):
   - `WHITE` / `WHITE_STATIC` → backend;
   - `BLACK` / `BLACK_LOCAL` / `COUNTRY_BLACK` → **403**;
   - domain whitelisted → backend;
   - `GRAY` → splashscreen-as-captcha (HTML) or 415, **except through
     Cloudflare with `cloudflare_captcha off` (earth): backend**;
   - `SPLASH` without a `wsuserid` cookie → antibot splashscreen (JS check,
     `wsidchk`);
   - cPanel 2082/2083 antibot splash when `cpanel_protection` is on;
   - else → backend, from 127.0.0.1 with `X-Real-IP: <real IP>`.
4. **Feedback**: a solved captcha is reported to the agent
   (`defence360agent/protobuf.sock`); too many captcha requests blacklist the IP
   (`Blacklisted for CAPTCHA_DOS_ALERT after 101 captcha requests`).

## Measured on earth (the ~4 h before the switch, WebShield's own log)

| | requests | 403 |
|---|---:|---:|
| via Cloudflare | 108 866 | 15 982 (14.7%) |
| direct (graylist / splash / captcha sets) | 12 414 | 50 |
| via QUIC.cloud | 816 | 0 |
| via ShortPixel | 20 | 0 |

Of the 15 982 Cloudflare 403s, **14 690 came from 62 real IPs on Imunify's
`blacklist` / `drop.sync`** (WebShield's `BLACK` verdict); the other 1 292
(326 IPs) are the origin's own 403s. In the 45 minutes after the switch, 11 of
those 62 reached the edge through Cloudflare (211 requests): CFM's own rules
stopped 129 (403), and **82 went through** (200/301/302/401/404).

No country is blocked (`blocked_country_codes.conf` is empty).

## What CFM loses at -101, and what it does not

| WebShield function | At -101 | Comment |
|---|---|---|
| Imunify blacklist on the **real IP behind Cloudflare** | **lost** | nft cannot drop it: the peer is Cloudflare. CFM's `edgeban` covers only CFM's own web bans, and CFM's own fleet blacklist has the same gap. **P1.** |
| Imunify blacklist, direct client | kept | Imunify's filter rules (`imunify360_log_bl` → DROP) match the source on every port, 9043/9080 included. |
| `GRAY` / `captcha.sync`, direct client | **changed: hard drop** | Imunify accepts those sets only on WebShield's ports; anything else goes to `imunify360_log_gl` → DROP. A graylisted visitor's new connection to 80/443 is dropped instead of meeting a captcha. Counter on earth: 0 drops in 4 h (37 graylisted IPs), so it rarely bites; titan/rigel/orion have behaved like this all along. **P3.** |
| `GRAY` via Cloudflare | no change | `cloudflare_captcha off`: WebShield let them through too. |
| `SPLASH` antibot (`splashscreen.sync`) | **lost** | No DROP rule for that set: a splash-listed client now reaches the edge unchallenged. 20 479 such connections were accepted on WebShield's ports since boot; the set is empty right now. **P2.** |
| Real IP behind other CDNs | n/a | The edge trusts Cloudflare only, on purpose (`trusted_proxies.conf`: XFF from a CDN that passes the client's own is forgeable). QUIC.cloud is in the bypass list; the rest is negligible on earth. **P4.** |
| reCAPTCHA, captcha-DoS blacklisting | covered | CFM's PoW challenge, the page rate limit ban, `CHALLENGE_V2_PATHS_REJECT_BAN`. reCAPTCHA (Google dependency) is not worth copying. |
| Country block | n/a | Not configured; CFM's geo policy is challenge-tier only by doctrine. |

## Proposals

### P1. The fleet blocklist at the edge, for proxied clients (recommended first)

The gap is not Imunify's: **CFM's own fleet blacklist never reaches a client
behind Cloudflare either.** Nodes pull cfm-web's `/blacklist.txt` (`MYBLOCK` in
`/etc/cfm/cfm.blocklists`) into nft (`block_ext_v4_hosts`: 267 782 addresses on
earth). nft only sees the proxy's address for a Cloudflare visitor, and the
edge's proxied-client check (`writeEdgeBan`, `px=1`) consults only the
`edgeban` store, which by design takes no fleet feeds (CLAUDE.md §6, "An nft
ban never stops a client behind a trusted proxy"). Measured on earth in the
45 minutes after the switch, through Cloudflare:

- 20.43.87.186, fleet-blacklisted by orion (`WAF/WEBSHELL | waf_security`),
  not in earth's `edgeban`: 200 / 301 / 404 from the origin;
- 45.138.12.32, fleet-blacklisted by virgo (`WAF/CVE-2025-11833`): 404 from
  the origin;
- 20.87.218.237, in earth's own `edgeban` too: 126 × 403 `up=cfm_block`.

So a scanner another node caught is stopped on every node for direct traffic
and on none for Cloudflare traffic. The same holds on titan, rigel and orion,
which have run CFM first all along.

- **No list in Lua.** 268 k addresses in a shared dict or in the workers is
  the regression already ruled out; the edge copy of `edgeban` is capped at
  20 k (`lua_shared_dict cfm_edgeban 16m`, two copies of the daemon's cap).
- **Lookup in the bridge (Go):** the daemon keeps the feed it already fetches
  for `block_ext_v4_hosts` as an in-memory lookup (sorted `[]uint32` for v4:
  ~1 MB, a binary search per query; v6 apart). `writeEdgeBan` (bridge
  decision, `px=1`, web scope) answers `block` when the real client is in the
  edge ban store **or** in the fleet list. No new RPC: the edge asks the bridge
  for every request it has no cached clean allow for, and a `block` is never
  cached, so a listed client meets the lookup on every page and `.php`
  request (the `.php` / `wp-admin` location runs cfm.lua).
- **What the bridge does not see:** the static location (css/js/images, which
  checks only the edge copy) and URLs a client warmed with a clean allow in the
  last 90 s before it was listed.
- **Promote on hit, bounded:** on a `block` answered from the fleet list, the
  address also goes to `edgeban` (source `fleet`, TTL = the feed entry's
  expiry, at most a few hours), so within ~5 s the edge copy covers the static
  location and the cached URLs too. Only addresses that actually show up are
  promoted, not the list; a quota (e.g. 5 k of the 20 k) keeps them from ever
  pushing the node's own web bans out, and past it the bridge alone enforces.
  The fleet unblock path (`pending-unblocks`) must `edgeban.Unban` them.
  Size check from earth: the 62 Imunify-blacklisted IPs that hit through
  Cloudflare drove 14 690 requests in ~4 h, so a day's promotions are in the
  hundreds, not thousands; the `log` phase measures it fleet-wide first.
- **Precedence:** IGNORE_IPS, the static bypass and every allow (the fleet
  whitelist `MYALLOW` included) win, as they do in nft.
- **Rollout:** a `[webdetector]` mode `log | enforce | off` (log first:
  `would_block src=fleet`), a week of `node="all"` reads, then enforce.
- **Imunify's lists as a second source (optional):** `i360.ipv4.blacklist`,
  `.blacklist.custom`, `.drop.sync` (~1.5 k on earth, read from the kernel
  ipsets every ~60 s). Of the 62 Imunify-blacklisted IPs WebShield 403'd,
  several are also on the fleet list (20.87.218.237, 20.43.87.186,
  45.138.12.32); the rest are Imunify's own detections (`CAPTCHA_DOS_ALERT`).
  Worth adding only if the shadow reads show the fleet list leaves a real
  remainder.

### P2. Imunify's splash list as a CFM challenge source (measure first)

`splashscreen.sync` is the list Imunify wants an antibot check for. Feed it as
a per-IP v1 challenge source (`src=imunify_splash`), proxied and direct, in
shadow first. Only worth it if the set is non-empty on the fleet: today it is
empty on earth.

### P3. Graylisted direct visitors: decide, do not code

At -101, Imunify's own filter drops a graylisted client's new connections to
the edge ports. CFM cannot undo a DROP in another base chain. The options are
Imunify-side (shorter graylist TTL, `cloudflare_captcha`-like settings) or
accepting it, as titan/rigel/orion have. Track the drop counter
(`imunify360_log_gl`) in the fleet before deciding.

### P4. Never ban a CDN node as a client

The edge trusts Cloudflare only. Another CDN's node (BunnyCDN, Gcore,
CloudFront, Fastly, ...) reaching the edge looks like one client carrying many
visitors, and a per-IP ban would take a site down for all of them. Imunify's
`remote_proxy_static` names those ranges. Measure them across the fleet
(`edge_access_tail` by client, `node="all"`), then either add them to an
"address is a proxy" list that per-IP autoblock never bans, or confirm that
CFM's existing guards cover them.

### Not proposed

Copying WebShield's reCAPTCHA, its domain whitelist or its country block:
CFM has its own challenge, exclude and geo-policy mechanisms, and none of them
is a measured gap.
