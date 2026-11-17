# Proxied-client IP filter (`internal/proxyipfilter`)

Status: **built, log mode** (2026-11-17). Enforcement is a knob, off by default.

## Why

nft drops by source address, and a visitor behind a trusted proxy (Cloudflare)
reaches the node from the proxy's address. So none of CFM's IP lists ever
applied to that visitor: not the fleet blacklist (cfm-web's `MYBLOCK` feed,
267 782 addresses on earth), not the node's own bans (`block_v4`: `cfm.deny`,
detector TTL bans), not the allows. The edge ban store (`internal/edgeban`)
covers only the node's web-related bans, and on purpose holds no fleet feed:
the edge keeps a Lua copy of it, sized for 20 k entries (`lua_shared_dict
cfm_edgeban 16m`), and 268 k there is the regression ruled out before.

Measured on earth, 2026-11-17, in the 45 minutes after its web redirect moved
ahead of Imunify360's (`NFT_DNAT_PRIORITY = -101`): 20.43.87.186, fleet-banned
by orion for `WAF/WEBSHELL`, and 45.138.12.32, fleet-banned by virgo for
`WAF/CVE-2025-11833`, reached the origin through Cloudflare (200 / 301 /
404). Before that move, Imunify's WebShield answered 403 for the 62 addresses
on Imunify's own blacklist that came through Cloudflare (14 690 requests in
about 4 hours), a job nothing in CFM did.

## How

- **Lists in the daemon's memory, never in Lua.** Each source is a table:
  IPv4 hosts as a sorted `[]uint32` (the 268 k-entry fleet list is ~1 MB),
  networks and ranges as merged `[lo,hi]` pairs, IPv6 the same way. A lookup
  is a binary search with no allocation; a refresh builds a new snapshot and
  swaps an atomic pointer.
- **Sources.** Feeds: `blocklists.Manager` hands every successfully applied
  feed over (built outside its lock, published under it only while the feed is
  still configured, so a fetch that finishes after a Reload removed the feed
  does not bring it back). A feed holds until its next apply, as in nft: a
  per-element TTL (`|TTL=1h`) times only the per-feed set, while the base
  rules drop on the union sets, which are rebuilt without one. The
  node's own sets of `inet cfm input` are read from the kernel every minute
  (`StartLocalRefresh`, the backend's `ListSetElementsRaw`): `block_v4/v6`,
  `block_v4/v6_nets`, `allow_v4/v6`, `allow_v4/v6_nets`, `allow_dyn_v4/v6`.
  A set that cannot be read keeps what it had. Not read: `self_*`,
  `ignore_*` (no input rule uses them), `ps_pairs_*`, `th_*`, `throttled_*`.
- **The verdict follows `inet cfm input`:** every allow set accepts before any
  block set drops, so an allow only cancels a block. It does not exempt the
  request from the WAF or a challenge, exactly as an nft allow does not for a
  direct client.
- **Unblocks apply at once.** `edgeban.Unban`, which every unblock and allow
  path calls, also clears the address from every block source here
  (`Forget`) for two refreshes (2 min), by when the sets read show the
  kernel's own view (the block gone, or the allow an unblock adds for a
  feed-listed address). A network allow (`cfm allow 203.0.113.0/24`) does the
  same for the whole range. A ban the address earns again inside those 2 minutes
  reaches the proxied filter when the override ends; nft's own drop of a
  direct client is immediate.
- **Where:** the nginx bridge's decision (`writeEdgeBan`), for a web-scope
  request that came through a trusted proxy (`px=1`), after IGNORE_IPS / the
  static bypass and the edge ban store. No new round trip: the edge asks the
  bridge for every request it has no cached clean allow for, and a `block` is
  never cached. In log mode the allow for a listed client (one no allow
  cancels) carries `rule_action=observe`, which the edge does not cache either (cfm.lua acts on
  block / challenge / throttle only, so it is an allow), so the counts are
  per request, as enforce would see them. Not covered: the static location
  (css/js/images, which checks only the edge copy of `edgeban`) and URLs a
  client warmed with a clean allow in the 90 s before it was listed.
- **The local sets on nftlib** are dumped without the backend's write lock
  (the read connection dials its own socket per call), so the minute's reads
  never hold up a ban or a feed write.

- **After a daemon start** the feed lists are empty until the first fetch
  succeeds (a fetch is never skipped then): with cfm-web unreachable, nft keeps
  the old feed and the proxied filter answers nothing from it until the next
  successful fetch. It fails open, as before this existed.

## Modes and the log

`[webdetector] PROXIED_IPFILTER_FEED` (the block feeds) and
`PROXIED_IPFILTER_LOCAL` (the node's own block sets): `log` (default), `enforce`
(the decision answers `ip_action=block`, header `X-CFM-Proxied-IPFilter: 1`),
`off`. An unknown value is `log`.

One line per client and outcome every 10 minutes, in `cfm.log`, with how many
decisions it stands for (totals and each source's size: `GET
/api/v1/webdet/edge-ban` → `proxied_ipfilter`, also in `cfm debug`):

```
[proxied_ipfilter] would_block ip=20.43.87.186 host=olicatessen.gr block=feed:MYBLOCK allow=- mode=feed:log,local:log n=37 cc=US asn=8075 asn_name=MICROSOFT-CORP-MSN-AS-BLOCK
[proxied_ipfilter] allowed ip=… host=… block=block_v4 allow=allow_dyn_v4 mode=… n=1 cc=GR asn=6799 asn_name=OTEnet_S.A.
[proxied_ipfilter] block ip=… host=… block=block_v4,feed:MYBLOCK allow=- mode=feed:enforce,local:log n=4 cc=- asn=- asn_name=-
```

`block=` names every block source the address is on (overlaps show), `allow=`
every allow that cancelled it. `cc=` / `asn=` / `asn_name=` come from the
node's GeoIP database (an mmdb read when the line is written, no DNS; `-`
when it does not know, spaces in the name as `_`). They are what the review
reads: a `cc=GR` would_block is the likely customer, and a foreign one on a
network that serves real users (Google, Microsoft, Meta, a CDN) needs a look
before enforce, unlike a scanner's hosting provider.

## Next

1. A week of `log` fleet-wide: how many clients and requests per source, and
   whether any `would_block` is a customer (a Greek address on `block_v4` from
   an SSH or mail ban is the likely false positive; `cc=GR`), or a network
   that serves real users (`asn=`). The first read (2026-11-17) found Meta's
   forward proxies (`fwdproxy-*.fbsv.net`, AS32934) permanently on mars' and
   titan's `block_v4` since May, from the SYN / port-flood detectors.
2. `enforce` per group, feed first.
3. Promote on hit: a client the bridge blocks from these lists also goes to the
   edge ban store (bounded quota, e.g. 5 k of its 20 k, the feed entry's
   expiry), so the edge's own copy covers the static location and cached URLs
   within ~5 s. The fleet unblock path then has to `edgeban.Unban` it too.
