# Proxied-client IP filter (`internal/proxyipfilter`)

Gives a client behind a trusted proxy (Cloudflare) the verdict CFM's nft IP
filter would give it if it came direct. Default modes: the node's own block
sets (`LOCAL`) are **enforced** since 2026-11-26; the fleet feeds (`FEED`) are
`log` (nothing is blocked).

## Why

nft drops by source address, and a visitor behind a trusted proxy reaches the
node from the proxy's address. So none of CFM's IP lists applied to that
visitor: not the fleet blacklist (cfm-web's `MYBLOCK` feed, ~268 k addresses;
an opt-in line in `/etc/cfm/cfm.blocklists`, which the stock file ships
commented out and cfm-web does not provision),
not the node's own bans (`block_v4`: `cfm.deny`, detector TTL bans), not the
allows. On earth (2026-11-17) addresses other nodes had fleet-banned for WAF
hits reached the origin through Cloudflare with 200 / 301 / 404.

The edge ban store (`internal/edgeban`) covers only the node's web-related
bans and on purpose holds no fleet feed: the edge keeps a Lua copy of it,
capped by its dict (`lua_shared_dict cfm_edgeban 64m`: ~83 k entries, which
the edge reports to the daemon), and 268 k there is the regression ruled out. So these lists live in the daemon, never in Lua.

## How

- **Lists in the daemon's memory.** Each source is a table: IPv4 hosts as a
  sorted `[]uint32` (the fleet list is ~1 MB), networks and ranges as merged
  `[lo,hi]` pairs, IPv6 the same way. A lookup is a binary search with no
  allocation; a refresh builds a new snapshot and swaps an atomic pointer.
- **Feeds.** `blocklists.Manager` hands over every successfully applied feed,
  BLOCK and ALLOW (built outside its lock, published under it only while the
  feed is still configured, so a fetch that finishes after a Reload removed the
  feed does not bring it back; a removed feed is dropped). A feed's per-element
  TTL (`|TTL=`) is not applied: in nft it times only the per-feed set, while
  the base rules drop on the union sets, which carry none. A feed holds until
  its next apply, there as here.
- **Local sets.** The node's own sets of `inet cfm input`. The small ones are
  read from the kernel every minute (`StartLocalRefresh` with the backend's
  `ListSetElementsRaw`, started in `cmd/cfm`): `block_v4/v6_nets`,
  `allow_v4/v6`, `allow_v4/v6_nets`, `allow_dyn_v4/v6`. The ban sets
  (`block_v4/v6`, `block_v6_clients`: every automatic ban, `cfm.deny`, the TTL
  bans) are not read here: the edge ban reconcile hands over the read it makes
  every two minutes anyway (`SetLocalBans`), with each element's time left,
  and every minute's refresh drops the bans that ended since. With 50 000 bans
  a dump of `block_v4` every minute was a steady share of the daemon's CPU
  (2026-11-24). A new ban reaches this filter within two minutes (a web ban
  reaches the edge ban store, checked first, at once); an ended one leaves it
  within a minute, as before. A set that cannot be read keeps what it had (the
  error is logged when it changes); a failed reconcile read leaves the ban
  sets as they were, still dropping what ends. Not read: `self_*`, `ignore_*`, `ps_pairs_*`, `th_*`,
  `throttled_*` (no address verdict). On nftlib the dump runs on the read
  connection without the backend's write lock, so these reads never hold up a
  ban or a feed write.
- **The verdict follows `inet cfm input`:** every allow set accepts before any
  block set drops, so an allow only cancels a block. It does not exempt the
  request from the WAF or a challenge, exactly as an nft allow does not for a
  direct client.
- **Unblocks apply at once.** `edgeban.Unban`, which every unblock and allow
  path of an address calls, also clears the address from every block source
  (`Forget`) for two reads of the ban sets (4 min), by when the sets read show the
  kernel's own view. A network the daemon applies from `cfm.allow` (where a
  permanent `cfm allow 203.0.113.0/24` lands) is cleared the same way; a timed
  network allow is seen at the next minute's read. A ban the address earns
  again inside those 4 minutes reaches this filter when the override ends;
  nft's own drop of a direct client is immediate.
- **Where.** The nginx bridge's decision (`writeEdgeBan`, `nginx_bridge.go`),
  for a web-scope request that came through a trusted proxy (`px=1`), after
  the static bypass (IGNORE_IPS / IGNORE_NETS) and the edge ban store. No new
  round trip: the edge asks the bridge for every request it has no cached
  clean allow for, and a `block` is never cached. In log mode the allow for a
  listed client that no allow cancels carries `rule_action=observe`, which
  the edge does not cache and treats as an allow (cfm.lua acts on block /
  challenge / throttle only), so every request is decided and counted, as
  enforce would see them. An address an allow cancels gets a plain, cacheable
  allow.
- **Not covered:** the static-asset locations (css/js/images, which check only
  the edge copy of `edgeban`), and URLs a client warmed with a clean allow in
  the 90 s (`decision_cache_ttl_ms`) before it was listed.
- **After a daemon start** the feed lists are empty until each feed's first
  successful apply (the first fetch is never skipped as unchanged): with
  cfm-web unreachable, nft keeps the old feed and this filter answers nothing
  from it until a fetch succeeds. It fails open.

## Modes

`[webdetector]` in `detectors.conf`, applied without a restart:

- `PROXIED_IPFILTER_FEED` — the block feeds;
- `PROXIED_IPFILTER_LOCAL` — the node's own block sets.

Each is `log`, `enforce` (the decision answers `ip_action=block` with header
`X-CFM-Proxied-IPFilter: 1`), or `off` (`0` also means off). An empty value is
the group's default: `FEED` `log`, `LOCAL` `enforce` (since 2026-11-26). An
unknown value is `log` and logged as such. A source in an `off` group is not
consulted.

**Why LOCAL is enforced by default.** A week of `log` on eight nodes
(2026-11-18 to 11-24) found only scanners on the local sets: Censys, the
45.138.12.0/24 panel scanner, Techoff, an Iranian address. No customer, and no
network that serves real users, once Meta's forward proxies were cleared and
the flood / portscan autoblock was taught to spare forward-confirmed good bots.
A few hundred lines per node a week. **Why FEED is not (yet).** The fleet list
holds permanent bans on shared mobile / CGNAT addresses (a Cosmote
`cgn.athe.cosmote.net` address, a Vodafone one): enforced, they would refuse
every customer behind them. Enforce it once those bans expire on their own.

## Log and stats

One line per client and outcome every 10 minutes in `cfm.log`, `n=` saying how
many decisions it stands for:

```
[proxied_ipfilter] would_block ip=20.43.87.186 host=olicatessen.gr block=feed:MYBLOCK allow=- mode=feed:log,local:enforce n=37 cc=US asn=8075 asn_name=MICROSOFT-CORP-MSN-AS-BLOCK
[proxied_ipfilter] allowed ip=… host=… block=block_v4 allow=allow_dyn_v4 mode=… n=1 cc=GR asn=6799 asn_name=OTEnet_S.A.
[proxied_ipfilter] block ip=… host=… block=block_v4 allow=- mode=feed:log,local:enforce n=4 cc=- asn=- asn_name=-
```

`block=` names every block source the address is on, `allow=` every allow
that cancelled it. `cc=` / `asn=` / `asn_name=` come from the node's GeoIP
database (an mmdb read when the line is written, no DNS; `-` when unknown,
whitespace in the name as `_`). They are what the review reads: a `cc=GR`
would_block is the likely customer (a Greek address on `block_v4` from an SSH
or mail ban), and a foreign one on a network that serves real users (Google,
Microsoft, Meta, a CDN) needs a look before enforce, unlike a scanner's hosting
provider.

Stats: `GET /api/v1/webdet/edge-ban` → `proxied_ipfilter` (also in the
`cfm debug` bundle's `edge-ban.json`): `mode_feed`, `mode_local`, `checks`,
`would_block`, `blocked`, `allowed`, `forgotten`, `geo` (false: no enricher,
every geo field reads `-`) and `sources` (each source's `entries` and
`unparsed`).

## Rollout and open items

The burn-in reads and the order of `enforce` are tracked in
`docs/imunify360-gap-analysis.md` ("Order"): LOCAL first (2026-11-26, once
Meta's forward proxies, `fwdproxy-*.fbsv.net` / AS32934, were off every node's
`block_v4`), FEED after the fleet list's permanent bans on shared mobile /
CGNAT addresses are gone.

Not built: **promote on hit**. A client the bridge blocks from these lists
would also go to the edge ban store (a bounded quota of its 20 k, with the feed
entry's expiry), so the edge's own copy covers the static locations and cached
URLs within ~5 s; the fleet unblock path would then have to `edgeban.Unban` it
too.
