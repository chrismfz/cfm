# Proxied-client IP filter (`internal/proxyipfilter`)

Gives a client behind a trusted proxy (Cloudflare) the verdict CFM's nft IP
filter would give it if it came direct. Default modes: the node's own block
sets (`LOCAL`) and the fleet BLOCK feeds (`FEED`) are both **enforced** since
2026-11-26.

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
  the edge copy of `edgeban`), URLs a client warmed with a clean allow in
  the 90 s (`decision_cache_ttl_ms`) before it was listed, and a client
  holding a valid clearance cookie (cfm.lua Step 2b returns before the
  decision). The challenge page (`/__cfm_challenge`, reached directly) and
  its verify do not ask this filter, so a listed client can still solve a
  challenge and then pass on the cookie.
- **Its refusals never escalate.** The edge logs them as `cfm_block`, and the
  web detector's 403 counters (403_flood, 40x_combo, the per-IP 4xx challenge
  counters) skip a 403 `cfm_block` for a client this filter enforces on
  (`isProxiedIPFilterBlock403`, inside `skip403`). Counted, a shared mobile /
  CGNAT address on the fleet list could reach 150 refusals in minutes and
  become this node's own nft + edge ban, which clearing the entry in cfm-web does not
  lift.
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
the group's default: `enforce` for both (since 2026-11-26). An
unknown value is `log` and logged as such. A source in an `off` group is not
consulted.

**Why LOCAL is enforced by default.** A week of `log` on eight nodes
(2026-11-18 to 11-24) found only scanners on the local sets: Censys, the
45.138.12.0/24 panel scanner, Techoff, an Iranian address. No customer, and no
network that serves real users, once Meta's forward proxies were cleared and
the flood / portscan autoblock was taught to spare forward-confirmed good bots.
A few hundred lines per node a week. **Why FEED is enforced too (2026-11-26).** A day of log on seven nodes:
~22 700 decisions for ~14 400 addresses, >98% of them MYBLOCK, mostly US /
BD / UA / BR datacenter and residential proxies. Four Greek residential
addresses: three 1h greylist entries (GR leniency, gone within the hour) and
one permanent modsec ban on a Vodafone address since July. That is the risk:
the fleet list holds permanent bans on shared mobile / CGNAT addresses (a
Cosmote `cgn.athe.cosmote.net` one, a Vodafone one), and enforced, each
refuses every customer behind it on a proxied site. Clear them in cfm-web;
`PROXIED_IPFILTER_FEED = log` is the per-node way back.

## CHALLENGE feeds (`LIST_CHALLENGE`)

A `cfm.blocklists` line with type `CHALLENGE` (`TOR|CHALLENGE|3600|0|https://check.torproject.org/torbulkexitlist`)
is a list whose members include people, where a block is too much. It is
**never written to nft** (the manager does not apply it, the nft prune drops a
feed's old block sets when its type turns to CHALLENGE, and `cfm firewall
status` expects no set for it). The daemon keeps it here, next to the block
feeds, and the bridge's decision asks it (`DecideChallenge`) for **every**
web-scope request, direct or behind a trusted proxy: the decision's `ip` is the
visitor's address either way.

In enforce it is a challenge **floor**, the geo policy's, at the same place in
`handleDecision`: only an uncleared client meets it (a cleared one returns at
`cfm.lua` Step 2b), a real per-IP entry overrides it, a solve (okState) clears
it, and the machine-to-machine carve-out (payment webhooks, WooCommerce REST),
the verified good-bot and Challenge Access exemptions lift it. Every allow
source (MYALLOW, cfm.allow, dyndns) cancels it. A solve it caused carries
`src=list`. Panel scope (`cfm_panel.lua`) is never challenged by it, and mail
ports never see it.

`[webdetector] LIST_CHALLENGE` = `enforce` (default since 2026-11-28) | `log` |
`off`. A day of log on eight nodes (TOR, CINS, blocklist.de) found no Greek or
Cypriot address on the lists (orion: 651 listed addresses), while Tor exits
registered bot accounts on clients.nixpal.com past the log-only list.
blocklist.de was then removed (2026-11-28): it lists Meta's link-preview
proxies, and in enforce ~3% of `facebookexternalhit` requests got the
challenge, the first request of an IPv6 fwdproxy before the good-bot check
could verify it. A list that names verified crawlers' or preview fetchers'
addresses is not a CHALLENGE candidate. In log
mode the decision's allow carries `rule_action=observe` (not cached), and one
line per client and outcome every 10 minutes goes to `cfm.log`:

```
[list_challenge] would_challenge ip=185.220.101.1 host=example.gr list=feed:TOR allow=- mode=log n=12 cc=DE asn=… asn_name=…
```

(`challenge` in enforce, `allowed` when an allow cancelled it). Stats, in the
same `proxied_ipfilter` block: `mode_challenge`, `challenge_listed`,
`would_challenge`, `challenged`, `challenge_allow`.

Measured before it was built (2026-11-26, the edge access logs of 8 nodes,
3.5–18.5 h each): ~4 700 requests from 1 260 Tor exits, <= 0.13% of any node's
traffic, 22% of them through Cloudflare, ~85% answered 200 by the origin; 62%
the quoted-UA form-spam tool (rule 202), the rest contact forms, `wp-login` /
`xmlrpc`, shop newsletters, WHMCS sign-ups, and a few plain GETs on news sites
(readers).

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
`block_v4`), then FEED the same day (106 permanent / long bans on Greek and
Cypriot ISP addresses were unblocked in cfm-web that day; detectors no longer
ban GR/CY permanently).

Not built: **promote on hit**. A client the bridge blocks from these lists
would also go to the edge ban store (a bounded quota of its 20 k, with the feed
entry's expiry), so the edge's own copy covers the static locations and cached
URLs within ~5 s; the fleet unblock path would then have to `edgeban.Unban` it
too.
