# Edge IPv6 listen

The web DNAT redirect is `table inet` (`internal/firewall/nft/dnat.go`), so it
catches IPv6 as well as IPv4: an IPv6 visitor to a node's address on 80/443 is
redirected to the edge's 9080/9043. The reference edge confs listen on
`listen 9080;` / `listen 9043 ssl;` / `listen 9043 quic`, which is IPv4 only.
Without an IPv6 listen that connection is refused (checked from rigel to
speedhost's IPv6 address, 2026-11-19): a browser falls back to IPv4 (Happy
Eyeballs), an IPv6-only client fails.

The listen cannot simply be `listen [::]:9043` in the reference conf: on a host
without an IPv6 stack (`ipv6.disable=1`) it fails the config test and the edge
does not start. So the IPv6 listens live in two generated files, and a script
decides on each host whether they exist.

**Off by default for now.** Per-IP defences (nft bans and rate / connection
limits, waf_security autoblock, webdetector scoring, login bruteforce) key on
the full IPv6 address, so a direct IPv6 client rotating inside its /64 (any
VPS has one) evades them, while an edge without IPv6 refuses it and the
browser falls back to IPv4, where they hold. Behind Cloudflare that never
mattered (Cloudflare absorbs the volume and nft never sees the client).
Until they group IPv6 by /64 (`docs/ROADMAP.md` §9c), a node listens on IPv6
only when `EDGE_LISTEN_V6 = on` in `/etc/cfm/cfm.conf` allows it; then the
default becomes automatic (`V6_DEFAULT` in the script and `edgeIPv6Default`
in `internal/originrealip`, one switch each, pinned equal by
`check_edge_listen_v6.sh`) and the key is no longer needed. Where it is
allowed, the edge listens on IPv6 by itself wherever the host can and the
origin is ready for it.

## How it works

| Piece | What it does |
|---|---|
| `configs/openresty.conf`, `configs/angie.conf` | each listener `server{}` includes `cfm-listen-v6-http.con[f]` / `cfm-listen-v6-https.con[f]` from the engine's conf dir (`/usr/local/openresty/nginx/conf`, `/etc/angie`). The glob makes an **absent file mean IPv4 only**, not a failed config test. |
| `scripts/cfm-edge-listen-v6.sh` | decides, writes or removes the two files (`listen [::]:9080;` and `listen [::]:9043 ssl;` + `quic reuseport`), runs the engine's own config test after a change and removes them again if it fails. Always exits 0. A `render` that writes the files reloads a running edge at once and checks (`/proc/net/tcp6`) that it listens on `[::]:9080` and `[::]:9043`; if not, it removes them and reloads back. A `render` that removes files a running edge listens with reloads it too. `prestart` and `deploy` never reload. |
| `cfm-edge-listen-v6.service` (`configs/`, installed to `/etc/systemd/system/`) | oneshot running the script (`prestart`) before every edge start; `TimeoutStartSec=60`. |
| drop-in `openresty.service.d/cfm-listen-v6.conf`, `angie.service.d/cfm-listen-v6.conf` | `Wants=` + `After=` that unit, so it runs **before** the edge unit's own `ExecStartPre` config test (a drop-in `ExecStartPre` would run after it, too late). `Wants=`, not `Requires=`: the edge starts if the unit fails. |
| `package-proxy-config-deploy.sh` (`deploy_edge_listen_v6`) | on every package install/upgrade: installs the unit and drop-ins, then runs the script (`deploy`) after the new edge configs are deployed: it keeps or removes files (prestart's rules) but never writes new ones and never reloads, so an upgrade never turns IPv6 on. It never rewrites a kept file either (a changed body is `render`'s to apply), and when it removes files a running edge listens with it says to reload. The installers (`install-openresty.sh`, `install-angie.sh`) run `render`, after `cfm realip fix`. |

## The decision

The edge listens on IPv6 when **all** of these hold, and stays on IPv4
otherwise (the script logs which one failed):

0. `EDGE_LISTEN_V6` allows it: `on` / `yes` / `true` / `1` / `auto`; `off` /
   `no` / `false` / `0` / `disabled` and any unknown value forbid it; absent,
   the default (off for now). Last uncommented line wins; an inline `;` / `#`
   comment and one pair of matching quotes are stripped. The script and
   `cfm realip` read it the same way: both run
   `scripts/tests/fixtures/edge_listen_v6_mode.txt`;
1. the host has a global IPv6 address (`/proc/net/if_inet6`, scope `00`;
   the stack alone is not enough: earth has it, empty, and no IPv6 visitor
   can reach it);
2. the edge's IPv6 ports (tcp 9080 / 9043, udp 9043) are the edge's own or
   free (`nginx -t` ignores a port in use, so a taken port would pass the test and
   then fail the edge's start, IPv4 included). Read from the uid column of
   `/proc/net/tcp6` / `udp6`, never from `ss`: `ss` prints process names raw,
   so a tenant process can pose as root's nginx. A root listener on
   `[::]:PORT` (udp: a root socket there) is the edge's own, and while it
   holds the port nothing else can bind it (tcp), so the other sockets on it
   are the connections it accepted: those belong to the worker that accepted
   them (`nobody` / `cfm`, not root: speedhost's are uid 969) and do not
   count. On udp a tenant can co-bind with `SO_REUSEADDR`; that cannot stop
   the edge's own bind, so it is ignored there (it counts at a cold start).
   A stopped edge's leftovers (FIN_WAIT, TIME_WAIT) read uid 0.
   With no such listener, a non-root socket on the port counts as taken in
   any state (one that bound the port and connected out holds it too) and on
   every address, `[::1]` included (it fails the edge's `[::]` bind too), and
   the port is then really bound, IPv6-only as nginx does, by
   `cfm realip v6-bindcheck`: a socket that is bound and never listens is not
   in `/proc/net/tcp6` at all. A `cfm` that cannot run the check, and an
   unreadable table, count as taken;
3. the origin listens on IPv6 on both 80 and 443 (`ss`: `[::]`, a specific
   IPv6 address, or a dual-stack `*`; not `::1`, not v4-mapped), because an
   IPv6 visitor's hop goes to the IPv6 address it came to;
4. `cfm realip` says the origin trusts the edge's IPv6 hop from `::1` (below).
   It is asked **before** the files are written, so no reload can catch the
   edge on IPv6 with an untrusting origin, and its JSON must carry
   `"edge_ipv6":true` (an older `cfm` gives no verdict, which counts as no);
5. the engine's live main config includes the files (an older main config or
   a refused package deploy does not, and the files are then removed);
6. the engine's config test passes with them.

`render` (deploy, by hand) makes the full decision. `prestart` (before every
edge start) makes the same one, except that files a `render` already approved
are **kept** when only readiness is missing, which at boot is common: no
global IPv6 address yet (SLAAC, the network still coming up), the origin not
seen on IPv6 yet (it can start after the edge), `cfm realip` giving no
verdict. Otherwise a reboot would silently put the edge back on IPv4. The
reasons that would break the start, or that the operator chose, always remove
them: `EDGE_LISTEN_V6` not allowing it, no IPv6 stack at all, a taken port,
`ss` failing, a main config without the include, a failed config test, and a
definite "the origin does not trust `::1`" from `cfm realip` (every IPv6
visitor would be localhost to the origin). An origin that stops listening on
IPv6 for good keeps the edge's IPv6 until the next `render` (by hand). The
package deploy (`deploy`) applies the same keep / remove rules, and never
writes files that are not there.

```bash
sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh status
```

prints each engine's decision and why, and whether the files are present.
Removing the `cfm` package (not upgrading it) removes the unit, the drop-ins
and the files.

**Turning it on and off on a node:** uncomment `EDGE_LISTEN_V6 = on` in
`/etc/cfm/cfm.conf` (run `cfm realip fix` first), or set `off`; then run the
script with `render`. When it writes the files it reloads a running edge and
checks (`/proc/net/tcp6`) that it listens on IPv6, else removes them and
reloads back: a failed reload leaves nginx on its old config, never down.
When it removes files a running edge listens with, it reloads it too. A
restart re-decides as well (`prestart`), but a plain `systemctl reload` does
not. A package upgrade (`deploy`) never turns IPv6 on.

**Limits.** A hand-written `listen [::]` with `ipv6only=off` is not
supported: IPv4 visitors then arrive as `::ffff:a.b.c.d`, and the origin hop
(bracketed, bound to `::1`) cannot reach that. A downgrade to a cfm without
this script leaves the unit, the drop-ins and the files behind (the unit's
`-` and the drop-in's `Wants=` keep the edge starting); remove them by hand
or run `render` with `EDGE_LISTEN_V6 = off` before downgrading.

## The origin's `::1` trust

The origin hop of an IPv6 visitor binds `::1` (`$cfm_pass_bind` /
`$cfm_origin_bind` in the confs) and goes to the bracketed IPv6 destination.
**The origin must trust `::1` as well as 127.0.0.1**, or every IPv6 visitor
reaches it as `::1`: localhost to `Require local` (cPanel's server-status), to
apps that trust localhost, and one bucket for every login limiter. So:

- `cfm realip` requires both as soon as the host **can** do IPv6 (kernel IPv6
  + the origin on a global IPv6 address on 80 and 443, read from
  `/proc/net/tcp6`) and `EDGE_LISTEN_V6` allows IPv6, before the edge listens,
  and whenever the edge does listen on IPv6: the files exist, or the kernel
  shows a root listener on a global IPv6 address on 9080 / 9043 (a
  `listen [::]` added by hand). Until
  then it warns "the edge does not listen on IPv6 (run: cfm realip fix, then
  then run the script with render)"; once the edge listens, a gap reads "logs ::1 for every
  IPv6 visitor".
- `cfm realip fix` then writes the `::1` trust for Apache and nginx, also on
  an origin whose 127.0.0.1 trust comes from a file CFM did not write
  (Imunify's `i360.remoteip.conf`, a hand-written one). The script never runs
  `fix` itself (it edits and reloads the origin), and `fix` does not render:
  run the script with `render` after it.
- LiteSpeed: `fix` only prints the step, `::1T` in its Access Control allow
  list (the `::1T` spelling is the analogue of `127.0.0.1T` and has not been
  tried on a real LiteSpeed yet). On rigel and titan the Apache RemoteIP trust
  LiteSpeed loads already covers `::1` (verified on rigel, below).

## What changes for an IPv6 visitor

- **A behaviour change for a domain with an AAAA record whose vhost is not
  bound to that IPv6 address** (a customer's own AAAA at an external DNS, an
  account without IPv6 in cPanel): until now its IPv6 visitors were refused at
  the edge and the browser fell back to IPv4, so the right site loaded; now
  the edge answers on IPv6 and the origin serves its default vhost (cPanel's
  `defaultwebpage.cgi`), with no fallback. Fix the record or give the account
  IPv6; `EDGE_LISTEN_V6 = off` is the node-wide way back.
- The hop goes to the IPv6 address the visitor dialled, so the origin
  answers with whatever vhost it binds there. On cPanel a vhost includes the
  IPv6 address only when the account has IPv6 assigned (which is also when
  its AAAA record points at the node); a site without it gets the default
  vhost over IPv6, exactly as it did without CFM (speedhost and qualityweb,
  2026-11-19: every vhost on the IPv4 address, `defaultwebpage.cgi` over
  IPv6).
- The panel ports (2083/2087/2096 …) stay IPv4 only: cpsrvd does not listen
  on IPv6 on the fleet, and opening the panel to IPv6 is a separate decision.
- Per-IP counters and bans see each IPv6 address on its own. That was already
  true for visitors behind Cloudflare, which reach the edge with their own
  IPv6 address; aggregation by /64 is in progress (below).

## IPv6 /64 grouping

An IPv6 client is its /64: any VPS or ISP line hands its customer one, and a
client rotating its address inside it would get a fresh identity per address.
So per-client counters, rate limits and bans key on the /64 (an IPv4 client
on its address), always the whole /64 for a ban, with no per-node switch.

- **One key, two twins:** `internal/ipkey` (Go) and `configs/lua/cfm_ipkey.lua`
  (edge), pinned by the shared `scripts/tests/fixtures/ipkey.txt` (plus a
  Go↔Lua differential fuzz, 50k addresses, no difference). The key is the
  prefix text (`2001:db8:1:2::/64`); a v4-mapped address is IPv4. Left as
  they are: loopback, link-local (a /64 there is the whole link), anything in
  `::/64` (it holds `::1`, the origin hop's source), multicast,
  `64:ff9b::/64` (it holds NAT64's `/96`, each address an IPv4 client), the
  local-use NAT64 `64:ff9b:1::/48`, Teredo `2001::/32` (a /64 there is a
  Teredo server, shared by its clients), zoned and unparsable addresses.
  Only a key holding `/` is a /64; an ungrouped address comes back as given
  (callers key canonical text). Known limits: an operator-chosen NAT64 /96
  outside those ranges cannot be told apart; a 6to4 (`2002::/16`) or any
  /48 / /56 customer can still rotate across its /64s; a ULA (`fc00::/7`) or
  site-local /64 is grouped (the node's own is guarded).
- **Never on an allow or an exact match** (an allow widened to a /64 allows a
  whole customer prefix), nor on a clearance cookie or a log line.
- **nft:** a masked key (`ip6 saddr and ffff:ffff:ffff:ffff::`) in a dynamic
  set, a `limit` meter and a `ct count` works on the fleet's kernels: two
  addresses of one /64 make one element and share one limit (2026-11-19, in
  a throwaway netns on earth, 4.18, and rigel, 5.14).
- **Bans (done):** every automatic L7 ban of an IPv6 client takes its /64
  (`firewall.ExtendClientBlock` / `BlockClientPermanent`): the detector
  sinks, the challenge server and the admin API's login autoblock, TTL and
  permanent. These see a real session (an HTTP request, a login). The
  kernel flood / port-scan autoblock counts packets whose source can be
  spoofed, so it stays per address: a /64 there would let a forged prefix
  ban someone else's (a crawler's, the node's own). Manual bans stay exactly
  what the operator typed.
  - **Own set:** `block_v6_clients` (interval, timeout), with its drops
    right after `block_v6_nets'` in both engines' EnsureBase. In
    `block_v6_nets` an automatic /64 made the operator's own IPv6 CIDRs fail
    (nft refuses overlapping elements: `cfm block <v6 /48>`, and a
    `cfm.deny` /48 after a reboot). On a chain from an older version the two
    drops are added right after their `block_v6_nets` anchors (`add rule …
    position <handle>`, `firewall.BaseRuleAnchors`), never at the top above
    the self / allow accepts (live test `LiveNFTClientSlash64`).
  - **Never shortened:** only ever added or extended; an extend replaces the
    element in one transaction (`firewall.SetElemWriter`: one `nft -f` run
    on exec, one netlink batch on nftlib; a failed transaction keeps the old
    element, checked on earth's 4.18).
  - **Guards:** the address is banned instead when the /64 holds this node's
    own address (its interfaces and `self_v6`: a provider handing one /64 to
    several customers' VPSes) or a default-route gateway (`/proc/net/ipv6_route`:
    dropping the router's neighbour discovery would cut the node off), an ignored address or network (`ignore_v6`,
    `ignore_v6_nets`, `IGNORE_IPS` / `IGNORE_NETS`), or a trusted proxy's
    range (`trusted_proxies.conf`, loaded before the TTL restore: a
    detector that saw a proxy's own address must not ban the proxy's /64),
    since nft accepts none of those before its drops; an allowed address or
    network (the manual allow sets, read per ban, and the fleet whitelist
    from the edge ban store's last read): nft would still accept it, but the
    edge never answers a /64 an allow touches and the restore drops one, so
    the address is banned for all three alike; and when nft cannot read or
    write the set. A live ban reads these guards at most once per 10 s
    (`guardCacheTTL`; an allow or ignore added in that window is seen by the
    next read, and the edge's own check is per answer). The TTL ban restore at boot checks the same sources
    (`ttlban.Store.ExcludeNet`, read from the files before the daemon loads
    them) and counts a refused /64 excluded. `cfm flush` empties the set
    like the other block sets.
  - **Edge:** the edge ban store keys it as the /64 and answers every
    address of it, except where an allow, a trusted proxy range or an
    `IGNORE_IPS` entry touches any of it. An allow added after a /64 ban:
    the edge stops answering the /64 at its next reconcile, while nft keeps
    the ban to its TTL (it accepts the allowed address before its drops
    anyway); `cfm unblock` frees the rest at once.
  - **Restart, unblock:** TTL /64 bans survive a restart (`internal/ttlban`;
    a permanent one, like a detector's permanent host ban, is not
    persisted). The restore writes the /64s in batches (one transaction per
    500, `firewall.ExtendBlockNets`, one guard and set read for all; a
    refused batch falls back one at a time): one at a time, 1000 /64s took
    33.6 s on the exec engine, past the edge ban reconcile's 30 s wait, and
    that reconcile then dropped them from the edge. Unblocking any address of
    the /64, or the /64 itself (`cfm unblock 2001:db8:1:2::/64`, the API
    alike), frees the /64 (nft, the edge, `ttlbans.json`, `cfm unblock` with
    the daemon down too). The alert says "Banned as: <the /64>".
  - **Downgrade:** a cfm from before this leaves `block_v6_clients` and its
    drops in place (nothing removes them), but its `cfm unblock` and
    `cfm flush` do not touch the set: free a /64 there with
    `nft delete element inet cfm block_v6_clients '{ <the /64> }'`, or flush
    it, or let its TTL run out.
- **Counters (detectors, admin API: done):** a detector's sliding window,
  ladder or solve count keys an IPv6 client on its /64 (`core.ClientKey`,
  `firewall.CountKey`): the log detectors (ssh, ftp, dovecot, mysql, cPanel,
  Proxmox, ngm, custom, exim, postfix, ModSecurity), waf_security,
  `cfm_endpoints`, cookie discard, login_bruteforce; the admin API's login
  autoblock, login and password-change throttle, embed bootstrap limit and
  probe signals; the MCP consent limit.
  - **Only where the ban would take the /64:** `firewall.CountKey` asks the
    bans' own guards (the daemon's backend, `SetCountBackend`). The answer
    is cached 10 s per /64 (a newly registered check applies at once); the
    guard view behind it is refreshed in the background and every read runs
    outside its lock, so a counter does not wait on nft (or on a ban's read)
    while the reads succeed (after a failed one, or when the set list
    changes, the next read is synchronous); a failed read is answered for 5 s and logged once
    a minute (a /64 first seen meanwhile counts per address for up to 10 s
    more). A guarded /64 (this node, its gateway, an ignored, allowed or
    trusted proxy address, or nft cannot tell) counts per address, as its
    ban does: counted as one client, one address's alert would spend the
    /64's and leave the other addresses unbanned, or name an ignored
    neighbour while the attacker went free (found by the review). Not
    foreseen: a ban that falls back to the address because nft failed to
    write the /64 (transient); the /64's count is then spent on one address
    until the detector's cooldown (waf_security: a Window after the alert,
    even while its addresses keep hitting; a /64 still hitting after its
    ban, behind a proxy with `EDGE_BAN_MODE = log`, logs an alert a Window
    without a second ban or notification).
  - **Only the count:** the alert keeps a real address, the /64's busiest
    now (`core.TopAddr`: each hit weighs 1 and decays by e per detector
    window, a tie goes to the address hitting now; bounded, 8 addresses per
    key and 10000 keys per detector, ~10 MB; `Extra["client"]` is the /64):
    it is what the fleet report, the leniency and exclude checks and the
    notification name, so neither a neighbour's last hit nor an address that
    trickled hits for hours or stopped a while ago takes the blame. `firewall.ExtendClientBlock`
    widens it to the /64 itself. Allow lists (`ALLOW_IPS`, …) stay exact
    matches.
  - **A detector's own allows:** an `ALLOW_IPS` / `ALLOW_NETS` entry
    narrower than a /64 in waf_security, cfm_endpoints, cookie discard or
    login_bruteforce guards its /64 (`core.GuardAllows`, rebuilt with the
    sections): that /64 is counted and banned per address by every section
    and is not answered as a /64 at the edge, as a /64 holding an
    nft-allowed address is, so its neighbours' hits never ban the allowed
    address. A /64 or wider entry allows its /64s in that detector already
    and guards nothing (it would switch the grouping off for every /64 it
    covers).
  - **Like IPv4 behind NAT:** every device of a home or office /64 adds to
    one count, as every device behind one IPv4 address already does.
  - **Section cooldown:** stamped on what the ban took (the /64, or the
    address when a guard kept the /64), so another address of a banned /64
    is not banned again while an address banned alone does not shield its
    neighbours. The sink's challenge cooldown stays per address (the edge
    challenges the address).
  - **The notification** says "Banned as: <the /64>" (the sink passes
    `block_net` on).
  - `TestDetectorWindowKeysGroupIPv6Clients` fails a detector window keyed
    on the raw address.
- **Still per address:**
  - the kernel nft meters (`pps_v6`, `syn_v6`, `new_v6`, `icmp6`, port flood,
    connlimit `ct count`): they count packets whose source can be spoofed,
    and a /64 meter would let a forged prefix throttle someone else's whole
    /64 (decided 2026-11-19; revisit only if the burn-in shows rotation
    there);
  - webdetector scoring and the challenge server (next), the edge's shared
    dicts, then `EDGE_LISTEN_V6` defaults to on (`docs/ROADMAP.md` §9c).

## Verified

On 2026-11-19, a scratch edge instance beside the live one (its own ports,
removed after), with the exact maps and Lua of the confs:

| Node | Engine | Result |
|---|---|---|
| speedhost (CloudLinux 9, Apache) | OpenResty 1.31.8.1 | direct URL, keepalive balancer `set_current_peer("[v6]")`, static literal line and plain HTTP: 200 from Apache at `[v6]:443` / `:80`, bound to `::1`. The old server-level `proxy_bind 127.0.0.1`: `bind(127.0.0.1) failed (22: Invalid argument)`. |
| qualityweb (AlmaLinux 10, Apache) | Angie 1.12.4 | the same, the same results. |
| rigel (LiteSpeed, `useIpInProxyHeader` 2 with only `127.0.0.1T`, Apache RemoteIP trusting `::1`) | (curl from `::1`) | LiteSpeed took the client from `X-Forwarded-For` for a `::1` peer (`[::1]:49796 ... >192.0.2.66` in its error_log): the Apache RemoteIP trust it loads covers `::1`, as `cfm realip` reads it. |

Not yet seen: an external IPv6 client through the DNAT into the live edge with
the files rendered (the first node where the script turns IPv6 on).

## Verify on a node

```bash
sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh status
ss -ltnp | grep -E ':(9080|9043)\b'
curl -6 -sv https://<a site with an AAAA record to the node>/ -o /dev/null
cfm realip
```
