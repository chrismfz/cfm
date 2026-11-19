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
  `64:ff9b::/64` (it holds NAT64's `/96`, each address an IPv4 client), zoned and unparsable
  addresses. Known limits: a Teredo client shares its server's /64; a 6to4
  (`2002::/16`) or any /48 / /56 customer can still rotate across its /64s.
- **Never on an allow or an exact match** (an allow widened to a /64 allows a
  whole customer prefix), nor on a clearance cookie or a log line.
- **nft:** a masked key (`ip6 saddr and ffff:ffff:ffff:ffff::`) in a dynamic
  set, a `limit` meter and a `ct count` works on the fleet's kernels: two
  addresses of one /64 make one element and share one limit (2026-11-19, in
  a throwaway netns on earth, 4.18, and rigel, 5.14). `block_v6_nets`
  (interval, timeout) already holds a /64 ban.
- **Status:** the key exists; the controls move to it one area at a time
  (bans, counters, the edge's shared dicts), then `EDGE_LISTEN_V6` defaults
  to on (`docs/ROADMAP.md` §9c).

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
