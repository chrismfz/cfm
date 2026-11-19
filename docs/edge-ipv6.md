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
decides on each host whether they exist. **There is no setting to turn it on:**
the edge listens on IPv6 by itself wherever the host can and the origin is
ready for it.

## How it works

| Piece | What it does |
|---|---|
| `configs/openresty.conf`, `configs/angie.conf` | each listener `server{}` includes `cfm-listen-v6-http.con[f]` / `cfm-listen-v6-https.con[f]` from the engine's conf dir (`/usr/local/openresty/nginx/conf`, `/etc/angie`). The glob makes an **absent file mean IPv4 only**, not a failed config test. |
| `scripts/cfm-edge-listen-v6.sh` | decides, writes or removes the two files (`listen [::]:9080;` and `listen [::]:9043 ssl;` + `quic reuseport`), runs the engine's own config test after a change and removes them again if it fails. Always exits 0. Never reloads the edge: a change applies at its next start or reload. |
| `cfm-edge-listen-v6.service` (`configs/`, installed to `/etc/systemd/system/`) | oneshot running the script (`prestart`) before every edge start; `TimeoutStartSec=60`. |
| drop-in `openresty.service.d/cfm-listen-v6.conf`, `angie.service.d/cfm-listen-v6.conf` | `Wants=` + `After=` that unit, so it runs **before** the edge unit's own `ExecStartPre` config test (a drop-in `ExecStartPre` would run after it, too late). `Wants=`, not `Requires=`: the edge starts if the unit fails. |
| `package-proxy-config-deploy.sh` (`deploy_edge_listen_v6`) | on every package install/upgrade: installs the unit and drop-ins, then runs the script (`render`) after the new edge configs are deployed. The installers (`install-openresty.sh`, `install-angie.sh`) run it too, after `cfm realip fix`. |

## The decision

The edge listens on IPv6 when **all** of these hold, and stays on IPv4
otherwise (the script logs which one failed):

1. the host has a global IPv6 address (`/proc/net/if_inet6`, scope `00`;
   the stack alone is not enough: earth has it, empty, and no IPv6 visitor
   can reach it);
2. nothing but the edge holds an IPv6 listener on tcp 9080 / 9043 or udp 9043
   (`nginx -t` does not bind, so a taken port would pass the test and then
   fail the edge's start, IPv4 included); an unknown owner counts as taken;
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
seen on IPv6 yet (it can start after the edge), `cfm realip` unable to confirm
the `::1` trust (it reads the origin before it runs). Otherwise a reboot would
silently put the edge back on IPv4. The reasons that would break the start, or
that the operator chose, always remove them: the kill switch, no IPv6 stack at
all, a taken port, `ss` failing, a main config without the include, a failed
config test. A change on the origin side for good (trust removed, no more
IPv6) keeps the edge's IPv6 until the next `render` (a package upgrade, or by
hand); `cfm realip` warns meanwhile.

```bash
sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh status
```

prints each engine's decision and why, and whether the files are present.
Removing the `cfm` package (not upgrading it) removes the unit, the drop-ins
and the files.

**Kill switch, for an emergency only:** `EDGE_LISTEN_V6 = off` in
`/etc/cfm/cfm.conf` (also `no` / `false` / `0` / `disabled`; the last such line
wins) keeps every edge on IPv4. It is commented out in the reference
`cfm.conf`. After setting it, **restart** the edge (a restart re-decides; a
plain reload keeps the files), or run the script with `render` and reload.

## The origin's `::1` trust

The origin hop of an IPv6 visitor binds `::1` (`$cfm_pass_bind` /
`$cfm_origin_bind` in the confs) and goes to the bracketed IPv6 destination.
**The origin must trust `::1` as well as 127.0.0.1**, or every IPv6 visitor
reaches it as `::1`: localhost to `Require local` (cPanel's server-status), to
apps that trust localhost, and one bucket for every login limiter. So:

- `cfm realip` requires both as soon as the host **can** do IPv6 (kernel IPv6
  + the origin on a global IPv6 address on 80 and 443, read from
  `/proc/net/tcp6`; not with the kill switch), before the edge listens. Until
  then it warns "the edge does not listen on IPv6 (run: cfm realip fix, then
  restart the edge)"; once the edge listens, a gap reads "logs ::1 for every
  IPv6 visitor".
- `cfm realip fix` then writes the `::1` trust for Apache and nginx, also on
  an origin whose 127.0.0.1 trust comes from a file CFM did not write
  (Imunify's `i360.remoteip.conf`, a hand-written one). The script never runs
  `fix` itself (it edits and reloads the origin), and `fix` does not render:
  restart the edge after it (or run the script with `render` and reload).
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
  IPv6; the kill switch is the node-wide way back.
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
  IPv6 address; aggregation by /64 is open (`docs/ROADMAP.md` §9c).

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
