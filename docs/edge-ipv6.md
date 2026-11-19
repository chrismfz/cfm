# Edge IPv6 listen

The web DNAT redirect is `table inet` (`internal/firewall/nft/dnat.go`), so it
catches IPv6 as well as IPv4: an IPv6 visitor to a node's address on 80/443 is
redirected to the edge's 9080/9043. The reference edge confs listen on
`listen 9080;` / `listen 9043 ssl;` / `listen 9043 quic`, which is IPv4 only.
Without an IPv6 listen that connection is refused: a browser falls back to
IPv4 (Happy Eyeballs), an IPv6-only client fails.

The listen cannot simply be `listen [::]:9043` in the reference conf: on a host
without an IPv6 stack (`ipv6.disable=1`) it fails the config test and the edge
does not start. So the IPv6 listens live in two generated files, and a script
decides on each host whether they exist.

## How it works

| Piece | What it does |
|---|---|
| `configs/openresty.conf`, `configs/angie.conf` | each listener `server{}` includes `cfm-listen-v6-http.con[f]` / `cfm-listen-v6-https.con[f]` from the engine's conf dir (`/usr/local/openresty/nginx/conf`, `/etc/angie`). The glob makes an **absent file mean IPv4 only**, not a failed config test. |
| `scripts/cfm-edge-listen-v6.sh` | decides, writes or removes the two files (`listen [::]:9080;` and `listen [::]:9043 ssl;` + `quic reuseport`), runs the engine's own config test after a change and removes them again if it fails. Always exits 0. Never reloads the edge: a change applies at its next start or reload. |
| `cfm-edge-listen-v6.service` (`configs/`, installed to `/etc/systemd/system/`) | oneshot running the script (`prestart`) before every edge start. |
| drop-in `openresty.service.d/cfm-listen-v6.conf`, `angie.service.d/cfm-listen-v6.conf` | `Wants=` + `After=` that unit, so it runs **before** the edge unit's own `ExecStartPre` config test (a drop-in `ExecStartPre` would run after it, too late). `Wants=`, not `Requires=`: the edge starts if the unit fails. |
| `package-proxy-config-deploy.sh` (`deploy_edge_listen_v6`) | on every package install/upgrade: installs the unit and drop-ins, then runs the script (`render`) after the new edge configs are deployed. The installers (`install-openresty.sh`, `install-angie.sh`) run it too. |

## The decision

`EDGE_LISTEN_V6` in `/etc/cfm/cfm.conf` (absent = `off`; anything that is not
`off`/`auto`/`on` reads as `off`):

| Mode | Listens on IPv6 when |
|---|---|
| `off` (default) | never. The default until the IPv6 origin hop has been verified on a real IPv6 node (`docs/ROADMAP.md` §9c): if that hop failed, an IPv6 visitor would get a 502 instead of today's refused connection, and a 502 does not make a browser fall back to IPv4. |
| `auto` | all of: the kernel has an IPv6 stack (`/proc/net/if_inet6`); nothing but the edge holds an IPv6 listener on tcp 9080 / 9043 or udp 9043 (`nginx -t` does not bind, so a taken port would pass the test and then fail the edge's start, IPv4 included); the origin listens on IPv6 on both 80 and 443 (`ss`: `[::]`, a specific IPv6 address, or a dual-stack `*`; not `::1`, not v4-mapped), because an IPv6 visitor's hop goes to the IPv6 address it came to; and `cfm realip` says the origin trusts the edge's IPv6 hop from `::1`. It is asked **before** the files are written (no reload can catch the edge on IPv6 with an untrusting origin): `EDGE_LISTEN_V6 = auto` / `on` alone makes it require `::1`, and its JSON must carry `"edge_ipv6":true` (an older `cfm` gives no verdict). |
| `on` | the kernel and port checks only; an origin or `::1`-trust gap is logged as a warning. |

In every mode the files are removed when the engine's live main config does
not include them (an older main config, a refused package deploy): there they
listen nowhere and would only make `cfm realip` demand a `::1` trust.

`render` (deploy, by hand) makes the full decision. `prestart` (before every
edge start) makes the same one, except that "`ss` ran and showed no IPv6
origin listener" never removes files already there: at boot the edge can start
before Apache/LiteSpeed. Every other reason removes them: `off`, no IPv6 stack,
a taken port, `ss` failing, no `::1` trust (or no `cfm` to ask), no engine
binary to test with, a failed config test. An origin that stopped listening
on IPv6 for good keeps the edge's IPv6 until the next `render` (a package
upgrade, or by hand).

```bash
sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh status
```

prints each engine's decision and whether the files are present. Removing the
`cfm` package (not upgrading it) removes the unit, the drop-ins and the files.

## What changes for an IPv6 visitor

- The origin hop binds `::1` (`$cfm_pass_bind` / `$cfm_origin_bind` in the
  confs) and goes to the bracketed IPv6 destination. **The origin must trust
  `::1` as well as 127.0.0.1**, or every IPv6 visitor reaches it as `::1`:
  localhost to `Require local`, to apps that trust localhost, and one bucket
  for every login limiter. `auto` refuses to listen without it; `cfm realip`
  requires both once `EDGE_LISTEN_V6` is `auto` / `on` (or the files are
  present), and `cfm realip fix` then writes both, also on an origin whose
  127.0.0.1 trust comes from a file CFM did not write (Imunify's
  `i360.remoteip.conf`, a hand-written one): set the mode, run
  `cfm realip fix`, then render
  for Apache and nginx ([origin-real-ip.md](origin-real-ip.md)); LiteSpeed
  needs `::1T` by hand.
- The hop goes to the IPv6 address the visitor dialled, so the origin
  answers with whatever vhost it binds there. On cPanel a vhost includes the
  IPv6 address only when the account has IPv6 assigned (which is also when
  its AAAA record points at the node); a site without it gets the default
  vhost over IPv6, exactly as it did without CFM (speedhost, 2026-11-19:
  every vhost on the IPv4 address, `defaultwebpage.cgi` over IPv6).
- The panel ports (2083/2087/2096 …) stay IPv4 only: cpsrvd does not listen
  on IPv6 on the fleet, and opening the panel to IPv6 is a separate decision.
- Per-IP counters and bans see each IPv6 address on its own. That was already
  true for visitors behind Cloudflare, which reach the edge with their own
  IPv6 address; aggregation by /64 is open (`docs/ROADMAP.md`).

## Verify on a node

Set `EDGE_LISTEN_V6 = auto` (or `on`) in `/etc/cfm/cfm.conf`, then:

```bash
cfm realip fix          # with EDGE_LISTEN_V6 set, it writes the ::1 trust too
sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh render
systemctl reload openresty   # or angie
```

and check:

```bash
sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh status
ss -ltn | grep -E ':(9080|9043)\b'
curl -6 -sv https://<a site on the node>/ -o /dev/null
cfm realip
```
