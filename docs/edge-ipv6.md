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

`EDGE_LISTEN_V6` in `/etc/cfm/cfm.conf` (absent = `auto`; anything that is not
`off`/`auto`/`on` reads as `off`):

| Mode | Listens on IPv6 when |
|---|---|
| `auto` (default) | the kernel has an IPv6 stack (`/proc/net/if_inet6` exists) **and** the origin listens on IPv6 on both 80 and 443 (`ss -ltn`: `[::]`, a specific IPv6 address, or a dual-stack `*`; not `::1`, not v4-mapped). The origin hop of an IPv6 visitor goes to the IPv6 address it came to, so an origin that does not listen there would 502 it. |
| `on` | the kernel has an IPv6 stack (origin not checked) |
| `off` | never |

`render` (deploy, by hand) makes the full decision. `prestart` (before every
edge start) makes the same one, except that "the origin was not seen on IPv6"
never removes files already there: at boot the edge can start before
Apache/LiteSpeed. The safety reasons (`off`, no IPv6 stack, a failed config
test) always remove them. Anything unknown (no `ss`, no engine binary to test
with) leaves the edge on IPv4.

```bash
sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh status
```

prints each engine's decision and whether the files are present.

## What changes for an IPv6 visitor

- The origin hop binds `::1` (`$cfm_pass_bind` / `$cfm_origin_bind` in the
  confs) and goes to the bracketed IPv6 destination. **The origin must trust
  `::1` as well as 127.0.0.1** to log the visitor: `cfm realip` requires both
  once the files are present, and `cfm realip fix` writes both
  ([origin-real-ip.md](origin-real-ip.md)); LiteSpeed needs `::1T` by hand.
- The panel ports (2083/2087/2096 …) stay IPv4 only: cpsrvd does not listen
  on IPv6 on the fleet, and opening the panel to IPv6 is a separate decision.
- Per-IP counters and bans see each IPv6 address on its own. That was already
  true for visitors behind Cloudflare, which reach the edge with their own
  IPv6 address; aggregation by /64 is open (`docs/ROADMAP.md`).

## Verify on a node

```bash
sh /usr/share/cfm/scripts/cfm-edge-listen-v6.sh status
ss -ltn | grep -E ':(9080|9043)\b'
curl -6 -sv https://<a site on the node>/ -o /dev/null
cfm realip
```
