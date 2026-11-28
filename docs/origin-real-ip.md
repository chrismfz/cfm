# Origin real IP — the origin sees the visitor, not the edge

The CFM edge (Angie / OpenResty) proxies every web request to the origin web
server (Apache, LiteSpeed or nginx) from **127.0.0.1**. It names the client in
three headers, set to its own `$remote_addr` on every origin location:
`X-Real-IP`, `X-Forwarded-For` (the client appended last) and
`CF-Connecting-IP`.

Unless the origin trusts the loopback to name the client, its access logs and
PHP's `$_SERVER['REMOTE_ADDR']` read 127.0.0.1 for every visitor. Rate limits
and IP rules in the apps break too (WordPress plugins, fail2ban on app logs).

On most of the fleet Imunify360's `/etc/apache2/conf.d/i360.remoteip.conf`
carried the Apache trust, so CFM never needed one of its own. qualityweb
(2026-10-29) is a cPanel node without Imunify360. It had only cPanel's
`includes/cloudflare.conf`, which trusts Cloudflare's ranges only, so every site
logged 127.0.0.1. A customer reported it. The check and the fix below exist
because of that.

## Check

| Where | What |
|---|---|
| `cfm edge realip` (also `cfm realip`, which scripts call) | One-line verdict; `--json` for the probe. Exit 1 = an edge is in front and the origin logs 127.0.0.1. |
| `cfm health` | The `Origin real-IP` line under the edge diagnostics. |
| `edge_health` (MCP / `/api/v1/system/edge-health`) | Check G, `origin-real-ip`; a `warn` reaches `whats_wrong`. |

The verdict is **trusted** when the origin trusts 127.0.0.1 (or
`127.0.0.1/32`, `127.0.0.0/8`) *and* the client header in effect is one of the
edge's three. `::1` alone does not count: the edge proxies from 127.0.0.1. When the edge listens on IPv6, or may and can (`EDGE_LISTEN_V6` allows it, a global IPv6 address and the origin on IPv6 on 80 and 443: [edge-ipv6.md](edge-ipv6.md)), an IPv6 visitor's hop comes from `::1`, so the same trust must hold for `::1` too, and the verdict is trusted only when both do (`edge_ipv6` / `edge_ipv6_listening` in `--json`; a gap reads "the edge does not listen on IPv6", or "logs ::1 for every IPv6 visitor" once it listens). The `cfm edge realip fix` files trust both; LiteSpeed needs `::1T` as well. It is **n/a (OK)** when no edge engine runs: then the origin faces
the internet itself (avgerinos, a DirectAdmin nginx).

It reads configuration only (`internal/originrealip`), the way the server loads
it: from the main config (`/etc/apache2/conf/httpd.conf` on cPanel,
`/etc/apache2/apache2.conf` on Debian, `/etc/httpd/conf/httpd.conf` on EL and
DirectAdmin, `/etc/nginx/nginx.conf`) along its `Include` / `IncludeOptional` /
`include` chain. A file the server never loads does not count. Neither does a
setting inside one `<VirtualHost>` or `server{}`: it covers that site only, so
it is reported ("override the server-level ones for those sites") and the
verdict rests on the server-level settings. nginx is the exception: it is
read per `server{}` (below), because a block's own `set_real_ip_from` list
replaces the http-level one.

The origin is the process listening on **:80**, the port the edge proxies to
(`ss -ltnp`). That is right even when Apache and nginx both run (DirectAdmin
nginx_apache, cPanel ea-nginx), and when DirectAdmin or NGM keep a leftover
`/etc/httpd` (avgerinos, ngm.myip.gr) or a host keeps a leftover
`/usr/local/lsws`. When the listener cannot be read, systemd unit state and
then the installed directories decide.

What counts, per stack:

- **Apache:** `RemoteIPInternalProxy` / `RemoteIPTrustedProxy` listing the
  loopback, plus the **last** server-level `RemoteIPHeader` (Apache keeps the
  last one) naming one of the edge's headers. mod_remoteip reads no header
  without `RemoteIPHeader`, and the loopback alone does nothing. A
  `RemoteIPHeader` the edge does not set (say `X-Client-IP`) is reported, never
  overridden.
- **LiteSpeed:** `useIpInProxyHeader` 1 in `httpd_config.xml`, or 2 ("Trusted
  IP Only") with `127.0.0.1T` in the Access Control allow list (mars). The
  Apache RemoteIP trust it loads (`loadApacheConf`) also counts.
- **OpenLiteSpeed:** no `httpd_config.xml`, a plain-text
  `/usr/local/lsws/conf/httpd_config.conf` and the files it `include`s (on
  DirectAdmin a symlink to `/etc/openlitespeed/httpd_config.conf`, with
  `useIpInProxyHeader` in `httpd-defaults.conf` and the allow list in
  `httpd-accesscontrol.conf`, which CustomBuild writes with Cloudflare's
  ranges: server3, 2026-11-20). The same rule, at server level: every
  `useIpInProxyHeader` 1 or 4 (any peer: Yes, Use Last IP), or 2 / 3 (Trusted
  IP Only, Keep Header from Trusted IP) with `127.0.0.1T` (and `::1T` for an
  IPv6 edge) in every `accessControl` allow list (the values from OLS's own
  WebAdmin) (which one OpenLiteSpeed keeps
  when a setting appears twice is not measured, so all of them must agree). A
  `virtualhost{}` block's own settings do not count, and it loads no Apache
  config.
- **nginx:** per `server{}` block, the way nginx resolves it. A block with its
  own `set_real_ip_from` list uses only that list, and the http-level list only
  when it has none; its own `real_ip_header` likewise beats the http-level one
  (default `X-Real-IP`). Every site block must end up trusting the loopback
  with one of the edge's headers; `proxy_protocol` or any other header is
  reported. Only blocks the edge proxies to count: no `listen` (nginx's
  default, `*:80`) or one on 80 or 443; a status page on `127.0.0.1:8090` or a
  unix socket is noted, not counted. Lines inside `location{}` apply to those
  locations only, so the verdict reads the `server{}` level, and anything
  under `stream{}` is ignored. With no `server{}` found, the http-level
  settings decide. A walk that hits a limit (include depth, files,
  inclusions) says so in the note: the verdict is then partial.
  - **cPanel ea-nginx** includes `conf.d/includes-optional/cloudflare.conf`
    (Cloudflare's ranges, `real_ip_header CF-Connecting-IP`) in every
    `server{}`, so an http-level trust reaches no vhost. The site blocks also
    include `conf.d/server-includes/*.conf`, and a `set_real_ip_from 127.0.0.1`
    there adds to the block's list: Imunify360's
    `imunify360-webshield.conf` does that, and so does the file
    `cfm edge realip fix` writes. earth (2026-11-17) logged real IPs that way while
    the http-level-only reading of this check warned.
  - The cPanel **proxy-subdomain** blocks (every name `cpanel.`, `webmail.`,
    `whm.`, `webdisk.`, `cpcalendars.`, `cpcontacts.`, `autoconfig.`,
    `autodiscover.`) include only `cloudflare.conf`. They proxy to cpsrvd, and
    only ea-nginx's own log reads 127.0.0.1 for them, so they are reported in
    the note and not counted.

## Fix: `cfm edge realip fix`

It writes only where the trust is missing. It checks that the module is loaded
(`apachectl -M` shows `remoteip_module`, on cPanel the
`ea-apache24-mod_remoteip` package; `nginx -V` shows
`--with-http_realip_module`), runs the config test, and reloads gracefully. A
failed config test restores the file byte for byte and reloads nothing. A
second run changes nothing; it writes through a symlink and keeps the file's
owner and mode; a marked block whose markers no longer pair up is refused
rather than guessed at. `--dry-run` prints what it would write. Every command
has a deadline.

| Panel / stack | Written |
|---|---|
| cPanel Apache | `/etc/apache2/conf.d/cfm-remoteip.conf` (cPanel keeps `conf.d` across rebuilds) |
| DirectAdmin Apache | a marked block in `/etc/httpd/conf/extra/httpd-includes.conf` |
| Debian/Ubuntu Apache | `/etc/apache2/conf-enabled/cfm-remoteip.conf` |
| EL Apache | `/etc/httpd/conf.d/cfm-remoteip.conf` |
| cPanel ea-nginx | `/etc/nginx/conf.d/server-includes/cfm-realip.conf` (included by every site `server{}`; cPanel keeps it across rebuilds) |
| DirectAdmin nginx | a marked block in `/etc/nginx/nginx-includes.conf` (loaded inside `http{}`) |
| nginx | `/etc/nginx/conf.d/cfm-realip.conf` (when `nginx.conf` includes `conf.d/*.conf`) |
| nginx, every untrusted block with its own list | nothing: an http-level trust would not reach them; the blocks are named, add `set_real_ip_from 127.0.0.1;` to their lists |
| LiteSpeed | nothing: WebAdmin → Server → General → *Use Client IP in Header* = "Trusted IP Only", add `127.0.0.1T` (and `::1T` when the edge listens on IPv6) to Security → Access Control → Allowed List, restart |
| OpenLiteSpeed | nothing: set the server-level `useIpInProxyHeader 2` and add `127.0.0.1T` (and `::1T`) to the server-level `accessControl` allow list, in the files the probe names, then `/usr/local/lsws/bin/lswsctrl restart` |
| OpenLiteSpeed on DirectAdmin | the server-level allow list file (`/etc/openlitespeed/httpd-accesscontrol.conf` on server3) gets `127.0.0.1T, ::1T` appended to its allow line, and `useIpInProxyHeader 2` is set where it is not 1-4; each edited file is written live AND as its copy in `/usr/local/directadmin/custombuild/custom/openlitespeed/conf/`, the DirectAdmin way: `da build rewrite_confs` rewrites every global file under `/etc/openlitespeed` from CustomBuild's templates except `httpd-includes.conf`, and always uses a custom copy instead (DirectAdmin FAQ, "templating system for nginx/openlitespeed/apache configurations"), so the live file already is what a rebuild installs and no rebuild is run. OpenLiteSpeed has no config test: the fix reloads it gracefully through its systemd unit (`systemctl reload openlitespeed`, DirectAdmin's own path: `ExecReload=kill -USR1 $MAINPID`, and systemd then follows the new master; a USR1 from outside can leave the unit failed with the server running unsupervised), or `lswsctrl restart` where there is no unit, and requires a new master PID (`systemctl show -p MainPID`, else `lswsctrl status`; the old master still running is the config not taken, and a PID it cannot read refuses the fix before anything is written). The edge installers run `cfm realip fix`, so on such a node they reload OpenLiteSpeed too; if not, it restores the files and restarts again, and says if OpenLiteSpeed is then down. A trust held only in a live file (the warning below) is kept by `fix` writing its custom copy, with no restart. A planned fix that the next `rewrite_confs` would undo (another custom copy or template sets it otherwise), or a file changed since the plan, is refused. Several server-level lists or values, a custom copy that differs from the live file, or a file outside `/etc/openlitespeed` leave it to the operator (the manual step names the files). A trust that would not survive a rebuild is reported as trusted with a warning (`warning` in `--json`, a `warn` in edge_health and `cfm health`) |
| NGM | nothing: NGM renders nginx itself, and a hand-written file is overwritten on apply. NGM (2026-11-28 and later) trusts the loopback in its `ngm-realip.conf` while CFM is installed, refreshed daily or by `ngm trusted-proxies refresh`; an older NGM needs an upgrade, then `ngm init --only=nginx-provision` |

The Apache file is

```apache
<IfModule remoteip_module>
    RemoteIPInternalProxy 127.0.0.1
    RemoteIPInternalProxy ::1
    RemoteIPHeader X-Real-IP
</IfModule>
```

and the nginx one is `set_real_ip_from 127.0.0.1; set_real_ip_from ::1;` (with
nginx's default `X-Real-IP`). On cPanel the drop-in loads after
`cloudflare.conf`, so its `X-Real-IP` becomes the header in effect; Cloudflare
visitors are already resolved by the edge. On DirectAdmin the managed block
loads before `httpd-cloudflare.conf`, whose `X-Forwarded-For` stays in effect.

The edge installers (`scripts/install-angie.sh`, `scripts/install-openresty.sh`,
`scripts/install-edge.sh`)
run `cfm realip fix` (= `cfm edge realip fix`; the installers keep the old name, which every cfm has) after deploying the edge conf. It is never fatal: the edge
works either way. `CFM_SKIP_REALIP=1` skips it, and a `cfm` without the command
prints the upgrade hint.

## What the trust lets through

The edge also sends its own TCP peer as `X-CFM-Peer` (`$realip_remote_addr`:
the visitor, or the Cloudflare address of a proxied one) in every web (80/443)
proxy block, replacing any the client sent (`check_edge_peer_header.sh`). The
panel-port listeners (2082-2096, 2222) do not: cPanel and DirectAdmin read no
`X-CFM-Peer`. The headers above
carry the visitor the edge resolved, which a Cloudflare Worker can write; an
origin that keys a security decision on the peer reads `X-CFM-Peer` from a
loopback peer instead (NGM's panel does, for its login limiter and bans).

From outside, nothing: the edge overwrites `X-Real-IP` and `CF-Connecting-IP`
with the real peer and appends it to `X-Forwarded-For`, and a Cloudflare visitor
is resolved by the edge itself (`trusted_proxies.conf`) first.

From the server itself, trusting the loopback means trusting every local
process: a tenant's PHP that connects to the origin directly on 127.0.0.1 can
set the header and pose as any client (to an app's IP rules, `Require ip`, rate
limits). That is inherent in the design, and `i360.remoteip.conf` has the same
exposure. Two choices keep it no wider:

- **Only the loopback is trusted**, never the server's public address (any
  process could reach that too, and the edge never uses it).
- **The fix writes `X-Real-IP`, not `X-Forwarded-For`.** Through the edge, the
  edge sets `X-Real-IP` to its peer, so a local process gets 127.0.0.1 and
  nothing more. With `X-Forwarded-For`, mod_remoteip walks past the trusted
  127.0.0.1 hop the edge appends and takes a forged entry before it. Hosts whose
  existing trust reads `X-Forwarded-For` (Imunify360's file) are left as they
  are.
