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
| `cfm realip` | One-line verdict; `--json` for the probe. Exit 1 = an edge is in front and the origin logs 127.0.0.1. |
| `cfm health` | The `Origin real-IP` line under the edge diagnostics. |
| `edge_health` (MCP / `/api/v1/system/edge-health`) | Check G, `origin-real-ip`; a `warn` reaches `whats_wrong`. |

The verdict is **trusted** when the origin trusts 127.0.0.1 (or `::1`,
`127.0.0.1/32`, `127.0.0.0/8`) *and* the client header in effect is one of the
edge's three. It is **n/a (OK)** when no edge engine runs: then the origin faces
the internet itself (avgerinos, a DirectAdmin nginx).

It reads configuration only (`internal/originrealip`), the way the server loads
it: from the main config (`/etc/apache2/conf/httpd.conf` on cPanel,
`/etc/apache2/apache2.conf` on Debian, `/etc/httpd/conf/httpd.conf` on EL and
DirectAdmin, `/etc/nginx/nginx.conf`) along its `Include` / `IncludeOptional` /
`include` chain. A file the server never loads does not count. Neither does a
setting inside one `<VirtualHost>` or `server{}`: it covers that site only, so
it is reported ("override the server-level ones for those sites") and the
verdict rests on the server-level settings. A `server{}` with its own
`set_real_ip_from` list replaces the http-level list for that site, which is
worth knowing after a fix.

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
- **nginx:** an http-level `set_real_ip_from` listing the loopback. The default
  `real_ip_header` (`X-Real-IP`) or any of the edge's headers is fine;
  `proxy_protocol` or any other header is reported. `stream{}` is ignored.

## Fix: `cfm realip fix`

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
| DirectAdmin nginx | a marked block in `/etc/nginx/nginx-includes.conf` (loaded inside `http{}`) |
| nginx | `/etc/nginx/conf.d/cfm-realip.conf` (when `nginx.conf` includes `conf.d/*.conf`) |
| LiteSpeed | nothing: WebAdmin → Server → General → *Use Client IP in Header* = "Trusted IP Only", add `127.0.0.1T` to Security → Access Control → Allowed List, restart |
| NGM | nothing: NGM renders nginx itself, and a hand-written file is overwritten on apply. The trust has to come from NGM's templates (NGM `docs/cfm-integration-map.md`, "real_ip gap") |

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

The edge installers (`scripts/install-angie.sh`, `scripts/install-openresty.sh`)
run `cfm realip fix` after deploying the edge conf. It is never fatal: the edge
works either way. `CFM_SKIP_REALIP=1` skips it, and a `cfm` without the command
prints the upgrade hint.

## What the trust lets through

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
