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

The verdict is **trusted** when the origin trusts 127.0.0.1 (or `::1`, `/32`,
`127.0.0.0/8`) *and* reads one of the edge's three headers. It is **n/a (OK)**
when no edge engine runs: then the origin faces the internet itself (avgerinos,
a DirectAdmin nginx). It reads configuration only (`internal/originrealip`). The origin is the
service that runs (`systemctl is-active` lsws / httpd / apache2 / nginx), not
whatever is installed: DirectAdmin and NGM hosts running nginx keep a leftover
`/etc/httpd` (avgerinos, ngm.myip.gr). An installed LiteSpeed still wins, as
before (it is often misreported as nginx).

What counts, per stack:

- **Apache:** `RemoteIPInternalProxy` / `RemoteIPTrustedProxy` with the loopback,
  plus a `RemoteIPHeader` naming one of the edge's headers. mod_remoteip reads
  no header without `RemoteIPHeader`, and the loopback alone does nothing. A
  `RemoteIPHeader` the edge does not set (say `X-Client-IP`) is reported, never
  overridden.
- **LiteSpeed:** `useIpInProxyHeader` 1 in `httpd_config.xml`, or 2 ("Trusted
  IP Only") with `127.0.0.1T` in the Access Control allow list (mars). The
  Apache RemoteIP trust it loads (`loadApacheConf`) also counts.
- **nginx:** `set_real_ip_from` with the loopback. The default `real_ip_header`
  (`X-Real-IP`) or any of the edge's headers is fine; `proxy_protocol` or any
  other header is reported.

Files read: Apache `conf.d/*.conf`, `conf.d/includes/*.conf`, the main
`httpd.conf` / `apache2.conf`, `conf-enabled/`, `/etc/httpd/conf.d/`,
DirectAdmin's `conf/extra/*.conf`; nginx `nginx.conf`, `/etc/nginx/*.conf`
(DirectAdmin's http-level includes), `conf.d/`, `sites-enabled/`, NGM's
`conf/sites/`.

## Fix: `cfm realip fix`

It writes only where the trust is missing, checks that the module is loaded
(`apachectl -M` shows `remoteip_module`; `nginx -V` shows
`--with-http_realip_module`), runs the config test, and reloads gracefully. A
failed config test restores the file byte for byte and reloads nothing. A
second run changes nothing. `--dry-run` prints what it would write.

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
    RemoteIPHeader X-Forwarded-For    # only when no RemoteIPHeader is set anywhere
</IfModule>
```

and the nginx one is `set_real_ip_from 127.0.0.1; set_real_ip_from ::1;`. When
the origin already reads an edge header (cPanel's `cloudflare.conf` sets
`RemoteIPHeader CF-Connecting-IP`), the fix adds the loopback trust only: the
edge sets that header too.

The edge installers (`scripts/install-angie.sh`, `scripts/install-openresty.sh`)
run `cfm realip fix` after deploying the edge conf. It is never fatal: the edge
works either way. `CFM_SKIP_REALIP=1` skips it, and a `cfm` without the command
prints the upgrade hint.

## Why only the loopback

The edge always connects from 127.0.0.1. Trusting the server's public address
as well would let any process on the server set the header and pose as any
client: a tenant's PHP calling its own site, for instance. From outside the
header cannot be spoofed: the edge overwrites `X-Real-IP` and
`CF-Connecting-IP`, and appends the real peer to `X-Forwarded-For`, which
mod_remoteip and nginx read from the right. A Cloudflare visitor is resolved
by the edge itself (`trusted_proxies.conf`) before it reaches the origin.
