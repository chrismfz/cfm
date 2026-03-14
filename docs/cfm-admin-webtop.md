# CFM Admin (WebTop MVP)

This document describes the shipped starter UI under `/usr/share/cfm/html/` and
how to expose it via OpenResty using `/cfm-admin/`.

## What gets installed

- Static UI files: `/usr/share/cfm/html/`
- Vue app: `index.html` + `assets/app.js` + `assets/style.css`
- Data source: CFM API on `127.0.0.1:6060`

The UI currently focuses on **WebTop**:

- `/api/v1/webdet/top-short`
- `/api/v1/webdet/suspicious`
- `/api/v1/webdet/drilldown?host=...`

It also includes placeholders for MySQL, Challenge, and System panels.

## OpenResty locations

`configs/openresty.conf` and `configs/openresty-cache.conf` include:

- `location ^~ /cfm-admin/` (serves static files)
- `location ^~ /cfm-admin/api/` (proxies to `127.0.0.1:6060`)
- `auth_basic` on both locations using `/etc/cfm/cfm-admin.htpasswd`

## Create credentials

Install `htpasswd` (apache2-utils/httpd-tools), then run:

```bash
htpasswd -c /etc/cfm/cfm-admin.htpasswd admin
chmod 640 /etc/cfm/cfm-admin.htpasswd
chown root:root /etc/cfm/cfm-admin.htpasswd
```

Then test and reload OpenResty:

```bash
openresty -t
systemctl reload openresty
```

### Alternative: generate with CFM CLI

CFM now includes a helper to print one htpasswd line for copy/paste:

```bash
cfm htpasswd admin
# or non-interactive:
cfm htpasswd admin 'strong-password-here'
```

Append the printed line into `/etc/cfm/cfm-admin.htpasswd`.

The helper emits Apache-compatible `{SHA}` hashes.

> Package installs now create `/etc/cfm/cfm-admin.htpasswd` as an empty
> conffile so OpenResty does not fail on missing file.

## Access

- `https://YOUR-HOST/cfm-admin/`

## Notes

- Keep the CFM debug API local/trusted only.
- This starter uses polling every 5s for live WebTop updates.
