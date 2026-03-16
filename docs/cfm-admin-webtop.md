# CFM Admin (WebTop MVP)

This document describes the shipped starter UI under `/usr/share/cfm/html/` and
how to expose it via OpenResty using `/cfm-admin/`.

The UI is now split into pages:

- `/cfm-admin/` — lightweight landing/status placeholder + module menu
- `/cfm-admin/webdetector/` — WebDetector overview (live)
- `/cfm-admin/webdetector/vhost/` — WebDetector vhost-focused live view
  - vhost page accepts `?host=example.com` for direct live focus
- `/cfm-admin/webdetector/forensics/` — WebDetector investigation view (history/IP/analyze)

## What gets installed

- Static UI files: `/usr/share/cfm/html/`
- Vue app: `index.html` + `assets/app.js` + `assets/style.css`
- Data source: CFM API on `127.0.0.1:6060`

The UI currently focuses on **WebTop**:

- `/api/v1/webdet/top-short`
- `/api/v1/webdet/suspicious`
- `/api/v1/webdet/drilldown?host=...`

It also includes placeholders for MySQL, Challenge, and System panels.

The WebTop table now also shows lightweight runtime flags per host:

- `suspicious` (from `/api/v1/webdet/suspicious`)
- `challenged` (from `/api/v1/challenge/vhosts?status=active&mode=all`)

And provides actions directly in the UI:

- **Live** a vhost (opens `/cfm-admin/webdetector/vhost/?host=<vhost>` in new tab)
- **Challenge / Unchallenge** a vhost (calls `/api/v1/challenge/vhost/add|remove`)
- **Block 1h** for top drilldown IPs (calls `/api/v1/firewall/block`)


The drilldown panel now renders structured cards/tables (key metrics, top IPs,
paths, user-agents) and keeps raw JSON under a collapsible **Raw JSON** section
for debugging.

Top-right controls include:

- The UI avoids per-host `/challenge/vhost/status` fan-out polling; challenge state is
  derived from active-vhosts list endpoint to reduce API/worker load.

- **Refresh now** (manual refresh)
- **Stop / Start** (pause/resume 5s polling)
- **Logout** (best-effort only due to HTTP Basic Auth browser behavior)

> Basic Auth logout is browser-dependent; some browsers keep credentials until
> tab/window close. The UI logout button attempts a best-effort credential reset.


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
- `https://YOUR-HOST/cfm-admin/webdetector/`

> The config now also redirects `/cfm-admin/webdetector` (no trailing slash) to
> `/cfm-admin/webdetector/` and serves nested subpages (e.g. `/vhost/`,
> `/forensics/`) via `try_files $uri $uri/index.html /index.html` so directory
> URLs resolve directly to their nested `index.html`.

## Notes

- Keep the CFM debug API local/trusted only.
- This starter uses polling every 5s for live WebTop updates.

## API debug command reference

For copy/paste `curl` examples against local API (`127.0.0.1:6060`) and `/cfm-admin/api` proxy paths, see:

- `docs/webui-api-curl-recipes.md`
- `docs/webui-api-sample-responses.md` (redacted success + error payloads)
