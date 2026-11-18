# CFM API curl recipes

`curl` recipes for the `/api/v1/*` endpoints the cfm-admin UI and the CLI
use, with the response shape of the common ones. Useful for local debugging
and for capturing fixtures. Which endpoints a scoped (cPanel) token may call:
[`endpoint_scope_inventory.md`](endpoint_scope_inventory.md).

## Where the API listens

| Entry | URL | Notes |
|---|---|---|
| Plaintext, loopback | `http://127.0.0.1:6060/api/v1/…` | `PORT`; `LISTEN_ADDRESS` defaults to `127.0.0.1` |
| TLS | `https://<server>:6061/api/v1/…` | `TLS_PORT` / `TLS_LISTEN_ADDRESS` |
| Through the edge | `https://<vhost>/cfm-admin/api/v1/…` | what the browser calls; the edge strips `/cfm-admin` and proxies to the daemon |

All three serve the same handlers behind the same auth.

## Auth

Every request needs a token, sent as `Authorization: Bearer <token>`
(`X-CFM-Token: <token>` is also accepted). Without one the API answers
`401 {"error":"authorization required"}`.

- **Admin:** `AUTH_TOKEN`, kept in `/etc/cfm/cfm.api.conf` (which overlays
  `/etc/cfm/cfm.conf`). With `ADMIN_TOKEN_IP_BINDING = enforce` it is accepted
  only from loopback, the server's own IPs, `cfm.allow` / `cfm.dyndns` and the
  `API_URL` host. See [`security/control-plane.md`](security/control-plane.md).
- **Scoped:** a per-tenant viewer token minted by the cPanel plugin. It sees
  and changes only its own vhosts; admin-only endpoints answer `403`.

Endpoints that change state accept only `POST` (anything else gets `405`).

## Setup

```bash
export CFM_API="http://127.0.0.1:6060"
export CFM_TOKEN='…'   # AUTH_TOKEN from /etc/cfm/cfm.api.conf
cfm_api() { curl -sS -H "Authorization: Bearer $CFM_TOKEN" "$@"; }
```

Through the edge, only the base changes:

```bash
export CFM_API="https://YOUR-HOST/cfm-admin"
cfm_api "$CFM_API/api/v1/webdet/top-short" | jq .
```

---

## 1) Web detector (WebTop)

### Busiest vhosts, short window

```bash
cfm_api "$CFM_API/api/v1/webdet/top-short" | jq .
cfm_api "$CFM_API/api/v1/webdet/top-short?limit=20" | jq .
```

```json
{
  "window_sec": 120,
  "long_horizon_sec": 1200,
  "rows": [
    {
      "host": "<vhost-a>",
      "rps": 10.168,
      "rps_2xx": 9.912,
      "rps_3xx": 0.088,
      "rps_4xx": 0.168,
      "rps_5xx": 0,
      "rps_401": 0,
      "rps_403": 0,
      "rps_404": 0.168,
      "rps_499": 0,
      "unique_ips": 105,
      "err_ratio": 0.0165,
      "auth401_ratio": 0,
      "proc_avg_sec": 0.4862,
      "score": 0.414,
      "reasons": ["scanner_like_path_diversity"],
      "bytes_rps": 1530619.944,
      "bot_ratio": 0.1849,
      "ua_diversity": 0.0212,
      "path_diversity": 0.5067,
      "post_ratio": 0.1833,
      "solver_farm": false,
      "shadow_outliers": 0,
      "query_cardinality": 0,
      "cost_pressure": 0,
      "dc_fraction": 0
    }
  ]
}
```

`reasons` can be `null`. `solver_farm`, `shadow_outliers`,
`query_cardinality`, `cost_pressure` and `dc_fraction` are live marks from
other detectors stamped onto the row, not inputs to `score`.

### Suspicious vhosts, long window

Scored rows at or above the web detector's `MIN_SCORE`, top 50. A bare array:

```bash
cfm_api "$CFM_API/api/v1/webdet/suspicious" | jq .
```

```json
[
  {
    "host": "<vhost-c>",
    "score": 0.678,
    "reasons": ["high_error_ratio", "many_bot_user_agents", "scanner_like_path_diversity"],
    "rps": 1.2167,
    "rps_3xx": 0.005,
    "rps_4xx": 0.2667,
    "rps_5xx": 0,
    "unique_ips": 49,
    "err_ratio": 0.2647,
    "auth401_ratio": 0,
    "hot_ips": 1,
    "bot_ratio": 0.5321,
    "path_diversity": 0.7119,
    "ua_diversity": 0.2542,
    "post_ratio": 0.3253,
    "solver_farm": false,
    "shadow_outliers": 0,
    "query_cardinality": 0,
    "cost_pressure": 0,
    "dc_fraction": 0
  }
]
```

### One vhost

`top` sets the length of the top-N lists (default 10, at most 100).

```bash
HOST="example.com"
cfm_api "$CFM_API/api/v1/webdet/drilldown?host=${HOST}&top=25" | jq .
```

```json
{
  "short": {
    "host": "<vhost>",
    "window_sec": 120,
    "total_req": 157,
    "direct_pct": 14.0127,
    "bot_pct": 1.9108,
    "path_diversity": 0.8025,
    "unique_paths": 126,
    "ua_diversity": 0.1274,
    "unique_uas": 20,
    "post_ratio": 0.0955,
    "proc_avg_sec": 0.2038,
    "short_score": 0.319,
    "short_reasons": ["scanner_like_path_diversity"],
    "top_ips": [{ "key": "<ip-1>", "count": 64 }],
    "top_agents": [{ "key": "<agent-1>", "count": 64 }],
    "top_referrers": [{ "key": "<ref-1>", "count": 54 }],
    "top_paths": [{ "key": "/", "count": 9 }],
    "enriched_top_ips": [
      {
        "ip": "<ip-1>",
        "count": "64",
        "country": "Greece",
        "asn": "200736",
        "asn_name": "<asn-name>",
        "ptr": "<ptr>"
      }
    ],
    "median_per_ip_rps": 0.0083,
    "bytes_rps": 613046.03,
    "hot_ips": 0,
    "failure_index": 0.0318,
    "ua_entropy": 0.6652,
    "path_entropy": 0.9594,
    "ip_skew": 13.8599
  },
  "long": { "host": "<vhost>", "score": 0.3788, "reasons": ["scanner_like_path_diversity"], "rps": 1.2608 },
  "state": "normal"
}
```

`long` (a suspicious-vhost row, abbreviated here) is present only when the
long window holds the vhost. `state` is `normal`, `suspicious`, `challenged`
or `under_attack`; `attack_since` is added while the vhost is under attack.
In `enriched_top_ips` every value is a string, and `ptr`, `asn`, `asn_name`
and `country` appear only when known (a PTR not yet cached resolves in the
background and shows on a later call).

### IPs

```bash
cfm_api "$CFM_API/api/v1/webdet/ip-short?limit=30" | jq .
IP="1.2.3.4"
cfm_api "$CFM_API/api/v1/webdet/ip-drilldown?ip=${IP}" | jq .
```

`ip-short`:

```json
{
  "window_sec": 120,
  "long_horizon_sec": 1200,
  "short": [
    {
      "ip": "<ip-1>",
      "req": 458,
      "vhosts": 75,
      "rps": 3.8167,
      "score": 0.7,
      "reasons": ["med_rps", "many_vhosts"],
      "ptr": "<ptr>",
      "asn": "216285",
      "asn_name": "<asn-name>",
      "country": "Greece",
      "proposals": [{ "action": "notify", "reason": "ip_score_elevated", "score": 0.7 }]
    }
  ],
  "long": [
    { "ip": "<ip-2>", "req": 381, "vhosts": 72, "rps": 3.178, "score": 0.7, "reasons": ["med_rps", "many_vhosts"] }
  ]
}
```

On IP rows `reasons`, the enrichment fields, `proposals` and the whole `long`
list are omitted when empty.

### Window metadata

```bash
cfm_api "$CFM_API/api/v1/webdet/summary" | jq .
```

```json
{ "now": "2026-03-16T21:03:08.819216004+02:00", "window_sec": 120, "long_horizon_sec": 1200 }
```

### Offline log scan

Scans the web detector's access log (`LOG_PATH`) for one IP or one vhost.
`max_lines` bounds the scan (default: the whole file); `last=<duration>`
keeps only the trailing window.

```bash
IP="1.2.3.4"
cfm_api "$CFM_API/api/v1/webdet/analyze-ip?ip=${IP}&max_lines=200000" | jq .
HOST="example.com"
cfm_api "$CFM_API/api/v1/webdet/analyze-host?host=${HOST}&last=1h" | jq .
```

### Bot UA drilldown (Web Bots page)

Vhosts hit, source IPs with geo/ASN (and cached PTR), top paths and raw UA
variants for one UA. Admin only.

```bash
cfm_api "$CFM_API/api/v1/webdet/ua-drill?ua=go-http-client" | jq .
```

Each call turns on per-UA IP and path tracking for 10 minutes.
`ip_tracking_active: false` means it was off before this call, so the IP and
path data is still filling in.

---

## 2) Vhost challenge

### List challenged vhosts (admin)

`status` = `active` | `inactive` | `all`, `mode` = `auto` | `manual` |
`all`, `limit` default 200.

```bash
cfm_api "$CFM_API/api/v1/challenge/vhosts?status=active&mode=all&limit=200" | jq .
```

```json
[
  {
    "host": "<vhost-d>",
    "status": "active",
    "mode": "auto",
    "since": "2026-03-16T20:46:38.748725035+02:00",
    "expires_at": "0001-01-01T00:00:00Z",
    "score": 0.6546,
    "on_threshold": 0.68,
    "off_threshold": 0.64,
    "uniq_ip": 227,
    "rps": 1.1125,
    "reasons": ["many_bot_user_agents", "scanner_like_path_diversity"],
    "last_action": "auto_on",
    "last_changed": "2026-03-16T20:46:38.748725035+02:00",
    "solver_farm": false,
    "shadow_outliers": 0,
    "query_cardinality": 0,
    "cost_pressure": 0,
    "dc_fraction": 0,
    "state": "challenged"
  },
  {
    "host": "<vhost-e>",
    "status": "active",
    "mode": "manual",
    "since": "2026-03-16T21:02:11.113401882+02:00",
    "expires_at": "2026-03-17T03:02:11.113401882+02:00",
    "ttl_sec": 21600,
    "rung": "v2",
    "rung_source": "manual",
    "score": 0,
    "on_threshold": 0,
    "off_threshold": 0,
    "uniq_ip": 0,
    "rps": 0,
    "reasons": ["manual"],
    "last_action": "manual_on",
    "last_changed": "2026-03-16T21:02:11.113401882+02:00",
    "solver_farm": false,
    "shadow_outliers": 0,
    "query_cardinality": 0,
    "cost_pressure": 0,
    "dc_fraction": 0,
    "state": "challenged"
  }
]
```

- `expires_at` is the zero time on an auto row.
- `ttl_sec` is the window granted to a **manual** challenge (remaining time is
  `expires_at - now`). It is absent on auto rows, including a row that went
  back to `mode: "auto"` after its manual challenge lapsed. That change does
  not clear `expires_at`, so compute the remaining time only when
  `mode == "manual"`.
- `rung` is `"v2"` when solves are held to ChallengeV2 and absent for v1;
  `rung_source` (`manual` / `pin` / `auto`), `rung_trigger`, `rung_pin` and
  `rung_auto` say where the tier comes from. `lockdown` / `lockdown_until`
  appear while a lockdown holds.

### Status of one vhost

A scoped token may read its own vhosts.

```bash
HOST="example.com"
cfm_api "$CFM_API/api/v1/challenge/vhost/status?host=${HOST}" | jq .
```

```json
{
  "host": "<vhost>",
  "manual_active": true,
  "expires_at": "2026-03-16T21:45:33.123456789+02:00",
  "reason": "manual",
  "rung": "v2",
  "rung_source": "manual",
  "rung_trigger": "",
  "rung_pin": "",
  "rung_auto": "",
  "manual_default_rung": "v2",
  "rung_pin_locked": false,
  "rung_unpin_locked": false,
  "lockdown": false,
  "lockdown_until": null,
  "auto_active": false,
  "auto_since": "0001-01-01T00:00:00Z",
  "solver_farm": false,
  "shadow_outliers": 0,
  "query_cardinality": 0,
  "cost_pressure": 0,
  "dc_fraction": 0,
  "state": "challenged"
}
```

Here `rung` is `""` for v1.

### Arm a manual challenge

Query parameters or a JSON body. `ttl` defaults to 30m (a scoped token is
capped at 24h and the response says `ttl_capped`), `reason` to `manual`.
`rung` = `v1` | `v2`; left out, it keeps the tier of the manual challenge
already covering the host, else the node default (`CHALLENGE_V2_MANUAL`).

```bash
HOST="example.com"
cfm_api -X POST "$CFM_API/api/v1/challenge/vhost/add?host=${HOST}&ttl=30m&reason=manual" | jq .

cfm_api -X POST -H 'Content-Type: application/json' \
  -d "{\"host\":\"${HOST}\",\"ttl\":\"30m\",\"reason\":\"manual\",\"rung\":\"v2\"}" \
  "$CFM_API/api/v1/challenge/vhost/add" | jq .
```

```json
{
  "host": "<vhost>",
  "status": "active",
  "expires_at": "2026-03-16T21:45:33.123456789+02:00",
  "ttl": "30m0s",
  "reason": "manual",
  "rung": "v2",
  "rung_default": true,
  "tier": { "rung": "v2", "source": "manual", "trigger": "" },
  "lockdown": false
}
```

`tier` is the host's effective tier after the call: a manual v1 challenge
never lowers an automatic v2 one.

### Switch an armed manual challenge between v1 and v2

Keeps its expiry and reason. `409` when no manual challenge is active: an
automatic challenge's tier is set with a tier pin (next recipe).

```bash
HOST="example.com"
cfm_api -X POST "$CFM_API/api/v1/challenge/vhost/rung?host=${HOST}&rung=v1" | jq .
```

### Pin an automatic challenge's tier (v1 / v2 / auto)

Automatic vhost challenges run at v2 when their source is in
`CHALLENGE_V2_AUTO_VHOST`. A pin overrides that per vhost: `v1` drops it back,
`v2` forces it, `auto` removes the pin. Optional `ttl` (none = until cleared;
a scoped token's pin is capped at 24h). The pin never creates or clears a
challenge, and a manual challenge outranks it; the response's `tier` is the
effective result.

```bash
HOST="example.com"
cfm_api -X POST "$CFM_API/api/v1/challenge/vhost/tier?host=${HOST}&rung=v1" | jq .
cfm_api -X POST "$CFM_API/api/v1/challenge/vhost/tier?host=${HOST}&rung=auto" | jq .
cfm_api "$CFM_API/api/v1/challenge/vhost/tier" | jq .   # GET: list pins (admin)
```

### Lockdown: no client exemption on a vhost's challenge

Crawlers on the bypass list, verified good bots, Challenge Access-Control
entries and exclude-file matches stop getting through the vhost's challenge.
Default 30m, at most 6h, never longer than the challenge. What still passes:
[`vhost-lockdown.md`](vhost-lockdown.md).

```bash
HOST="example.com"
# Arm a manual challenge with the lockdown at once:
cfm_api -X POST "$CFM_API/api/v1/challenge/vhost/add?host=${HOST}&ttl=1h&lockdown=1&lockdown_ttl=30m" | jq .
# Switch it on an armed vhost (409 without a manual challenge):
cfm_api -X POST "$CFM_API/api/v1/challenge/vhost/lockdown?host=${HOST}&lockdown=1&ttl=30m" | jq .
# Lift it (the challenge stays):
cfm_api -X POST "$CFM_API/api/v1/challenge/vhost/lockdown?host=${HOST}&lockdown=0" | jq .
```

### Remove a manual challenge

```bash
HOST="example.com"
cfm_api -X POST "$CFM_API/api/v1/challenge/vhost/remove?host=${HOST}" | jq .
```

```json
{ "host": "<vhost>", "status": "removed" }
```

---

## 3) Firewall block (admin)

JSON body only. `ttl` is a Go duration; empty = permanent. The ban also goes
to the edge ban store, so it holds for clients behind a trusted proxy.

```bash
IP="1.2.3.4"
cfm_api -X POST -H 'Content-Type: application/json' \
  -d "{\"ip\":\"${IP}\",\"ttl\":\"1h\",\"reason\":\"webui_manual\"}" \
  "$CFM_API/api/v1/firewall/block" | jq .
```

```json
{ "ok": true, "ip": "1.2.3.4", "ttl": "1h", "reason": "webui_manual" }
```

Errors carry `"ok": false` and an `error` (`invalid json`,
`invalid or missing ip`, `invalid ttl`). Several IPs at once:
`POST /api/v1/firewall/block/batch` with `{"ips":[…],"ttl":"…","reason":"…"}`
(at most 256; the server's own IPs and the caller's IP are skipped).

---

## 4) ClamAV (ClamAV / Controls pages)

### Per-vhost scan override

A listed host is flipped relative to the global `CLAM_SCAN_DEFAULT`: opted out
when the default is on (the shipped value), opted in when it is off.
`type=host` only. A scoped token may flip only its own vhosts. Every write is
logged to `cfm.clam.log` (`[clam_override]`).

```bash
cfm_api "$CFM_API/api/v1/clam/override/list" | jq .
cfm_api -X POST "$CFM_API/api/v1/clam/override/add?type=host&value=example.com" | jq .
cfm_api -X POST "$CFM_API/api/v1/clam/override/remove?type=host&value=example.com" | jq .
```

### Per-vhost scan mode (async / inline)

A listed host is flipped relative to the global `CLAM_SCAN_MODE` (shipped:
`async`, so listing a host makes it inline). Inline answers 403 to an infected
upload and fails open. Logged as `[clam_mode]`. See [`clamav.md`](clamav.md).

```bash
cfm_api "$CFM_API/api/v1/clam/mode/list" | jq .
cfm_api -X POST "$CFM_API/api/v1/clam/mode/add?type=host&value=shop.example.com" | jq .
cfm_api -X POST "$CFM_API/api/v1/clam/mode/remove?type=host&value=shop.example.com" | jq .
```

### Signature excludes

A matching infected verdict is only logged (no notification, no quarantine).
No `host` = a global entry (admin only); with `host`, a scoped token may manage
its own vhost. Logged as `[clam_sigignore]`.

```bash
cfm_api "$CFM_API/api/v1/clam/sigignore/list" | jq .
cfm_api -X POST "$CFM_API/api/v1/clam/sigignore/add?pattern=*_Hunting.UNOFFICIAL" | jq .
cfm_api -X POST "$CFM_API/api/v1/clam/sigignore/add?pattern=Doc.Dropper.Agent-*&host=shop.example.com" | jq .
cfm_api -X POST "$CFM_API/api/v1/clam/sigignore/remove?pattern=Doc.Dropper.Agent-*&host=shop.example.com" | jq .
```

### Scanner health and recent infections

`clam/health` (admin only) is the scanner state: breaker, queue, scan scope
and mode, counters, the global scan default. It answers `available: false`
when ClamAV is not running. Recent infections come from the history API.

```bash
cfm_api "$CFM_API/api/v1/clam/health" | jq .
cfm_api "$CFM_API/api/v1/webdet/history/events?type=clam_infected&limit=50&enrich=1" | jq .
```

---

## 5) System (admin)

### Node health

`health.snapshot.v1`: host CPU/RAM/swap, disks, SMART/MDADM/ZFS, services,
DNAT/edge runtime, conntrack, throughput.

```bash
# fresh collection (~1-2 s), what `cfm health` uses
cfm_api "$CFM_API/api/v1/health/snapshot" | jq .
# cached, what the dashboard polls: recollects at most once per cache_ttl
# (clamped to 1s..1m); collected_at gives the real age
cfm_api "$CFM_API/api/v1/health/snapshot?cache_ttl=60s" | jq .
# metric history (in-memory, about 24 h) and the anomaly feed: the Health page
cfm_api "$CFM_API/api/v1/health/timeseries?window=1h&step=1m" | jq .
cfm_api "$CFM_API/api/v1/health/anomalies?since=24h" | jq .
```

`timeseries`: `window` 1m–7d (default 1h), `step` 1s–24h (default 5m), and
`step` may not exceed `window`. `anomalies`: `since` is a duration or an
RFC3339 time (default 24h).

### TLS certificates (dashboard)

```bash
cfm_api "$CFM_API/api/v1/system/ssl/stats" | jq .            # `cfm ssl stats --json`
cfm_api -X POST "$CFM_API/api/v1/system/ssl/refresh" | jq .  # "Rescan certs": `cfm ssl refresh --json`, up to 90 s
```

Both answer `{"ok": true, "duration_ms": …, "stats": …}`, and `ok: false` with
the error and the command output on failure.

---

## 6) Error shapes

Handlers answer JSON with an `error` field and a matching status:

```bash
# 400 {"error":"missing host"}
cfm_api -i "$CFM_API/api/v1/webdet/drilldown"
# 400 {"error":"invalid ttl: banana"}
cfm_api -i -X POST "$CFM_API/api/v1/challenge/vhost/add?host=example.com&ttl=banana"
# 403 {"error":"host not in scope"}: a scoped token naming a vhost it does not own
# 405 {"error":"method not allowed"}: a GET on a POST-only endpoint
```

---

## 7) Capturing fixtures

```bash
mkdir -p tmp/webui-captures
TS="$(date +%Y%m%d-%H%M%S)"
HOST="example.com"

cfm_api "$CFM_API/api/v1/webdet/top-short?limit=50"             > "tmp/webui-captures/${TS}-top-short.json"
cfm_api "$CFM_API/api/v1/webdet/suspicious"                     > "tmp/webui-captures/${TS}-suspicious.json"
cfm_api "$CFM_API/api/v1/webdet/drilldown?host=${HOST}&top=25"  > "tmp/webui-captures/${TS}-drilldown-${HOST}.json"
cfm_api "$CFM_API/api/v1/webdet/ip-short?limit=30"              > "tmp/webui-captures/${TS}-ip-short.json"
cfm_api "$CFM_API/api/v1/challenge/vhosts?status=active&mode=all&limit=200" > "tmp/webui-captures/${TS}-challenge-vhosts.json"
```

Redact hosts and IPs (`<vhost-x>`, `<ip-x>`) before committing, keeping key
names and types. Numbers are floats with varying precision, so tests should
compare selected fields and types, not whole JSON strings.
