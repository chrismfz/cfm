# WebUI API curl recipes (local debug)

This quick reference is for the CFM WebUI/API when the API listens on `127.0.0.1:6060`.

It is intended to make local debugging and test fixture collection easier.

## Base URL

```bash
export CFM_API="http://127.0.0.1:6060"
```

Optional helper for pretty JSON:

```bash
alias j='jq -C .'
```

---

## 0) Sample JSON payloads (for WebUI development)

If you want representative response shapes before running commands, see:

- `docs/webui-api-sample-responses.md` (redacted real-world examples)

---

## 1) WebTop endpoints used by the UI

### Top short window

```bash
curl -sS "$CFM_API/api/v1/webdet/top-short" | jq .
curl -sS "$CFM_API/api/v1/webdet/top-short?limit=20" | jq .
```

### Suspicious hosts

```bash
curl -sS "$CFM_API/api/v1/webdet/suspicious" | jq .
```

### Drilldown for one host

```bash
HOST="example.com"
curl -sS "$CFM_API/api/v1/webdet/drilldown?host=${HOST}" | jq .
curl -sS "$CFM_API/api/v1/webdet/drilldown?host=${HOST}&top=25" | jq .
```

### IP short + IP drilldown

```bash
curl -sS "$CFM_API/api/v1/webdet/ip-short?limit=30" | jq .
IP="1.2.3.4"
curl -sS "$CFM_API/api/v1/webdet/ip-drilldown?ip=${IP}" | jq .
```

### API summary (window metadata)

```bash
curl -sS "$CFM_API/api/v1/webdet/summary" | jq .
```

---

## 2) Challenge controls used by WebUI actions

### List active challenged vhosts

```bash
curl -sS "$CFM_API/api/v1/challenge/vhosts?status=active&mode=all&limit=200" | jq .
```

### Manual challenge ON (query params)

```bash
HOST="example.com"
curl -sS -X POST \
  "$CFM_API/api/v1/challenge/vhost/add?host=${HOST}&ttl=30m&reason=manual" | jq .
```

### Manual challenge ON (JSON body)

```bash
HOST="example.com"
curl -sS -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"host\":\"${HOST}\",\"ttl\":\"30m\",\"reason\":\"manual\"}" \
  "$CFM_API/api/v1/challenge/vhost/add" | jq .
```

### Manual challenge OFF

```bash
HOST="example.com"
curl -sS -X POST "$CFM_API/api/v1/challenge/vhost/remove?host=${HOST}" | jq .
```

### Check challenge status for one host

```bash
HOST="example.com"
curl -sS "$CFM_API/api/v1/challenge/vhost/status?host=${HOST}" | jq .
```

---

## 3) Firewall block action (used by WebUI top-IP action)

```bash
IP="1.2.3.4"
curl -sS -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"ip\":\"${IP}\",\"ttl\":\"1h\",\"reason\":\"webui_manual\"}" \
  "$CFM_API/api/v1/firewall/block" | jq .
```

---

## 2a) ClamAV per-vhost scan override + scanner health (ClamAV / Controls pages)

The override set FLIPS a host relative to the global `CLAM_SCAN_DEFAULT`
(opt-out when the default is ON — the shipped default — opt-in when OFF).
Host type only. Scoped tokens may flip only hosts inside their vhost scope;
every write is audit-logged to `cfm.clam.log` (`[clam_override]` lines).

```bash
# list current overrides (scope-filtered for scoped tokens)
curl -sS "$CFM_API/api/v1/clam/override/list" | jq .

# opt a vhost out of scanning (with default ON) / in (with default OFF)
curl -sS -X POST "$CFM_API/api/v1/clam/override/add?type=host&value=example.com" | jq .

# undo the flip
curl -sS -X POST "$CFM_API/api/v1/clam/override/remove?type=host&value=example.com" | jq .
```

Per-signature excludes ("sig-ignore"): a matching infected verdict is
downgraded to log-only (no email, no quarantine). `host` empty = GLOBAL entry
(admin-only); with `host`, scoped tokens may manage their own vhost. Audit
trail in `cfm.clam.log` (`[clam_sigignore]` lines).

```bash
curl -sS "$CFM_API/api/v1/clam/sigignore/list" | jq .
curl -sS -X POST "$CFM_API/api/v1/clam/sigignore/add?pattern=*_Hunting.UNOFFICIAL" | jq .
curl -sS -X POST "$CFM_API/api/v1/clam/sigignore/add?pattern=Doc.Dropper.Agent-*&host=shop.example.com" | jq .
curl -sS -X POST "$CFM_API/api/v1/clam/sigignore/remove?pattern=Doc.Dropper.Agent-*&host=shop.example.com" | jq .
```

Scanner health (admin-only; box-level daemon state for the ClamAV page's
status card — breaker, queue, scan scope, lifetime counters incl.
skipped-by-scope and sig-ignored, global scan default):

```bash
curl -sS "$CFM_API/api/v1/clam/health" | jq .
```

Recent infections for the ClamAV page come from the existing scoped history
endpoint:

```bash
curl -sS "$CFM_API/api/v1/webdet/history/events?type=clam_infected&limit=50&enrich=1" | jq .
```

---

## 2b) Web Bots UA drilldown (Web Bots page "details" panel)

Per-UA breakdown: vhosts hit, source IPs with geo/ASN (and cached PTR), top
paths, raw UA variants. Admin-only.

```bash
curl -sS "$CFM_API/api/v1/webdet/ua-drill?ua=go-http-client" | jq .
```

Side effect: each drill request arms detailed per-UA tracking (unique IPs +
top paths) for 10 minutes — without it, only Reqs/RPS/Vhosts accumulate
(`ip_tracking_active: false` in the response means the data is still
warming). Country/ASN come from the local MaxMind DBs; a PTR for a fresh IP
resolves async and appears on the next call.

---

## 3a) Force SSL certificate rescan (dashboard "Rescan certs" button)

Runs `cfm ssl refresh --json` (cert-source rescan + collector refresh),
bounded to 90s. Admin-only, POST-only.

```bash
curl -sS -X POST "$CFM_API/api/v1/system/ssl/refresh" | jq .
```

Both this and `/api/v1/system/ssl/stats` tolerate CLI log lines before the
JSON body (the daemon extracts the first JSON object from the output).

---

## 3b) Node health snapshot (dashboard "Node health" card)

Full `health.snapshot.v1` payload (host CPU/RAM/swap, disks + SMART/MDADM/ZFS,
services, DNAT/edge/challenge-flow runtime, conntrack, throughput). Admin-only.

```bash
# fresh collection (~1-2s: smartctl/systemd/socket probes) — what `cfm health` uses
curl -sS "$CFM_API/api/v1/health/snapshot" | jq .

# cached, stale-while-revalidate — what the dashboard polls (recollects at most
# once per TTL; TTL clamped to 1s..1m; check `collected_at` for the real age)
curl -sS "$CFM_API/api/v1/health/snapshot?cache_ttl=60s" | jq .

# metric history (in-memory ring, ~24h reach) + anomaly feed — the /cfm-admin/health/ page
curl -sS "$CFM_API/api/v1/health/timeseries?window=1h&step=1m" | jq .
curl -sS "$CFM_API/api/v1/health/anomalies?since=24h" | jq .
```

---

## 4) Offline analysis (helpful for TSV validation)

These endpoints are useful when you want to inspect behavior against real/sampled TSV logs.

```bash
IP="1.2.3.4"
curl -sS "$CFM_API/api/v1/webdet/analyze-ip?ip=${IP}&max_lines=200000" | jq .

HOST="example.com"
curl -sS "$CFM_API/api/v1/webdet/analyze-host?host=${HOST}&max_lines=200000" | jq .
```

---

## 5) Quick capture commands for bug reports / fixture generation

Capture current API responses to JSON files:

```bash
mkdir -p tmp/webui-captures
TS="$(date +%Y%m%d-%H%M%S)"

curl -sS "$CFM_API/api/v1/webdet/top-short?limit=50" \
  | tee "tmp/webui-captures/${TS}-top-short.json" >/dev/null

curl -sS "$CFM_API/api/v1/webdet/suspicious" \
  | tee "tmp/webui-captures/${TS}-suspicious.json" >/dev/null

HOST="example.com"
curl -sS "$CFM_API/api/v1/webdet/drilldown?host=${HOST}&top=25" \
  | tee "tmp/webui-captures/${TS}-drilldown-${HOST}.json" >/dev/null
```

Tip: sanitize IPs/hosts before committing captured fixtures.

---

## 6) Through OpenResty (if testing via /cfm-admin/api)

If you want to test exactly what the browser calls, use the proxy path:

```bash
export CFM_UI_API="https://YOUR-HOST/cfm-admin/api"
curl -sS -u 'admin:password' "$CFM_UI_API/v1/webdet/top-short" | jq .
```

(Adjust auth/TLS flags based on your local setup.)

---

## 7) Capture a complete live snapshot bundle (good for WebUI test fixtures)

```bash
mkdir -p tmp/webui-captures
TS="$(date +%Y%m%d-%H%M%S)"
HOST="example.com"

curl -sS "$CFM_API/api/v1/webdet/top-short?limit=50"   > "tmp/webui-captures/${TS}-top-short.json"
curl -sS "$CFM_API/api/v1/webdet/suspicious"   > "tmp/webui-captures/${TS}-suspicious.json"
curl -sS "$CFM_API/api/v1/webdet/drilldown?host=${HOST}&top=25"   > "tmp/webui-captures/${TS}-drilldown-${HOST}.json"
curl -sS "$CFM_API/api/v1/webdet/ip-short?limit=30"   > "tmp/webui-captures/${TS}-ip-short.json"
curl -sS "$CFM_API/api/v1/challenge/vhosts?status=active&mode=all&limit=200"   > "tmp/webui-captures/${TS}-challenge-vhosts.json"
```

---

## 8) Capture common error payloads (for UI error-state testing)

```bash
# missing host in drilldown -> HTTP 400 + {"error":"missing host"}
curl -sS -i "$CFM_API/api/v1/webdet/drilldown"   | tee tmp/webui-captures/error-missing-host-drilldown.txt

# invalid ttl in challenge add -> HTTP 400 + {"error":"invalid ttl: ..."}
curl -sS -i -X POST   "$CFM_API/api/v1/challenge/vhost/add?host=example.com&ttl=banana"   | tee tmp/webui-captures/error-invalid-ttl.txt
```

---
