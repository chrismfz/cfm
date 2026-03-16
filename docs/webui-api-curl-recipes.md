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
