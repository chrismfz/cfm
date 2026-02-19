# CFM – Configurable Firewall Manager

CFM is a modern **firewall + intrusion detection manager** written in Go.
It combines nftables policy enforcement, log-driven detection, autoblocking, system hardening, and notifications into one daemon.
It now includes a **unified Web detector** for Nginx / Apache / LiteSpeed with live “top” views, per-vhost drill-downs, and a “Suspicious vhosts” scorer.

More information at [https://infected.gr/category/cfm/](https://infected.gr/category/cfm/) 

## Ready to run packages for Debian and EL (Almalinux/Rocky/Cloudlinux)
Debian:

wget -qO - https://repo.nixpal.com/debian/nixpal-repo.gpg | gpg --dearmor -o /etc/apt/trusted.gpg.d/nixpal-repo.gpg

wget https://repo.nixpal.com/debian/nixpal.list -O /etc/apt/sources.list.d/nixpal.list

apt update ; apt install cfm



EL:

dnf install https://repo.nixpal.com/el/nixpal.rpm

dnf install cfm


---

## Simple breakdown:

### Primary categories:

- Firewall manager (nftables-based, similar to CSF)
- Intrusion Detection System (IDS) with log monitoring
- Intrusion Prevention System (IPS) with automatic blocking
- Connection/rate limiter (PPS limits, connection limits, port flood protection)
- System hardening tool (sysctl tweaks, anti-spoofing)

### What makes it unique:
- Written in Go (modern, lightweight, single binary)
- Direct nftables backend (not iptables)
- Very comprehensive detection modules: SSH, Exim, Dovecot, FTP, MySQL, cPanel, ModSec, and a sophisticated unified web detector for Nginx/Apache/LiteSpeed
- Built-in health monitoring (CPU, RAM, disk, SMART/RAID/ZFS)
- ML-ready features for anomaly detection (HBOS, Isolation Forest compatible)
- API integration support
- Web-based "top" views for analyzing traffic patterns per vhost


## ✨ Key Features

### 🔒 Firewall Core
- **nftables backend** (table `inet cfm`) with auto-created chains.
- **Hook priority control** (`NFT_INPUT_PRIORITY`) to run before/after CSF or Imunify360.
- **ALLOW / BLOCK lists**:
  - Manual: `allow_v4`, `allow_v6`, `block_v4`, `block_v6`.
  - Dynamic: `allow_dyn_v4`, `allow_dyn_v6` (hostname/DynDNS resolution).
- **Blocklists & whitelists** via `cfm.blocklists` (IPs, domains, RBL/DNSBL feeds).
- **ApplyPortsPolicy** enforces service port access from config (`TCP_IN`, `UDP_IN`, etc.).
- **SMTP_BLOCK mode** (CSF-compatible) — restricts outgoing SMTP except for trusted daemons.

### ⚡ Connection Protections
- **ConnLimit**: per-IP concurrent connection limits per port (e.g. `80;200`, `22;50`).
- **PortFlood**: per-port connection rate limiting (e.g. max 80 new SMTP sessions per 60s).
- **PPS Limits**: per-IP packet rate limiting (`PKT_RATE`, `PKT_BURST`, `PKT_MODE`).
- **New connection rate limiting** (`NEW_RATE`, `NEW_BURST`).
- **ICMP rate limiting** (`ICMP_RATE_LIMIT`, `ICMP_RATE_BURST`).
- **Bad TCP flag filter**: drop NULL/XMAS/SYN+FIN packets.

### 🔎 Detection Engine
Detectors parse logs and metrics to spot abuse:
- **Exim** (queues, relay abuse, security failures).
- **SSH** (auth failures, DDOS attempts).
- **Dovecot** (auth failures).
- **FTP** (pure-ftpd/proftpd/vsftpd).
- **cPanel logins**.
- **MySQL denied/scanner attempts**.
- **Web (nginx/httpd/LiteSpeed)**: live per-vhost stats (RPS, status-mix, unique IPs, 499/401), top IPs/agents/referrers/paths, “Suspicious vhosts” scoring and drill-downs.
- **ModSecurity alerts**.
- **Health detector** (CPU, RAM, disk, conntrack spikes, throughput, SMART/RAID/ZFS).
- Configurable thresholds, cooldowns, and autoblock modes per detector.

### 🚨 Autoblock Engine
- Inserts IPs into nftables sets with **TTL** or **permanent**.
- Per-detector policies: `dryrun`, `ttl=1h`, `permanent`.
- **Throttle autoblock**: if IP hits PPS/SYN/ConnLimit/PortFlood triggers repeatedly → autoblock.
- Dedupe suppresses noisy repeats (`host|kind|ip|reason`).
- Reasons: `SSH_BRUTE`, `PORTSCAN`, `CONNLIMIT`, `HEALTH_SPIKE`, etc.

### 🛡️ Portscan & Flood Defenses
- **Portscan detection** (distinct ports per window, TCP+UDP).
- **AckGuard** to block invalid ACK/SYN/ACK/RST floods.
- **Reflection/handshake junk filtering**.

### 📧 SMTP Autoblock
Blocks unauthorized **outgoing SMTP**, forces scripts to relay via the local MTA.
Includes PTR/ASN/Geo enrichment.

### 🖥️ System Hardening
Includes sysctl tweaks, conntrack scaling, anti-spoofing, redirect suppression, persistent configuration.

### 🌍 Enrichment
PTR, ASN, ASN Name, Country using MaxMind + async DNS.

### 🌍 MaxMind Auto-Updater
Downloads and refreshes GeoLite2 databases automatically.

### 📬 Notifiers
Email, SMTP, Slack. JSONL audit log.

### 🖧 API Integration
Outbound sync + agent runner + inbound logs.

### 🛠 CLI Commands
```
cfm version
cfm test
cfm block <IP>
cfm unblock <IP>
cfm list
cfm allow <IP>
cfm daemon
cfm httpd-top [vhost]
cfm nginx-top [vhost]
...
```

---

# 🌐 Unified Web Detector (nginx / Apache / LiteSpeed)

The **web detector** ingests access logs and keeps a rolling window  
(**default 60 seconds**) per vhost.

It powers:

- `cfm nginx-top`
- `cfm httpd-top`
- Drill-down details (`cfm httpd-top <vhost>`)
- Suspicious vhosts detection
- ML-ready scoring (HBOS / EHBOS / iForest pipeline compatible)

---

## 📁 Log Format Samples
Available in:

```
/usr/share/cfm/

ready .conf examples for httpd and nginx to be placed in /etc/nginx/conf.d/ or /etc/apache2/conf.d/

```

Each includes a **TSV format**:

```
ts  ip  host  method  uri  proto  status  bytes  rt  urt  ref  ua
```

For Apache we normalize `%D` or `%T` to seconds.

---

# 🧭 How to Configure Web Detection

### Example in `detectors.conf`

```
[nginx_access]
ENABLED = 1
MODE = file
LOG_PATH = "/var/log/nginx/access_cfm_combined.log"

EVERY   = "5s"
WINDOW  = "60s"
COOLDOWN = "10m"
SAMPLE_LIMIT = 20

# Thresholds (notify-only to start)
RPS_TOTAL_MIN     = 500
UNIQUE_IPS_MIN    = 300
ERR_RATIO_MIN     = 0.20
RPS_499_MIN       = 100
RPS_5XX_MIN       = 60
MEDIAN_IP_RPS_MAX = 3

# Optional 401-focused triggers
RPS_401_MIN = 200
AUTH401_RATIO_MIN = 0.60


# Optional enrichment
ENRICH = 1
PTR    = 1
ENRICH_DIRS = "/var/lib/cfm/maxmind"


[httpd_access]
ENABLED = 1
MODE = file
LOG_PATH = "/var/log/apache2/access_cfm_tsv.log"

EVERY = "5s"
WINDOW = "60s"
COOLDOWN = "10m"
SAMPLE_LIMIT = 20

RPS_TOTAL_MIN = 500
UNIQUE_IPS_MIN = 300
ERR_RATIO_MIN = 0.20
RPS_499_MIN = 100
RPS_5XX_MIN = 60
MEDIAN_IP_RPS_MAX = 3

# Optional 401-focused triggers
RPS_401_MIN = 200
AUTH401_RATIO_MIN = 0.60

# Enrichment
ENRICH = 1
PTR = 1
ENRICH_DIRS = "/var/lib/cfm/maxmind"



```

Works with any source that outputs the TSV line format.

---

# 📊 cfm httpd-top / nginx-top

### Live table
```
cfm httpd-top
cfm nginx-top
```

Columns:
- **RPS** — Requests/sec  
- **2xx / 3xx / 4xx / 5xx** — status buckets  
- **401** — auth failures  
- **499** — Nginx client aborts  
- **uniqIP** — distinct IPs in window  
- **err%** — (499 + 5xx) / total  
- **rt_avg** — average request CPU time (seconds)

Example:

```
HOST            RPS   2xx 3xx 4xx 5xx 401 499 uniqIP err% rt_avg
mysite.gr       8.2   7.1 0.4 0.6 0.0  0   0    19    0.0  0.120
```

---

# 🔍 Per-vhost Drill-down

```
cfm httpd-top <vhost>
```

Outputs:

- Top IPs (with `(2xx:x, 3xx:x, 4xx:x, 5xx:x)` per IP)
- Top User Agents
- Top Referrers
- Top Paths
- PTR + ASN + Country enrichment

---

# 🚨 Suspicious Vhosts

Run:

```
cfm httpd-top suspicious
cfm nginx-top suspicious
```

Or combined with top:

```
cfm httpd-top --smin 0.60 --slimit 10
```

### Signals used:
- High 3xx ratio (redirect loops)
- High 4xx / 5xx (broken app or scanners)
- High uniq IPs (scatter)
- High median-per-IP rate (hammering)
- High auth 401 ratio (brutes)
- High error%  
- Low diversity + high volume  
- Dominant IP making too many requests

This **does not autoblock** — it is advisory so the admin investigates.

---

# 🤖 ML‑Ready (optional)

The web detector emits clean numerical features making it compatible with:

- **HBOS**
- **EHBOS**
- **Isolation Forest**

Future mode (optional) will:

- Write `web.features.log` and `web.anom.log` into `/var/log/cfm/`
- Add `ml_suspect` reason in Suspicious  
- Allow tuning or training thresholds offline  

Matches the anomaly engine in FlowEnricher.

---

# 🧪 Debug Server
Enabled from `cfm.conf`.

Endpoints:

```
/nginx/top?limit=10
/nginx/host?name=<vhost>&top=10
/nginx/suspicious?min=0.6&limit=10

/httpd/top?limit=10
/httpd/host?name=<vhost>&top=10
/httpd/suspicious?min=0.6&limit=10
```

---

# SSLCollector (CFM) — Certificate Discovery + Unix Socket API for OpenResty

CFM includes an **SSLCollector** subsystem that discovers and tracks TLS certificates and private keys that already exist on the server (e.g. cPanel/Let’s Encrypt and other common layouts). It keeps an in-memory index so other parts of CFM (and optionally OpenResty) can quickly resolve a hostname/SNI to the correct `cert+key` pair.

This README section explains:

- What SSLCollector already does
- What the **Unix socket API** adds (and why it exists)
- How to enable it
- How to test it with `curl`
- How to consume it from **OpenResty** using `ssl_certificate_by_lua*`

---

## What SSLCollector does

SSLCollector continuously discovers certificates/keys from supported sources and builds an index:

- **Exact hostnames** (SAN/CN hostnames found in certs)
- **Wildcard zones** (e.g. `*.example.com`)
- **Host → Entry mapping** for fast lookup
- Tracks useful metadata:
  - `cert_path`, `key_path`
  - `fingerprint`
  - `not_after`
  - `source` (e.g. `cpanel`, `generic`)
- Maintains internal caches so repeated lookups are fast
- Periodically refreshes via:
  - lightweight stat checks (mtime/size changes)
  - full rediscovery on a longer interval

> Note: A wildcard cert like `*.example.com` does **not** cover the apex `example.com` (only subdomains).

---

## What the Unix socket API does (Purpose)

The Unix socket API exposes SSLCollector over a **local-only** HTTP interface via a Unix domain socket, so OpenResty can dynamically load the correct certificate for a given **SNI** during TLS handshake.

This enables setups like:

- DNAT 443 → OpenResty (front proxy)
- OpenResty terminates TLS using the correct cert/key fetched from CFM
- OpenResty reverse-proxies to Apache/LiteSpeed/Nginx backends
- CFM can keep private-key permissions restricted (OpenResty doesn't need filesystem access)

### Why a socket (instead of files)?

- **Local-only** access via Unix socket
- Optional token auth (`X-SSLCollector-Token`)
- Allows OpenResty to retrieve cert/key even if it does not have direct read permissions on `/etc/letsencrypt/...` or cPanel cert stores
- Works well with OpenResty `ssl_certificate_by_lua*` + Lua caching

---

## Configuration (cfm.conf)

```ini
; SSLCollector Unix Socket API (OpenResty dynamic SNI certificates)
SSLCOLLECTOR_SOCK_ENABLE   = 1
SSLCOLLECTOR_SOCK_PATH     = /var/run/sslcollector.sock
SSLCOLLECTOR_SOCK_TOKEN    = supersecret

; In-daemon PEM cache (reduces disk reads during repeated handshakes)
SSLCOLLECTOR_SOCK_PEM_TTL  = 10m
SSLCOLLECTOR_SOCK_PEM_MAX  = 50000
```

Restart CFM after enabling:

```bash
systemctl restart cfm
```

---

## Socket API endpoints

All endpoints are HTTP-over-unix-socket.

### `GET /stats`
Returns collector stats as JSON.

### `GET /cert?host=<hostname>`
Returns the resolved cert+key for the host as JSON:
- `cert_pem` (fullchain PEM)
- `key_pem`  (private key PEM)
- plus metadata (`not_after`, `fingerprint`, `source`, paths)

### `POST /refresh`
Triggers an immediate collector refresh/rescan.

---

## Examples (curl)

### 1) Check the daemon is alive (`/stats`)

```bash
curl --unix-socket /var/run/sslcollector.sock \
  -H 'X-SSLCollector-Token: supersecret' \
  'http://localhost/stats'
```

Expected output (example):

```json
{"ExactHosts":3821,"WildcardZones":39,"UniquePairs":552,"BySource":{"cpanel":551,"generic":1},"KnownFiles":1212,"CachedTLS":0,"GeneratedAt":"2026-02-19T20:02:57+02:00"}
```

---

### 2) Fetch certificate + key for a hostname (`/cert`)

```bash
curl --unix-socket /var/run/sslcollector.sock \
  -H 'X-SSLCollector-Token: supersecret' \
  'http://localhost/cert?host=120.gr' | head
```

Expected output (example, truncated):

```json
{
  "cert_path":"/var/cpanel/ssl/apache_tls/120.gr/certificates",
  "key_path":"/var/cpanel/ssl/apache_tls/120.gr/keys",
  "fingerprint":"...",
  "not_after":"2026-05-12T16:49:13Z",
  "source":"cpanel",
  "cert_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n...",
  "key_pem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
}
```

---

### 3) Force refresh (`/refresh`)

```bash
curl --unix-socket /var/run/sslcollector.sock \
  -H 'X-SSLCollector-Token: supersecret' \
  -X POST \
  'http://localhost/refresh' -i
```

Expected:

```
HTTP/1.1 204 No Content
```

---

## OpenResty integration example (ssl_certificate_by_lua)

### nginx.conf (excerpt)

```nginx
lua_shared_dict cert_cache 50m;
lua_shared_dict cert_locks 2m;

server {
    listen 9099 ssl default_server;
    server_name _;

    # Dummy cert required for initial SSL context
    ssl_certificate     /opt/openresty/conf/dummy.crt;
    ssl_certificate_key /opt/openresty/conf/dummy.key;

    # Dynamic SNI cert loading
    ssl_certificate_by_lua_file /opt/openresty/lua/ssl_by_sni.lua;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

### /opt/openresty/lua/ssl_by_sni.lua (excerpt)

> IMPORTANT: `ssl_certificate_by_lua*` runs during TLS handshake, so you **must** cache results
> (shared_dict + lock) and use **tight timeouts**.

```lua
local ssl  = require "ngx.ssl"
local http = require "resty.http"
local cjson = require "cjson.safe"
local lock  = require "resty.lock"

local sni, err = ssl.server_name()
if not sni then
  return
end
sni = sni:lower()

local dict = ngx.shared.cert_cache

-- Negative cache (prevents random-SNI misses hammering the socket)
if dict:get("nf:" .. sni) then
  return
end

local cert_pem = dict:get("cert:" .. sni)
local key_pem  = dict:get("key:" .. sni)

if not (cert_pem and key_pem) then
  local l = lock:new("cert_locks", { timeout = 0.20, exptime = 1.0 })
  local ok = l:lock(sni)
  if not ok then return end

  -- Re-check after lock
  cert_pem = dict:get("cert:" .. sni)
  key_pem  = dict:get("key:" .. sni)

  if not (cert_pem and key_pem) then
    local httpc = http.new()
    httpc:set_timeouts(100, 200, 200) -- ms

    local res, req_err = httpc:request_uri("http://unix:/var/run/sslcollector.sock:/cert", {
      method  = "GET",
      query   = { host = sni },
      headers = {
        ["Host"] = "localhost",
        ["X-SSLCollector-Token"] = "supersecret",
      },
    })

    if (not res) or res.status ~= 200 then
      -- Cache "not found" for a short period
      dict:set("nf:" .. sni, 1, 60)
      l:unlock()
      return
    end

    local data = cjson.decode(res.body)
    if not data or type(data.cert_pem) ~= "string" or type(data.key_pem) ~= "string" then
      l:unlock()
      return
    end

    cert_pem, key_pem = data.cert_pem, data.key_pem

    -- Cache for 10 minutes (tune as needed)
    dict:set("cert:" .. sni, cert_pem, 600)
    dict:set("key:"  .. sni, key_pem,  600)
  end

  l:unlock()
end

-- Apply certificate to the handshake
ssl.clear_certs()

local cert, e1 = ssl.parse_pem_cert(cert_pem)
if not cert then return end

local pkey, e2 = ssl.parse_pem_priv_key(key_pem)
if not pkey then return end

ssl.set_cert(cert)
ssl.set_priv_key(pkey)
```

---

## Common responses / troubleshooting

- `403 forbidden`  
  Token is enabled and missing/incorrect. Ensure header:
  `X-SSLCollector-Token: <token>`

- `404 not found` (from `/cert`)  
  No matching cert+key pair for that host in the collector index.
  Try a subdomain like `www.<domain>` if you only have a wildcard cert.

- Slow handshakes / high CPU  
  Ensure Lua caching + lock is enabled. Avoid socket calls per handshake.

---

## Notes on permissions

Recommended model:

- CFM (daemon) can read private keys from the system stores.
- OpenResty **does not** need filesystem read access to private keys.
- OpenResty retrieves cert/key over the local unix socket and caches in memory.
