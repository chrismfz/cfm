# CFM – Configurable Firewall Manager

CFM is a modern Go-based firewall + detection + mitigation daemon.  
It combines nftables policy enforcement, log-driven detectors, enrichment, notifications,
and an HTTP challenge engine that can be enforced either via nftables redirect/DNAT or directly
in OpenResty in-path mode through a decision socket.

> More information: https://infected.gr/category/cfm/

---

## Table of Contents

1. [What is CFM?](#1-what-is-cfm)
2. [Installation](#2-installation)
3. [Repository Layout](#3-repository-layout)
4. [Configuration Files](#4-configuration-files)
5. [Key Features](#5-key-features)
   - [Firewall Core](#-firewall-core)
   - [Connection Protections](#-connection-protections)
   - [Detection Engine](#-detection-engine)
   - [Autoblock Engine](#-autoblock-engine)
6. [Web Detector](#6-web-detector)
   - [Ingestion Modes](#ingestion-modes)
   - [Log Line Format](#log-line-format-tsv)
   - [Configuration Examples](#configuration-examples)
   - [Hard-Block Triggers](#web-abuse-hard-block-triggers)
   - [Suspicious Scoring](#suspicious-scoring)
7. [Challenge System](#7-challenge-system)
   - [DNAT Mode](#dnat-mode)
   - [Challenge Triggers](#challenge-triggers)
   - [Challenge Abuse Protection](#challenge-abuse-protection)
8. [OpenResty In-Path Mode](#8-openresty-in-path-mode)
   - [Architecture](#architecture)
   - [Smart Lua WAF Layer](#smart-lua-waf-layer)
   - [Advanced Challenge Rules](#advanced-challenge-rules)
9. [SSLCollector](#9-sslcollector)
10. [CLI Reference – `cfm webtop`](#10-cli-reference--cfm-webtop)
11. [Web Detector HTTP API](#11-web-detector-http-api)
12. [Appendix: cfm.conf Snippets](#12-appendix-cfmconf-snippets)
13. [Security Notes](#13-security-notes)

---

## 1. What is CFM?

CFM is a **unified L3–L7 enforcement platform** — a single Go binary with a direct nftables
backend and no iptables dependency.

| Layer | Function |
|---|---|
| L3/L4 | Firewall, IDS/IPS, connection/rate limiting, system hardening |
| L7 | Behavioral Web Detection, OWASP-inspired WAF, Interactive Challenge Engine |
| Support | Enrichment (PTR / ASN / Country), TLS-aware smart bridge, notifications |

**What makes it unique:**
- Single Go binary, low footprint
- Direct nftables backend (no iptables dependency)
- Broad detector coverage: SSH, Exim, Dovecot, FTP, MySQL, cPanel, ModSecurity, Web
- Web Detector that can escalate to an **interactive challenge** instead of always hard-blocking
- ML-Ready: the scoring system is a hand-crafted classifier based on trusted signals

---

## 2. Installation

Ready-to-run packages are available for Debian and EL (AlmaLinux / Rocky / CloudLinux).

### Debian
```bash
wget -qO - https://repo.nixpal.com/debian/nixpal-repo.gpg | gpg --dearmor -o /etc/apt/trusted.gpg.d/nixpal-repo.gpg
wget https://repo.nixpal.com/debian/nixpal.list -O /etc/apt/sources.list.d/nixpal.list
apt update && apt install cfm
```

### EL (AlmaLinux / Rocky / CloudLinux)
```bash
dnf install https://repo.nixpal.com/el/nixpal.rpm
dnf install cfm
```

---

## 3. Repository Layout

CFM ships **reference configs** under `configs/` (packaged to `/usr/share/cfm/configs/`) and
**live configs** under `/etc/cfm/`.

```text
configs/
  cfm.conf                  # main daemon config (ports policy, nft, sysctl, maxmind, api, logs)
  detectors.conf            # detectors + thresholds + per-section BLOCK policies
  notify.conf               # notifier channels + dedupe + per-detector routing
  cfm.blocklists            # external feed definitions (ALLOW/BLOCK, refresh interval, etc.)
  cfm.allow / cfm.deny      # static allow/deny lists (IP/CIDR/host)
  cfm.ignore                # IPs that must never be blocked (global ignore list)
  cfm.dyndns                # hostnames resolved periodically and added to allow
  httpd-cfm.conf            # Apache LogFormat for WebDetector TSV
  nginx-cfm.conf            # nginx log_format for WebDetector TSV
  cfm-modsec.conf           # ModSecurity integration (file uploads → cfm-scan.sh)
  sslcollector.lua          # OpenResty Lua helper for dynamic cert loading (via unix socket)
  trusted_proxies.conf      # real_ip / trusted proxy include for Cloudflare/LB setups
  openresty-example*.conf   # full OpenResty "in-path WAF/challenge" examples (+ optional cache)
  webdetector_*.txt         # webdetector path lists: challenge_paths, malpaths, exclude, etc.
packaging/
  debian/DEBIAN/*           # postinst/prerm/postrm, conffiles, etc.
  rpm/SPECS/cfm.spec
internal/
  detectors/                # ssh/mysql/ftp/exim/dovecot/cpanel/webdetector/modsec/health/postfix...
  notify/                   # notifier engine (sendmail/smtp/slack), dedupe, templates
  firewall/nft/             # nftables backend + hardening + ports policy
  sslcollector/             # cert discovery + socket API for OpenResty
```

---

## 4. Configuration Files

### `cfm.conf` — Main daemon config
- Ports policy: `TCP_IN`, `UDP_IN`, `TCP_OUT`, `UDP_OUT`
- nftables hook ordering: `NFT_INPUT_PRIORITY`
- Connection protections: `CONNLIMIT`, `PORTFLOOD`, `PKT_RATE/PKT_BURST`, `NEW_RATE/NEW_BURST`, `ICMP_*`
- Throttle-to-autoblock glue: `THROTTLE_*`
- Portscan tracking: `PS_*`
- MaxMind updater: `MAXMIND_*`
- Optional API integration: `API_URL`, `AUTH_TOKEN`, `*_SEND_TO_API`
- Debug server: `LISTEN_ADDRESS`, `PORT`

### `detectors.conf` — Detection engine
- `[global]` defaults: `DEFAULT_EVERY`, `DEFAULT_TIMEOUT`, `DEFAULT_COOLDOWN`
- Global ignores: `IGNORE_IPS`, `IGNORE_NETS`, `LOG_IGNORED`
- Per-detector sections: `[ssh_auth]`, `[mysql]`, `[ftpd]`, `[cpanel]`, `[exim_*]`, `[dovecot_*]`, `[postfix_*]`, `[modsec]`, `[health]`, `[webdetector]`
- Per-section block policy: `BLOCK = no|dryrun|permanent|<duration>` + `BLOCK_COOLDOWN`

### `notify.conf` — Notifier
- Global on/off + JSONL audit log
- Dedupe keying: `[dedupe]`
- Channels: `sendmail`, `smtp`, `slack_webhook`
- Per-detector routing + severity gating: `[detector "..."]`

### `cfm.blocklists` — External feed pulls
Defines scheduled pulls of external feeds into allow/block sets.

### `cfm.dyndns` — Dynamic DNS allow
Hostnames periodically resolved and kept in the allow set (e.g. dynamic office IPs).

### Web log format snippets (`httpd-cfm.conf`, `nginx-cfm.conf`)
Ensures WebDetector sees a consistent TSV schema across stacks.

### ModSecurity integration (`cfm-modsec.conf` + `scripts/cfm-scan.sh`)
Wires ModSecurity file upload temp paths into `cfm-scan.sh` (local scanner hook).

---

## 5. Key Features

### 🔒 Firewall Core
- nftables backend (auto-created table/chains)
- Hook priority control (`NFT_INPUT_PRIORITY`) to run before/after other stacks (CSF/Imunify)
- ALLOW/BLOCK sets (v4/v6) + dynamic allow via hostname/DynDNS resolution
- Port policy from config (`TCP_IN`, `UDP_IN`, etc.)
- SMTP_BLOCK mode (CSF-compatible pattern)

### ⚡ Connection Protections
- ConnLimit per port (concurrent connections per IP)
- PortFlood per port (new connection rate limits per IP)
- PPS limits: `PKT_RATE`, `PKT_BURST`, `PKT_MODE`
- New connection rate limiting: `NEW_RATE`, `NEW_BURST`
- ICMP rate limiting
- Bad TCP flag filtering (NULL / XMAS / SYN+FIN)

### 🔎 Detection Engine
Detectors parse logs/metrics to spot abuse:
- Exim (queues, auth failures, relay abuse)
- SSH (auth fails, brute force)
- Dovecot (auth fails)
- FTP (pure-ftpd / proftpd / vsftpd)
- cPanel logins
- MySQL denied / scanner attempts
- ModSecurity alerts
- Health detector (CPU / RAM / disk / SMART / RAID / ZFS / conntrack spikes)
- **Web Detector** (see [§6](#6-web-detector))

### 🚨 Autoblock Engine
- Inserts IPs into nftables sets (TTL or permanent)
- Per-detector policies: `dryrun`, `ttl=1h`, `permanent`
- Dedupe suppression for noisy repeats (`host|kind|ip|reason`)
- Unified reasons: `SSH_BRUTE`, `PORTSCAN`, `CONNLIMIT`, `WEB_*`, etc.

---

## 6. Web Detector

The Web Detector ingests access logs and maintains:
- a **short sliding window** — real-time top/drilldown views,
- a **long window** — aggregated suspicious scoring + "under attack" signals.

It supports both **visibility** (who is doing what, on which vhost) and **action** (challenge/mitigate abusive IPs or under-attack vhosts).

### Ingestion Modes

**File mode** — single TSV log. Best for nginx/Apache custom log formats you control.

**Folder mode** — directory tailing. Best for hosting layouts:
- cPanel domlogs
- DirectAdmin-like layouts
- Any "one file per vhost" layout

Supports recursion + glob filtering.

### Log Line Format (TSV)

```
ts  ip  host  method  uri  proto  status  bytes  rt  urt  ref  ua
```

- `host` — the vhost
- `rt` — request time in seconds
- UA/referrer are normalized for aggregation

Format helpers are available under `/usr/share/cfm/` (nginx/Apache samples).

### Configuration Examples

#### File mode (nginx/Apache)
```ini
[webdetector]
ENABLED   = 1

MODE      = file
LOG_PATH  = "/var/log/nginx/access_cfm_tsv.log"

EVERY       = "5s"
WINDOW      = "120s"
LONG_FACTOR = 10        ; long horizon = LONG_FACTOR * WINDOW
MIN_SCORE   = 0.60      ; suspicious threshold
SAMPLE_LIMIT = 20

; Enrichment (optional)
ENRICH      = 1
PTR         = 1
ENRICH_DIRS = "/var/lib/cfm/maxmind"

; Web detector local API (CLI uses this)
API_LISTEN  = "127.0.0.1:9070"
```

#### Folder mode (cPanel domlogs)
```ini
[webdetector]
ENABLED    = 1

MODE       = folder
LOG_DIR    = "/usr/local/apache/domlogs"
RECURSIVE  = 1
GLOB       = "*.log"

EVERY       = "5s"
WINDOW      = "120s"
LONG_FACTOR = 10
MIN_SCORE   = 0.60

ENRICH      = 1
PTR         = 1
ENRICH_DIRS = "/var/lib/cfm/maxmind"

API_LISTEN  = "127.0.0.1:9070"
```

### Web Abuse Hard-Block Triggers

These are **high-confidence** triggers that go straight to the **block set** (instead of challenge),
designed for aggressive scanners.

```ini
# Many 404s / 403s within WINDOW
IP404_COUNT = 220
IP403_COUNT = 120

# Suspicious UAs (comma-separated substrings) and how many hits to consider abuse
AGENT_LIST  = "python-requests,spider"
AGENT_COUNT = 25

# Combined 40x (403/404/405/406/410/429...) + path diversity
IP40X_COMBO        = 180
IP40X_UNIQUE_PATHS = 20

# Optional: ignore "expected" 40x paths so they don't inflate ratios
IGNORE40X_PREFIXES = "/.well-known/,/robots.txt,/favicon.ico,/sitemap"

# Block policy
BLOCK          = 1h
BLOCK_COOLDOWN = 30m

# Known malicious path substrings (fast path match list)
MALPATH_COUNT = 20
MALPATH_FILE  = /etc/cfm/webdetector_malpaths.txt
```

> - Counters are evaluated per IP within your `WINDOW`.
> - `BLOCK_COOLDOWN` prevents block/unblock/block loops for the same noisy bot.
> - Keep `IGNORE40X_PREFIXES` limited to truly harmless noise.

### Suspicious Scoring

CFM maintains:
- **Short-window signals** — live visibility
- **Long-window scoring** — stability + under-attack decisions

Common signals: status mix (2xx/3xx/4xx/5xx, 401, 403, 404, 499), unique IP scatter, median per-IP rate, bot ratio (UA heuristics), UA diversity / path diversity, POST ratio, failure/error index.

The score drives:
- the **"suspicious"** view (admin visibility)
- optional automatic vhost **"under attack" mode** (see Challenge System)

---

## 7. Challenge System

CFM can respond to web abuse with an **interactive challenge** instead of blunt blocking.
Useful when:
- traffic is high but not trivially blockable (CGNAT / shared NATs),
- you want a reversible "speed bump" before banning,
- you want to slow automated clients without punishing legitimate users.

The Challenge System can run in two modes:

| Mode | How it works |
|---|---|
| **DNAT mode** | nftables redirects the IP's traffic to the local Challenge Server |
| **OpenResty in-path mode** | No DNAT; OpenResty consults CFM per-request via unix socket (see [§8](#8-openresty-in-path-mode)) |

### DNAT Mode

#### Flow (high level)
1. Web Detector decides an IP (or vhost) should be challenged.
2. Firewall inserts the IP into a **challenge set**.
3. nftables **DNAT redirects** that IP's HTTP/HTTPS to the local Challenge Server.
4. Browser receives a challenge page and must pass:
   - cookie
   - HMAC token (bound to IP + UA + cookie)
   - PoW (bound to UA + cookie)
   - CID (server-issued challenge id; must match what the sink issued)
5. On solve: IP is removed from challenge set, `CHALLENGE_COOLDOWN` prevents loops, user is redirected back to original path.

#### Challenge Server Listeners
```ini
[webdetector]
CHALLENGE_HTTP_LISTEN  = 127.0.0.1:9098
CHALLENGE_HTTPS_LISTEN = 127.0.0.1:9099

CHALLENGE_ACCESS_LOG = /var/log/cfm/challenge.access.log

CHALLENGE_LOG    = 1
CHALLENGE_NOTIFY = 0

CHALLENGE_COOLDOWN    = 15m
CHALLENGE_COOKIE_LIFE = 15m
```

### Challenge Triggers

#### 1) Known-bad paths (probing/scans)
```ini
CHALLENGE_PATHS       = 1
CHALLENGE_PATHS_FILE  = /etc/cfm/webdetector_challenge_paths.txt
CHALLENGE_PATHS_COUNT = 1
CHALLENGE_PATHS_TTL   = 10m
```

#### 2) Per-IP behavior thresholds
Set any value to `0` to disable.
```ini
CHALLENGE_RPS_TOTAL_MIN  = 20.0
CHALLENGE_RPS_4XX_MIN    = 12.0
CHALLENGE_RPS_5XX_MIN    = 0.9
CHALLENGE_ERR_RATIO_MIN  = 0.99
CHALLENGE_POST_RATIO_MIN = 0
CHALLENGE_NO_UA_MIN      = 5
CHALLENGE_HTTP10_MIN     = 1
```

#### 3) Per-vhost challenge modes (manual + auto)

Manual "panic mode":
```ini
CHALLENGE_VHOST        = victim.com, *.victim.com, www.nixpal.com
CHALLENGE_VHOST_IGNORE = api.mybank.gr
```

Absolute bypass (wins over everything):
```ini
CHALLENGE_HOST_BYPASS = api.mybank.gr, health.victim.com, *.internal.victim.com
```

Auto "under attack" mode (based on long-window score + hysteresis):
```ini
CHALLENGE_SUSPICIOUS_VHOST = 1
CHALLENGE_SUSPICIOUS_VHOST_SCORE_ON   = 0.70
CHALLENGE_SUSPICIOUS_VHOST_SCORE_OFF  = 0.65
CHALLENGE_SUSPICIOUS_VHOST_MIN_UNIQIP = 80
CHALLENGE_SUSPICIOUS_VHOST_HOLDDOWN   = 10m
```

Optional exclude list (never challenge if `host` matches):
```ini
CHALLENGE_EXCLUDE      = 1
CHALLENGE_EXCLUDE_FILE = /etc/cfm/webdetector_challenge_exclude.txt
```

### Challenge Abuse Protection

Protects the challenge endpoint itself from bots that hammer it.

```ini
CHALLENGE_ABUSE_ENABLED   = 1
CHALLENGE_ABUSE_WINDOW    = 10s
CHALLENGE_ABUSE_BAD_N     = 15
CHALLENGE_ABUSE_BLOCK_TTL = 1h
CHALLENGE_ABUSE_COOLDOWN  = 30m
```

---

## 8. OpenResty In-Path Mode

When `OPENRESTY_MODE=1`, CFM stops relying on per-IP DNAT redirects. Instead, OpenResty
decides at request time by querying CFM over a **unix socket**.

Benefits:
- No DNAT table/rule management per IP
- Decisions apply immediately (allow / challenge / block)
- Easier per-vhost "under attack" behavior

### Architecture

```
Client
  ↓
OpenResty (80/443)
  → Lua WAF (cfm_waf.lua)
  → CFM Decision Socket (cfm.lua)
  → Challenge (if required)
  → Proxy to origin
```

This creates a full in-path L7 enforcement layer combining:
- Lua-based WAF inspection (OWASP-inspired rules)
- Behavioral escalation to CFM
- Per-IP and per-vhost anomaly detection
- Challenge orchestration (no DNAT required)
- TLS SNI integration via SSLCollector
- Micro-cache compatibility

#### Configuration
```ini
OPENRESTY_MODE  = 1
OPENRESTY_SOCK  = /var/run/cfm/cfm_nginx.sock
OPENRESTY_TOKEN = cfm

# When OpenResty sees a challenge solved, it can cache the OK IP locally.
OPENRESTY_OK_IP_TTL = 15m
```

#### nginx.conf integration
```nginx
access_by_lua_file         /usr/local/openresty/nginx/lua/cfm.lua;
ssl_certificate_by_lua_file /usr/local/openresty/nginx/lua/sslcollector.lua;
```

### Socket API

All requests require header `X-CFM-Token: <OPENRESTY_TOKEN>`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/nginx/decision?ip=1.2.3.4&host=example.com` | Returns `{"ip_action":"allow\|challenge\|block","vhost_action":"allow\|challenge"}` |
| `POST` | `/nginx/ip` | Push IP override: `{"ip":"1.2.3.4","action":"challenge\|block","ttl_sec":600}` |
| `POST` | `/nginx/ip/clear` | Clear IP override: `{"ip":"1.2.3.4"}` |
| `POST` | `/nginx/vhost` | Push vhost override: `{"host":"example.com","action":"challenge","ttl_sec":600}` |
| `POST` | `/nginx/vhost/clear` | Clear vhost override: `{"host":"example.com"}` |
| `GET` | `/nginx/status` | Active pushes + stats (debug) |

### Smart Lua WAF Layer

The bridge performs per-request inspection before proxying.

#### Path Inspection
- wp-admin probing, xmlrpc abuse, phpmyadmin scans
- `.env` leaks, vendor/config exposure
- Shell / eval / base64 patterns

#### Query Inspection
- SQLi patterns (`union select`, `sleep()`, `benchmark()`)
- XSS fragments (`<script>`, `javascript:`, `onerror=`)
- LFI/RFI attempts (`../`, `file://`, `http://` injection)
- Null byte abuse, excessive parameter length

#### Header Sanity
- Missing or suspicious UA
- HTTP/1.0 anomalies
- Invalid Host header
- Malformed content-type

#### Enforcement Options
- Visibility only
- Escalate to CFM (challenge)
- Immediate 403 block

### Advanced Challenge Rules

#### Per-IP Unique Paths
Detects directory scanners enumerating large path sets.
```ini
CHALLENGE_IP_UNIQPATHS_ENABLED = 1
CHALLENGE_IP_UNIQPATHS_MIN     = 200
CHALLENGE_IP_UNIQPATHS_TTL     = 20m
CHALLENGE_IP_UNIQPATHS_CAP     = 512
```

#### Per-IP Unique Hosts (Multi-Vhost Scanners)
Detects bots scanning many vhosts from a single IP.
```ini
CHALLENGE_IP_UNIQHOSTS_ENABLED = 1
CHALLENGE_IP_UNIQHOSTS_MIN     = 10
CHALLENGE_IP_UNIQHOSTS_TTL     = 30m
CHALLENGE_IP_UNIQHOSTS_CAP     = 128
```

#### Per-Vhost Unique Paths (Bridge-Level)
Triggers automatic "under attack" mode for heavy path spray attacks.
```ini
CHALLENGE_VHOST_UNIQPATHS_ENABLED = 1
CHALLENGE_VHOST_UNIQPATHS_MIN     = 1500
CHALLENGE_VHOST_UNIQPATHS_OFF     = 900
CHALLENGE_VHOST_UNIQPATHS_TTL     = 20m
CHALLENGE_VHOST_UNIQPATHS_CAP     = 5000
```

#### Malformed Request Burst
Counts HTTP 400 / 414 / 431 bursts to detect protocol abuse and fuzzers.
```ini
CHALLENGE_MALFORMED_MIN = 15
CHALLENGE_MALFORMED_TTL = 30m
```

#### UA Churn (User-Agent Rotation)
Detects bots rotating User-Agents to evade scoring.
```ini
CHALLENGE_UNIQUA_MIN = 8
CHALLENGE_UNIQUA_TTL = 20m
CHALLENGE_UNIQUA_CAP = 64
```

---

## 9. SSLCollector

CFM includes an **SSLCollector** subsystem that discovers and tracks TLS certificates and
private keys already on the server (e.g. cPanel / Let's Encrypt and other common layouts).
It maintains an in-memory index so CFM and optionally OpenResty can quickly resolve a
hostname/SNI to the correct `cert+key` pair.

The **Challenge Server** uses this via a `GetCertificate` callback so it can present the
correct cert for the hostname requested by the client (SNI-based selection).

### What SSLCollector Does
- Discovers certificates/keys from supported sources and builds an index:
  - Exact hostnames (SAN/CN hostnames found in certs)
  - Wildcard zones (e.g. `*.example.com`)
  - Host → Entry mapping for fast lookup
- Tracks metadata: `cert_path`, `key_path`, `fingerprint`, `not_after`, `source`
- Periodically refreshes via mtime/size checks + scheduled rescans

> **Note:** A wildcard cert like `*.example.com` does **not** cover the apex `example.com`.

### Why a Unix Socket?
- Local-only access
- Optional token auth (`X-SSLCollector-Token`)
- OpenResty can retrieve cert/key even without direct read access to `/etc/letsencrypt/...` or cPanel stores
- Works with `ssl_certificate_by_lua*` + Lua caching

### Configuration (`cfm.conf`)
```ini
SSLCOLLECTOR_SOCK_ENABLE  = 1
SSLCOLLECTOR_SOCK_PATH    = /var/run/sslcollector.sock
SSLCOLLECTOR_SOCK_TOKEN   = supersecret

SSLCOLLECTOR_SOCK_PEM_TTL = 10m
SSLCOLLECTOR_SOCK_PEM_MAX = 50000
```

### Socket API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/stats` | Index statistics |
| `GET` | `/cert?host=<hostname>` | Retrieve cert+key for hostname |
| `POST` | `/refresh` | Trigger a rescan |

### Examples
```bash
# Stats
curl --unix-socket /var/run/sslcollector.sock \
  -H 'X-SSLCollector-Token: supersecret' \
  'http://localhost/stats'

# Cert lookup
curl --unix-socket /var/run/sslcollector.sock \
  -H 'X-SSLCollector-Token: supersecret' \
  'http://localhost/cert?host=example.com' | head

# Force refresh
curl --unix-socket /var/run/sslcollector.sock \
  -H 'X-SSLCollector-Token: supersecret' \
  -X POST 'http://localhost/refresh' -i
```

---

## 10. CLI Reference – `cfm webtop`

```bash
cfm webtop                       # summary (short + suspicious)
cfm webtop top 20                # top 20 vhosts by RPS
cfm webtop top 20 5xx            # sort by 5xx error rate
cfm webtop --limit 15 --sort err # sort by error ratio
cfm webtop <vhost>               # drilldown into a vhost

cfm webtop long 30               # long-window top by score
cfm webtop ip 50                 # global IP view
cfm webtop ip 1.2.3.4            # drilldown a specific IP

cfm webtop analyze <ip|host>     # offline drilldown from TSV (debug/forensics)
```

**Sort keys:** `rps`, `2xx`, `3xx`, `4xx`, `5xx`, `uniq`, `err`, `rt`, `bot`, `ua_div`, `score`

---

## 11. Web Detector HTTP API

The Web Detector exposes a local API used by the CLI and integrations (`API_LISTEN`).

| Endpoint | Description |
|---|---|
| `GET /api/v1/webdet/top-short` | Short-window vhost top |
| `GET /api/v1/webdet/suspicious` | Suspicious vhosts |
| `GET /api/v1/webdet/drilldown?host=<vhost>` | Vhost drilldown |
| `GET /api/v1/webdet/hot-ips?limit=20` | Top IPs (short window) |
| `GET /api/v1/webdet/long-top?limit=50` | Long-window top |
| `GET /api/v1/webdet/ip-short?limit=50` | IP short view |
| `GET /api/v1/webdet/ip-drilldown?ip=<ip>` | IP drilldown |
| `GET /api/v1/webdet/analyze-ip?ip=<ip>` | Analyze IP (forensics) |
| `GET /api/v1/webdet/analyze-host?host=<vhost>` | Analyze vhost (forensics) |

---

## 12. Appendix: cfm.conf Snippets

Representative snippets showing typical real-world setups.

### nftables Hook Ordering
```ini
NFT_INPUT_PRIORITY = -50
```

### Logging
```ini
LOG_STDOUT = "1"
LOG_FILE   = "/var/log/cfm/cfm.log"

API_LOG_STDOUT = "0"
API_LOG_FILE   = "/var/log/cfm/cfm.api.log"

DETECTOR_LOG_STDOUT = "0"
DETECTOR_LOG_FILE   = "/var/log/cfm/cfm.detector.log"

CHALLENGES_LOG_STDOUT = 0
CHALLENGES_LOG_FILE   = /var/log/cfm/cfm.challenges.log
```

### Debug Server (pprof + debug endpoints)
```ini
LISTEN_ADDRESS = "0.0.0.0"
PORT = 6060
```

### MaxMind Updater
```ini
MAXMIND_ENABLED      = 1
MAXMIND_ACCOUNT_ID   = 000000
MAXMIND_LICENSE_KEY  = maxmind_key
MAXMIND_EDITIONS     = GeoLite2-ASN,GeoLite2-City
MAXMIND_DIR          = /var/lib/cfm/maxmind
MAXMIND_CHECK_EVERY  = 24h
MAXMIND_MIN_AGE      = 72h
MAXMIND_HTTP_TIMEOUT = 30s
```

### ConnLimit (examples)
```ini
CONNLIMIT = "80;150,443;200"
CONNLIMIT = "25;60,465;60,587;60"
CONNLIMIT = "143;90,993;100"
CONNLIMIT = "110;100,995;100"
CONNLIMIT = "21;90,990;90"
CONNLIMIT = "22;50,3306;50,53;80,65535;80"
```

### PortFlood (examples)
```ini
PORTFLOOD = "80;tcp;60;160,443;tcp;60;220"
PORTFLOOD = "25;tcp;60;80,465;tcp;60;80,587;tcp;60;80"
PORTFLOOD = "143;tcp;60;90,993;tcp;60;90"
PORTFLOOD = "110;tcp;60;90,995;tcp;60;90"
PORTFLOOD = "21;tcp;60;90,990;tcp;60;90"
PORTFLOOD = "3306;tcp;60;50,53;udp;60;100,53;tcp;60;100,65535;tcp;60;100"
```

### Packet Rate Limiting (kernel-only)
```ini
PKT_RATE  = "100"
PKT_BURST = "200"
PKT_MODE  = "syn"
```

### Autoblock from Throttling
```ini
THROTTLE_ENABLED  = "1"
THROTTLE_WINDOW   = "60"
THROTTLE_HITS     = "3"
THROTTLE_MODE     = "permanent"
THROTTLE_TTL      = "86400"
THROTTLE_SOURCES  = "syn,portflood,pps,new,icmp,connlimit"
THROTTLE_SET_TTL  = "60"
THROTTLE_COOLDOWN = "180"
```

### Portscan Tracking (CSF-like)
```ini
PS_INTERVAL   = "30"
PS_LIMIT      = "10"
PS_DIVERSITY  = "1"
PS_TRACK_TCP  = "1"
PS_TRACK_UDP  = "1"
PS_MODE       = "permanent"
PS_TTL        = "3600"
PS_ONLY_PORTS = "0:40000"
```

### System Tweaks (sysctl Hardening)
```ini
SYS_TWEAKS_ENABLE  = "1"
SYS_TWEAKS_PERSIST = "1"

SYS_CT_PER_GB = "12288"
SYS_CT_MIN    = "262144"
SYS_CT_MAX    = "16777216"

SYS_TCP_LOOSE_STRICT   = "1"
SYS_TCP_SYN_RETRIES    = "3"
SYS_TCP_SYNACK_RETRIES = "3"
SYS_TCP_FIN_TIMEOUT    = "20"

SYS_RP_FILTER        = "1"
SYS_ACCEPT_REDIRECTS = "0"
SYS_SEND_REDIRECTS   = "0"
```

### SMTP Block (CSF-like)
```ini
SMTP_BLOCK      = 0
SMTP_PORTS      = 25,465,587
SMTP_ALLOWLOCAL = 1
SMTP_ALLOWUSER  = exim,mailman
SMTP_ALLOWGROUP = mail,mailman

SMTP_LOG        = 1
SMTP_LOG_LIMIT  = 5/second
SMTP_LOG_BURST  = 20
SMTP_LOG_ENRICH = 1

SMTP_LOG_STDOUT = 0
SMTP_LOG_FILE   = /var/log/cfm/cfm.smtp.log
```

---

## 13. Security Notes

- In **DNAT mode**, keep the challenge listeners local-only (`127.0.0.1`). Do not expose them directly to the internet.
- In **OpenResty mode**, treat the unix socket as sensitive — enforce tight file permissions and always use the token.
- When using OpenResty `ssl_certificate_by_lua*`, cache aggressively (shared_dict + lock) and use tight timeouts.
