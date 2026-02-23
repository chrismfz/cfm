# CFM – Configurable Firewall Manager

CFM is a modern Go-based firewall + detection + mitigation daemon.
It combines nftables policy enforcement, log-driven detectors, enrichment, notifications, 
and an HTTP challenge engine that can be enforced either via nftables redirect/DNAT or directly in OpenResty in-path mode through a decision socket.

It includes a **unified Web Detector** (nginx / Apache / LiteSpeed / cPanel domlogs) with:

- live “top” views (per‑vhost + global),
- drill‑downs (top IPs/UAs/paths/referrers),
- long‑window scoring (“suspicious”),
- hard‑block triggers (high‑confidence abuse → block),
- and an optional **Challenge System** (challenge instead of blunt ban) that can run in:
  - **DNAT mode** (nftables redirect → challenge server), or
  - **OpenResty in‑path mode** (no DNAT; OpenResty asks CFM for decisions via unix socket).

More information at: https://infected.gr/category/cfm/

---

## Ready-to-run packages for Debian and EL (AlmaLinux/Rocky/CloudLinux)

### Debian
```bash
wget -qO - https://repo.nixpal.com/debian/nixpal-repo.gpg | gpg --dearmor -o /etc/apt/trusted.gpg.d/nixpal-repo.gpg
wget https://repo.nixpal.com/debian/nixpal.list -O /etc/apt/sources.list.d/nixpal.list
apt update && apt install cfm
```

### EL
```bash
dnf install https://repo.nixpal.com/el/nixpal.rpm
dnf install cfm
```

---

## Repository layout & shipped configuration

CFM ships a set of **reference configs** under `configs/` (packaged to `/usr/share/cfm/configs/`), plus **live configs** under `/etc/cfm/`.

A quick map (from your repo tree):

```text
configs/
  cfm.conf                 # main daemon config (ports policy, nft, sysctl, maxmind, api, logs)
  detectors.conf            # detectors + thresholds + per-section BLOCK policies
  notify.conf               # notifier channels + dedupe + per-detector routing
  cfm.blocklists            # external feed definitions (ALLOW/BLOCK, refresh interval, etc.)
  cfm.allow / cfm.deny      # static allow/deny lists (IP/CIDR/host, depending on build)
  cfm.ignore                # IPs that must never be blocked (global ignore list)
  cfm.dyndns                # hostnames resolved periodically and added to allow
  httpd-cfm.conf            # Apache LogFormat for WebDetector TSV
  nginx-cfm.conf            # nginx log_format for WebDetector TSV (if present in your repo)
  cfm-modsec.conf           # ModSecurity integration (file uploads -> cfm-scan.sh)
  sslcollector.lua          # OpenResty Lua helper for dynamic cert loading (via unix socket)
  trusted_proxies.conf      # real_ip / trusted proxy include for Cloudflare/LB setups
  openresty-example*.conf   # full OpenResty “in-path WAF/challenge” examples (+ optional cache)
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

### What’s worth mentioning (beyond WebDetector)

- **Main config (`cfm.conf`)**: this is where you define:
  - ports policy (`TCP_IN`, `UDP_IN`, `TCP_OUT`, `UDP_OUT`)
  - nftables hook ordering (`NFT_INPUT_PRIORITY`)
  - connection protections (`CONNLIMIT`, `PORTFLOOD`, `PKT_RATE/PKT_BURST`, `NEW_RATE/NEW_BURST`, `ICMP_*`)
  - throttle-to-autoblock glue (`THROTTLE_*`)
  - portscan tracking (`PS_*`)
  - MaxMind updater (`MAXMIND_*`)
  - optional API integration (`API_URL`, `AUTH_TOKEN`, `*_SEND_TO_API`)
  - debug server (`LISTEN_ADDRESS`, `PORT`)

- **Detectors config (`detectors.conf`)**:
  - `[global]` defaults (`DEFAULT_EVERY`, `DEFAULT_TIMEOUT`, `DEFAULT_COOLDOWN`)
  - global ignores (`IGNORE_IPS`, `IGNORE_NETS`, `LOG_IGNORED`)
  - per-detector sections (`[ssh_auth]`, `[mysql]`, `[ftpd]`, `[cpanel]`, `[exim_*]`, `[dovecot_*]`, `[postfix_*]`, `[modsec]`, `[health]`, `[webdetector]`)
  - per-section block policy (`BLOCK = no|dryrun|permanent|<duration>` + `BLOCK_COOLDOWN`)

- **Notifier config (`notify.conf`)**:
  - global notifier on/off + JSONL audit log
  - dedupe keying (`[dedupe]`)
  - channels (`sendmail`, `smtp`, `slack_webhook`)
  - per-detector routing + severity gating (`[detector "..."]`)

- **Blocklists (`cfm.blocklists`)**:
  - defines scheduled pulls of external feeds into allow/block sets

- **DynDNS allow (`cfm.dyndns`)**:
  - hostnames periodically resolved and kept in allow (good for “my dynamic office IP” style workflows)

- **Web log format snippets (`httpd-cfm.conf`, `nginx-cfm.conf`)**:
  - ensures WebDetector sees a consistent TSV schema across stacks

- **ModSecurity upload scanning (`cfm-modsec.conf` + `scripts/cfm-scan.sh`)**:
  - wires ModSecurity file upload temp paths into `cfm-scan.sh` (your local scanner hook)


---

## What CFM is (high level)

### Primary categories
- Firewall manager (**nftables** / table `inet cfm`, CSF‑like workflows)
- IDS (log monitoring) + IPS (automatic blocking)
- Connection/rate limiting (ConnLimit / PortFlood / PPS / new‑rate controls)
- System hardening (sysctl tweaks, anti‑spoofing, conntrack tuning)
- Enrichment (PTR / ASN / ASN name / Country)

### What makes it unique
- Go, single binary, low footprint
- Direct nftables backend (no iptables dependency)
- Very broad detector coverage (SSH / Exim / Dovecot / FTP / MySQL / cPanel / ModSecurity / Web)
- A **Web Detector** that can escalate to an **interactive challenge** instead of always hard blocking

---

# ✨ Key Features

## 🔒 Firewall Core
- nftables backend (auto‑created table/chains)
- Hook priority control (`NFT_INPUT_PRIORITY`) to run before/after other stacks (CSF/Imunify)
- ALLOW/BLOCK sets (v4/v6) + dynamic allow via hostname/DynDNS resolution
- ApplyPortsPolicy from config (`TCP_IN`, `UDP_IN`, etc.)
- SMTP_BLOCK mode (CSF compatible pattern)

## ⚡ Connection Protections
- ConnLimit per port (concurrent connections per IP)
- PortFlood per port (new connection rate limits per IP)
- PPS limits (`PKT_RATE`, `PKT_BURST`, `PKT_MODE`)
- New connection rate limiting (`NEW_RATE`, `NEW_BURST`)
- ICMP rate limiting
- Bad TCP flag filtering (NULL/XMAS/SYN+FIN)

## 🔎 Detection Engine
Detectors parse logs/metrics to spot abuse:
- Exim (queues, auth failures, relay abuse)
- SSH (auth fails, brute)
- Dovecot (auth fails)
- FTP (pure-ftpd / proftpd / vsftpd)
- cPanel logins
- MySQL denied/scanner attempts
- ModSecurity alerts
- Health detector (CPU/RAM/disk/SMART/RAID/ZFS/conntrack spikes)
- **Web Detector** (details below)

## 🚨 Autoblock Engine
- Inserts IPs into nftables sets (TTL or permanent)
- Per‑detector policies: `dryrun`, `ttl=1h`, `permanent`
- Dedupe suppression for noisy repeats (`host|kind|ip|reason`)
- Unified reasons: `SSH_BRUTE`, `PORTSCAN`, `CONNLIMIT`, `WEB_*`, etc.

---

# 🌐 Unified Web Detector

The Web Detector ingests access logs and keeps:

- a **short sliding window** (for real‑time top/drilldown),
- a **long window** (aggregated suspicious scoring + “under attack” signals).

It is designed to support both:
- **visibility** (who is doing what, on which vhost), and
- **action** (challenge/mitigate abusive IPs or under‑attack vhosts).

## ✅ Ingestion modes

### 1) File mode (single TSV log)
Best for nginx/apache custom log formats you control.

### 2) Folder mode (directory tailing)
Best for hosting layouts:
- cPanel domlogs
- DirectAdmin-like layouts
- Any “one file per vhost” layout

Supports recursion + glob filtering.

## 📁 Log line format (TSV)

CFM’s Web Detector uses a normalized TSV line format:

```
ts  ip  host  method  uri  proto  status  bytes  rt  urt  ref  ua
```

Notes:
- `host` is the vhost
- `rt` is request time in seconds
- UA/referrer are normalized for aggregation

Format helpers are typically available under `/usr/share/cfm/` (nginx/apache samples).

---

# 🧭 Web Detector configuration

Below are examples showing the main knobs.

## Example: TSV file mode
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

## Example: folder mode (cPanel domlogs)
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

---

# 🧱 Web abuse hard‑block triggers (new)

These are **high‑confidence** triggers that go straight to the **block set** (instead of challenge), designed for aggressive scanners.

```ini
# many 404s / 403s within WINDOW
IP404_COUNT = 220
IP403_COUNT = 120

# suspicious UAs (comma-separated substrings), and how many hits to consider it abuse
AGENT_LIST  = "python-requests,spider"
AGENT_COUNT = 25

# combined 40x (403/404/405/406/410/429...) + path diversity
IP40X_COMBO = 180
IP40X_UNIQUE_PATHS = 20

# optional: ignore "expected" 40x paths so they don't inflate ratios
IGNORE40X_PREFIXES = "/.well-known/,/robots.txt,/favicon.ico,/sitemap"

# block policy
BLOCK = 1h
BLOCK_COOLDOWN = 30m

# known malicious path substrings (fast path match list)
MALPATH_COUNT = 20
MALPATH_FILE  = /etc/cfm/webdetector_malpaths.txt
```

Notes:
- These counters are evaluated per IP within your `WINDOW`.
- `BLOCK_COOLDOWN` prevents “block/unblock/block” loops for the same noisy bot.
- Keep `IGNORE40X_PREFIXES` limited to truly harmless noise.

---

# 🖥️ CLI: `cfm webtop`

The unified CLI entrypoint is:

```bash
cfm webtop
```

## Common usage
```bash
cfm webtop                       # summary (short + suspicious)
cfm webtop top 20                # top 20 vhosts by RPS
cfm webtop top 20 5xx            # sort by 5xx
cfm webtop --limit 15 --sort err # sort by error ratio
cfm webtop <vhost>               # drilldown into a vhost

cfm webtop long 30               # long-window top by score
cfm webtop ip 50                 # global IP view
cfm webtop ip 1.2.3.4            # drilldown IP

cfm webtop analyze <ip|host>     # offline drilldown from TSV (debug/forensics)
```

Sort keys:
`rps, 2xx, 3xx, 4xx, 5xx, uniq, err, rt, bot, ua_div, score`

---

# 🔌 Web Detector HTTP API

The Web Detector exposes a local API (used by the CLI and integrations).

Typical endpoints:
- `GET /api/v1/webdet/top-short`
- `GET /api/v1/webdet/suspicious`
- `GET /api/v1/webdet/drilldown?host=<vhost>`
- `GET /api/v1/webdet/hot-ips?limit=20`
- `GET /api/v1/webdet/long-top?limit=50`
- `GET /api/v1/webdet/ip-short?limit=50`
- `GET /api/v1/webdet/ip-drilldown?ip=<ip>`
- `GET /api/v1/webdet/analyze-ip?ip=<ip>`
- `GET /api/v1/webdet/analyze-host?host=<vhost>`

---

# 🚨 Suspicious scoring (short + long)

CFM keeps:
- **short-window signals** (live visibility)
- **long-window scoring** (stability + under‑attack decisions)

Common signals:
- status mix (2xx/3xx/4xx/5xx, 401, 403, 404, 499)
- uniq IP scatter
- median per‑IP rate
- bot ratio (simple UA heuristics)
- UA diversity / path diversity
- POST ratio
- failure/error index

The score is used for:
- the **“suspicious”** view (admin visibility)
- optional **automatic vhost “under attack” mode** (see Challenge System)

---

# 🧩 Challenge System (DNAT mode)

CFM can respond to web abuse with an **interactive challenge** instead of blunt blocking.
This is useful when:
- traffic is high but not trivially blockable (CGNAT / shared NATs),
- you want a reversible “speedbump” before banning,
- you want to slow automated clients without punishing everyone.

## Flow (high level)
1. Web Detector decides an IP (or vhost) should be challenged.
2. Firewall inserts the IP into a **challenge set**.
3. nftables **DNAT redirects** that IP’s HTTP/HTTPS to the local Challenge Server.
4. Browser receives a challenge page and must pass:
   - cookie
   - HMAC token (bound to IP + UA + cookie)
   - PoW (bound to UA + cookie)
   - CID (server‑issued challenge id; must match what the sink issued)
5. On solve:
   - IP is removed from challenge set (redirect stops)
   - `CHALLENGE_COOLDOWN` prevents loops
   - user is redirected back to original path

## Challenge server listeners
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

## Challenge triggers (examples)

### 1) Known-bad paths (probing/scans)
```ini
CHALLENGE_PATHS       = 1
CHALLENGE_PATHS_FILE  = /etc/cfm/webdetector_challenge_paths.txt
CHALLENGE_PATHS_COUNT = 1
CHALLENGE_PATHS_TTL   = 10m
```

### 2) Per-IP behavior thresholds
All are optional. Set any value to `0` to disable.

```ini
CHALLENGE_RPS_TOTAL_MIN = 20.0
CHALLENGE_RPS_4XX_MIN   = 12.0
CHALLENGE_RPS_5XX_MIN   = 0.9
CHALLENGE_ERR_RATIO_MIN = 0.99
CHALLENGE_POST_RATIO_MIN = 0
CHALLENGE_NO_UA_MIN      = 5
CHALLENGE_HTTP10_MIN     = 1
```

### 3) Per‑vhost challenge modes (manual + auto)

Manual “panic mode”:
```ini
CHALLENGE_VHOST        = victim.com, *.victim.com, www.nixpal.com
CHALLENGE_VHOST_IGNORE = api.mybank.gr
```

Absolute bypass (wins over everything):
```ini
CHALLENGE_HOST_BYPASS = api.mybank.gr, health.victim.com, *.internal.victim.com
```

Auto “under attack” mode (based on long‑window score + hysteresis):
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

## Challenge abuse protection (new)

Some bots will hammer the challenge endpoint itself. This protection watches **challenge responses** and blocks abusers.

```ini
CHALLENGE_ABUSE_ENABLED    = 1
CHALLENGE_ABUSE_WINDOW     = 10s
CHALLENGE_ABUSE_BAD_N      = 15
CHALLENGE_ABUSE_BLOCK_TTL  = 1h
CHALLENGE_ABUSE_COOLDOWN   = 30m
```

---

# 🌉 OpenResty in‑path mode (no DNAT) (new)

When `OPENRESTY_MODE=1`, CFM stops relying on per‑IP DNAT redirects. Instead, OpenResty decides at request time by asking CFM over a **unix socket**.

Benefits:
- no DNAT tables/rules management per IP
- decisions apply immediately (allow/challenge/block)
- easier per‑vhost “under attack” behavior

## Socket API (served by CFM, consumed by Lua)

All requests require:
- header `X-CFM-Token: <OPENRESTY_TOKEN>`

Endpoints:

- `GET  /nginx/decision?ip=1.2.3.4&host=example.com`
  - returns JSON like:
    - `{"ip_action":"allow|challenge|block","vhost_action":"allow|challenge"}`

- Push/clear overrides:
  - `POST /nginx/ip          {"ip":"1.2.3.4","action":"challenge|block","ttl_sec":600}`
  - `POST /nginx/ip/clear    {"ip":"1.2.3.4"}`
  - `POST /nginx/vhost       {"host":"example.com","action":"challenge","ttl_sec":600}`
  - `POST /nginx/vhost/clear {"host":"example.com"}`

- Debug:
  - `GET  /nginx/status` (active pushes + stats)

Config:
```ini
OPENRESTY_MODE  = 1
OPENRESTY_SOCK  = /var/run/cfm/cfm_nginx.sock
OPENRESTY_TOKEN = cfm

# When OpenResty sees a challenge solved, it can cache the OK IP locally.
OPENRESTY_OK_IP_TTL = 15m
```

---

# 🔐 TLS for Challenge Server (sslcollector integration)

The Challenge Server can serve HTTPS and choose the correct certificate via **SSLCollector**:

- Challenge HTTPS listener uses a `GetCertificate` callback.
- Certificate selection is driven by SNI and resolved by SSLCollector’s in‑memory index.
- This lets the challenge endpoint present the correct cert for the hostname that the client requested.

---

# SSLCollector (CFM) — Certificate Discovery + Unix Socket API for OpenResty

CFM includes an **SSLCollector** subsystem that discovers and tracks TLS certificates and private keys that already exist on the server (e.g. cPanel/Let’s Encrypt and other common layouts).
It keeps an in‑memory index so other parts of CFM (and optionally OpenResty) can quickly resolve a hostname/SNI to the correct `cert+key` pair.

## What SSLCollector does
- Continuously discovers certificates/keys from supported sources and builds an index:
  - Exact hostnames (SAN/CN hostnames found in certs)
  - Wildcard zones (e.g. `*.example.com`)
  - Host → Entry mapping for fast lookup
- Tracks metadata (`cert_path`, `key_path`, `fingerprint`, `not_after`, `source`)
- Periodically refreshes via mtime/size checks + scheduled rescans

> Note: A wildcard cert like `*.example.com` does **not** cover the apex `example.com`.

## Unix socket API (Purpose)
Exposes SSLCollector over a **local-only** HTTP interface via a Unix domain socket, so OpenResty can dynamically load the correct certificate for a given **SNI** during TLS handshake.

### Why a socket (instead of files)?
- Local-only access via Unix socket
- Optional token auth (`X-SSLCollector-Token`)
- OpenResty can retrieve cert/key even if it does not have read permissions on `/etc/letsencrypt/...` or cPanel stores
- Works well with `ssl_certificate_by_lua*` + Lua caching

## Configuration (cfm.conf)
```ini
SSLCOLLECTOR_SOCK_ENABLE   = 1
SSLCOLLECTOR_SOCK_PATH     = /var/run/sslcollector.sock
SSLCOLLECTOR_SOCK_TOKEN    = supersecret

SSLCOLLECTOR_SOCK_PEM_TTL  = 10m
SSLCOLLECTOR_SOCK_PEM_MAX  = 50000
```

## Socket API endpoints
- `GET /stats`
- `GET /cert?host=<hostname>`
- `POST /refresh`

## Examples (curl)
```bash
curl --unix-socket /var/run/sslcollector.sock \
  -H 'X-SSLCollector-Token: supersecret' \
  'http://localhost/stats'
```

```bash
curl --unix-socket /var/run/sslcollector.sock \
  -H 'X-SSLCollector-Token: supersecret' \
  'http://localhost/cert?host=example.com' | head
```

```bash
curl --unix-socket /var/run/sslcollector.sock \
  -H 'X-SSLCollector-Token: supersecret' \
  -X POST \
  'http://localhost/refresh' -i
```

---

# 🛠 Appendix: cfm.conf snippets (real-world example)

Below are representative snippets (trimmed) showing typical server setups.

## nftables hook ordering
```ini
NFT_INPUT_PRIORITY = -50
```

## Logging
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

## Debug server (pprof + debug endpoints)
```ini
LISTEN_ADDRESS = "0.0.0.0"
PORT = 6060
```

## MaxMind updater
```ini
MAXMIND_ENABLED=1
MAXMIND_ACCOUNT_ID=000000
MAXMIND_LICENSE_KEY=maxmind_key
MAXMIND_EDITIONS=GeoLite2-ASN,GeoLite2-City
MAXMIND_DIR=/var/lib/cfm/maxmind
MAXMIND_CHECK_EVERY=24h
MAXMIND_MIN_AGE=72h
MAXMIND_HTTP_TIMEOUT=30s
```

## ConnLimit (examples)
```ini
CONNLIMIT="80;150,443;200"
CONNLIMIT="25;60,465;60,587;60"
CONNLIMIT="143;90,993;100"
CONNLIMIT="110;100,995;100"
CONNLIMIT="21;90,990;90"
CONNLIMIT="22;50,3306;50,53;80,65535;80"
```

## PortFlood (examples)
```ini
PORTFLOOD="80;tcp;60;160,443;tcp;60;220"
PORTFLOOD="25;tcp;60;80,465;tcp;60;80,587;tcp;60;80"
PORTFLOOD="143;tcp;60;90,993;tcp;60;90"
PORTFLOOD="110;tcp;60;90,995;tcp;60;90"
PORTFLOOD="21;tcp;60;90,990;tcp;60;90"
PORTFLOOD="3306;tcp;60;50,53;udp;60;100,53;tcp;60;100,65535;tcp;60;100"
```

## Packet rate limiting (kernel-only)
```ini
PKT_RATE  = "100"
PKT_BURST = "200"
PKT_MODE  = "syn"
```

## Autoblock from throttling (PPS/SYN/ConnLimit/PortFlood/etc.)
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

## Portscan tracking (CSF-like)
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

## System tweaks (sysctl hardening)
```ini
SYS_TWEAKS_ENABLE   = "1"
SYS_TWEAKS_PERSIST  = "1"

SYS_CT_PER_GB       = "12288"
SYS_CT_MIN          = "262144"
SYS_CT_MAX          = "16777216"

SYS_TCP_LOOSE_STRICT   = "1"
SYS_TCP_SYN_RETRIES    = "3"
SYS_TCP_SYNACK_RETRIES = "3"
SYS_TCP_FIN_TIMEOUT    = "20"

SYS_RP_FILTER        = "1"
SYS_ACCEPT_REDIRECTS = "0"
SYS_SEND_REDIRECTS   = "0"
```

## SMTP block (CSF-like)
```ini
SMTP_BLOCK        = 0
SMTP_PORTS        = 25,465,587
SMTP_ALLOWLOCAL   = 1
SMTP_ALLOWUSER    = exim,mailman
SMTP_ALLOWGROUP   = mail,mailman

SMTP_LOG          = 1
SMTP_LOG_LIMIT    = 5/second
SMTP_LOG_BURST    = 20
SMTP_LOG_ENRICH   = 1

SMTP_LOG_STDOUT   = 0
SMTP_LOG_FILE     = /var/log/cfm/cfm.smtp.log
```

---

## Notes

- In **DNAT mode**, keep the challenge listeners local-only; do not expose them directly to the internet.
- In **OpenResty mode**, treat the unix socket as sensitive (permissions + token).
- When using OpenResty `ssl_certificate_by_lua*`, **cache aggressively** (shared_dict + lock) and use tight timeouts.
