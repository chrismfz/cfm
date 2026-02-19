# CFM – Configurable Firewall Manager

CFM is a modern **firewall + intrusion detection / prevention manager** written in Go.
It combines nftables policy enforcement, log-driven detection, autoblocking, system hardening, enrichment, and notifications into one daemon.

It includes a **unified Web Detector** (nginx / Apache / LiteSpeed / cPanel domlogs) with:

- live “top” views (per-vhost + global),
- drill-downs (top IPs/UAs/paths/referrers),
- long-window scoring (“suspicious”),
- and an optional **Challenge System** (DNAT redirect → PoW + token + cookie + CID → release).

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

## What CFM is (high level)

### Primary categories
- Firewall manager (**nftables** / table `inet cfm`, CSF-like workflows)
- IDS (log monitoring) + IPS (automatic blocking)
- Connection/rate limiting (ConnLimit / PortFlood / PPS / new-rate controls)
- System hardening (sysctl tweaks, anti-spoofing, conntrack tuning)
- Enrichment (PTR / ASN / ASN name / Country)

### What makes it unique
- Go, single binary, low footprint
- Direct nftables backend (no iptables dependency)
- Very broad detector coverage (SSH / Exim / Dovecot / FTP / MySQL / cPanel / ModSecurity / Web)
- A **Web Detector** that can escalate to **interactive challenge** instead of blunt blocking

---

# ✨ Key Features

## 🔒 Firewall Core
- nftables backend (auto-created table/chains)
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
- Per-detector policies: `dryrun`, `ttl=1h`, `permanent`
- Dedupe suppression for noisy repeats (`host|kind|ip|reason`)
- Unified reasons: `SSH_BRUTE`, `PORTSCAN`, `CONNLIMIT`, `WEB_*`, etc.

---

# 🌐 Unified Web Detector

The Web Detector ingests access logs and keeps:

- a **short sliding window** (for real-time top/drilldown),
- a **long window** (aggregated suspicious scoring + “under attack” signals).

It is designed to support both:
- **visibility** (who is doing what, on which vhost), and
- **action** (challenge/mitigate abusive IPs or under-attack vhosts).

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

Below are examples showing the **main knobs**. Exact section names may differ depending on your detectors loader layout.

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
- **long-window scoring** (stability + under-attack decisions)

Common signals:
- status mix (2xx/3xx/4xx/5xx, 401, 403, 404, 499)
- uniq IP scatter
- median per-IP rate
- bot ratio (simple UA heuristics)
- UA diversity / path diversity
- POST ratio
- failure/error index

The score is used for:
- the **“suspicious”** view (admin visibility)
- optional **automatic vhost “under attack” mode** (see Challenge System)

---

# 🧩 Challenge System (DNAT + PoW + Token + Cookie + CID)

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
   - CID (server-issued challenge id; must match what the sink issued)
5. On solve:
   - IP is removed from challenge set (redirect stops)
   - optional “challenge OK” cooldown prevents loops
   - user is redirected back to original path

## Challenge server listeners
```ini
[webdetector]
CHALLENGE_HTTP_LISTEN  = "127.0.0.1:9080"
CHALLENGE_HTTPS_LISTEN = "127.0.0.1:9443"
```

## PoW defaults
- enabled by default
- typical starting difficulty: **16 bits** (increase gradually if bots pass)
- short TTL tokens

## Challenge triggers (examples)
CFM supports multiple trigger styles (all optional, configurable):

1) **Known-bad paths** (probing/scans)
```ini
CHALLENGE_PATHS       = 1
CHALLENGE_PATHS_FILE  = "/etc/cfm/webdetector_challenge_paths.txt"
CHALLENGE_PATHS_COUNT = 1
CHALLENGE_PATHS_TTL   = "30m"
```

2) **Per-IP rate/ratio behavior**
- total RPS / 4xx RPS / 5xx RPS
- error ratio
- POST ratio
- “no UA” hits, HTTP/1.0 hits
(Set any threshold to `0` to disable.)

3) **Manual vhost-wide challenge**
```ini
CHALLENGE_VHOST        = "victim.com, *.victim.com"
CHALLENGE_VHOST_IGNORE = "api.victim.com"
```

4) **Auto “under attack” mode** (based on long-window score + hysteresis)
```ini
CHALLENGE_SUSPICIOUS_VHOST = 1
CHALLENGE_SUSPICIOUS_VHOST_SCORE_ON  = 0.70
CHALLENGE_SUSPICIOUS_VHOST_SCORE_OFF = 0.60
CHALLENGE_SUSPICIOUS_VHOST_MIN_UNIQIP = 80
CHALLENGE_SUSPICIOUS_VHOST_HOLDDOWN   = "10m"
```

---

# 🔐 TLS for Challenge Server (sslcollector integration)

The Challenge Server can serve HTTPS and choose the correct certificate via **SSLCollector**:

- Challenge HTTPS listener uses a `GetCertificate` callback.
- Certificate selection is driven by SNI and resolved by SSLCollector’s in-memory index.
- This lets the challenge endpoint present the correct cert for the hostname that the client requested.

---

# SSLCollector (CFM) — Certificate Discovery + Unix Socket API for OpenResty

CFM includes an **SSLCollector** subsystem that discovers and tracks TLS certificates and private keys that already exist on the server (e.g. cPanel/Let’s Encrypt and other common layouts). It keeps an in-memory index so other parts of CFM (and optionally OpenResty) can quickly resolve a hostname/SNI to the correct `cert+key` pair.

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

SYS_TCP_LOOSE_STRICT  = "1"
SYS_TCP_SYN_RETRIES   = "3"
SYS_TCP_SYNACK_RETRIES = "3"
SYS_TCP_FIN_TIMEOUT   = "20"

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

- If you enable the Web Challenge system, ensure your nftables rules include the DNAT redirections required by CFM.
- Keep challenge endpoints local-only; do not expose them directly to the internet.
- When using OpenResty `ssl_certificate_by_lua*`, **cache aggressively** (shared_dict + lock) and use tight timeouts.


