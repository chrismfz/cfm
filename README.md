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

# 🛠 Roadmap Additions (Web Detector)
- Configurable suspicious weights  
- Docker log tailer support  
- JSON export of feature vectors  
- Optional full ML integration  
- Notifications for suspicious vhosts  
- Auto-block policies per-host (opt‑in)

---

# 📜 License
MIT
