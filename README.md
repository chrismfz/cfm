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
10. [MySQL Governor](#10-mysql-governor)
    - [Overview](#overview)
    - [MySQL Grants](#mysql-grants)
    - [Operating Modes](#operating-modes)
    - [Dedicated Log Channel](#dedicated-log-channel)
    - [Connection Pressure](#connection-pressure)
    - [Lock Fan-out Kill](#lock-fan-out-kill)
    - [Query Rules — QUERY_RULES](#query-rules--query_rules)
    - [Connection Limit Rules — CONN_RULES](#connection-limit-rules--conn_rules)
    - [Sleep Reaper](#sleep-reaper)
    - [Kill Rate Limiting](#kill-rate-limiting)
    - [CPU and Performance Tracking](#cpu-and-performance-tracking)
    - [CLI Reference — cfm mysqltop](#cli-reference--cfm-mysqltop)
    - [HTTP API](#http-api)
    - [Full detectors.conf Example](#full-detectorsconf-example)
11. [CLI Reference – `cfm webtop`](#11-cli-reference--cfm-webtop)
12. [Web Detector HTTP API](#12-web-detector-http-api)
13. [Appendix: cfm.conf Snippets](#13-appendix-cfmconf-snippets)
14. [Security Notes](#14-security-notes)

---

## 1. What is CFM?

CFM is a **unified L3–L7 enforcement platform** — a single Go binary with a direct nftables
backend and no iptables dependency.

| Layer | Function |
|---|---|
| L3/L4 | Firewall, IDS/IPS, connection/rate limiting, system hardening |
| L7 | Behavioral Web Detection, OWASP-inspired WAF, Interactive Challenge Engine |
| MySQL | Processlist governor, runaway query kill, connection-limit enforcement |
| Support | Enrichment (PTR / ASN / Country), TLS-aware smart bridge, notifications |

**What makes it unique:**
- Single Go binary, low footprint
- Direct nftables backend (no iptables dependency)
- Broad detector coverage: SSH, Exim, Dovecot, FTP, MySQL, cPanel, ModSecurity, Web
- Web Detector that can escalate to an **interactive challenge** instead of always hard-blocking
- MySQL Governor that can kill runaway queries and enforce per-user connection limits
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
  cfm-admin.htpasswd        # optional OpenResty /cfm-admin BasicAuth file (shipped empty)
  httpd-cfm.conf            # Apache LogFormat for WebDetector TSV
  nginx-cfm.conf            # nginx log_format for WebDetector TSV
  cfm-modsec.conf           # ModSecurity integration (file uploads → cfm-scan.sh)
  sslcollector.lua          # OpenResty Lua helper for dynamic cert loading (via unix socket)
  trusted_proxies.conf      # real_ip / trusted proxy include for Cloudflare/LB setups
  openresty-example*.conf   # full OpenResty "in-path WAF/challenge" examples (+ optional cache)
  webdetector_*.txt         # webdetector path lists: challenge_paths, malpaths, exclude, etc.
  
  webui/cfm-admin/          # starter Vue-based /cfm-admin dashboard (WebTop MVP)
  docs/cfm-admin-webtop.md  # deployment/auth notes for /cfm-admin
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
- MySQL governor log: `MYSQL_LOG_STDOUT`, `MYSQL_LOG_FILE`

### `detectors.conf` — Detection engine
- `[global]` defaults: `DEFAULT_EVERY`, `DEFAULT_TIMEOUT`, `DEFAULT_COOLDOWN`
- Global ignores: `IGNORE_IPS`, `IGNORE_NETS`, `LOG_IGNORED`
- Per-detector sections: `[ssh_auth]`, `[mysql]`, `[mysql_governor]`, `[ftpd]`, `[cpanel]`, `[exim_*]`, `[dovecot_*]`, `[postfix_*]`, `[modsec]`, `[health]`, `[webdetector]`
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
- **MySQL Governor** (processlist monitor, runaway query kill, connection-limit enforcement — see [§10](#10-mysql-governor))
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

```ini
[webdetector]
ENABLED  = 1
MODE     = file
LOG_PATH = /var/log/nginx/access_cfm_tsv.log

# Folder mode (cPanel domlogs):
# MODE    = folder
# LOG_DIR = /usr/local/apache/domlogs
# GLOB    = *
# START_AT_END = 1   ; 1=tail only new lines (default), 0=replay existing lines once
```

### Web Abuse Hard-Block Triggers

| Trigger | Key | Description |
|---|---|---|
| `IP_RPS` | RPS per IP | Raw request rate |
| `IP_404` | 404s per IP | Scanner / path-probe |
| `IP_403` | 403s per IP | WAF/auth block rate |
| `MALPATH` | malicious path hits | Paths matching malpaths list |
| `AGENT` | UA blacklist hits | Matching agent_list |
| `40X_COMBO` | 403+404 combos | Probing pattern |

### Suspicious Scoring

The long-window scorer combines: RPS, error ratio, 4xx/5xx rates, unique path diversity, bot signals, UA diversity, and request-time anomalies into a single score. Vhosts above `MIN_SCORE` are flagged and can trigger automatic challenge activation.

---

## 7. Challenge System

The Challenge System intercepts HTTP(S) traffic and presents a browser-solvable challenge (JS proof-of-work / cookie check) before forwarding requests to the origin.

### DNAT Mode

```
Client → nftables DNAT → CFM challenge listener → (pass) → origin
```

Configured via `CHALLENGE_HTTP_LISTEN` / `CHALLENGE_HTTPS_LISTEN`. Keep listeners on `127.0.0.1`.

### Challenge Triggers

- Automatic: vhost score exceeds threshold + minimum unique IPs
- Manual: `cfm webtop challenge on <vhost>`
- Path-based: paths matching `CHALLENGE_PATHS_FILE`
- IP-based: unique path count or unique host count per IP

### Challenge Abuse Protection

`CHALLENGE_ABUSE_ENABLED = 1` blocks IPs that repeatedly fail challenges within a short window — stops bots that retry challenge endpoints as a DoS vector.

---

## 8. OpenResty In-Path Mode

### Architecture

```
Client → OpenResty (cfm decision socket) → (challenge/block/pass) → upstream
```

No DNAT required. CFM exposes a unix socket (`OPENRESTY_SOCK`). The Lua layer queries it per-request.

### Smart Lua WAF Layer

The included `openresty-example.conf` Lua block implements:
- IP block set lookup (cfm nft sets)
- Challenge cookie validation
- Real-time cfm decision socket query
- Optional cache via `shared_dict`

`configs/cfm_waf.lua` also includes staged payload detectors with per-rule modes
(`disabled|logonly|challenge|block`). Two body-focused rules are designed to be
deployed conservatively:

- `rule_b64_injection` (default `logonly`): scans base64-looking POST values,
  decodes them, then checks decoded content for webshell / XSS / SQLi markers.
- `rule_php_webshell_body` (default `logonly`): scored raw-PHP body detector
  for snippets such as `<?php system($_GET['cmd']); ?>`,
  `<?php @eval($_POST['x']); ?>`, and `<?php passthru($_REQUEST['c']); ?>`.
  It only evaluates textual body types and requires multiple signals
  (PHP tag + dangerous callable + superglobal/statement shape) to reduce false positives.

Recommended rollout: keep both in `logonly`, review emitted
`WAF_B64_INJECT:*` and `WAF_PHP_WEBSHELL_BODY:*` tags for your traffic, then
promote to `challenge` or `block` once clean.

### Advanced Challenge Rules

The `webdetector_challenge_rules.conf` system supports per-IP, per-vhost, per-UA, and per-ASN matching with TTL-based actions (`challenge`, `block`, `allow`). Rules are evaluated in priority order and can reference enrichment data (ASN, PTR, country).

---

## 9. SSLCollector

SSLCollector discovers TLS certificates from the filesystem (cPanel, Plesk, DirectAdmin layouts) and exposes them via a unix socket for dynamic loading in OpenResty (`ssl_certificate_by_lua*`).

```ini
SSLCOLLECTOR_SOCK_ENABLE = 1
SSLCOLLECTOR_SOCK_PATH   = /run/cfm/sslcollector.sock
SSLCOLLECTOR_SOCK_TOKEN  = your_token_here
```

The companion `sslcollector.lua` handles Lua-side cert loading with shared_dict caching and lock-based deduplication.

---

## 10. MySQL Governor

The MySQL Governor is a processlist monitor and enforcement engine that runs inside cfm. It polls `information_schema.PROCESSLIST` every few seconds and can: notify on slow queries, kill runaway queries, enforce per-user connection caps, reap idle sleeping connections, and track per-user CPU usage.

It operates entirely through a standard MySQL connection — no agent, no plugin, no kernel module required.

### Overview

Two complementary detectors cover MySQL:

| Section | What it does |
|---|---|
| `[mysql]` | Reads the **error log** for failed auth attempts. Blocks brute-force IPs via nft. No DB connection needed. |
| `[mysql_governor]` | Connects to MySQL live. Monitors the **processlist** every poll tick. Kills runaway queries and enforces connection limits. |

### MySQL Grants

The governor needs a dedicated account. Create it once:

```sql
-- Both MariaDB and MySQL 5.7+
CREATE USER 'cfm_governor'@'localhost' IDENTIFIED BY 'strongpassword';
GRANT PROCESS ON *.* TO 'cfm_governor'@'localhost';

-- MySQL 8.0+ also needs:
GRANT CONNECTION_ADMIN ON *.* TO 'cfm_governor'@'localhost';

-- For CONN_RULES alter_user action (dynamic connection caps):
GRANT CREATE USER ON *.* TO 'cfm_governor'@'localhost';
```

Credentials are auto-detected in this order:
1. `DSN =` in `detectors.conf` (explicit override)
2. `/root/.my.cnf` (standard cPanel / server root)
3. `/etc/cfm/mysql_governor.cnf`
4. `/usr/local/directadmin/conf/mysql.conf` (DirectAdmin)

### Operating Modes

```ini
MODE = monitor   # observe and log "WOULD_KILL …" — never issues actual kills (safe default)
MODE = enforce   # live kills + ALTER USER
```

Start in `monitor` mode for at least a week. Review `cfm mysqltop kills` and `/var/log/cfm/cfm.mysql.log` to validate that the rules match your expectations before switching to `enforce`.

The following users are **always exempt** regardless of rules — they can never be killed:
`root`, `cpanel`, `cpanelroundcube`, `cpaneleximscanner`, `da_admin`, `debian-sys-maint`,
`proxysql_monitor`, `mysql.sys`, `mysql.session`, `mariadb.sys`, `event_scheduler`.

### Dedicated Log Channel

All governor activity is written to a separate log file, independent of the main cfm log:

```ini
# In cfm.conf:
MYSQL_LOG_STDOUT = 0
MYSQL_LOG_FILE   = /var/log/cfm/cfm.mysql.log
```

If `MYSQL_LOG_FILE` is not set, log lines are auto-derived from the main `LOG_FILE` path (e.g. `/var/log/cfm/cfm.log` → `/var/log/cfm/cfm.mysql.log`).

Example log output (enforce mode):
```
2026-03-05 17:15:29 [mysql/governor] KILL QUERY pid=3321367 user=mathemat_db db=mathemat_mkportal runtime=90s reason="rule: kill_query runtime=90s" unblocked=315 result=OK
2026-03-05 17:15:30 [mysql/conn_limit] REAP_SLEEP pid=3344003 user=mediains_db idle=2129s excess=12 result=OK
2026-03-05 17:20:01 [mysql/conn_limit] ALTER_USER user=mathemat_db MAX_USER_CONNECTIONS=80 applied
```

### Connection Pressure

The governor tracks global connection usage as a percentage of `@@max_connections` and fires alerts at two thresholds:

```ini
CONN_WARN_PCT = 70   # notify at 70% of max_connections
CONN_ACT_PCT  = 85   # act (sleep reaper, dynamic CONN_RULES) at 85%
```

Alerts are rate-limited to once per 5 minutes per severity level to avoid notification storms during sustained pressure events.

### Lock Fan-out Kill

The lock fan-out rule is an independent safety net that fires regardless of `QUERY_RULES`. When a single query is blocking `>= N` other queries and has been running for at least `TTL`, it is killed immediately:

```ini
LOCK_FANOUT_KILL = 20   # kill blocker when it holds >= 20 waiters
LOCK_FANOUT_TTL  = 60s  # must have been running for >= 60s first
```

This rule exists specifically to prevent table-lock cascade incidents (the kind where a single phpBB full-text search query holds 315 connections hostage until the server requires a manual MySQL restart).

### Query Rules — QUERY_RULES

`QUERY_RULES` is a multiline block evaluated per running query every poll tick. Rules are evaluated top-to-bottom; the first match for a given query wins.

```ini
QUERY_RULES =
    <user_pattern> : <max_runtime> : <action> [: condition]
```

| Field | Values |
|---|---|
| `user_pattern` | Exact username, `prefix*`, `*suffix`, `*contains*`, or `*` for everyone |
| `max_runtime` | Duration (`30s`, `5m`, `1h`) or `0` to never touch this user (`ignore`) |
| `action` | `notify` \| `kill_query` \| `kill_connection` \| `ignore` |
| `condition` | `lock_fanout=N` — only fire if blocking >= N others |
| | `conn_pct=N` — only fire if global connections >= N% |

**Pattern matching:**
- `mathemat_db` — exact match
- `mediains_*` — matches any user starting with `mediains_`
- `*_wp*` — matches any user containing `_wp` (e.g. `happykids_wp861`)
- `*_mage*` — matches any user containing `_mage`
- `*` — matches everyone (use last, as the catch-all)

**Actions:**
- `notify` — enqueues a `MYSQL/GOVERNOR warn` alert. Does not kill.
- `kill_query` — issues `KILL QUERY id`. The statement dies but the connection stays open. The application sees an error and can retry.
- `kill_connection` — issues `KILL id`. The connection is dropped entirely. Use for connection-leak users.
- `ignore` — hard exemption. Used with `max_runtime=0` to protect long-running cron/import jobs.

**Example ladder for a phpBB tenant:**
```ini
QUERY_RULES =
    *_cron      : 0    : ignore        ; never touch internal cron jobs
    mathemat_db : 50s  : notify        ; warn early
    mathemat_db : 60s  : kill_query   : lock_fanout=5   ; kill if already blocking
    mathemat_db : 90s  : kill_query                     ; kill unconditionally
    mediains_*  : 20m  : notify
    mediains_*  : 30m  : kill_query
    *_mage*     : 5m   : notify
    *_mage*     : 15m  : kill_query   : lock_fanout=3
    *_mage*     : 30m  : kill_query
    *_wp*       : 30s  : notify
    *_wp*       : 60s  : kill_query
    *           : 5m   : notify
    *           : 15m  : kill_query
```

### Connection Limit Rules — CONN_RULES

`CONN_RULES` is a separate multiline block evaluated per-user against total connection counts each poll tick. Independent from `QUERY_RULES` — both run on every poll.

```ini
CONN_RULES =
    <user_pattern> : max=N : <action> [: conn_pct=N]
```

| Field | Values |
|---|---|
| `user_pattern` | Same wildcard rules as `QUERY_RULES` |
| `max=N` | Total connection cap (sleeping + active + locked) |
| `action` | `notify` \| `reap_sleep` \| `alter_user` |
| `conn_pct=N` | Optional: only enforce when global connections >= N% (dynamic cap). Omit for always-active (static). |

**Actions:**

`notify` — alert only. No kills. Use to observe baselines before enforcing.

`reap_sleep` — when a user exceeds their cap, kill their oldest sleeping connections (by idle time) until back under the limit. The InnoDB open-transaction guard is always applied: a sleeping connection with an open transaction is never killed.

`alter_user` — issues `ALTER USER 'x'@'%' WITH MAX_USER_CONNECTIONS N` so MariaDB itself refuses new connections beyond the cap at the protocol level. Also falls through to `reap_sleep` to clean up existing sleeping connections already over the cap. Reversed automatically (set back to 0) when the user drops back under their limit. Requires `GRANT CREATE USER` on the `cfm_governor` account.

**Static vs dynamic caps:**

A rule without `conn_pct` is always active. A rule with `conn_pct=70` only activates when the server reaches 70% of `max_connections` and deactivates when it drops back below. Dynamic caps are useful as pressure-release valves without constantly restricting tenants during normal operation.

**Example CONN_RULES for shared hosting:**
```ini
CONN_RULES =
    mathemat_db : max=80  : alter_user              ; hard cap via MariaDB itself
    mediains_*  : max=40  : reap_sleep              ; reap sleepers over limit
    *_mage*     : max=60  : notify                  ; observe Magento first
    *_wp*       : max=30  : notify                  ; observe WordPress first
    *           : max=25  : reap_sleep : conn_pct=70 ; dynamic valve under pressure
```

### Sleep Reaper

The sleep reaper is a global sweep separate from `CONN_RULES`. It kills sleeping connections older than `SLEEP_REAPER_AGE` across all users when global connections exceed `CONN_ACT_PCT`. The InnoDB open-transaction guard is always applied.

```ini
SLEEP_REAPER        = 1
SLEEP_REAPER_AGE    = 180s
SLEEP_REAPER_EXEMPT = proxysql_monitor, root
```

The sleep reaper only activates in `enforce` mode and only when connection pressure exceeds `CONN_ACT_PCT`. It is a last-resort mechanism for connection-pool leaks (WP plugins, PHP without persistent connection cleanup, Magento reindexers). For targeted cleanup, use `CONN_RULES reap_sleep` instead.

### Kill Rate Limiting

A hard rate limit prevents a misconfigured rule from wiping out a tenant's entire connection pool:

```ini
KILL_PER_DB_PER_WINDOW = 8    # max kills for a single DB user in the window
KILL_TOTAL_PER_WINDOW  = 30   # max kills across all users in the window
KILL_WINDOW            = 10m  # rolling window duration
```

This limit applies to both `QUERY_RULES` kills and `CONN_RULES reap_sleep` kills. When the limit is reached, the governor logs a rate-limit warning and skips further kills until the window expires.

### CPU and Performance Tracking

The governor tracks per-user CPU and query statistics from `performance_schema` (MySQL 8+) or `information_schema.USER_STATISTICS` (MariaDB with `userstat=ON`). Three paths are supported:

| Path | Database | Requirements |
|---|---|---|
| A | MySQL 8+ | `performance_schema=ON` + statement instruments enabled |
| B | MariaDB | `performance_schema=ON` + `userstat=ON` |
| C | MariaDB fallback | `performance_schema=ON`, `userstat=OFF` (query count only, no CPU) |

The governor auto-detects which path is available at startup and retries every 5 minutes after a MySQL restart.

**To enable CPU tracking on MariaDB (Path B):**
```sql
SET GLOBAL userstat = ON;
-- Make permanent in /etc/my.cnf: userstat = ON
```

**To enable CPU tracking on MySQL 8+ (Path A):**
```sql
UPDATE performance_schema.setup_instruments SET ENABLED='YES', TIMED='YES' WHERE NAME LIKE 'statement/%';
UPDATE performance_schema.setup_consumers  SET ENABLED='YES'               WHERE NAME LIKE 'events_statements%';
```

CPU data is visible via `cfm mysqltop cpu` and the `/api/v1/mysql/cpu` endpoint.

### CLI Reference — cfm mysqltop

```bash
cfm mysqltop                        # live summary: connections, per-user table, lock graph, recent kills
cfm mysqltop top [N]                # top N users by connection count (live)
cfm mysqltop locks                  # lock graph — blockers and their waiters
cfm mysqltop kills                  # recent governor kill/reap actions (last 100)
cfm mysqltop ps                     # full processlist as JSON (running + waiting)
cfm mysqltop history [window] [N]   # busiest N users over a historical window
                                    #   window: 30m, 1h (default), 6h, 24h
cfm mysqltop cpu                    # per-user CPU-seconds and query counts
                                    #   shows how to enable tracking if not yet active
cfm mysqltop help                   # usage summary
```

**`cfm mysqltop` (default view) shows:**
- Server flavor + mode (monitor/enforce)
- Connection summary: total/max/pct, active/sleeping/locked with risk icons (🟢🟡🔴)
- Per-user table: connections, active, sleeping, locked, max idle age, risk
- Lock graph: each blocker with waiter count and query preview
- Running queries: top 10 by runtime with lock indicator
- Governor actions: recent kills with PID, user, DB, runtime, reason, result

**`cfm mysqltop history 6h 10`** — peak and average connections per user over the last 6 hours. Useful for identifying which tenants consistently hold many connections versus one-off spikes.

**`cfm mysqltop cpu`** — per-poll CPU-seconds and query counts. If CPU tracking is not yet active, prints the exact SQL or `my.cnf` change needed to enable it.

### HTTP API

The governor registers on the cfm debug server (`LISTEN_ADDRESS:PORT`, default `127.0.0.1:6060`).

| Endpoint | Description |
|---|---|
| `GET /api/v1/mysql/state` | Full `GovernorState` snapshot (JSON) |
| `GET /api/v1/mysql/processlist` | Running queries + per-user connection summary |
| `GET /api/v1/mysql/top` | Per-user connection counts + server flavor/mode |
| `GET /api/v1/mysql/locks` | Lock graph (blockers → waiters) |
| `GET /api/v1/mysql/kills` | Recent kill records (last 100) |
| `GET /api/v1/mysql/history?window=1h&top=20` | Historical per-user aggregates |
| `GET /api/v1/mysql/cpu` | Per-user CPU/query deltas + perf_schema status flags |

### Full detectors.conf Example

```ini
[mysql_governor]
ENABLED    = 1
MODE       = monitor        ; start here — switch to enforce after validating rules
POLL_EVERY = 5s

; ── Connection pressure ────────────────────────────────────────────────────
CONN_WARN_PCT = 70
CONN_ACT_PCT  = 85

; ── Lock fan-out kill ──────────────────────────────────────────────────────
LOCK_FANOUT_KILL = 20
LOCK_FANOUT_TTL  = 60s

; ── Per-query runtime rules ────────────────────────────────────────────────
QUERY_RULES =
    *_cron          : 0     : ignore
    *_import        : 0     : ignore
    mathemat_db     : 50s   : notify
    mathemat_db     : 60s   : kill_query   : lock_fanout=5
    mathemat_db     : 90s   : kill_query
    mediains_*      : 20m   : notify
    mediains_*      : 30m   : kill_query
    *_mage*         : 5m    : notify
    *_mage*         : 15m   : kill_query   : lock_fanout=3
    *_mage*         : 30m   : kill_query
    *_wp*           : 30s   : notify
    *_wp*           : 60s   : kill_query
    *               : 5m    : notify
    *               : 15m   : kill_query

; ── Per-user connection limits ─────────────────────────────────────────────
CONN_RULES =
    mathemat_db     : max=80  : alter_user
    mediains_*      : max=40  : reap_sleep
    *_mage*         : max=60  : notify
    *_wp*           : max=30  : notify
    *               : max=25  : reap_sleep : conn_pct=70

; ── Sleep reaper ───────────────────────────────────────────────────────────
SLEEP_REAPER        = 1
SLEEP_REAPER_AGE    = 180s
SLEEP_REAPER_EXEMPT = proxysql_monitor, root

; ── Kill rate limits ───────────────────────────────────────────────────────
KILL_PER_DB_PER_WINDOW = 8
KILL_TOTAL_PER_WINDOW  = 30
KILL_WINDOW            = 10m
```

---

## 11. CLI Reference – `cfm webtop`

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

## 12. Web Detector HTTP API

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

## 13. Appendix: cfm.conf Snippets

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

MYSQL_LOG_STDOUT = 0
MYSQL_LOG_FILE   = /var/log/cfm/cfm.mysql.log
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

## 14. Security Notes

- In **DNAT mode**, keep the challenge listeners local-only (`127.0.0.1`). Do not expose them directly to the internet.
- In **OpenResty mode**, treat the unix socket as sensitive — enforce tight file permissions and always use the token.
- When using OpenResty `ssl_certificate_by_lua*`, cache aggressively (shared_dict + lock) and use tight timeouts.
- The **MySQL Governor** debug API (`/api/v1/mysql/*`) is served on the cfm debug port (`PORT` in cfm.conf). Keep that port firewalled to localhost or trusted management IPs — it exposes live processlist data and kill history.
- The `alter_user` action in `CONN_RULES` requires `GRANT CREATE USER`. This is a powerful privilege — scope it to `'cfm_governor'@'localhost'` only and use a strong password.
- Always run the governor in `monitor` mode for at least one week before switching to `enforce` on a production server.
