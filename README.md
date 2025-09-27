# CFM – Configurable Firewall Manager

CFM is a modern **firewall + intrusion detection manager** written in Go.  
It combines nftables policy enforcement, log-driven detection, autoblocking, system hardening, and notifications into one daemon.

---

## ✨ Key Features

### 🔒 Firewall Core
- **nftables backend** (table `inet cfm`) with auto-created chains.
- **Hook priority control** (`NFT_INPUT_PRIORITY`) to run before/after CSF or Imunify360.
- **ALLOW / BLOCK lists**:
  - Manual: `allow_v4`, `allow_v6`, `block_v4`, `block_v6`.
  - Dynamic: `allow_dyn_v4`, `allow_dyn_v6` (hostnames, DYNDNS).
- **Blocklists & whitelists** can be loaded from `cfm.blocklists` (domains, IPs, RBL sources).
- **ApplyPortsPolicy** ensures service ports are enforced from config (`TCP_IN`, `UDP_IN`, etc.).
- **SMTP_BLOCK mode** (CSF-compatible) — restricts outgoing SMTP except for trusted daemons.

### ⚡ Connection Protections
- **ConnLimit**: per-IP concurrent connection limits per port (e.g. `80;200`, `22;50`).
- **PortFlood**: per-port connection rate limiting (e.g. max 80 new SMTP sessions per 60s).
- **PPS Limits**: per-IP packet rate limiting (`PKT_RATE`, `PKT_BURST`, `PKT_MODE`).
- **New connection limits** (`NEW_RATE`, `NEW_BURST`).
- **ICMP rate limiting** (`ICMP_RATE_LIMIT`, `ICMP_RATE_BURST`).
- **Bad TCP flag filter**: drop NULL/XMAS/SYN+FIN packets.

### 🔎 Detection Engine
Detectors parse logs and metrics to spot abuse:
- **Exim** (queues, relay abuse, security failures).
- **SSH** (auth failures, DDOS attempts).
- **Dovecot** (auth failures).
- **FTP (pure-ftpd/proftpd/vsftpd)**.
- **cPanel logins**.
- **MySQL denied/scanner attempts**.
- **ModSecurity alerts**.
- **Health detector** (CPU, RAM, disk, conntrack spikes, network throughput, SMART/RAID/ZFS alerts).
- Configurable thresholds, cooldowns, and autoblock modes per detector.

### 🚨 Autoblock Engine
- Automatically inserts IPs into nftables sets with TTL or permanent.
- Policies per detector: `dryrun`, `ttl=1h`, `permanent`.
- **Throttle autoblock**: if an IP is throttled (`pps`, `syn`, `connlimit`, `icmp`) ≥N times in a window, it’s blocked with TTL.
- Dedupe suppresses noisy repeats (host+kind+ip+reason).
- Block reasons include `SSH_BRUTE`, `PORTSCAN`, `CONNLIMIT`, `HEALTH_SPIKE`.

### 🛡️ Portscan & Flood Defenses
- **Portscan detection** (distinct ports in a window, TCP+UDP).
- **AckGuard**:
  - Detects fake ACK floods, invalid ACK packets, unsolicited SYN+ACKs.
  - Drops `NEW+ACK`, `RST floods`, `SYN/ACK floods`, optionally fragments.
  - Modes: dryrun, TTL autoblock, permanent autoblock.
- **Reflection/handshake junk filtering** before services.

### 🖥️ System Hardening
- Auto-applies **sysctl tweaks** on startup (`SYS_TWEAKS_ENABLE`).
- Scales conntrack size with RAM.
- Tightens TCP timeouts and retries.
- Anti-spoofing (`rp_filter=1`).
- Disable ICMP redirects (`accept_redirects=0`, `send_redirects=0`).
- Persistent sysctl config (`SYS_TWEAKS_PERSIST=1`).

### 🌍 Enrichment
- Built-in MaxMind + PTR lookups.
- Every block/detection is enriched with:
  - ASN, ASN Name, Country, PTR hostname.
- Useful in notifications, logs, and API.

### 📬 Notifiers
- Configurable **channels**:
  - Sendmail (local MTA).
  - Remote SMTP relay.
  - Slack webhook.
- JSON Lines audit log (`notify.log.jsonl`).
- Per-detector routing (e.g. SSH → email, Health → Slack+email).
- Subject/body templates with placeholders (`{{.Host}} {{.SrcIP}} {{.Reason}}`).
- Dedupe cooldown to avoid spam.

### 🖧 API Integration
- **Outbound API sync**:
  - Send autoblock, manual block, and unblock events to a controller (`API_URL`, `AUTH_TOKEN`).
- **Inbound API logs**: optional file logging (`cfm.api.log`).
- Future: REST API endpoints for live queries and blocklist exports.

### 🛠 CLI
- `cfm daemon -c /etc/cfm/` → run with config dir.
- `cfm status` → shows daemon state, nftables status, offenders, counters.
- `cfm flush` → reset block sets.
- `cfm_profiler.sh` → monitor detector CPU spikes.

---

## 📂 Config Overview

- **`cfm.conf`** → Core firewall, connlimit, portflood, ackguard, sysctl.
- **`detectors.conf`** → Log-based detectors, thresholds, autoblock policies.
- **`notify.conf`** → Notification channels, templates, routing, dedupe.
- **`cfm.blocklists`** → External allow/block lists (IPs, domains, DNSBL/RBL).

---

## 🚀 Example Autoblock

[CFM] titan.myip.gr — autoblock 47.237.101.145 (AS45102 Alibaba US Technology Co., Ltd., Singapore) reason=PORTSCAN ttl=1h0m0s
Host: titan.myip.gr
Kind: autoblock
IP: 47.237.101.145
ASN: AS45102 Alibaba US Technology Co., Ltd.
Country: Singapore
PTR:
Reason: PORTSCAN
TTL: 1h0m0s
Count: 1
Section: autoblock
Extra: ports=148,668,1018,2083,2087,2096


---

## 🛠 Roadmap
- [ ] SMTP BLOCK based on nft
- [ ] Advanced anomaly detection (geo-login alerts, ML baselines).

---

## 📜 License
MIT

