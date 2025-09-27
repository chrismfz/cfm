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
- **ModSecurity alerts**.
- **Health detector** (CPU, RAM, disk, conntrack spikes, throughput, SMART/RAID/ZFS).
- Configurable thresholds, cooldowns, and autoblock modes per detector.

### 🚨 Autoblock Engine
- Inserts IPs into nftables sets with **TTL** or **permanent**.
- Per-detector policies: `dryrun`, `ttl=1h`, `permanent`.
- **Throttle autoblock**: if IP hits PPS/SYN/ConnLimit/ICMP throttles ≥N times in a window, block with TTL.
- Dedupe suppresses noisy repeats (`host|kind|ip|reason`).
- Reasons: `SSH_BRUTE`, `PORTSCAN`, `CONNLIMIT`, `HEALTH_SPIKE`, etc.

### 🛡️ Portscan & Flood Defenses
- **Portscan detection** (distinct ports per window, TCP+UDP).
- **AckGuard**:
  - Blocks fake ACK floods, unsolicited SYN+ACKs, invalid ACK packets.
  - Drops `NEW+ACK`, RST floods, SYN/ACK floods, optionally fragments.
  - Modes: `dryrun`, TTL autoblock, permanent autoblock.
- **Reflection/handshake junk filtering** before service rules.

### 🖥️ System Hardening
- Auto-applies **sysctl tweaks** on startup (`SYS_TWEAKS_ENABLE`).
- Scales conntrack size with RAM.
- Tightens TCP timeouts and retries.
- Anti-spoofing (`rp_filter=1`).
- Disables ICMP redirects (`accept_redirects=0`, `send_redirects=0`).
- Can persist sysctl config (`SYS_TWEAKS_PERSIST=1`).

### 🌍 Enrichment
- MaxMind GeoIP + reverse DNS PTR lookups.
- Every block/detection is enriched with:
  - ASN, ASN Name, Country, PTR hostname.
- Used in notifications, logs, CLI, and API.

### 📬 Notifiers
- Configurable **channels**:
  - Sendmail (local MTA).
  - Remote SMTP relay.
  - Slack webhook.
- JSON Lines audit log (`notify.log.jsonl`).
- Per-detector routing (e.g. SSH → email only, Health → Slack+email).
- Subject/body templates (`{{.Host}} {{.SrcIP}} {{.Reason}}`).
- Dedupe cooldown avoids alert spam.

### 🖧 API Integration
- **Outbound sync**:
  - Send autoblock, manual block, and unblock events to controller (`API_URL`, `AUTH_TOKEN`).
- **Agent runner** (`agentpkg.Runner`):
  - Runs inside daemon, keeps syncing with API.
- **Inbound logs**: optional API log file (`cfm.api.log`).
- Roadmap: full REST API (block/unblock/list).

### 🛠 CLI Commands
```
cfm version
cfm test                      # check environment, backends, kernel modules
cfm block <IP|CIDR> [-r REASON] [--ttl 1h]
cfm unblock <IP>
cfm list [--json]             # list blocked IPs
cfm allow <IP|CIDR> [--ttl 1h]
cfm unallow <IP|CIDR>
cfm allow-list [--json]       # list allowed IPs
cfm daemon [--interval 20s]
cfm status [--json]
cfm flush                     # flush block_v4/v6 sets
cfm which <IP> [--json]       # show which set/feed an IP belongs to
cfm reset                     # reset table (flush rules & sets)
cfm disable                   # drop everything (firewall off)
```

### 🧩 Extra Features
- **Live config reload**: daemon watches `cfm.allow`, `cfm.deny`, `cfm.blocklists`, `cfm.conf` and applies changes live.
- **DynDNS allow**: maintains hostnames in `allow_dyn_v4/v6` by periodic resolution.
- **Inline TTL/until**: `cfm.allow`/`cfm.deny` entries can include `ttl=1h` or `until=2025-09-30T12:00:00Z`.
- **Unblock reports**: `cfm unblock` prints detailed step-by-step report (feeds, sources, whitelist overrides).
- **Debug server**: daemon runs a local **pprof** server (`127.0.0.1:6060`) for profiling & metrics.

---

## 📂 Config Overview

- **`cfm.conf`** → Core firewall, ports, connlimit, portflood, ackguard, sysctl.
- **`detectors.conf`** → Log detectors, thresholds, autoblock policy per service.
- **`notify.conf`** → Notifier channels, templates, routing, dedupe.
- **`cfm.blocklists`** → External feeds for IP/domain blocking.

---

## 🚀 Example Autoblock

```
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
```

---

## 🛠 Roadmap
- [ ] SMTP Block based on nft and uid/gid
- [ ] More notifier channels (Telegram, Webhooks).
- [ ] Advanced anomaly detection (geo-login alerts, ML baselines).

---

## 📜 License
MIT
