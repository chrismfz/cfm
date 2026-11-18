# Outbound Abuse Sentinel

The inbound detectors ask "who is attacking us?". The sentinel asks "which
hosted account is generating outbound abuse?": the question that decides
whether the mail IPs end up on Spamhaus, the upstream nullroutes the egress IP,
or a compromised PHP site turns the server into a botnet node.

Code: `internal/outbound/` (collector, analyzer, alerter, forensics). Knobs:
the "Outbound Abuse Sentinel" block of `/etc/cfm/cfm.conf`. **Off by default.**

## What it does (observe + warn only)

- Watches **new outbound TCP connections per Linux uid** via NFLOG.
- Classifies each by destination port group (ports configurable):

  | Signal | Ports (key) | Typical cause |
  |---|---|---|
  | SMTP | 25, 465, 587 (`OUTBOUND_SMTP_PORTS`) | compromised CMS sending spam |
  | SCAN | 22, 23, 3389 (`OUTBOUND_SCAN_PORTS`) | brute-forcer running on the box |
  | HTTP | 80, 443, 8080, 8443 (`OUTBOUND_HTTP_PORTS`) | POST flood, botnet C2 |
  | UNIQ_DST | any port, many distinct destination IPs | horizontal scanner |

- Per-uid sliding window (`OUTBOUND_WINDOW_SECONDS`) with per-signal dedup
  (`OUTBOUND_LOG_DEDUP_SECONDS`), so a runaway account does not flood the log.
- On a threshold trip: one forensic line in `cfm.smtp.log` (user, process,
  pid, **cwd**, **cmdline**, a peer sample, destination ASN / country / PTR,
  and for SMTP an **exim queue snapshot** of msgids and senders), and a
  `notify` event (`kind=outbound_abuse`, `section=outbound`, severity
  `OUTBOUND_NOTIFY_SEVERITY`) for the usual Slack / mail channels.
- HTTP signals report destination IP/port samples only: the collector sees
  connection metadata, never the URL, path or Host.

Nothing is throttled or suspended. The nft chain is `policy accept`: if cfm
crashes, outbound traffic is unaffected.

## How it is wired

```
nft OUTPUT chain cfm_outbound_observe (priority 10)
  ├─ skuid 0 / exempt users and groups → return   (filtered in the kernel)
  └─ ct state new, tcp dport in the port groups → NFLOG group OUTBOUND_NFLOG
                          ↓
  internal/outbound collector → analyzer (per-uid window) → alerter
                          ↓
            cfm.smtp.log + notify event
```

Priority 10 runs after `smtpblock` (-100), so a packet SMTP_BLOCK already
denies is not logged twice.

## Configuration

```ini
OUTBOUND_ENABLED                 = 0      # turn on
OUTBOUND_NFLOG                   = 0      # NFLOG group, 0 = disabled. Must differ
                                          # from SMTP_LOG_NFLOG and any other NFLOG
                                          # consumer (ulogd2, suricata). Convention:
                                          # 100 = SMTP, 101 = outbound
OUTBOUND_WINDOW_SECONDS          = 60
OUTBOUND_SMTP_CONN_PER_MIN       = 30
OUTBOUND_SCAN_UNIQUE_DST_PER_MIN = 50
OUTBOUND_HTTP_RATE_PER_MIN       = 200
OUTBOUND_LOG_DEDUP_SECONDS       = 300
OUTBOUND_NOTIFY_SEVERITY         = warning
OUTBOUND_QUEUE_SAMPLES           = 5      # exim msgid/sender lines per warning
OUTBOUND_LOG_ENRICH              = 1      # GeoIP/ASN on the destination
OUTBOUND_ALLOW_USERS  = mailman,exim,cfm,imunify360-webshield
OUTBOUND_ALLOW_GROUPS = mailman,cfm,imunify360-webshield
# OUTBOUND_ALLOW_UIDS / OUTBOUND_ALLOW_GIDS for numeric exemptions
```

Root is always exempt; the `cfm` and `mailnull` users and the `cfm` and `mail`
groups are auto-exempt when present. The `OUTBOUND_DNS_*` keys are
deprecated and ignored. `OUTBOUND_HTTP_ATTRIBUTION_ENABLED` is reserved for a
future opt-in attribution component and does nothing today.

## Example forensic line

```
2026-04-27 14:23:45 outbound signal=smtp uid=1042 (user:johndoe) gid=1042 (group:johndoe) \
  count=31 threshold=30 window=1m0s uniq_dst=14 proc=php pid=28104 cwd="/home/johndoe/public_html/wp-content/uploads/cache" \
  cmd="/usr/bin/php /home/johndoe/public_html/wp-content/uploads/cache/x.php" \
  peers=185.220.101.5:25,193.150.10.7:25,... | dst_asn=AS15169 (Google LLC) cc=US city=Mountain View ptr=mx.google.com \
  | exim_queue total=412 frozen=8 msgids=1uH...,1uI... senders=johndoe@example.com
```

`cwd` and `cmd`, with the queue snapshot, usually name the compromised script
in seconds. When DNS evidence is needed for one suspect account, the
short-capture runbook is `docs/admin-notes/ad-hoc-dns-forensics.md`.
