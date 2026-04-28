# Detectors Guide

This guide explains how to configure CFM detectors safely in production, starting from `dryrun` and then moving to active blocking.

- Main runtime file: `/etc/cfm/detectors.conf`
- Reference template/examples: [`../configs/detectors.conf`](../configs/detectors.conf)
- Leniency companion sections: [`Detectors.Leniency.md`](Detectors.Leniency.md)
- Web UI / detectors settings page: [`cfm-admin-webtop.md`](cfm-admin-webtop.md)

---

## 1) Detector model overview

### Section naming

CFM parses detector sections using these patterns:

- `[type]`  
  Single built-in detector section (for example `[ssh_auth]`, `[mysql]`, `[webdetector]`).
- `[type:instance]`  
  Named instance pattern, used for custom detectors (for example `[custom:ssh_file]`).
- `[type.leniency]` (and `[type:instance.leniency]` where relevant)  
  Optional companion section for softer policy on matched Country/ASN cohorts.

### Source modes (`MODE`)

Depending on detector type, sources can be:

- `file`: tail a log file (`LOG_PATH`)
- `journal`: read systemd journald (`JOURNAL_UNIT` / `JOURNAL_MATCHES`)
- `docker`: read container logs (`DOCKER_CONTAINER`, optional `DOCKER_ARGS`) where supported

If a detector supports multiple source backends, choose exactly one clear path in each section (comment the others out).

### Threshold / window / cooldown semantics

Most detectors use this model:

- `EVERY`: poll interval (how often detector scans)
- `WINDOW`: rolling time window used for counters
- threshold keys (for example `AUTHFAIL_IP`, `DENIED_USER`, `MODSEC_IP`): alert when count is `>= threshold` inside `WINDOW`
- `COOLDOWN`: detector-side alert dedupe interval per key (helps reduce noisy repeats)
- `SAMPLE_LIMIT`: max matched lines attached to alert context

### Block behavior and block cooldown

Autoblock is configured per detector section:

```ini
BLOCK = off        ; aliases: no, 0
# BLOCK = dryrun
# BLOCK = permanent
# BLOCK = 30m      ; any Go-style duration
BLOCK_COOLDOWN = 20m
```

- `off`/`no`/`0`: alert only, never write firewall block set
- `dryrun`: logs “would block …” without enforcement
- `permanent`: non-expiring nft block
- duration (for example `10m`, `2h`, `24h`): TTL block, auto-expired by timed sets
- `BLOCK_COOLDOWN`: minimum time before same section can block same IP again

> **Production-safe rollout:** begin with `BLOCK=dryrun`, tune, then move to short TTL (for example `10m` or `30m`) before permanent blocks.

---

## 2) Built-in detector catalog

Typical defaults below are representative from the shipped template and should be tuned per host profile.

| Detector key | What it detects | Key knobs | Typical defaults |
|---|---|---|---|
| `api_abuse` | API path abuse / anomaly stages | `STAGE1/2/3_THRESHOLD`, `STAGE2_CHALLENGE_TTL`, `BLOCK`, allowlists | `EVERY=2s`, `WINDOW=2m`, `BLOCK=15m` |
| `ssh_auth` | SSH auth failures / brute-force | `MODE`, `AUTHFAIL_IP`, `AUTHFAIL_USER`, `DDOS_IP`, `BLOCK` | `MODE=journal`, `WINDOW=15m`, `BLOCK=permanent` |
| `dovecot_auth` | Dovecot auth abuse | `MODE`, `AUTHFAIL_IP`, `AUTHFAIL_USER`, `BLOCK` | `MODE=journal`, `WINDOW=15m`, `BLOCK=permanent` |
| `ftpd` | FTP auth failures | `MODE`, `AUTHFAIL_IP`, `AUTHFAIL_USER`, `BLOCK` | `MODE=auto`, `WINDOW=15m`, `BLOCK=permanent` |
| `cpanel` | cPanel auth/root login anomalies | `AUTHFAIL_IP`, `AUTHFAIL_USER`, `ROOT_IP`, `BLOCK` | `WINDOW=10m`, `BLOCK=1h` |
| `mysql` | MySQL/MariaDB auth failures / scans | `LOG_PATH`, `DENIED_IP`, `DENIED_USER`, `ROOT_IP`, `SCAN_IP`, `BLOCK` | `WINDOW=10m`, `LOG_PATH=auto`, `BLOCK=permanent` |
| `mysql_governor` | Processlist pressure, long query, conn cap enforcement | `MODE`, `POLL_EVERY`, `QUERY_RULES`, `CONN_RULES`, kill limits | `MODE=enforce`, `POLL_EVERY=5s` |
| `exim_security` | Exim security/auth/reject patterns | `LOG_PATH`, `REJECT_LOG_PATH`, per-rule thresholds, `BLOCK` | `WINDOW=30m`, `BLOCK=12h` |
| `exim_relays` | Exim relay/throughput abuse | `LOCAL_USER_MAX`, `AUTH_*`, `UNAUTH_IP_MAX`, `BLOCK` | `WINDOW=15m`, `BLOCK=dryrun` |
| `exim_queues` | Exim queue growth/frozen queue pressure | `QUEUE_TOTAL_MAX`, `QUEUE_FROZEN_MAX`, `COOLDOWN` | `EVERY=60s`, alerting focus |
| `postfix_security` | Postfix auth/reject/rbl/tls anomalies | `MODE` or Docker/Journal source keys, thresholds, `BLOCK` | `WINDOW=30m`, `BLOCK=permanent` |
| `postfix_relays` | Postfix relay-style abuse counters | threshold family similar to Exim relays, `BLOCK` | `WINDOW=15m` |
| `postfix_queues` | Postfix queue saturation | `TOTAL_CMD`, `LIST_CMD`, queue thresholds | `EVERY=60s`, alerting focus |
| `modsec` | ModSecurity denial bursts per IP | `LOG_PATH`, `MODSEC_IP`, `BLOCK` | `WINDOW=15m`, `BLOCK=permanent` |
| `outbound` | outbound abuse sentinel (per-uid SMTP/scan/HTTP bursts) | `OUTBOUND_*` thresholds, allow users/groups, dedupe | `WINDOW=60s`, alerting focus |
| `health` | host health anomalies (CPU/RAM/disk/temp/net spikes) | `% thresholds`, spike multipliers, watch lists | `EVERY=20s`, mostly alerting |
| `webdetector` | L7 abuse behavior / challenge integration | `MODE`, path files, scoring knobs, challenge knobs, `BLOCK` | `EVERY=5s`, `WINDOW=120s`, `BLOCK=2h` |

---

## 3) Custom detectors

Custom detectors use regex rules with named captures and can read from file or journal (and docker where source plumbing is available for that section pattern).

### Required syntax and keys

```ini
[custom:your_name]
ENABLED = 1
MODE = file                 ; file | journal (docker only where supported)
LOG_PATH = /var/log/auth.log
; JOURNAL_UNIT = sshd.service
EVERY = 2s
WINDOW = 10m
COOLDOWN = 20m
SAMPLE_LIMIT = 10

AUTHFAIL_IP = 12
AUTHFAIL_USER = 8

MATCH_TARGET = both         ; ip | user | both
FAIL_REGEX =
    ... named captures ...

; optional pre-filter
IGNORE_REGEX =
    ... regex to skip noisy benign lines ...

BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

### Capture groups and normalization

Use named captures in `FAIL_REGEX`:

- `(?P<ip>...)` for source IP
- `(?P<user>...)` for account/user key

Matching behavior:

- `MATCH_TARGET=ip` requires named `ip`
- `MATCH_TARGET=user` requires named `user`
- `MATCH_TARGET=both` requires both captures

Normalization behavior (engine-side):

- IP capture is parsed/normalized before block decisions
- user capture is trimmed and counted as detector key material
- if both are present, both per-IP and per-user counters can trigger

### Example A — single regex (safe starter, file source)

```ini
[custom:ssh_file_safe]
ENABLED = 1
MODE = file
LOG_PATH = /var/log/auth.log
EVERY = 2s
WINDOW = 10m
COOLDOWN = 20m
SAMPLE_LIMIT = 10
AUTHFAIL_IP = 20
AUTHFAIL_USER = 10
MATCH_TARGET = both
FAIL_REGEX =
    Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)
BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

### Example B — multi-regex + ignore-regex (file source)

```ini
[custom:mail_auth_mix]
ENABLED = 1
MODE = file
LOG_PATH = /var/log/mail.log
EVERY = 3s
WINDOW = 15m
COOLDOWN = 20m
SAMPLE_LIMIT = 12
AUTHFAIL_IP = 15
AUTHFAIL_USER = 10
MATCH_TARGET = both
IGNORE_REGEX =
    cfm-healthcheck
    trusted-monitor
FAIL_REGEX =
    authentication failure; .*rhost=(?P<ip>\S+).*user=(?P<user>\S+)
    SASL (?:LOGIN|PLAIN) authentication failed.*rip=(?P<ip>\S+).*user=(?P<user>\S+)
BLOCK = 15m
BLOCK_COOLDOWN = 20m
```

### Example C — journal source

```ini
[custom:sshd_journal_safe]
ENABLED = 1
MODE = journal
JOURNAL_UNIT = sshd.service
JOURNAL_MATCHES = _SYSTEMD_UNIT=sshd.service
EVERY = 2s
WINDOW = 10m
COOLDOWN = 20m
SAMPLE_LIMIT = 10
AUTHFAIL_IP = 12
AUTHFAIL_USER = 8
MATCH_TARGET = ip
FAIL_REGEX =
    Failed password for .* from (?P<ip>\S+) port \d+ ssh2
BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

### Example D — docker/container log source (where section supports it)

```ini
[custom:container_auth_probe]
ENABLED = 1
MODE = docker
DOCKER_CONTAINER = auth-service
DOCKER_ARGS = --details,--tail=200
EVERY = 3s
WINDOW = 10m
COOLDOWN = 20m
SAMPLE_LIMIT = 10
AUTHFAIL_IP = 12
AUTHFAIL_USER = 8
MATCH_TARGET = both
FAIL_REGEX =
    login failed.*ip=(?P<ip>\S+).*user=(?P<user>\S+)
BLOCK = dryrun
BLOCK_COOLDOWN = 20m
```

---

## 4) Troubleshooting

### “enabled but waiting”

Symptoms:
- Section shows enabled but no alerts.

Checks:
- Confirm source path/unit/container exists and is receiving new lines.
- Confirm `EVERY` and `WINDOW` are not too large for your test cadence.
- Generate one known-bad synthetic line matching your regex and observe counters.

Safe action:
- Keep `BLOCK=dryrun` while validating.

### Outbound alerts need DNS corroboration

Symptoms:
- Outbound sentinel warns on unusual per-uid destination churn or burst rates.

Checks:
- Confirm the triggering uid/gid and process metadata from the alert line.
- Pivot to the ad-hoc DNS forensics runbook only when baseline telemetry is insufficient:
  [`admin-notes/ad-hoc-dns-forensics.md`](admin-notes/ad-hoc-dns-forensics.md).

Safe action:
- Keep captures short, identity-scoped, and temporary (no permanent detector/rule changes).

### Source not found

Symptoms:
- Logs indicate missing file/journal unit/container.

Checks:
- `MODE=file`: verify `LOG_PATH` path/permissions.
- `MODE=journal`: verify unit name (`sshd.service` vs `ssh.service` distro difference).
- `MODE=docker`: verify container name and that daemon user can read `docker logs`.

### Regex compiles but no matches

Symptoms:
- Section loads cleanly, but counters remain zero.

Checks:
- Escape rules properly (double-backslashes where needed in ini templates).
- Make sure named captures (`?P<ip>`, `?P<user>`) exist per `MATCH_TARGET`.
- Add temporary broad pattern first, then tighten incrementally.
- Remove over-broad `IGNORE_REGEX` rules that may swallow target lines.

### False positives

Symptoms:
- Legitimate clients trigger alerts/challenges/blocks.

Mitigation path:
- Lower sensitivity (raise thresholds, widen `WINDOW`).
- Use `BLOCK=dryrun` or short TTL while tuning.
- Add detector-specific allow/ignore controls and leniency companions where appropriate.
- For web traffic, review path/UA lists and tune high-noise signatures.

---

## 5) Cross-links

- Reference config and inline presets: [`../configs/detectors.conf`](../configs/detectors.conf)
- Leniency companion docs: [`Detectors.Leniency.md`](Detectors.Leniency.md)
- Web UI / detector settings docs: [`cfm-admin-webtop.md`](cfm-admin-webtop.md)

