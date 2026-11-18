# ClamAV upload scanning

The edge hands every file part of a multipart upload to clamd through the
daemon: `configs/lua/cfm_clamav.lua` → the nginx bridge → `internal/clam` →
clamd on `/run/cfm-clamd.sock`. Knobs live in `/etc/cfm/cfm.conf` (the
"ClamAV / clamd" block); per-vhost choices live in stores changed from the
CLI or the cfm-admin ClamAV page and vhost-controls grid, with no reload.

## What gets scanned

```
scan(host) = CLAMD_ENABLED && CLAMD_NGINX_HOOK_ENABLED
             && (CLAM_SCAN_DEFAULT XOR host in the scan override list)
```

| Knob | Default | Meaning |
|---|---|---|
| `CLAMD_ENABLED` | 1 | The scanner runs and connects to clamd. Off = nothing is scanned |
| `CLAMD_NGINX_HOOK_ENABLED` | 1 | The edge intercepts uploads. Off keeps `cfm clam scan <file>` working |
| `CLAM_SCAN_DEFAULT` | 1 | Global policy. A vhost in the override list flips it (opt out when on, opt in when off) |
| `CLAM_SCAN_SCOPE` | `archives` | Decided by **magic bytes** in the scanner, not by extension: `archives` = zip (incl. docx/xlsx/jar), gzip, rar, 7z, xz, bzip2, the one class the WAF cannot look inside; `all` = every file part |
| `CLAMD_MAX_WORKERS` / `CLAMD_QUEUE_SIZE` / `CLAMD_TIMEOUT` | 2 / 256 / 10s | Async scanner capacity |

The scope check runs after the upload is spooled to
`/var/lib/cfm/scanner/pending`; a non-archive costs the spool and the queue
slot, not a clamd scan. An edge-side pre-filter was considered and dropped
(2026-11-18): only worth it if the spool cost ever shows up.

## What happens on a hit

**Async (`CLAM_SCAN_MODE = async`, the default).** The upload is never
delayed. On an infected verdict: a line in `/var/log/cfm/cfm.clam.log`, a
`detection_history` row, a `CLAM/INFECTED` notification and a quarantine copy
in `/var/lib/cfm/scanner/infected`.

**Inline (`CLAM_SCAN_MODE = inline`, opt-in).** The edge waits for the
verdict, up to `CLAM_INLINE_TIMEOUT` (3s), and answers 403 to an infected
upload. **Fail-open by contract** (`internal/clam/inline.go`): clamd down or
hung, breaker open, timeout, an oversized stream, any error → the upload is
allowed and handed to the async queue, so a clamd outage never takes uploads
down. A missing or corrupt rendered Lua config falls back to async. URIs under
`/acctxfer` never wait (the cPanel account-transfer hang class). Inline honours
the scope and the signature excludes: an ignored signature never blocks.

Arming inline: `CLAM_INLINE_DRY_RUN = 1` first (scans inline, records what
WOULD block, never blocks: watch latency and false positives), then
`cfm clam mode add <host>` per vhost, or `cfm clam mode inline` globally.

## Signature excludes

A signature that matches is downgraded to **log-only**: it stays in the log
and the history (flagged `sig_ignored`) but sends no notification, makes no
quarantine copy and never blocks inline.

- Baseline: `CLAM_SIG_IGNORE` in `cfm.conf`, comma-separated case-insensitive
  globs on the signature name. Default `*_Hunting.UNOFFICIAL`: signature-base
  "Hunting" YARA rules are false-positive-prone by design (seen on a
  legitimate `.docx`). An explicit empty value acts on every verdict.
- Runtime, global or per vhost: `cfm clam sigignore add '<glob>' [--host
  <vhost>]`, or "Ignore this signature" on a row of the cfm-admin ClamAV page.
  Global excludes need admin; a scoped user can add one for their own vhosts.

## Commands

```
cfm clam status | ping | version
cfm clam enable | disable                    # CLAMD_ENABLED
cfm clam hook enable | disable | status      # CLAMD_NGINX_HOOK_ENABLED
cfm clam scan on | off                       # CLAM_SCAN_DEFAULT
cfm clam override add | remove | list <host> # per-vhost flip of the scan policy
cfm clam scope archives | all                # CLAM_SCAN_SCOPE
cfm clam mode async | inline                 # CLAM_SCAN_MODE (global)
cfm clam mode add | remove | list <host>     # per-vhost flip of the mode
cfm clam sigignore list | add | remove ...   # signature excludes
cfm clam infections [--host <vhost>] [--limit N]
cfm clam scan [--quiet-clean] <file-or-dir>  # on-demand scan
```

MCP: `clam_status`. The `cfm.conf` keys apply through the daemon's config
watch, no restart.
