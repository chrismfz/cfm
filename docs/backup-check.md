# Backup check (as built)

> Node side of `cfm-web:docs/fleet-alerting.md` step 4. Code:
> `internal/backupcheck` (adapters + pure evaluation) and
> `internal/detectors/health/backup.go` (scheduling + publishing).

## Why

On 7 Oct 2026 a customer, not our tooling, told us orion had no backup since
~21 Sep. The real picture was worse: the daily JetBackup job **failed on 19 and
20 Sep** (`Disk quota exceeded` from the cPanel API), then a run **stuck for 16
days** on one account. JetBackup's own `notran` monitor noticed and mailed
`logs@` — one mail among ~2 000 a day. The job's `last_completed` read *today*
the whole time it was broken, because JetBackup advances it on a failed run.

## What it does

The health detector runs the check every `BACKUP_EVERY` (15 min) in a
background goroutine and publishes what it finds as durable node faults —
the same `detection_history` path RAID/SMART/ECC take — which cfm-web ingests
and routes to Mattermost. **No local mail** (`core.Alert`) is emitted: the
point is to replace the `logs@` stream, not add to it.

Adapters are auto-detected by their CLI on `PATH`; a node with none checks
nothing.

| Adapter | CLI | Covers |
|---|---|---|
| `jetbackup` | `jetbackup5api` (`listBackupJobs`, `listLogs`) | cPanel and DirectAdmin (same CLI; verified on avgerinos) |
| `virtualmin` | `virtualmin list-scheduled-backups` / `list-backup-logs` (`--json`) + `/etc/webmin/virtual-server/backups/<id>` | Virtualmin scheduled backups |
| `proxmox` | `pvesh` (`/cluster/backup`, `/cluster/backup-info/not-backed-up`, node `tasks` + `storage`) | Proxmox VE vzdump |

## Findings (detection_history types)

| Type | Severity | Meaning |
|---|---|---|
| `backup_failed` | critical | the latest finished run failed (JetBackup status not 1/2; vzdump error text; Virtualmin `Failed`) |
| `backup_partial` | warning | the latest run finished with some accounts/guests/domains failed (JetBackup 2; vzdump `job errors`; Virtualmin OK with `failed_domains`) |
| `backup_stale` | critical | no **successful** run for longer than the job's period × 1.5 + 2 h (Proxmox: `BACKUP_PROXMOX_STALE`, 8 d) |
| `backup_stuck` | critical | a run still going after `BACKUP_STUCK_AFTER` (24 h) |
| `backup_uncovered` | warning | Proxmox guests in no backup job (one finding; re-published when a NEW guest joins the set) |
| `backup_dest` | critical (offline) / warning (< `BACKUP_DEST_FREE_PCT` free) | a backup destination/storage the jobs use |
| `backup_check_error` | warning | an installed backup system could not be read — "unknown", never "healthy" |

Publishing is edge-triggered per finding key (a run id, a job id, a storage):
once when it appears, re-armed when it is gone. While an adapter cannot be
read, its findings stay armed (no repeat when it reads again). A daemon
restart re-publishes what is still true once.

## Rules learned from the fleet's real output

- **Freshness = the last successful run in the history**, never the job's own
  timestamps (orion: `last_completed` advanced on failed runs).
- **The period comes from how often the job actually started** (median gap
  between run starts), not `next_run − last_run`: a stuck run pins `last_run`,
  which made orion's daily job look like a 17-day one and would have hidden
  the 16-day stall.
- **Virtualmin periods come from the schedule file** (`special` or the cron
  fields): a weekly schedule with one run in its history has no observed
  period, and gde's weekly push to rosso would otherwise be judged as daily.
  Without the file, observed gaps decide, floored at a day.
- **Only scheduled runs count** for Virtualmin (`run_from = sched`): a failed
  test run from the UI is not the schedule's health.
- JetBackup's `listLogs` ignores a `type` filter and mixes plugin scans
  (type 8) and integrity checks (type 4) into the stream; only type 1 (backup
  runs) is read, matched to its job by `info.ID`.
- Virtualmin's `started` text is local 12-hour time; the run `name` starts
  with the start epoch, which is used instead.
- A running vzdump task reads `status: RUNNING`, `endtime: null`
  (`--source all` is needed to list it at all).

## Knobs (`[health]` in detectors.conf)

```
BACKUP_ALERT = 1
BACKUP_EVERY = "15m"
BACKUP_STUCK_AFTER = "24h"
BACKUP_PROXMOX_STALE = "8d"
BACKUP_DEST_FREE_PCT = 5
```

## Not covered yet

- Hosts without CFM (bare-metal NS, the backup server rosso) — install CFM
  health-only, or a destination-side check (newest snapshot per source host).
- ngm's own backups (`ngm backup run-scheduled` / `ngm-backup.timer`).
- JetBackup integrity checks (type 4 logs; orion's to Rosso were failing too).
- The central dead-man ("this node should report backups and doesn't") is
  cfm-web's job — `docs/fleet-alerting.md` step 4.
