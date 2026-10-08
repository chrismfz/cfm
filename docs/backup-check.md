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
| `backup_failed` | critical | the latest finished run failed (JetBackup Failed / Aborted / Never Finished, status 2/3/5; vzdump error text, or **3 `job errors` runs in a row** — vzdump says `job errors` even when every guest failed; Virtualmin `Failed`) |
| `backup_partial` | info | the latest run finished with some accounts/guests/domains failed (JetBackup Partially Completed, status 4 — one account over its own disk quota is enough; one or two vzdump `job errors`; Virtualmin OK with `failed_domains`). **Info**, so it reaches the dashboard but no warning/critical route: on a hosting node it is the normal state (one customer over quota), and what matters is caught elsewhere — vzdump escalates to `backup_failed` after 3, and a job that backs up nothing goes `backup_stale` |
| `backup_stale` | critical | no **successful** run for longer than the job's period × 1.5 + 2 h (Proxmox: `BACKUP_PROXMOX_STALE`, 8 d). A job is not judged before its own history (or, for Virtualmin, its schedule file) is that old |
| `backup_stuck` | critical | a run still going after `BACKUP_STUCK_AFTER` (24 h), measured from that run's own start |
| `backup_uncovered` | warning | Proxmox guests in no backup job, reported only by the node that hosts them (one finding; re-published when a NEW guest joins the set) |
| `backup_dest` | critical (Proxmox storage offline) / warning (< `BACKUP_DEST_FREE_PCT` free: Proxmox storage, JetBackup destination) | a backup destination the jobs use; Virtualmin destinations are not checked. A **shared** Proxmox storage (NFS, PBS) running low is reported by one node only — the lexically first online node of the cluster (`/cluster/status`) — not by every node; **offline** is per node (one node's mount can fail alone) and each such node reports it |
| `backup_no_job` | warning | JetBackup with no enabled account-backup job, Virtualmin with no enabled schedule (a job disabled during an incident and forgotten), or a Proxmox node that hosts guests (templates do not count) but runs no enabled vzdump job (`pve:nojob:<node>`; not raised when those guests already show as `backup_uncovered`) |
| `backup_check_error` | warning | an installed backup system could not be read on **two checks in a row**, or the check itself hung — "unknown", never "healthy" |
| `backup_recovered` | info | a finding above is gone. Same `key` as the finding it resolves; cfm-web closes that alert with it (unpins it, stops its reminders, posts RESOLVED). The message says why: "backup OK again" (the next run succeeded), "now failed: …" (the same job has another finding now — partial → failed, failed → stuck), "job disabled / job removed — no longer checked", "backup state readable again", "backup check finished again", or "<adapter> is no longer on this node" (absent for 24 h) |

Keys are per job / schedule / node / storage (`jb:failed:<job>`,
`vm:stale:<schedule>`, `pve:partial:<node>`, …), never per run: a job that
fails every night is ONE open alert (pinned and reminded by cfm-web), not one
a night. One job / node also has ONE per-run alert at a time: only its worst of
stuck > failed > stale > partial is published (a failing job that also goes
stale stays one alert, `backup_failed`; a Proxmox run stuck on a node folds
with that node's failed / stale). Publishing is edge-triggered per key:
once when it appears, again when its severity rises (a full storage that goes
offline) or a set gains a member, and re-armed when it is gone — announced as
`backup_recovered` under the same key (kept armed until that is delivered). While an
adapter cannot be read, its findings stay armed (no repeat when it reads
again). A key the check could not judge this time (a side read failed, the whole check
panicked, an adapter briefly absent) also stays armed. The edge state is
process-wide and saved to `/var/lib/cfm/backup_published.json`, so neither the
detector rebuilds that follow a `detectors.conf` save or a log rotation nor a
daemon restart (every package upgrade) re-announce what is already open. That
file also holds the hung-check alert (so a restart, the remedy for a hung CLI,
still resolves it) and when each adapter was last present. The "two checks in a
row" count for `backup_check_error` is in memory: after a restart an
open error is kept as it is until the adapter reads again, never resolved by
the restart itself. A JetBackup job the check cannot judge (it ran recently,
but no run of it is in the log history read) keeps ITS keys armed; the other
jobs are judged as usual. When NO job could be judged (an empty or truncated
`listLogs` answer) it is still a `backup_check_error`: `last_run` advances on
failed runs, so nothing else would ever alert.

**Delivery depends on the webdetector history store**: the findings reach
cfm-web as `detection_history` rows written through the node-fault sink the
webdetector registers. A node running without the webdetector, or with its
history off, records nothing. A finding (or recovery) is marked sent only
when the history row was actually written: no sink, no history store or a
failed INSERT leaves it armed and it is retried on the next check. The rows
(`backup_*`, like `mail_*`) are never returned to a scoped (cPanel) caller of
`history/events`, whose scope may include the server hostname they are
written under.

## Reading it

`GET /api/v1/health/backup` (admin) and the node MCP tool `backup_status`
return the latest check: `enabled` (BACKUP_ALERT), `status` (null until the
first check finishes) with every job's last result and last success,
`age_seconds`, and the open findings worst first. cfm-web polls it for its
fleet Backups table and for `backup_unreported` (a node that used to report
backups and stopped).

## Rules learned from the fleet's real output

- **Freshness = the last successful run in the history**, never the job's own
  timestamps (orion: `last_completed` advanced on failed runs). A JetBackup
  "Partially Completed" run counts: the other accounts were backed up.
- **JetBackup's log `status` is its `LOG_STATUS_*`**: 1 Completed, 2 Failed,
  3 Aborted, 4 Partially Completed, 5 Never Finished (from its UI code; every
  run's log ends with the word). The first build read 2 as partial and 4 as
  failed, so orion's and virgo's nightly partial runs (one account over its
  own disk quota) were reported as `backup_failed` + `backup_stale`.
- **The period is the LONG gap between runs, from how often the job actually
  started** (90th percentile of the gaps between run starts), not
  `next_run − last_run`: a stuck run pins `last_run`, which made orion's daily
  job look like a 17-day one and would have hidden the 16-day stall. The
  percentile, not the median, so a Mon–Fri job's weekend does not read as a
  missed backup. With fewer than 3 runs on record the job's schedule decides
  (`next_run − last_run` when it is not mid-run), else 8 days.
- **Virtualmin periods come from the schedule file** (`special` or the cron
  fields), as the LONGEST gap the schedule leaves (Mon–Fri → 3 d, hours 1–5 →
  20 h): a weekly schedule with one run in its history has no observed
  period, and gde's weekly push to rosso would otherwise be judged as daily.
  Without the file, observed gaps decide, floored at a day.
- A Virtualmin run in progress has an empty `final_status`: it is neither a
  failure nor (until it passes the stuck limit) stuck.
- Proxmox runs are judged **per node**, not per job — a vzdump task id
  carries no job id, so a broken weekly job can hide behind a healthy daily
  one on the same node. A node with no vzdump task at all is not judged (new,
  or all its jobs' guests live elsewhere).
- **Only scheduled runs count** for Virtualmin (`run_from = sched`): a failed
  test run from the UI is not the schedule's health.
- JetBackup's `listLogs` ignores a `type` filter and mixes plugin scans
  (type 8) and integrity checks (type 4) into the stream; only type 1 (backup
  runs) is read, matched to its job by `info.ID`.
- Virtualmin's `started` text is local 12-hour time; the run `name` starts
  with the start epoch, which is used instead.
- A running vzdump task reads `status: RUNNING`, `endtime: null`
  (`--source all` is needed to list it at all). A successful run that logged
  warnings reads `WARNINGS: <n>` — a success. Only a clean run (`OK` or
  `WARNINGS`) counts as fresh: `job errors` is also what a run where every
  guest failed reports, so a node ending that way every night goes stale.
- JetBackup's own `last_run` advances on failed runs, so it can only prove
  "has not run"; a job that ran recently but has no run in the log history
  read is reported as a check error (unknown), never as healthy. The whole
  retained history is read (5 000 entries; orion and earth held ~210).
- Virtualmin destinations are shown with their credentials removed
  (`ssh://user:***@host:/path`).

## Knobs (`[health]` in detectors.conf)

```
BACKUP_ALERT = 1
BACKUP_EVERY = "15m"
BACKUP_STUCK_AFTER = "24h"
BACKUP_PROXMOX_STALE = "8d"
BACKUP_DEST_FREE_PCT = 5    ; 0 turns the destination free-space check off
```

## Not covered yet

- Hosts without CFM (bare-metal NS, the backup server rosso) — install CFM
  health-only, or a destination-side check (newest snapshot per source host).
- ngm's own backups (`ngm backup run-scheduled` / `ngm-backup.timer`).
- JetBackup integrity checks (type 4 logs; orion's to Rosso were failing too).
- The central dead-man ("this node should report backups and doesn't") is
  cfm-web's job — `docs/fleet-alerting.md` step 4.
