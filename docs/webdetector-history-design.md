# Webdetector historical data plan (vhost-centric)

This document breaks the problem into a **webdetector-first** implementation, so we can deliver useful history/export quickly and expand later.

## Is it doable with current code?

Yes. The current code already has most raw signals; what is missing is a durable history sink and a unified vhost timeline/query layer.

### Signals already available

- **Challenge events and mode** are already recorded in memory via `ChallengeAPIStore`:
  - `RecordVhostAuto` writes `auto_on/auto_off` with reasons/score/uniq/rps.
  - `RecordVhostManual` writes `manual_on/manual_off` with ttl/reason.
  - `RecordIPChallenge` writes per-IP challenge events.
  - `RecordSolved` writes challenge solve events.
- **WAF-origin observations** are already ingested by webdetector (`InjectObserved`) and tracked in short-window counters (e.g. `ips403WAF`).
- **Suspicious scoring reasons** already exist (`SuspiciousRow` reasons), and are emitted for challenge decisions.
- **Long/short windows already aggregate 404/403/500 etc.** and drive suspicious/challenge/block decisions.

So we can persist these with low-risk hooks, without changing detector behavior.

---

## Phase 1 scope (webdetector only)

Build a dedicated historical store for webdetector events under `/var/lib/cfm`:

- file: `/var/lib/cfm/webdetector-history.db` (SQLite, WAL)
- append-only events, indexed for per-vhost/per-ip queries
- JSON export endpoints for CLI/WebUI

### Questions to answer from history

Per vhost:

1. **How many times challenged, when, and why**.
2. **Auto vs manual challenge** and source reason.
3. **Which IPs got challenged** for this vhost.
4. **WAF triggers** (especially WAF 403 observations) for this vhost.
5. **Suspicious periods without challenge** (why it was suspicious, score/reasons).
6. **HTTP behavior stats over time** (404/403/500 volume snapshots and trends).

---

## Proposed event model (single table first)

Use one normalized `events` table first (easy rollout), then optional materialized tables later.

```sql
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_unix INTEGER NOT NULL,
  event_type TEXT NOT NULL,      -- challenge_vhost_auto_on, challenge_ip, waf_observe_403, suspicious_snapshot, ...
  host TEXT,                     -- normalized vhost
  ip TEXT,
  mode TEXT,                     -- auto|manual when relevant
  reason TEXT,                   -- compact reason
  score REAL,
  uniq_ip INTEGER,
  rps REAL,
  status_code INTEGER,
  ttl_sec INTEGER,
  payload_json TEXT              -- structured extra data
);

CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host, ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts   ON events(ip, ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, ts_unix DESC);
```

### Why single-table first?

- fastest to implement and iterate
- supports JSON export directly
- avoids schema churn while we learn real query patterns

---

## Hook points in existing code

### 1) Challenge lifecycle (already centralized)

Best first integration points:

- `ChallengeAPIStore.RecordVhostAuto`
- `ChallengeAPIStore.RecordVhostManual`
- `ChallengeAPIStore.RecordIPChallenge`
- `ChallengeAPIStore.RecordSolved`

These already receive exactly the metadata we need (host/ip/rule/score/reasons/ttl/mode/timestamps).

### 2) WAF observed traffic (already injected)

`Engine.InjectObserved` is the right place to persist vhost/IP/status/reason events for WAF-origin 403s and other upstream-blocked outcomes.

### 3) Suspicious (non-challenge) snapshots

At suspicious scoring/evaluation points (where reasons/score exist before action selection), persist a `suspicious_snapshot` event for visibility even when no challenge/block happened.

This addresses: “why it was suspicious but not challenged”.

### 4) Block-trigger events (per-IP and per-vhost)

Yes — we should also persist **block trigger context** from rules like:

- `IP404_COUNT`, `IP403_COUNT`, `IP403WAF_COUNT`
- `AGENT_LIST`, `AGENT_COUNT`
- `IP40X_COMBO`, `IP40X_UNIQUE_PATHS`, `IGNORE40X_PREFIXES`
- `MALPATH_COUNT`, `MALPATH_FILE`
- resulting action metadata (`BLOCK`, `BLOCK_COOLDOWN`)

Recommended approach:

- Write a `block_trigger` event per IP decision candidate with:
  - `host`, `ip`, `reason` (e.g. `web_404_flood`, `web_403waf_flood`, `web_agent_flood`, `web_40x_combo`, `web_malpath_flood`)
  - counter snapshot in `payload_json` (actual counts + configured thresholds at that moment)
  - action outcome: `block`, `challenge`, `notify`, or `suppressed_by_cooldown`
- Also write a light `vhost_rollup` snapshot event every interval for host-level analytics:
  - totals for 404/403/403waf/500, unique paths, suspicious score bands.

This gives both views:
- **per-IP incident forensics** (who crossed what threshold and when)
- **per-vhost operational trends** (which host repeatedly produces trigger pressure)

### 5) Challenge outcome states (solved vs never-solved)

Yes — we should explicitly model challenge lifecycle status so you can query:

- challenged and solved
- challenged and still pending
- challenged and expired without solve ("never solved")

Suggested events:

- `challenge_issued` (ip, host, rule, ttl_sec)
- `challenge_solved` (ip, host, latency_ms, diff)
- `challenge_expired_unsolved` (ip, host, rule, ttl_sec)
- optional `challenge_escalated_block` when fail policy escalates

Implementation note:

- on `RecordIPChallenge`, store `challenge_issued` with `expires_at` in payload
- on `RecordSolved`, mark/emit `challenge_solved`
- periodic sweeper marks old open challenges as `challenge_expired_unsolved`

This directly supports CLI/WebUI filters like:

- `state=solved`
- `state=unsolved`
- `state=expired_unsolved`
- `state=escalated`


---

## JSON export design

Add webdetector history read APIs (HTTP) that CLI/WebUI can consume:

- `GET /api/v1/webdetector/history/vhost?host=example.com&from=...&to=...&limit=...`
- `GET /api/v1/webdetector/history/ip?ip=1.2.3.4&from=...&to=...&limit=...`
- `GET /api/v1/webdetector/history/vhost/summary?host=example.com&period=24h`

Return typed JSON sections:

- `challenge_auto`
- `challenge_manual`
- `challenge_ips`
- `challenge_outcomes` (`solved`, `pending`, `expired_unsolved`, `escalated`)
- `waf_observed`
- `block_triggers` (reason + counts + thresholds + action outcome)
- `suspicious`
- `http_status_timeseries` (e.g. 5m buckets for 404/403/500)

This gives you direct data for CLI and WebUI without parsing log files.

---

## Implementation order (small, safe slices)

1. Introduce `internal/webdetector/history` package:
   - sqlite open/init (WAL, busy timeout)
   - `Append(Event)` + query methods
2. Wire history appends in `ChallengeAPIStore` methods (`issued/solved` lifecycle).
3. Wire history appends in `Engine.InjectObserved` (WAF view).
4. Add `block_trigger` append at IP decision/proposal point (includes counters + thresholds snapshot).
5. Add suspicious snapshot append where score/reasons are computed.
6. Add challenge sweeper that emits `challenge_expired_unsolved` for open entries past TTL.
7. Add read APIs + CLI wrapper (`cfm webtop history ...` optional).

---

## Operational notes

- keep writes non-blocking enough (buffered channel + writer goroutine)
- bounded payload JSON size
- periodic retention cleanup (e.g. keep last N days)
- export endpoint supports `format=json` and deterministic ordering (`ts desc`)

### Retention, prune, truncate (SQLite)

Yes — SQLite can support all three cleanly:

1. **Keep only last X days** (recommended default policy)

   Example (keep 30 days):

   ```sql
   DELETE FROM events
   WHERE ts_unix < strftime('%s', 'now', '-30 days');
   ```

   Run this on a schedule (e.g. hourly or daily), then reclaim space:

   ```sql
   PRAGMA wal_checkpoint(TRUNCATE);
   PRAGMA optimize;
   ```

   Notes:
   - This gives ClickHouse-like TTL behavior at app level.
   - In WAL mode, file size may not drop immediately unless checkpoint/compaction runs.

2. **Prune action** (manual or API-triggered)

   Expose an admin action like:

   - `cfm webtop history prune --days 30`
   - or `POST /api/v1/webdetector/history/prune?days=30`

   Internally: execute the same `DELETE ... < now - X days` and return `rows_deleted`.

3. **Truncate action** (drop all history)

   SQLite has no `TRUNCATE TABLE`, but equivalent behavior is:

   ```sql
   DELETE FROM events;
   DELETE FROM sqlite_sequence WHERE name='events'; -- optional, reset AUTOINCREMENT
   PRAGMA wal_checkpoint(TRUNCATE);
   ```

   Expose as explicit destructive admin command only:

   - `cfm webtop history truncate --yes`
   - or `POST /api/v1/webdetector/history/truncate?confirm=yes`

### Suggested defaults

- `HISTORY_RETENTION_DAYS=30` (0 = disabled retention)
- `HISTORY_PRUNE_EVERY=1h` (or 24h for lower churn)
- `HISTORY_MAX_ROWS=1000000` (hard row cap, newest kept, enforced by the
  pruner in addition to the day window; 0 = uncapped. ~1M rows ≈ 150-200 MB.
  Bounds the DB on busy boxes where even a few retention days means millions
  of rows.)
- Admin/API verbs: `prune`, `truncate`, `vacuum` (optional)

Maintenance behavior (as built): the pruner deletes by time, then by row
cap; VACUUM runs only when ≥20% of pages **and** ≥8 MB sit on the freelist
(a full VACUUM rewrites the whole DB — unconditional hourly VACUUMs were
most of the history I/O); the WAL checkpoint (TRUNCATE) runs last so the
WAL file shrinks after VACUUM's writes, and `journal_size_limit=64MB` caps
the WAL between checkpoints.

This gives predictable disk usage while preserving useful recent incident context.

---


## Additional high-value additions: correlation

Yes — IP/vhost correlation is one of the most valuable next additions.

### A) IP ↔ vhost correlation graph

Persist explicit relationship events so you can answer:

- which IPs attacked/challenged multiple vhosts
- which vhosts are targeted by the same IP cluster/ASN/UA family
- whether a "solved" IP later reappears on other hosts with suspicious/block behavior

Minimal event shape (in `payload_json` or optional table):

- `corr_type`: `ip_vhost_link`
- `host`, `ip`
- `first_seen`, `last_seen`
- counters: `hits_404`, `hits_403`, `hits_403waf`, `malpath_hits`, `challenge_count`, `block_count`, `solve_count`
- enrich dimensions: `asn`, `country`, optional `ua_family`

### B) Session-like timelines per IP across hosts

Add a derived query/API returning one IP timeline across all vhosts:

- suspicious -> challenge_issued -> challenge_solved/expired -> block_trigger
- includes host transitions and elapsed times between events

Useful to detect:

- distributed probing (same IP rotating across vhosts)
- recurring bot actors that solve challenge on one host but attack another

### C) Vhost "co-target" view

Compute vhost-to-vhost similarity using shared attacking IPs in a time window.

Example metric:

- `shared_ips_24h`
- `jaccard_index = |A ∩ B| / |A ∪ B|`

This helps:

- identify campaigns affecting groups of domains
- prioritize defense changes per cluster (e.g. similar WAF/challenge tuning)

### D) Correlation-focused APIs

Add optional APIs after base history endpoints:

- `GET /api/v1/webdetector/history/correlation/ip?ip=1.2.3.4&period=7d`
- `GET /api/v1/webdetector/history/correlation/vhost?host=example.com&period=7d`
- `GET /api/v1/webdetector/history/correlation/cotarget?period=24h&min_shared=5`

### E) Practical implementation approach

1. Start event-only in SQLite (no complex graph DB needed).
2. Build correlation from indexed SQL queries/materialized rollups.
3. Add periodic rollup table for speed if needed:

```sql
CREATE TABLE IF NOT EXISTS ip_vhost_rollup (
  day TEXT NOT NULL,           -- YYYY-MM-DD UTC
  host TEXT NOT NULL,
  ip TEXT NOT NULL,
  suspicious_count INTEGER NOT NULL DEFAULT 0,
  challenge_count  INTEGER NOT NULL DEFAULT 0,
  solved_count     INTEGER NOT NULL DEFAULT 0,
  block_count      INTEGER NOT NULL DEFAULT 0,
  waf403_count     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, host, ip)
);

CREATE INDEX IF NOT EXISTS idx_rollup_ip_day   ON ip_vhost_rollup(ip, day DESC);
CREATE INDEX IF NOT EXISTS idx_rollup_host_day ON ip_vhost_rollup(host, day DESC);
```

This stays simple/portable and gives strong forensic + campaign-level visibility.

---
## Expected outcome

After Phase 1, you can print/export per-vhost history like:

- when challenge turned on/off
- auto/manual + reasons + thresholds/score context
- which IPs were challenged, solved, expired-unsolved, or escalated
- per-IP block trigger timeline (404/403/403waf/agent/40x-combo/malpath) with thresholds
- per-vhost trigger pressure and WAF 403 timeline
- suspicious timeline (including non-actioned suspicious states)
- status code trends (404/403/500) and unique-path pressure
- IP↔vhost correlation views (co-targeted hosts, recurring IP actors, cross-host timelines)

This is enough to power both CLI incident review and WebUI incident pages, while keeping compatibility with existing logs (`cfm.challenges.log`, `cfm.waf.log`).
