# Process health

Process health is being introduced in small, independently reviewable slices.

Current as-built surface:

- `procstat.Health()` provides a cheap single-scan `/proc` summary.
- `GET /api/v1/system/process-health` exposes that summary as admin-only JSON (`system.process_health.v1`).
- MCP `process_health` exposes the same snapshot read-only with no arguments.
- MCP `whats_wrong` consumes the endpoint's existing evaluation as a first-class triage source; it does not re-run process thresholds.

The snapshot reports total readable processes and threads, process-state counts (including D/Z), exact COMM-family aggregates ranked by count and aggregate RSS, and the largest direct-child fanouts. Each family aggregate also carries its own `states` breakdown, and `top_families_by_state` gives a separately bounded ranking for every observed process state. This means a small D- or Z-state family remains attributable even when it is not large enough to appear in the global top-by-count or top-by-RSS lists.

It also reports scan completeness as `scan.pids_enumerated`, `scan.pids_readable`, and `scan.pids_skipped`; a small skipped count is expected when processes exit between enumeration and reading `/proc/<pid>/stat`, while consumers can identify a materially partial snapshot instead of assuming it was complete. Malformed numeric stat fields are rejected and counted as skipped rather than silently entering the aggregates as zero-valued PPID/thread/RSS data.

## Conservative single-snapshot evaluation

The same endpoint now returns an additive `evaluation` object with `status=ok|issues|degraded`, `reliable`, and bounded findings. This first evaluator deliberately covers only process states that are generically pathological when they accumulate and can be judged conservatively without history:

- **D-state pileup**: warning only when both `D >= 8` and `D >= 2%` of readable processes; critical only when both `D >= 32` and `D >= 10%`.
- **Zombie accumulation**: warning only when both `Z >= 16` and `Z >= 1%` of readable processes; critical only when both `Z >= 64` and `Z >= 5%`.
- Findings include up to the top three contributing COMM families from `top_families_by_state` so the verdict is immediately attributable.

The count **and** ratio gates must both pass. They are intentionally high because this is a single snapshot, not a sustained/baseline detector. A few transient D-state tasks or zombies therefore do not become findings.

The evaluator refuses to make a healthy/unhealthy verdict when the snapshot is materially incomplete or internally inconsistent. In particular, `evaluation.status=degraded` and `reliable=false` when scan/state accounting is inconsistent, or when at least 3 enumerated PIDs were skipped **and** skipped PIDs are at least 10% of the enumeration. A degraded evaluation emits no anomaly findings; callers must not interpret it as healthy.

Deliberately still **not** classified from a single snapshot: raw COMM-family counts, family dominance, direct-child fanout, aggregate RSS, or total process count. Those are workload-dependent and remain descriptive until historical baselines make them safe to judge.

## `whats_wrong` integration

`whats_wrong` fetches `/api/v1/system/process-health` concurrently with its existing host/service/database/mail/security sources and maps only the endpoint's already-classified `evaluation` into the triage result:

- reliable D/Z findings keep their upstream warning/critical severity;
- the top contributing COMM family becomes a direct `process_list(match=..., details=true)` drill-down when available;
- `evaluation.status=degraded`, an unreliable evaluation, or a semantically inconsistent evaluation becomes a **warning** and marks `sources.process_health` as `degraded: ...`;
- therefore a materially partial process snapshot cannot leave the flagship result looking healthy.

This layer deliberately contains no duplicate D/Z thresholds and does not inspect the raw family/fanout/RSS counts.

## Rolling baseline storage, sampling, and descriptive statistics

`internal/procbaseline` now provides the persistence, sampling, daemon lifecycle, and descriptive statistics for a later historical process-count detector. The daemon starts collection best-effort against `/var/lib/cfm/processbaseline.db`; failure to open the store is logged and does not block CFM startup. The statistics layer still does not change any current process-health verdict.

- SQLite-backed minute buckets store only total readable process count plus exact COMM-family counts; there is no PID, argv, username, or other per-process history.
- One minute is a **snapshot**, not an additive counter. A retry in the same minute atomically replaces the whole bucket so stale families cannot survive.
- Family counts must sum exactly to the sample's total process count; malformed/incomplete samples are rejected before storage.
- A family absent from a valid host sample is represented as `count=0` when its series is read. A minute for which no valid sample exists remains a telemetry gap instead of becoming a fake zero.
- Retention is bounded to **72 hours**. Three days preserves minute-resolution recent host history while materially reducing row/index growth compared with week-scale retention on busy shared hosts.
- Retention pruning is transactional with each write and explicitly removes both sample and family rows; no background maintenance goroutine is required.
- `procstat.HealthWithFamilyCounts()` returns the existing bounded health summary plus the **complete** exact-COMM count map from the same single `/proc` scan. The full map is internal-only and does not expand the HTTP/MCP JSON surface.
- `procbaseline.Collector` samples immediately and then once per minute via `Run(ctx)`, with normal context cancellation.
- A sample is persisted only when the existing `procstat.EvaluateHealth(...).Reliable` contract is true. Materially partial/inconsistent scans become telemetry gaps rather than learned zeros.
- A reliable snapshot that contains a D/Z finding is still persisted: anomaly presence is real workload data; `Reliable=false` is the criterion for whether the observation itself is safe to learn from.
- Read/store failures do not terminate the collector loop; the failed minute is left as a gap and the next interval is attempted normally.
- `procbaseline.Lifecycle` owns the child context, collector goroutine, and SQLite store; shutdown is ordered as cancel sampler → wait for collector exit → close SQLite, and repeated close calls are safe.
- `Store.FamilyStats(comm, start, end)` derives a descriptive summary from an explicit half-open history window: valid sample count, expected minute buckets, coverage fraction, present/non-zero sample count, median, nearest-rank p95, and maximum process count.
- Valid host samples where a family is absent (`count=0`) participate in median/p95 normally. Missing host samples do **not** enter the distribution as zeroes; they only reduce coverage.
- The statistics layer deliberately applies **no** minimum sample count, minimum coverage, baseline floor, ratio threshold, absolute-delta threshold, or sustained-duration rule. Those belong to the later policy/evaluation layer.

The next slice can add conservative history-sufficiency gates and current-vs-baseline comparison semantics on top of these descriptive values. Sustained anomaly verdicts and process-health/API/MCP integration remain separate follow-up work, as do service-level protocol responsiveness checks.
