# Process health

Process health is being introduced in small, independently reviewable slices.

Current as-built surface:

- `procstat.Health()` provides a cheap single-scan `/proc` summary.
- `GET /api/v1/system/process-health` exposes that summary as admin-only JSON (`system.process_health.v1`).
- MCP `process_health` exposes the same snapshot read-only with no arguments.

The snapshot is descriptive only at this stage. It reports total readable processes and threads, process-state counts (including D/Z), exact COMM-family aggregates ranked by count and aggregate RSS, and the largest direct-child fanouts. It also reports scan completeness as `scan.pids_enumerated`, `scan.pids_readable`, and `scan.pids_skipped`; a small skipped count is expected when processes exit between enumeration and reading `/proc/<pid>/stat`, while consumers can now identify a materially partial snapshot instead of assuming it was complete.

Malformed numeric stat fields are rejected and counted as skipped rather than silently entering the aggregates as zero-valued PPID/thread/RSS data. The snapshot still does not classify any value as anomalous and does not use historical baselines.

Use `process_list` for PID/family drill-down. Anomaly classification, `whats_wrong` integration, historical baselines, and service-level responsiveness checks are separate follow-up slices.
