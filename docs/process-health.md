# Process health

Process health is being introduced in small, independently reviewable slices.

Current as-built surface:

- `procstat.Health()` provides a cheap single-scan `/proc` summary.
- `GET /api/v1/system/process-health` exposes that summary as admin-only JSON (`system.process_health.v1`).
- MCP `process_health` exposes the same snapshot read-only with no arguments.

The snapshot is descriptive only at this stage. It reports total processes and threads, process-state counts (including D/Z), exact COMM-family aggregates ranked by count and aggregate RSS, and the largest direct-child fanouts. It does not classify any value as anomalous yet and does not use historical baselines.

Use `process_list` for PID/family drill-down. Anomaly classification, `whats_wrong` integration, historical baselines, and service-level responsiveness checks are separate follow-up slices.
